//! In-memory [`SpaceAdmin`] for use-case and controller tests (exposed to
//! other crates by the `test-support` feature).

// A test double, only built for tests (`cfg(test)` or the `test-support`
// feature): a poisoned lock fails the test.
#![expect(clippy::unwrap_used, reason = "test double: a panic is a failed test")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::space::{
    Group, GroupAlias, GroupSpec, KubernetesRole, Mounted, OidcConfig, OidcRole, OpenbaoError,
    SpaceAdmin, SpaceAdminFactory, SpaceAdminFactoryError,
};

/// One OpenBao namespace's objects.
#[derive(Default, Clone, Debug)]
pub struct FakeNamespace {
    pub mounts: BTreeMap<String, Mounted>,
    pub auth: BTreeMap<String, Mounted>,
    pub oidc_configs: BTreeMap<String, OidcConfig>,
    pub kubernetes_configured: BTreeSet<String>,
    pub oidc_roles: BTreeMap<(String, String), OidcRole>,
    pub kubernetes_roles: BTreeMap<(String, String), KubernetesRole>,
    pub policies: BTreeMap<String, String>,
    pub groups: BTreeMap<String, Group>,
}

/// An OpenBao in memory. Ids are handed out in creation order; every write
/// is recorded ([`FakeSpaceAdmin::writes`]): a reconcile with nothing to
/// change must leave it empty.
#[derive(Default)]
pub struct FakeSpaceAdmin {
    namespaces: Mutex<BTreeMap<String, FakeNamespace>>,
    next_id: Mutex<u64>,
    failure: Mutex<Option<OpenbaoError>>,
    writes: Mutex<Vec<String>>,
}

impl FakeSpaceAdmin {
    /// Every call fails with `failure` until it is set back to `None`.
    pub fn fail_with(&self, failure: Option<OpenbaoError>) {
        *self.failure.lock().unwrap() = failure;
    }

    /// The writes so far, as `<op> <ns>/<what>`.
    pub fn writes(&self) -> Vec<String> {
        self.writes.lock().unwrap().clone()
    }

    pub fn clear_writes(&self) {
        self.writes.lock().unwrap().clear();
    }

    /// A namespace's state, to assert on or edit (a drift, a hand-made
    /// object).
    pub fn namespace(&self, ns: &str) -> Option<FakeNamespace> {
        self.namespaces.lock().unwrap().get(ns).cloned()
    }

    pub fn edit(&self, ns: &str, edit: impl FnOnce(&mut FakeNamespace)) {
        edit(
            self.namespaces
                .lock()
                .unwrap()
                .entry(ns.into())
                .or_default(),
        );
    }

    fn fail(&self) -> Result<(), OpenbaoError> {
        match self.failure.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn write(&self, what: String) {
        self.writes.lock().unwrap().push(what);
    }

    fn id(&self) -> String {
        let mut next = self.next_id.lock().unwrap();
        *next = next.saturating_add(1);
        format!("id-{next}")
    }

    fn read<T>(&self, ns: &str, f: impl FnOnce(&FakeNamespace) -> T) -> Result<T, OpenbaoError> {
        self.fail()?;
        Ok(f(&self
            .namespaces
            .lock()
            .unwrap()
            .get(ns)
            .cloned()
            .unwrap_or_default()))
    }

    fn modify<T>(
        &self,
        ns: &str,
        what: String,
        f: impl FnOnce(&mut FakeNamespace) -> T,
    ) -> Result<T, OpenbaoError> {
        self.fail()?;
        self.write(what);
        Ok(f(self
            .namespaces
            .lock()
            .unwrap()
            .entry(ns.into())
            .or_default()))
    }
}

#[async_trait::async_trait]
impl SpaceAdmin for FakeSpaceAdmin {
    async fn check(&self) -> Result<(), OpenbaoError> {
        self.fail()
    }

    async fn namespace_exists(&self, ns: &str) -> Result<bool, OpenbaoError> {
        self.fail()?;
        Ok(self.namespaces.lock().unwrap().contains_key(ns))
    }

    async fn create_namespace(&self, ns: &str, _owner: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("create namespace {ns}"), |_| ())
    }

    async fn mounts(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError> {
        self.read(ns, |n| n.mounts.clone())
    }

    async fn enable_kv2(&self, ns: &str, path: &str, _owner: &str) -> Result<(), OpenbaoError> {
        let mounted = Mounted {
            kind: "kv".into(),
            accessor: format!("kv_{path}"),
            description: String::new(),
        };
        self.modify(ns, format!("enable kv2 {ns}/{path}"), |n| {
            n.mounts.insert(path.into(), mounted);
        })
    }

    async fn auth_backends(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError> {
        self.read(ns, |n| n.auth.clone())
    }

    async fn enable_auth(
        &self,
        ns: &str,
        path: &str,
        kind: &str,
        _owner: &str,
    ) -> Result<(), OpenbaoError> {
        let mounted = Mounted {
            kind: kind.into(),
            accessor: format!("auth_{kind}_{ns}_{path}"),
            description: String::new(),
        };
        self.modify(ns, format!("enable auth {ns}/{path}"), |n| {
            n.auth.insert(path.into(), mounted);
        })
    }

    async fn write_oidc_config(
        &self,
        ns: &str,
        backend: &str,
        config: &OidcConfig,
    ) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("write oidc config {ns}/{backend}"), |n| {
            n.oidc_configs.insert(backend.into(), config.clone());
        })
    }

    async fn read_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<OidcRole>, OpenbaoError> {
        self.read(ns, |n| {
            n.oidc_roles.get(&(backend.into(), role.into())).cloned()
        })
    }

    async fn write_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &OidcRole,
    ) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("write oidc role {ns}/{backend}/{role}"), |n| {
            n.oidc_roles
                .insert((backend.into(), role.into()), spec.clone());
        })
    }

    async fn write_kubernetes_config(&self, ns: &str, backend: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("write kubernetes config {ns}/{backend}"), |n| {
            n.kubernetes_configured.insert(backend.into());
        })
    }

    async fn read_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<KubernetesRole>, OpenbaoError> {
        self.read(ns, |n| {
            n.kubernetes_roles
                .get(&(backend.into(), role.into()))
                .cloned()
        })
    }

    async fn write_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &KubernetesRole,
    ) -> Result<(), OpenbaoError> {
        self.modify(
            ns,
            format!("write kubernetes role {ns}/{backend}/{role}"),
            |n| {
                n.kubernetes_roles
                    .insert((backend.into(), role.into()), spec.clone());
            },
        )
    }

    async fn delete_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<(), OpenbaoError> {
        self.modify(
            ns,
            format!("delete kubernetes role {ns}/{backend}/{role}"),
            |n| {
                n.kubernetes_roles.remove(&(backend.into(), role.into()));
            },
        )
    }

    async fn list_policies(&self, ns: &str) -> Result<Vec<String>, OpenbaoError> {
        self.read(ns, |n| n.policies.keys().cloned().collect())
    }

    async fn read_policy(&self, ns: &str, name: &str) -> Result<Option<String>, OpenbaoError> {
        self.read(ns, |n| n.policies.get(name).cloned())
    }

    async fn write_policy(&self, ns: &str, name: &str, text: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("write policy {ns}/{name}"), |n| {
            n.policies.insert(name.into(), text.into());
        })
    }

    async fn delete_policy(&self, ns: &str, name: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("delete policy {ns}/{name}"), |n| {
            n.policies.remove(name);
        })
    }

    async fn list_groups(&self, ns: &str) -> Result<Vec<String>, OpenbaoError> {
        self.read(ns, |n| n.groups.keys().cloned().collect())
    }

    async fn read_group(&self, ns: &str, name: &str) -> Result<Option<Group>, OpenbaoError> {
        self.read(ns, |n| n.groups.get(name).cloned())
    }

    async fn write_group(
        &self,
        ns: &str,
        name: &str,
        spec: &GroupSpec,
    ) -> Result<String, OpenbaoError> {
        let fresh = self.id();
        self.modify(ns, format!("write group {ns}/{name}"), |n| {
            let group = n.groups.entry(name.into()).or_insert_with(|| Group {
                id: fresh,
                policies: vec![],
                metadata: BTreeMap::new(),
                alias: None,
            });
            group.policies = vec![spec.policy.clone()];
            group.metadata = spec.metadata.clone();
            group.id.clone()
        })
    }

    async fn delete_group(&self, ns: &str, name: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("delete group {ns}/{name}"), |n| {
            n.groups.remove(name);
        })
    }

    async fn write_group_alias(
        &self,
        ns: &str,
        id: Option<&str>,
        alias: &GroupAlias,
        canonical_id: &str,
    ) -> Result<String, OpenbaoError> {
        let alias_id = id.map_or_else(|| self.id(), String::from);
        self.modify(ns, format!("write alias {ns}/{}", alias.name), |n| {
            // OpenBao gives a group one alias: a new one replaces it.
            if let Some(group) = n.groups.values_mut().find(|g| g.id == canonical_id) {
                group.alias = Some(GroupAlias {
                    id: alias_id.clone(),
                    ..alias.clone()
                });
            }
            alias_id
        })
    }

    async fn delete_group_alias(&self, ns: &str, id: &str) -> Result<(), OpenbaoError> {
        self.modify(ns, format!("delete alias {ns}/{id}"), |n| {
            for group in n.groups.values_mut() {
                if group.alias.as_ref().is_some_and(|a| a.id == id) {
                    group.alias = None;
                }
            }
        })
    }
}

/// Serves one [`FakeSpaceAdmin`] for every instance.
#[derive(Default)]
pub struct StaticAdminFactory {
    pub admin: Arc<FakeSpaceAdmin>,
    pub failure: Mutex<Option<SpaceAdminFactoryError>>,
}

#[async_trait::async_trait]
impl SpaceAdminFactory for StaticAdminFactory {
    async fn admin_for(
        &self,
        _instance: &str,
    ) -> Result<Arc<dyn SpaceAdmin>, SpaceAdminFactoryError> {
        match self.failure.lock().unwrap().clone() {
            Some(e) => Err(e),
            None => Ok(self.admin.clone()),
        }
    }
}
