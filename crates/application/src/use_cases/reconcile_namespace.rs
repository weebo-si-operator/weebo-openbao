//! An `OpenbaoNamespace` (RFC 0007 §4.2): the namespace, a KV v2 mount per
//! type, its auth backends (enabled, configured, the OIDC `default` role),
//! and the personal spaces' policy of a `users` namespace. Created in that
//! order; nothing is ever disabled or deleted here: what is no longer
//! declared stays, as an advisory.

use std::collections::BTreeMap;

use api::access::UsersSpaces;
use api::namespace::{AuthBackend, SpaceType};
use domain::Failure;
use domain::RemoteWrite;
use domain::error::ReasonCode;
use domain::policy;

use crate::ports::{OidcConfig, OidcRole, OpenbaoError, SpaceAdmin};
use crate::use_cases::Outcome;

/// The `managed-by` mark in a description this operator wrote.
pub const MARK: &str = "managed-by weebo-openbao";

/// What the controller read for the reconcile, besides the CR's spec.
pub struct NamespaceInput<'a> {
    pub name: &'a str,
    pub types: &'a [SpaceType],
    pub auth: &'a [AuthBackend],
    /// The instance's `bounds.namespaces`.
    pub bounds: &'a [String],
    /// Per OIDC backend: its client secret and that secret's digest.
    pub client_secrets: &'a BTreeMap<String, (String, String)>,
    /// Per OIDC backend: the digest of the client secret last written.
    pub written_digests: &'a BTreeMap<String, String>,
    /// The layout's personal spaces, for a `users` namespace.
    pub users: Option<&'a UsersSpaces>,
    /// `Kind/name` of every organization and grant that exists: an object
    /// marked for another owner is left over (decision 20).
    pub live_owners: &'a std::collections::BTreeSet<String>,
    /// `allow-disruptive-update` on the namespace: left-over objects are
    /// removed (alias, group, policy), not only reported.
    pub allow_disruptive: bool,
}

/// An auth backend as it ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthReport {
    pub name: String,
    pub kind: String,
    pub accessor: String,
    pub client_secret_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceReport {
    pub outcome: Outcome,
    pub auth: Vec<AuthReport>,
    pub orphaned_mounts: Vec<String>,
    pub orphaned_auth: Vec<String>,
    /// Policies and groups marked for an organization or a grant that no
    /// longer exists (`policy <name>`, `group <name>`).
    pub left_over: Vec<String>,
}

impl NamespaceReport {
    fn failed(failure: impl Into<Failure>) -> Self {
        Self {
            outcome: Outcome::failed(failure),
            auth: vec![],
            orphaned_mounts: vec![],
            orphaned_auth: vec![],
            left_over: vec![],
        }
    }
}

pub async fn reconcile_namespace(
    admin: &dyn SpaceAdmin,
    input: &NamespaceInput<'_>,
) -> NamespaceReport {
    match run(admin, input).await {
        Ok(report) => report,
        Err(failure) => NamespaceReport::failed(failure),
    }
}

fn kind_of(backend: &AuthBackend) -> &'static str {
    if backend.oidc.is_some() {
        "oidc"
    } else {
        "kubernetes"
    }
}

async fn run(
    admin: &dyn SpaceAdmin,
    input: &NamespaceInput<'_>,
) -> Result<NamespaceReport, Failure> {
    let ns = input.name;
    let owner = format!("OpenbaoNamespace/{ns}");
    if !input.bounds.iter().any(|b| b == ns) {
        return Err(Failure::new(
            ReasonCode::OutOfBounds,
            format!("namespace {ns:?} is not in the instance's bounds.namespaces"),
        ));
    }
    let mut write = None;
    if !admin.namespace_exists(ns).await? {
        admin.create_namespace(ns, &owner).await?;
        write = Some(RemoteWrite::Created);
    }

    // A KV v2 mount per type; `kv` with version 2 is what OpenBao lists.
    let mounts = admin.mounts(ns).await?;
    for space in input.types {
        match mounts.get(space.mount()) {
            None => {
                admin.enable_kv2(ns, space.mount(), &owner).await?;
                write = Some(RemoteWrite::Created);
            }
            Some(m) if m.kind != "kv" => {
                return Err(Failure::new(
                    ReasonCode::MountTypeMismatch,
                    format!(
                        "mount {:?} of {ns} is a {} engine, not KV v2",
                        space.mount(),
                        m.kind
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    let orphaned_mounts: Vec<String> = [SpaceType::Orgs, SpaceType::Users]
        .into_iter()
        .filter(|t| !input.types.contains(t) && mounts.contains_key(t.mount()))
        .map(|t| t.mount().to_string())
        .collect();

    // The auth backends: enabled, then their accessors read back.
    let mut backends = admin.auth_backends(ns).await?;
    let mut enabled = Vec::new();
    for backend in input.auth {
        let kind = kind_of(backend);
        match backends.get(&backend.name) {
            None => {
                admin.enable_auth(ns, &backend.name, kind, &owner).await?;
                enabled.push(backend.name.clone());
            }
            Some(m) if m.kind != kind => {
                return Err(Failure::new(
                    ReasonCode::MountTypeMismatch,
                    format!(
                        "auth backend {:?} of {ns} is {}, not {kind}",
                        backend.name, m.kind
                    ),
                ));
            }
            Some(_) => {}
        }
    }
    if !enabled.is_empty() {
        backends = admin.auth_backends(ns).await?;
        write = Some(RemoteWrite::Created);
    }

    let users = input.types.contains(&SpaceType::Users);
    let mut reports = Vec::new();
    let mut failure: Option<Failure> = None;
    for backend in input.auth {
        let accessor = backends
            .get(&backend.name)
            .map(|m| m.accessor.clone())
            .unwrap_or_default();
        let mut report = AuthReport {
            name: backend.name.clone(),
            kind: kind_of(backend).into(),
            accessor,
            client_secret_digest: input.written_digests.get(&backend.name).cloned(),
        };
        if let Some(oidc) = &backend.oidc {
            let Some((secret, digest)) = input.client_secrets.get(&backend.name) else {
                failure.get_or_insert_with(|| {
                    Failure::new(
                        ReasonCode::SecretUnavailable,
                        format!(
                            "backend {:?}: the Secret {:?} (key {:?}) is not in the operator's namespace",
                            backend.name, oidc.client_secret_ref.name, oidc.client_secret_ref.key
                        ),
                    )
                });
                reports.push(report);
                continue;
            };
            // The secret can't be read back: its digest tells a change.
            if report.client_secret_digest.as_ref() != Some(digest) {
                let config = OidcConfig {
                    discovery_url: oidc.discovery_url.clone(),
                    client_id: oidc.client_id.clone(),
                    client_secret: secret.clone(),
                    default_role: "default".into(),
                };
                match admin.write_oidc_config(ns, &backend.name, &config).await {
                    Ok(()) => {
                        report.client_secret_digest = Some(digest.clone());
                        write.get_or_insert(RemoteWrite::Drift);
                    }
                    Err(OpenbaoError::Rejected(m)) => {
                        failure.get_or_insert_with(|| {
                            Failure::new(
                                ReasonCode::AuthConfigRejected,
                                format!("backend {:?}: {m}", backend.name),
                            )
                        });
                        reports.push(report);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            let mut claim_mappings = BTreeMap::new();
            if users && let Some(u) = input.users {
                claim_mappings.insert(u.username_claim.clone(), u.alias_metadata_key.clone());
            }
            let desired = OidcRole {
                user_claim: oidc.user_claim.clone(),
                groups_claim: oidc.groups_claim.clone(),
                scopes: oidc.scopes.clone(),
                redirect_uris: oidc.redirect_uris.clone(),
                bound_audiences: vec![oidc.client_id.clone()],
                claim_mappings,
                token_policy: users.then(|| "user_space".to_string()),
                token_ttl_seconds: oidc.token_ttl_seconds,
                token_max_ttl_seconds: oidc.token_max_ttl_seconds,
            };
            if admin
                .read_oidc_role(ns, &backend.name, "default")
                .await?
                .as_ref()
                != Some(&desired)
            {
                admin
                    .write_oidc_role(ns, &backend.name, "default", &desired)
                    .await?;
                write.get_or_insert(RemoteWrite::Drift);
            }
        } else if enabled.contains(&backend.name) {
            admin.write_kubernetes_config(ns, &backend.name).await?;
        }
        reports.push(report);
    }

    // The personal spaces' policy, on every OIDC backend's accessor.
    if users {
        let Some(spaces) = input.users else {
            return Err(Failure::new(
                ReasonCode::InvalidSpec,
                format!(
                    "namespace {ns} has the type users, but no OpenbaoSpaceLayout of its instance declares users"
                ),
            ));
        };
        let accessors: Vec<&str> = reports
            .iter()
            .filter(|r| r.kind == "oidc" && !r.accessor.is_empty())
            .map(|r| r.accessor.as_str())
            .collect();
        let text = policy::render_user_space(&owner, &accessors, &spaces.alias_metadata_key)
            .map_err(|e| Failure::new(ReasonCode::InvalidSpec, e.to_string()))?;
        match admin.read_policy(ns, "user_space").await? {
            Some(current) if !policy::is_owned_by(&current, &owner) => {
                return Err(Failure::new(
                    ReasonCode::NotOwned,
                    format!("policy user_space of {ns} is not this namespace's: left alone"),
                ));
            }
            Some(current) if current == text => {}
            _ => {
                admin.write_policy(ns, "user_space", &text).await?;
                write.get_or_insert(RemoteWrite::Drift);
            }
        }
    }

    let declared: Vec<&str> = input.auth.iter().map(|b| b.name.as_str()).collect();
    let orphaned_auth: Vec<String> = backends
        .iter()
        .filter(|(name, m)| m.description.starts_with(MARK) && !declared.contains(&name.as_str()))
        .map(|(name, _)| name.clone())
        .collect();

    let left_over = left_overs(admin, ns, input).await?;
    if input.allow_disruptive && !left_over.is_empty() {
        write = Some(RemoteWrite::Deleted);
    }

    let mut outcome = match failure {
        Some(f) => Outcome::failed(f),
        None => Outcome::synced(None, format!("namespace {ns} in place")),
    };
    outcome.write = write;
    for object in &left_over {
        let what = if input.allow_disruptive {
            "removed"
        } else {
            "left in place"
        };
        outcome = outcome.advise(
            ReasonCode::LeftOver,
            format!("{object} of {ns} belongs to no existing organization or grant: {what}"),
        );
    }
    for mount in &orphaned_mounts {
        outcome = outcome.advise(
            ReasonCode::MountOrphaned,
            format!("mount {mount} of {ns} is no longer declared: left with its secrets"),
        );
    }
    for backend in &orphaned_auth {
        outcome = outcome.advise(
            ReasonCode::AuthOrphaned,
            format!("auth backend {backend} of {ns} is no longer declared: left enabled"),
        );
    }
    Ok(NamespaceReport {
        outcome,
        auth: reports,
        orphaned_mounts,
        orphaned_auth,
        left_over,
    })
}

/// The owner a policy's first line names, if it is this operator's mark.
fn policy_owner(text: &str) -> Option<&str> {
    text.lines()
        .next()?
        .strip_prefix("# managed-by: weebo-openbao owner: ")
}

/// Decision 20: the `org_*` and `grant_*` policies and the `org_*` groups
/// of `ns` marked for an owner that no longer exists, removed (alias,
/// group, then policy) under `allow_disruptive`. Names only are listed.
async fn left_overs(
    admin: &dyn SpaceAdmin,
    ns: &str,
    input: &NamespaceInput<'_>,
) -> Result<Vec<String>, Failure> {
    let dead = |owner: &str| {
        (owner.starts_with("OpenbaoOrganization/") || owner.starts_with("OpenbaoAccessGrant/"))
            && !input.live_owners.contains(owner)
    };
    let mut left = Vec::new();
    for name in admin.list_groups(ns).await? {
        if !name.starts_with("org_") {
            continue;
        }
        let Some(group) = admin.read_group(ns, &name).await? else {
            continue;
        };
        let marked = group.metadata.get("managed-by").map(String::as_str) == Some("weebo-openbao");
        if marked && group.metadata.get("owner").is_some_and(|o| dead(o)) {
            if input.allow_disruptive {
                if let Some(alias) = &group.alias {
                    admin.delete_group_alias(ns, &alias.id).await?;
                }
                admin.delete_group(ns, &name).await?;
            }
            left.push(format!("group {name}"));
        }
    }
    for name in admin.list_policies(ns).await? {
        if !(name.starts_with("org_") || name.starts_with("grant_")) {
            continue;
        }
        let Some(text) = admin.read_policy(ns, &name).await? else {
            continue;
        };
        if policy_owner(&text).is_some_and(dead) {
            if input.allow_disruptive {
                admin.delete_policy(ns, &name).await?;
            }
            left.push(format!("policy {name}"));
        }
    }
    Ok(left)
}

#[cfg(test)]
mod tests {
    use api::namespace::{KubernetesAuth, OidcAuth};
    use weebo_kit_api::LocalSecretKeyRef;

    use super::*;
    use crate::test_support::FakeSpaceAdmin;

    fn oidc(name: &str) -> AuthBackend {
        AuthBackend {
            name: name.into(),
            oidc: Some(OidcAuth {
                discovery_url: "https://auth.example/".into(),
                client_id: "openbao".into(),
                client_secret_ref: LocalSecretKeyRef {
                    name: "openbao-oidc".into(),
                    key: "client-secret".into(),
                },
                scopes: vec!["openid".into(), "groups".into()],
                user_claim: "sub".into(),
                groups_claim: "groups".into(),
                redirect_uris: vec!["http://localhost:8250/oidc/callback".into()],
                token_ttl_seconds: 3_600,
                token_max_ttl_seconds: 28_800,
            }),
            kubernetes: None,
        }
    }

    fn kube(name: &str) -> AuthBackend {
        AuthBackend {
            name: name.into(),
            oidc: None,
            kubernetes: Some(KubernetesAuth {}),
        }
    }

    struct Fixture {
        live: std::collections::BTreeSet<String>,
        bounds: Vec<String>,
        secrets: BTreeMap<String, (String, String)>,
        users: UsersSpaces,
    }

    fn fixture() -> Fixture {
        Fixture {
            live: std::collections::BTreeSet::from(["OpenbaoOrganization/acme".to_string()]),
            bounds: vec!["prod".into(), "users".into()],
            secrets: BTreeMap::from([("authentik".into(), ("s3cret".into(), "sha-1".into()))]),
            users: UsersSpaces {
                username_claim: "preferred_username".into(),
                alias_metadata_key: "username".into(),
            },
        }
    }

    fn input<'a>(
        f: &'a Fixture,
        name: &'a str,
        types: &'a [SpaceType],
        auth: &'a [AuthBackend],
        digests: &'a BTreeMap<String, String>,
    ) -> NamespaceInput<'a> {
        NamespaceInput {
            name,
            types,
            auth,
            bounds: &f.bounds,
            client_secrets: &f.secrets,
            written_digests: digests,
            users: Some(&f.users),
            live_owners: &f.live,
            allow_disruptive: false,
        }
    }

    #[tokio::test]
    async fn a_namespace_is_built_in_order_then_stays_quiet() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        let auth = [oidc("authentik"), kube("kubernetes")];
        let none = BTreeMap::new();
        let report =
            reconcile_namespace(&admin, &input(&f, "prod", &[SpaceType::Orgs], &auth, &none)).await;
        assert_eq!(
            report.outcome.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            report.outcome
        );
        assert_eq!(
            admin.writes(),
            [
                "create namespace prod",
                "enable kv2 prod/orgs",
                "enable auth prod/authentik",
                "enable auth prod/kubernetes",
                "write oidc config prod/authentik",
                "write oidc role prod/authentik/default",
                "write kubernetes config prod/kubernetes",
            ]
        );
        let role = admin.namespace("prod").unwrap().oidc_roles
            [&("authentik".into(), "default".into())]
            .clone();
        assert_eq!(
            role.token_policy, None,
            "no policy on the role outside a users namespace"
        );
        assert_eq!(role.bound_audiences, ["openbao"]);
        // The second pass, with the digest the status now records: no write.
        let digests = BTreeMap::from([("authentik".into(), "sha-1".into())]);
        admin.clear_writes();
        let again = reconcile_namespace(
            &admin,
            &input(&f, "prod", &[SpaceType::Orgs], &auth, &digests),
        )
        .await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(admin.writes(), Vec::<String>::new());
        assert_eq!(again.outcome.write, None);
    }

    #[tokio::test]
    async fn out_of_bounds_calls_nothing() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        let none = BTreeMap::new();
        let report =
            reconcile_namespace(&admin, &input(&f, "autre", &[SpaceType::Orgs], &[], &none)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::OutOfBounds);
        assert!(admin.writes().is_empty());
    }

    #[tokio::test]
    async fn a_users_namespace_gets_user_space_on_its_oidc_role_and_policy() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        let auth = [oidc("authentik")];
        let none = BTreeMap::new();
        let report = reconcile_namespace(
            &admin,
            &input(&f, "users", &[SpaceType::Users], &auth, &none),
        )
        .await;
        assert_eq!(
            report.outcome.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            report.outcome
        );
        let state = admin.namespace("users").unwrap();
        let role = &state.oidc_roles[&("authentik".into(), "default".into())];
        assert_eq!(role.token_policy.as_deref(), Some("user_space"));
        assert_eq!(role.claim_mappings["preferred_username"], "username");
        assert!(
            state.policies["user_space"].contains("auth_oidc_users_authentik.metadata.username")
        );
    }

    #[tokio::test]
    async fn a_policy_made_by_hand_is_not_written_over() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        admin.edit("users", |n| {
            n.policies.insert(
                "user_space".into(),
                "path \"*\" { capabilities = [\"read\"] }\n".into(),
            );
        });
        let auth = [oidc("authentik")];
        let none = BTreeMap::new();
        let report = reconcile_namespace(
            &admin,
            &input(&f, "users", &[SpaceType::Users], &auth, &none),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::NotOwned);
        assert!(!admin.writes().iter().any(|w| w.starts_with("write policy")));
    }

    #[tokio::test]
    async fn a_missing_secret_or_a_mount_of_another_type_fails_closed() {
        let mut f = fixture();
        f.secrets.clear();
        let admin = FakeSpaceAdmin::default();
        let auth = [oidc("authentik")];
        let none = BTreeMap::new();
        let report =
            reconcile_namespace(&admin, &input(&f, "prod", &[SpaceType::Orgs], &auth, &none)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::SecretUnavailable);
        assert!(!admin.writes().iter().any(|w| w.starts_with("write oidc")));

        let admin = FakeSpaceAdmin::default();
        admin.edit("prod", |n| {
            n.mounts.insert(
                "orgs".into(),
                crate::ports::Mounted {
                    kind: "kv1".into(),
                    accessor: "x".into(),
                    description: String::new(),
                },
            );
        });
        let report = reconcile_namespace(
            &admin,
            &input(&fixture(), "prod", &[SpaceType::Orgs], &[], &none),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::MountTypeMismatch);
    }

    #[tokio::test]
    async fn what_is_no_longer_declared_stays_as_an_advisory() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        let none = BTreeMap::new();
        let both = [oidc("authentik")];
        reconcile_namespace(
            &admin,
            &input(
                &f,
                "prod",
                &[SpaceType::Orgs, SpaceType::Users],
                &both,
                &none,
            ),
        )
        .await;
        admin.edit("prod", |n| {
            if let Some(b) = n.auth.get_mut("authentik") {
                b.description = format!("{MARK} owner OpenbaoNamespace/prod");
            }
        });
        admin.clear_writes();
        let report =
            reconcile_namespace(&admin, &input(&f, "prod", &[SpaceType::Orgs], &[], &none)).await;
        assert_eq!(report.orphaned_mounts, ["users"]);
        assert_eq!(report.orphaned_auth, ["authentik"]);
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(report.outcome.advisories.len(), 2);
        assert!(
            admin.writes().is_empty(),
            "nothing disabled: {:?}",
            admin.writes()
        );
    }

    #[tokio::test]
    async fn left_overs_are_reported_then_removed_when_allowed() {
        let f = fixture();
        let admin = FakeSpaceAdmin::default();
        let mark = |owner: &str| {
            BTreeMap::from([
                ("managed-by".to_string(), "weebo-openbao".to_string()),
                ("owner".to_string(), owner.to_string()),
            ])
        };
        admin.edit("prod", |n| {
            n.policies.insert(
                "org_gone_dev".into(),
                "# managed-by: weebo-openbao owner: OpenbaoOrganization/gone\n".into(),
            );
            n.policies.insert(
                "org_acme_dev".into(),
                "# managed-by: weebo-openbao owner: OpenbaoOrganization/acme\n".into(),
            );
            n.policies
                .insert("org_by_hand".into(), "path \"x\" {}\n".into());
            n.groups.insert(
                "org_gone_dev_idp".into(),
                crate::ports::Group {
                    id: "g".into(),
                    policies: vec!["org_gone_dev".into()],
                    metadata: mark("OpenbaoOrganization/gone"),
                    alias: Some(crate::ports::GroupAlias {
                        id: "a".into(),
                        name: "gone_dev".into(),
                        mount_accessor: "x".into(),
                    }),
                },
            );
        });
        let none = BTreeMap::new();
        let mut input = input(&f, "prod", &[SpaceType::Orgs], &[], &none);
        let report = reconcile_namespace(&admin, &input).await;
        assert_eq!(
            report.left_over,
            ["group org_gone_dev_idp", "policy org_gone_dev"]
        );
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert!(
            admin
                .namespace("prod")
                .unwrap()
                .policies
                .contains_key("org_gone_dev"),
            "only reported"
        );
        input.allow_disruptive = true;
        admin.clear_writes();
        reconcile_namespace(&admin, &input).await;
        let writes = admin.writes();
        assert_eq!(
            writes,
            [
                "delete alias prod/a",
                "delete group prod/org_gone_dev_idp",
                "delete policy prod/org_gone_dev"
            ]
        );
        let state = admin.namespace("prod").unwrap();
        assert!(
            state.policies.contains_key("org_acme_dev")
                && state.policies.contains_key("org_by_hand")
        );
    }
}
