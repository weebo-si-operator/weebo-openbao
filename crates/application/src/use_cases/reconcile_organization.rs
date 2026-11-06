//! An `OpenbaoOrganization` (RFC 0007 §5.2): for each cell of the layout
//! (role × namespace of type `orgs`), a policy `org_<org>_<role>`, then one
//! external group per OIDC backend of the namespace (decision 15:
//! `org_<org>_<role>_<backend>`, a group holds one alias), then its alias.
//!
//! The invariant: an alias is created after its group and policy and
//! deleted before them, so no state in between grants more than declared.

use std::collections::{BTreeMap, BTreeSet};

use domain::error::ReasonCode;
use domain::policy::{self, Context, Level, Rule, RulePath};
use domain::{Failure, RemoteWrite};

use crate::ports::{GroupAlias, GroupSpec, OpenbaoError, SpaceAdmin};
use crate::use_cases::Outcome;

/// A namespace as the organization's cells need it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CellNamespace {
    /// Has the type `orgs`, and its `OpenbaoNamespace` is `Ready`.
    pub ready: bool,
    /// The OIDC backends: `(name, accessor)`.
    pub oidc: Vec<(String, String)>,
}

/// One cell as written, recorded in the status: what the next pass and the
/// finalizer delete, without listing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub namespace: String,
    pub role: String,
    pub policy: String,
    pub groups: Vec<CellGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellGroup {
    pub backend: String,
    pub name: String,
    pub id: String,
    pub alias_id: Option<String>,
}

pub struct OrgInput<'a> {
    /// `OpenbaoOrganization/<metadata.name>`, the mark on what it writes.
    pub owner: &'a str,
    /// `spec.name`: the organization at the identity provider.
    pub org: &'a str,
    /// The layout's matrix: role → namespace → level name.
    pub roles: &'a BTreeMap<String, BTreeMap<String, String>>,
    pub alias_template: &'a str,
    pub alias_names: &'a BTreeMap<String, String>,
    pub levels: &'a BTreeMap<String, Level>,
    pub namespaces: &'a BTreeMap<String, CellNamespace>,
    /// The cells of the last pass (status).
    pub previous: &'a [Cell],
    /// `allow-disruptive-update` on the layout.
    pub allow_disruptive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgReport {
    pub outcome: Outcome,
    pub cells: Vec<Cell>,
}

fn metadata(owner: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("managed-by".into(), "weebo-openbao".into()),
        ("owner".into(), owner.into()),
    ])
}

fn alias_name(input: &OrgInput<'_>, role: &str) -> String {
    input.alias_names.get(role).cloned().unwrap_or_else(|| {
        input
            .alias_template
            .replace("{org}", input.org)
            .replace("{role}", role)
    })
}

pub async fn reconcile_organization(admin: &dyn SpaceAdmin, input: &OrgInput<'_>) -> OrgReport {
    let mut cells = Vec::new();
    let mut failure: Option<Failure> = None;
    let mut write = None;
    let mut fail = |f: Failure| {
        if failure.is_none() {
            failure = Some(f);
        }
    };
    let previous: BTreeMap<(&str, &str), &Cell> = input
        .previous
        .iter()
        .map(|c| ((c.namespace.as_str(), c.role.as_str()), c))
        .collect();
    let mut wanted: BTreeSet<(String, String)> = BTreeSet::new();

    for (role, by_namespace) in input.roles {
        for (ns, level_name) in by_namespace {
            wanted.insert((ns.clone(), role.clone()));
            let kept = previous
                .get(&(ns.as_str(), role.as_str()))
                .map(|c| (*c).clone());
            let Some(level) = input.levels.get(level_name) else {
                fail(Failure::new(
                    ReasonCode::LevelNotFound,
                    format!("role {role} in {ns} cites level {level_name:?}, which doesn't exist"),
                ));
                cells.extend(kept);
                continue;
            };
            let Some(namespace) = input.namespaces.get(ns).filter(|n| n.ready) else {
                fail(Failure::new(
                    ReasonCode::NamespaceNotReady,
                    format!(
                        "role {role} names namespace {ns}, absent, not ready or without the type orgs"
                    ),
                ));
                cells.extend(kept);
                continue;
            };
            match write_cell(admin, input, ns, role, level, namespace, kept.as_ref()).await {
                Ok((cell, wrote)) => {
                    if wrote {
                        write.get_or_insert(RemoteWrite::Drift);
                    }
                    cells.push(cell);
                }
                Err(f) => {
                    fail(f);
                    cells.extend(kept);
                }
            }
        }
    }

    // Cells no longer in the layout: removed only when allowed.
    for cell in input.previous {
        if wanted.contains(&(cell.namespace.clone(), cell.role.clone())) {
            continue;
        }
        if !input.allow_disruptive {
            fail(Failure::new(
                ReasonCode::DisruptiveChangeBlocked,
                format!(
                    "role {} in {} left the layout: its access is only removed with allow-disruptive-update on the layout",
                    cell.role, cell.namespace
                ),
            ));
            cells.push(cell.clone());
            continue;
        }
        match delete_cell(admin, cell).await {
            Ok(()) => {
                write = Some(RemoteWrite::Deleted);
            }
            Err(e) => {
                fail(e.into());
                cells.push(cell.clone());
            }
        }
    }

    let mut outcome = match failure {
        Some(f) => Outcome::failed(f),
        None => Outcome::synced(
            None,
            format!("{} cells of {} in place", cells.len(), input.org),
        ),
    };
    outcome.write = write;
    OrgReport { outcome, cells }
}

/// One cell: the policy, then a group and its alias per OIDC backend.
/// Groups of backends gone from the namespace are removed only when
/// allowed. `true`: something was written.
async fn write_cell(
    admin: &dyn SpaceAdmin,
    input: &OrgInput<'_>,
    ns: &str,
    role: &str,
    level: &Level,
    namespace: &CellNamespace,
    previous: Option<&Cell>,
) -> Result<(Cell, bool), Failure> {
    let mut wrote = false;
    let policy_name = format!("org_{}_{role}", input.org);
    let organizations = [input.org.to_string()];
    let rule = Rule {
        mount: "orgs".into(),
        path: RulePath::parse("{org}/+/*").map_err(invalid)?,
        metadata_path: Some(RulePath::parse("{org}/*").map_err(invalid)?),
        level: level.clone(),
    };
    let text = policy::render(
        &[rule],
        &Context {
            owner: input.owner,
            organizations: &organizations,
            accessor: None,
        },
    )
    .map_err(invalid)?;
    match admin.read_policy(ns, &policy_name).await? {
        Some(current) if !policy::is_owned_by(&current, input.owner) => {
            return Err(not_owned(ns, &format!("policy {policy_name}")));
        }
        Some(current) if current == text => {}
        _ => {
            admin.write_policy(ns, &policy_name, &text).await?;
            wrote = true;
        }
    }

    let mut groups = Vec::new();
    let alias = alias_name(input, role);
    for (backend, accessor) in &namespace.oidc {
        let group_name = format!("{policy_name}_{backend}");
        let current = admin.read_group(ns, &group_name).await?;
        if let Some(g) = &current
            && g.metadata.get("owner").map(String::as_str) != Some(input.owner)
        {
            return Err(not_owned(ns, &format!("group {group_name}")));
        }
        let spec = GroupSpec {
            policy: policy_name.clone(),
            metadata: metadata(input.owner),
        };
        let id = match &current {
            Some(g) if g.policies == [policy_name.clone()] && g.metadata == spec.metadata => {
                g.id.clone()
            }
            _ => {
                wrote = true;
                admin.write_group(ns, &group_name, &spec).await?
            }
        };
        let desired = GroupAlias {
            id: String::new(),
            name: alias.clone(),
            mount_accessor: accessor.clone(),
        };
        let existing = current.as_ref().and_then(|g| g.alias.clone());
        let alias_id = match &existing {
            Some(a) if a.name == desired.name && a.mount_accessor == desired.mount_accessor => {
                a.id.clone()
            }
            _ => {
                wrote = true;
                admin
                    .write_group_alias(ns, existing.as_ref().map(|a| a.id.as_str()), &desired, &id)
                    .await?
            }
        };
        groups.push(CellGroup {
            backend: backend.clone(),
            name: group_name,
            id,
            alias_id: Some(alias_id),
        });
    }
    // Backends gone from the namespace: their group only goes when allowed.
    for old in previous.map(|c| c.groups.as_slice()).unwrap_or_default() {
        if groups.iter().any(|g| g.backend == old.backend) {
            continue;
        }
        if !input.allow_disruptive {
            groups.push(old.clone());
            return Err(Failure::new(
                ReasonCode::DisruptiveChangeBlocked,
                format!(
                    "backend {} left namespace {ns}: group {} is only removed with allow-disruptive-update",
                    old.backend, old.name
                ),
            ));
        }
        delete_group(admin, ns, old).await?;
        wrote = true;
    }
    Ok((
        Cell {
            namespace: ns.into(),
            role: role.into(),
            policy: policy_name,
            groups,
        },
        wrote,
    ))
}

async fn delete_group(
    admin: &dyn SpaceAdmin,
    ns: &str,
    group: &CellGroup,
) -> Result<(), OpenbaoError> {
    if let Some(alias) = &group.alias_id {
        admin.delete_group_alias(ns, alias).await?;
    }
    admin.delete_group(ns, &group.name).await
}

/// Alias, group, then policy: the first call cuts the access.
async fn delete_cell(admin: &dyn SpaceAdmin, cell: &Cell) -> Result<(), OpenbaoError> {
    for group in &cell.groups {
        delete_group(admin, &cell.namespace, group).await?;
    }
    admin.delete_policy(&cell.namespace, &cell.policy).await
}

/// The finalizer's cleanup: every recorded cell, in revocation order.
/// The organization's secrets stay in `<ns>/orgs/<org>/`.
pub async fn cleanup_organization(
    admin: &dyn SpaceAdmin,
    cells: &[Cell],
) -> Result<(), OpenbaoError> {
    for cell in cells {
        delete_cell(admin, cell).await?;
    }
    Ok(())
}

fn invalid(e: policy::PolicyError) -> Failure {
    Failure::new(ReasonCode::InvalidSpec, e.to_string())
}

fn not_owned(ns: &str, what: &str) -> Failure {
    Failure::new(
        ReasonCode::NotOwned,
        format!("{what} of {ns} is not this organization's: left alone"),
    )
}

#[cfg(test)]
mod tests {
    use domain::policy::Capability;

    use super::*;
    use crate::test_support::FakeSpaceAdmin;

    struct World {
        roles: BTreeMap<String, BTreeMap<String, String>>,
        levels: BTreeMap<String, Level>,
        namespaces: BTreeMap<String, CellNamespace>,
        alias_names: BTreeMap<String, String>,
    }

    fn world() -> World {
        let read = Level {
            data: vec![Capability::Read],
            metadata: vec![Capability::Read, Capability::List],
            versions: false,
        };
        World {
            roles: BTreeMap::from([(
                "dev".into(),
                BTreeMap::from([("preprod".into(), "read".into())]),
            )]),
            levels: BTreeMap::from([("read".into(), read)]),
            namespaces: BTreeMap::from([(
                "preprod".into(),
                CellNamespace {
                    ready: true,
                    oidc: vec![("authentik".into(), "auth_oidc_1".into())],
                },
            )]),
            alias_names: BTreeMap::new(),
        }
    }

    fn input<'a>(w: &'a World, previous: &'a [Cell], allow: bool) -> OrgInput<'a> {
        OrgInput {
            owner: "OpenbaoOrganization/acme",
            org: "acme",
            roles: &w.roles,
            alias_template: "{org}_{role}",
            alias_names: &w.alias_names,
            levels: &w.levels,
            namespaces: &w.namespaces,
            previous,
            allow_disruptive: allow,
        }
    }

    #[tokio::test]
    async fn grant_order_is_policy_group_alias_then_quiet() {
        let w = world();
        let admin = FakeSpaceAdmin::default();
        let report = reconcile_organization(&admin, &input(&w, &[], false)).await;
        assert_eq!(
            report.outcome.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            report.outcome
        );
        assert_eq!(
            admin.writes(),
            [
                "write policy preprod/org_acme_dev",
                "write group preprod/org_acme_dev_authentik",
                "write alias preprod/acme_dev",
            ]
        );
        let group = &admin.namespace("preprod").unwrap().groups["org_acme_dev_authentik"];
        assert_eq!(group.alias.as_ref().unwrap().name, "acme_dev");
        assert!(
            admin.namespace("preprod").unwrap().policies["org_acme_dev"]
                .contains("path \"orgs/data/acme/+/*\" { capabilities = [\"read\"] }")
        );
        admin.clear_writes();
        let again = reconcile_organization(&admin, &input(&w, &report.cells, false)).await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(admin.writes().is_empty(), "{:?}", admin.writes());
        assert_eq!(again.cells, report.cells);
    }

    #[tokio::test]
    async fn two_oidc_backends_get_one_group_each() {
        let mut w = world();
        if let Some(ns) = w.namespaces.get_mut("preprod") {
            ns.oidc.push(("dex".into(), "auth_oidc_2".into()));
        }
        let admin = FakeSpaceAdmin::default();
        let report = reconcile_organization(&admin, &input(&w, &[], false)).await;
        let groups = admin.namespace("preprod").unwrap().groups;
        assert_eq!(
            groups["org_acme_dev_authentik"]
                .alias
                .as_ref()
                .unwrap()
                .mount_accessor,
            "auth_oidc_1"
        );
        assert_eq!(
            groups["org_acme_dev_dex"]
                .alias
                .as_ref()
                .unwrap()
                .mount_accessor,
            "auth_oidc_2"
        );
        assert_eq!(report.cells[0].groups.len(), 2);
        // Quiet afterwards: no alias rewritten back and forth.
        admin.clear_writes();
        reconcile_organization(&admin, &input(&w, &report.cells, false)).await;
        assert!(admin.writes().is_empty(), "{:?}", admin.writes());
    }

    #[tokio::test]
    async fn a_role_left_out_is_removed_only_when_allowed_alias_first() {
        let w = world();
        let admin = FakeSpaceAdmin::default();
        let first = reconcile_organization(&admin, &input(&w, &[], false)).await;
        let empty = World {
            roles: BTreeMap::new(),
            ..world()
        };
        admin.clear_writes();
        let blocked = reconcile_organization(&admin, &input(&empty, &first.cells, false)).await;
        assert_eq!(
            blocked.outcome.reason(),
            ReasonCode::DisruptiveChangeBlocked
        );
        assert!(admin.writes().is_empty());
        assert_eq!(blocked.cells, first.cells, "still recorded");
        let removed = reconcile_organization(&admin, &input(&empty, &first.cells, true)).await;
        assert_eq!(removed.outcome.reason(), ReasonCode::Reconciled);
        let writes = admin.writes();
        assert!(writes[0].starts_with("delete alias"), "{writes:?}");
        assert_eq!(writes[1], "delete group preprod/org_acme_dev_authentik");
        assert_eq!(writes[2], "delete policy preprod/org_acme_dev");
        assert!(removed.cells.is_empty());
    }

    #[tokio::test]
    async fn a_missing_level_or_namespace_writes_nothing_and_keeps_the_cell() {
        let w = world();
        let admin = FakeSpaceAdmin::default();
        let first = reconcile_organization(&admin, &input(&w, &[], false)).await;
        let no_level = World {
            levels: BTreeMap::new(),
            ..world()
        };
        admin.clear_writes();
        let report = reconcile_organization(&admin, &input(&no_level, &first.cells, false)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::LevelNotFound);
        assert!(admin.writes().is_empty());
        assert_eq!(report.cells, first.cells);
        let not_ready = World {
            namespaces: BTreeMap::new(),
            ..world()
        };
        let report = reconcile_organization(&admin, &input(&not_ready, &first.cells, false)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::NamespaceNotReady);
        assert!(admin.writes().is_empty());
    }

    #[tokio::test]
    async fn another_owners_group_is_not_written_over() {
        let w = world();
        let admin = FakeSpaceAdmin::default();
        admin.edit("preprod", |n| {
            n.groups.insert(
                "org_acme_dev_authentik".into(),
                crate::ports::Group {
                    id: "foreign".into(),
                    policies: vec!["weebo_admin".into()],
                    metadata: BTreeMap::new(),
                    alias: None,
                },
            );
        });
        let report = reconcile_organization(&admin, &input(&w, &[], false)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::NotOwned);
        assert!(
            !admin
                .writes()
                .iter()
                .any(|w| w.contains("group") || w.contains("alias"))
        );
    }

    #[tokio::test]
    async fn cleanup_revokes_alias_group_policy() {
        let w = world();
        let admin = FakeSpaceAdmin::default();
        let first = reconcile_organization(&admin, &input(&w, &[], false)).await;
        admin.clear_writes();
        cleanup_organization(&admin, &first.cells).await.unwrap();
        let writes = admin.writes();
        assert!(writes[0].starts_with("delete alias"));
        assert!(writes[1].starts_with("delete group"));
        assert!(writes[2].starts_with("delete policy"));
        assert!(admin.namespace("preprod").unwrap().groups.is_empty());
    }
}
