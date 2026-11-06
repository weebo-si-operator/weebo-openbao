//! An `OpenbaoSpaceLayout` writes nothing to OpenBao (the organizations
//! write their cells): reconciling it checks what CEL can't, the objects
//! it cites (RFC 0007 §4.3).

use std::collections::{BTreeMap, BTreeSet};

use domain::Failure;
use domain::error::ReasonCode;

use crate::use_cases::Outcome;

/// A namespace of the layout's instance, as the check needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayoutNamespace {
    pub orgs: bool,
    pub users: bool,
}

pub fn check_layout(
    roles: &BTreeMap<String, BTreeMap<String, String>>,
    levels: &BTreeSet<String>,
    namespaces: &BTreeMap<String, LayoutNamespace>,
    users_declared: bool,
) -> Outcome {
    for (role, cells) in roles {
        for (ns, level) in cells {
            if !levels.contains(level) {
                return Outcome::failed(Failure::new(
                    ReasonCode::LevelNotFound,
                    format!("role {role} in {ns} cites level {level:?}, which doesn't exist"),
                ));
            }
            if !namespaces.get(ns).is_some_and(|n| n.orgs) {
                return Outcome::failed(Failure::new(
                    ReasonCode::NamespaceNotReady,
                    format!(
                        "role {role} names namespace {ns}, which is absent or without the type orgs"
                    ),
                ));
            }
        }
    }
    if !users_declared && let Some((ns, _)) = namespaces.iter().find(|(_, n)| n.users) {
        return Outcome::failed(Failure::new(
            ReasonCode::InvalidSpec,
            format!("namespace {ns} has the type users: the layout needs its users block"),
        ));
    }
    let cells: usize = roles.values().map(BTreeMap::len).sum();
    Outcome::synced(None, format!("{} roles, {cells} cells", roles.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles() -> BTreeMap<String, BTreeMap<String, String>> {
        BTreeMap::from([(
            "dev".into(),
            BTreeMap::from([("preprod".into(), "read".into())]),
        )])
    }

    #[test]
    fn a_layout_citing_what_exists_is_ready() {
        let levels = BTreeSet::from(["read".to_string()]);
        let namespaces = BTreeMap::from([(
            "preprod".to_string(),
            LayoutNamespace {
                orgs: true,
                users: false,
            },
        )]);
        assert_eq!(
            check_layout(&roles(), &levels, &namespaces, false).reason(),
            ReasonCode::Reconciled
        );
    }

    #[test]
    fn a_missing_level_namespace_or_users_block_is_reported() {
        let namespaces = BTreeMap::from([(
            "preprod".to_string(),
            LayoutNamespace {
                orgs: true,
                users: false,
            },
        )]);
        assert_eq!(
            check_layout(&roles(), &BTreeSet::new(), &namespaces, false).reason(),
            ReasonCode::LevelNotFound
        );
        let levels = BTreeSet::from(["read".to_string()]);
        assert_eq!(
            check_layout(&roles(), &levels, &BTreeMap::new(), false).reason(),
            ReasonCode::NamespaceNotReady
        );
        let with_users = BTreeMap::from([
            (
                "preprod".to_string(),
                LayoutNamespace {
                    orgs: true,
                    users: false,
                },
            ),
            (
                "users".to_string(),
                LayoutNamespace {
                    orgs: false,
                    users: true,
                },
            ),
        ]);
        assert_eq!(
            check_layout(&roles(), &levels, &with_users, false).reason(),
            ReasonCode::InvalidSpec
        );
        assert_eq!(
            check_layout(&roles(), &levels, &with_users, true).reason(),
            ReasonCode::Reconciled
        );
    }
}
