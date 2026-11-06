//! An `OpenbaoAccessGrant` (RFC 0007 §6.4): its rules rendered into the
//! policy `grant_<name>`, and one Kubernetes role per subject,
//! `grant_<name>_<index>` (decision 18: a role checks a ServiceAccount's
//! name and namespace against two separate lists, so one subject each).
//!
//! Order: the roles of subjects gone are removed first, then the policy
//! is written, then the roles: a grant never opens more on the way.

use std::collections::BTreeMap;

use api::grant::{OpenbaoAccessGrantSpec, Subject};
use domain::error::ReasonCode;
use domain::policy::{self, Context, Level, Rule, RulePath};
use domain::{Failure, RemoteWrite};

use crate::ports::{KubernetesRole, OpenbaoError, SpaceAdmin};
use crate::use_cases::Outcome;

/// The grant's namespace as the reconcile needs it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantNamespace {
    /// Its `OpenbaoNamespace` is `Ready`.
    pub ready: bool,
    /// The mounts it holds (`orgs`, `users`).
    pub mounts: Vec<String>,
    /// The Kubernetes backends: name → accessor.
    pub kubernetes: BTreeMap<String, String>,
}

pub struct GrantInput<'a> {
    /// `metadata.name`.
    pub name: &'a str,
    pub spec: &'a OpenbaoAccessGrantSpec,
    pub levels: &'a BTreeMap<String, Level>,
    /// Every organization of the instance, for `["*"]`.
    pub organizations: &'a [String],
    pub namespace: Option<&'a GrantNamespace>,
    /// The roles of the last pass (status).
    pub previous_roles: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantReport {
    pub outcome: Outcome,
    pub policy: Option<String>,
    pub roles: Vec<String>,
}

pub fn policy_name(name: &str) -> String {
    format!("grant_{name}")
}

fn role_name(name: &str, index: usize) -> String {
    format!("grant_{name}_{index}")
}

/// The role a subject logs in with.
fn role_of(subject: &Subject, policy: &str, ttl: u32) -> Result<KubernetesRole, Failure> {
    let selector = match &subject.namespace_selector {
        Some(labels) => Some(match_labels(labels).ok_or_else(|| {
            Failure::new(
                ReasonCode::InvalidSpec,
                "an empty namespaceSelector would match every namespace",
            )
        })?),
        None => None,
    };
    Ok(KubernetesRole {
        service_account_names: subject.name.clone(),
        service_account_namespaces: subject.namespace.clone(),
        namespace_selector: selector,
        token_policy: policy.into(),
        token_ttl_seconds: ttl,
    })
}

/// `{"matchLabels":{…}}`, as OpenBao parses a namespace selector; `None`
/// for no label (an empty selector matches every namespace). Labels are
/// keys and values the apiserver validated; quotes and backslashes are
/// escaped all the same.
fn match_labels(labels: &BTreeMap<String, String>) -> Option<String> {
    if labels.is_empty() {
        return None;
    }
    let quote = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
    let pairs: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}:{}", quote(k), quote(v)))
        .collect();
    Some(format!("{{\"matchLabels\":{{{}}}}}", pairs.join(",")))
}

pub async fn reconcile_grant(admin: &dyn SpaceAdmin, input: &GrantInput<'_>) -> GrantReport {
    match run(admin, input).await {
        Ok(report) => report,
        Err(failure) => GrantReport {
            outcome: Outcome::failed(failure),
            policy: None,
            roles: input.previous_roles.to_vec(),
        },
    }
}

async fn run(admin: &dyn SpaceAdmin, input: &GrantInput<'_>) -> Result<GrantReport, Failure> {
    let spec = input.spec;
    let ns = spec.namespace.as_str();
    let owner = format!("OpenbaoAccessGrant/{}", input.name);
    let not_ready = |why: String| Failure::new(ReasonCode::NamespaceNotReady, why);
    let namespace = input
        .namespace
        .filter(|n| n.ready)
        .ok_or_else(|| not_ready(format!("namespace {ns} is absent or not ready")))?;
    let accessor = namespace.kubernetes.get(&spec.auth).ok_or_else(|| {
        not_ready(format!(
            "namespace {ns} has no kubernetes backend {:?}",
            spec.auth
        ))
    })?;

    // The policy: each rule with its own organizations.
    let mut blocks = Vec::new();
    for rule in &spec.rules {
        if !namespace.mounts.contains(&rule.mount) {
            return Err(not_ready(format!(
                "namespace {ns} has no mount {:?}",
                rule.mount
            )));
        }
        let level = input.levels.get(&rule.level).ok_or_else(|| {
            Failure::new(
                ReasonCode::LevelNotFound,
                format!("a rule cites level {:?}, which doesn't exist", rule.level),
            )
        })?;
        let invalid = |e: policy::PolicyError| Failure::new(ReasonCode::InvalidSpec, e.to_string());
        let organizations: Vec<String> = if rule.organizations.iter().any(|o| o == "*") {
            input.organizations.to_vec()
        } else {
            rule.organizations.clone()
        };
        let text = policy::render(
            &[Rule {
                mount: rule.mount.clone(),
                path: RulePath::parse(&rule.path).map_err(invalid)?,
                metadata_path: rule
                    .metadata_path
                    .as_deref()
                    .map(RulePath::parse)
                    .transpose()
                    .map_err(invalid)?,
                level: level.clone(),
            }],
            &Context {
                owner: &owner,
                organizations: &organizations,
                accessor: Some(accessor),
            },
        )
        .map_err(invalid)?;
        // Every block after the owner mark.
        blocks.extend(text.lines().skip(1).map(String::from));
    }
    let policy = policy_name(input.name);
    let text = format!(
        "# managed-by: weebo-openbao owner: {owner}\n{}\n",
        blocks.join("\n")
    );

    let desired: Vec<(String, KubernetesRole)> = spec
        .subjects
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Ok((
                role_name(input.name, i),
                role_of(s, &policy, spec.token_ttl_seconds)?,
            ))
        })
        .collect::<Result<_, Failure>>()?;

    let mut write = None;
    // Narrow first: subjects gone lose their login before anything changes.
    for old in input.previous_roles {
        if !desired.iter().any(|(name, _)| name == old) {
            admin.delete_kubernetes_role(ns, &spec.auth, old).await?;
            write = Some(RemoteWrite::Deleted);
        }
    }
    match admin.read_policy(ns, &policy).await? {
        Some(current) if !policy::is_owned_by(&current, &owner) => {
            return Err(Failure::new(
                ReasonCode::NotOwned,
                format!("policy {policy} of {ns} is not this grant's: left alone"),
            ));
        }
        Some(current) if current == text => {}
        _ => {
            admin.write_policy(ns, &policy, &text).await?;
            write.get_or_insert(RemoteWrite::Drift);
        }
    }
    for (name, role) in &desired {
        if admin
            .read_kubernetes_role(ns, &spec.auth, name)
            .await?
            .as_ref()
            != Some(role)
        {
            admin
                .write_kubernetes_role(ns, &spec.auth, name, role)
                .await?;
            write.get_or_insert(RemoteWrite::Drift);
        }
    }
    let mut outcome = Outcome::synced(None, format!("{} subject(s) log in to {ns}", desired.len()));
    outcome.write = write;
    Ok(GrantReport {
        outcome,
        policy: Some(policy),
        roles: desired.into_iter().map(|(name, _)| name).collect(),
    })
}

/// The finalizer's cleanup: the roles (the logins), then the policy.
pub async fn cleanup_grant(
    admin: &dyn SpaceAdmin,
    ns: &str,
    backend: &str,
    name: &str,
    roles: &[String],
) -> Result<(), OpenbaoError> {
    for role in roles {
        admin.delete_kubernetes_role(ns, backend, role).await?;
    }
    admin.delete_policy(ns, &policy_name(name)).await
}

#[cfg(test)]
mod tests {
    use api::grant::GrantRule;
    use domain::policy::Capability;

    use super::*;
    use crate::test_support::FakeSpaceAdmin;

    fn spec(subjects: Vec<Subject>, path: &str, orgs: &[&str]) -> OpenbaoAccessGrantSpec {
        OpenbaoAccessGrantSpec {
            instance_ref: api::refs::NameRef::named("main"),
            namespace: "users".into(),
            auth: "kubernetes".into(),
            subjects,
            rules: vec![GrantRule {
                mount: "users".into(),
                path: path.into(),
                metadata_path: None,
                organizations: orgs.iter().map(|s| s.to_string()).collect(),
                level: "token-writer".into(),
            }],
            token_ttl_seconds: 900,
        }
    }

    fn subject(ns: &str, name: &str) -> Subject {
        Subject {
            namespace: Some(ns.into()),
            namespace_selector: None,
            name: name.into(),
        }
    }

    fn levels() -> BTreeMap<String, Level> {
        BTreeMap::from([(
            "token-writer".into(),
            Level {
                data: vec![
                    Capability::Create,
                    Capability::Read,
                    Capability::Update,
                    Capability::Delete,
                ],
                metadata: vec![
                    Capability::Create,
                    Capability::Read,
                    Capability::Update,
                    Capability::Delete,
                ],
                versions: false,
            },
        )])
    }

    fn users_ns() -> GrantNamespace {
        GrantNamespace {
            ready: true,
            mounts: vec!["users".into()],
            kubernetes: BTreeMap::from([("kubernetes".into(), "auth_kubernetes_1".into())]),
        }
    }

    #[tokio::test]
    async fn the_forgejo_grant_writes_its_policy_then_one_role_and_stays_quiet() {
        let spec = spec(
            vec![subject("weebo-forgejo", "weebo-forgejo")],
            "+/forgejo-token",
            &[],
        );
        let levels = levels();
        let ns = users_ns();
        let admin = FakeSpaceAdmin::default();
        let input = GrantInput {
            name: "forgejo-user-tokens",
            spec: &spec,
            levels: &levels,
            organizations: &[],
            namespace: Some(&ns),
            previous_roles: &[],
        };
        let report = reconcile_grant(&admin, &input).await;
        assert_eq!(
            report.outcome.reason(),
            ReasonCode::Reconciled,
            "{:?}",
            report.outcome
        );
        assert_eq!(
            admin.writes(),
            [
                "write policy users/grant_forgejo-user-tokens",
                "write kubernetes role users/kubernetes/grant_forgejo-user-tokens_0",
            ]
        );
        let state = admin.namespace("users").unwrap();
        assert!(state.policies["grant_forgejo-user-tokens"]
            .contains("path \"users/data/+/forgejo-token\" { capabilities = [\"create\", \"read\", \"update\", \"delete\"] }"));
        let role =
            &state.kubernetes_roles[&("kubernetes".into(), "grant_forgejo-user-tokens_0".into())];
        assert_eq!(role.token_policy, "grant_forgejo-user-tokens");
        assert_eq!(
            role.service_account_namespaces.as_deref(),
            Some("weebo-forgejo")
        );
        admin.clear_writes();
        let again = reconcile_grant(
            &admin,
            &GrantInput {
                previous_roles: &report.roles,
                ..input
            },
        )
        .await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(admin.writes().is_empty(), "{:?}", admin.writes());
    }

    #[tokio::test]
    async fn a_subject_gone_loses_its_role_before_the_policy_changes() {
        let two = spec(
            vec![subject("a", "runner"), subject("b", "runner")],
            "+/forgejo-token",
            &[],
        );
        let levels = levels();
        let ns = users_ns();
        let admin = FakeSpaceAdmin::default();
        let first = reconcile_grant(
            &admin,
            &GrantInput {
                name: "ci",
                spec: &two,
                levels: &levels,
                organizations: &[],
                namespace: Some(&ns),
                previous_roles: &[],
            },
        )
        .await;
        assert_eq!(first.roles, ["grant_ci_0", "grant_ci_1"]);
        let one = spec(vec![subject("a", "runner")], "+/*", &[]);
        admin.clear_writes();
        let report = reconcile_grant(
            &admin,
            &GrantInput {
                name: "ci",
                spec: &one,
                levels: &levels,
                organizations: &[],
                namespace: Some(&ns),
                previous_roles: &first.roles,
            },
        )
        .await;
        assert_eq!(report.roles, ["grant_ci_0"]);
        assert_eq!(
            admin.writes().first().map(String::as_str),
            Some("delete kubernetes role users/kubernetes/grant_ci_1"),
            "narrowed first: {:?}",
            admin.writes()
        );
    }

    #[tokio::test]
    async fn sa_namespace_templates_on_the_kubernetes_accessor_and_star_expands_to_every_org() {
        let mut grant = spec(vec![subject("*", "*")], "{org}/{sa.namespace}/*", &["*"]);
        grant.namespace = "devenv".into();
        if let Some(rule) = grant.rules.first_mut() {
            rule.mount = "orgs".into();
        }
        let levels = levels();
        let ns = GrantNamespace {
            ready: true,
            mounts: vec!["orgs".into()],
            kubernetes: BTreeMap::from([("kubernetes".into(), "auth_kubernetes_9".into())]),
        };
        let admin = FakeSpaceAdmin::default();
        let orgs = ["acme".to_string(), "batleforc-org".to_string()];
        reconcile_grant(
            &admin,
            &GrantInput {
                name: "own",
                spec: &grant,
                levels: &levels,
                organizations: &orgs,
                namespace: Some(&ns),
                previous_roles: &[],
            },
        )
        .await;
        let text = &admin.namespace("devenv").unwrap().policies["grant_own"];
        assert!(text.contains("orgs/data/acme/{{identity.entity.aliases.auth_kubernetes_9.metadata.service_account_namespace}}/*"), "{text}");
        assert!(text.contains("orgs/data/batleforc-org/"), "{text}");
    }

    #[tokio::test]
    async fn a_selector_renders_as_match_labels_and_missing_pieces_write_nothing() {
        let selector = Subject {
            namespace: None,
            namespace_selector: Some(BTreeMap::from([("weebo.io/org".into(), "acme".into())])),
            name: "*".into(),
        };
        let role = role_of(&selector, "grant_x", 900).unwrap();
        assert_eq!(
            role.namespace_selector.as_deref(),
            Some("{\"matchLabels\":{\"weebo.io/org\":\"acme\"}}")
        );
        let grant = spec(vec![subject("a", "b")], "+/x", &[]);
        let admin = FakeSpaceAdmin::default();
        let report = reconcile_grant(
            &admin,
            &GrantInput {
                name: "g",
                spec: &grant,
                levels: &BTreeMap::new(),
                organizations: &[],
                namespace: Some(&users_ns()),
                previous_roles: &[],
            },
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::LevelNotFound);
        assert!(admin.writes().is_empty());
        let report = reconcile_grant(
            &admin,
            &GrantInput {
                name: "g",
                spec: &grant,
                levels: &levels(),
                organizations: &[],
                namespace: None,
                previous_roles: &[],
            },
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::NamespaceNotReady);
        assert!(admin.writes().is_empty());
    }

    #[tokio::test]
    async fn cleanup_removes_the_logins_then_the_policy() {
        let admin = FakeSpaceAdmin::default();
        cleanup_grant(&admin, "users", "kubernetes", "g", &["grant_g_0".into()])
            .await
            .unwrap();
        assert_eq!(
            admin.writes(),
            [
                "delete kubernetes role users/kubernetes/grant_g_0",
                "delete policy users/grant_g"
            ]
        );
    }
}
