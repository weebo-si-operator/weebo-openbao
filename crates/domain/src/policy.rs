//! Rules rendered into OpenBao policy HCL — the one place the operator
//! writes HCL (RFC 0007 §6.2, decision 17).
//!
//! Every value that reaches the HCL is checked here against a closed
//! alphabet, whatever the CRD's schema already refused: a rule path is
//! segments of `[a-z0-9._-]`, `+`, a last `*`, or a whole-segment token
//! (`{org}`, `{sa.namespace}`, `{sa.name}`). Nothing is escaped: what is
//! outside the alphabet is refused, so no `"`, `{`, `}`, `#`, space or new
//! line can open a second `path` block.

use std::fmt;

/// A KV v2 capability of a level. `sudo`, `deny` and `subscribe` have no
/// place in a space and are not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Create,
    Read,
    Update,
    Patch,
    Delete,
    List,
}

impl Capability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Patch => "patch",
            Self::Delete => "delete",
            Self::List => "list",
        }
    }
}

/// What an `OpenbaoAccessLevel` grants on a rule's paths.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Level {
    pub data: Vec<Capability>,
    pub metadata: Vec<Capability>,
    /// `delete`, `undelete` and `destroy` of past versions, as `update`.
    pub versions: bool,
}

/// Why a value can't go into a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// A rule path outside the alphabet.
    Path { path: String, why: &'static str },
    /// A name (mount, org, accessor, owner mark) outside its alphabet.
    Name { what: &'static str, value: String },
    /// `{sa.namespace}` or `{sa.name}` without the Kubernetes backend's
    /// accessor to template on.
    NoAccessor { path: String },
    /// A level granting nothing: the rule would render no path.
    EmptyLevel,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { path, why } => write!(f, "rule path {path:?}: {why}"),
            Self::Name { what, value } => write!(f, "{what} {value:?} is not allowed in a policy"),
            Self::NoAccessor { path } => write!(
                f,
                "rule path {path:?} uses a ServiceAccount token but the namespace has no kubernetes backend"
            ),
            Self::EmptyLevel => write!(f, "the level grants no capability"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// One segment of a rule path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// `+`: exactly one segment.
    One,
    /// `*`, last only: the rest.
    Rest,
    /// `{org}`: expanded by the operator, one block per organization.
    Org,
    /// `{sa.namespace}` / `{sa.name}`: OpenBao templates on the alias
    /// metadata of the Kubernetes backend.
    SaNamespace,
    SaName,
}

/// A rule path, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulePath {
    segments: Vec<Segment>,
    source: String,
}

/// The longest rule path accepted, as the CRD's `maxLength`.
pub const MAX_RULE_PATH: usize = 256;

impl RulePath {
    pub fn parse(path: &str) -> Result<Self, PolicyError> {
        let bad = |why| PolicyError::Path {
            path: path.to_string(),
            why,
        };
        if path.is_empty() || path.len() > MAX_RULE_PATH {
            return Err(bad("empty or longer than 256 characters"));
        }
        let parts: Vec<&str> = path.split('/').collect();
        let last = parts.len().saturating_sub(1);
        let mut segments = Vec::with_capacity(parts.len());
        for (i, part) in parts.iter().enumerate() {
            let segment = match *part {
                "" => return Err(bad("empty segment (leading, trailing or double `/`)")),
                "." | ".." => return Err(bad("`.` and `..` segments are refused")),
                "+" => Segment::One,
                "*" if i == last => Segment::Rest,
                "*" => return Err(bad("`*` only as the last segment")),
                "{org}" => Segment::Org,
                "{sa.namespace}" => Segment::SaNamespace,
                "{sa.name}" => Segment::SaName,
                literal if is_name(literal) => Segment::Literal(literal.to_string()),
                _ => {
                    return Err(bad(
                        "a segment is [a-z0-9._-], `+`, a last `*`, or a whole token {org}, {sa.namespace}, {sa.name}",
                    ));
                }
            };
            segments.push(segment);
        }
        Ok(Self {
            segments,
            source: path.to_string(),
        })
    }

    /// Whether the path names `{org}`.
    pub fn has_org(&self) -> bool {
        self.segments.contains(&Segment::Org)
    }

    /// Whether the path names `{sa.namespace}` (a broad subject needs it).
    pub fn has_sa_namespace(&self) -> bool {
        self.segments.contains(&Segment::SaNamespace)
    }

    fn uses_service_account(&self) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s, Segment::SaNamespace | Segment::SaName))
    }

    fn render(&self, org: Option<&str>, accessor: Option<&str>) -> Result<String, PolicyError> {
        let sa = |field: &str| -> Result<String, PolicyError> {
            let accessor = accessor.ok_or_else(|| PolicyError::NoAccessor {
                path: self.source.clone(),
            })?;
            Ok(format!(
                "{{{{identity.entity.aliases.{accessor}.metadata.service_account_{field}}}}}"
            ))
        };
        let mut out = Vec::with_capacity(self.segments.len());
        for segment in &self.segments {
            out.push(match segment {
                Segment::Literal(s) => s.clone(),
                Segment::One => "+".to_string(),
                Segment::Rest => "*".to_string(),
                Segment::Org => org
                    .ok_or_else(|| PolicyError::Path {
                        path: self.source.clone(),
                        why: "`{org}` without an organization to expand",
                    })?
                    .to_string(),
                Segment::SaNamespace => sa("namespace")?,
                Segment::SaName => sa("name")?,
            });
        }
        Ok(out.join("/"))
    }
}

/// A rule: a level on a path of a KV v2 mount, metadata on `metadata_path`
/// (the same path when unset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub mount: String,
    pub path: RulePath,
    pub metadata_path: Option<RulePath>,
    pub level: Level,
}

/// What a policy is rendered for.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// `<kind>/<name>` of the owning CR, the first line's mark (§5.3).
    pub owner: &'a str,
    /// The organizations `{org}` expands over, in this order.
    pub organizations: &'a [String],
    /// The Kubernetes backend's accessor, for `{sa.*}`.
    pub accessor: Option<&'a str>,
}

/// The policy text of `rules`: the owner mark, then one `path` block per
/// rendered path, in rule order. Deterministic: the same input renders the
/// same text, which is what drift detection compares.
pub fn render(rules: &[Rule], cx: &Context<'_>) -> Result<String, PolicyError> {
    if !is_owner(cx.owner) {
        return Err(PolicyError::Name {
            what: "owner mark",
            value: cx.owner.to_string(),
        });
    }
    if let Some(accessor) = cx.accessor
        && !is_accessor(accessor)
    {
        return Err(PolicyError::Name {
            what: "accessor",
            value: accessor.to_string(),
        });
    }
    for org in cx.organizations {
        if !is_org(org) {
            return Err(PolicyError::Name {
                what: "organization",
                value: org.clone(),
            });
        }
    }
    let mut lines = vec![format!("# managed-by: weebo-openbao owner: {}", cx.owner)];
    for rule in rules {
        if !is_name(&rule.mount) {
            return Err(PolicyError::Name {
                what: "mount",
                value: rule.mount.clone(),
            });
        }
        if rule.level.data.is_empty() && rule.level.metadata.is_empty() && !rule.level.versions {
            return Err(PolicyError::EmptyLevel);
        }
        let metadata_path = rule.metadata_path.as_ref().unwrap_or(&rule.path);
        if (rule.path.uses_service_account() || metadata_path.uses_service_account())
            && cx.accessor.is_none()
        {
            return Err(PolicyError::NoAccessor {
                path: rule.path.source.clone(),
            });
        }
        let orgs: Vec<Option<&str>> = if rule.path.has_org() || metadata_path.has_org() {
            cx.organizations.iter().map(|o| Some(o.as_str())).collect()
        } else {
            vec![None]
        };
        for org in orgs {
            let data = rule.path.render(org, cx.accessor)?;
            let meta = metadata_path.render(org, cx.accessor)?;
            push_block(&mut lines, &rule.mount, "data", &data, &rule.level.data);
            push_block(
                &mut lines,
                &rule.mount,
                "metadata",
                &meta,
                &rule.level.metadata,
            );
            if rule.level.versions {
                for verb in ["delete", "undelete", "destroy"] {
                    push_block(&mut lines, &rule.mount, verb, &data, &[Capability::Update]);
                }
            }
        }
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}

/// The personal spaces' policy of a `users` namespace (RFC 0007 §6.2):
/// for each OIDC backend's accessor, the user's own folder of the `users`
/// mount, templated on the alias metadata `key` that the backend's role
/// maps the username to.
pub fn render_user_space(
    owner: &str,
    accessors: &[&str],
    key: &str,
) -> Result<String, PolicyError> {
    if !is_owner(owner) {
        return Err(PolicyError::Name {
            what: "owner mark",
            value: owner.to_string(),
        });
    }
    let key_ok = key.len() <= 32
        && key.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    if !key_ok {
        return Err(PolicyError::Name {
            what: "alias metadata key",
            value: key.to_string(),
        });
    }
    let mut lines = vec![format!("# managed-by: weebo-openbao owner: {owner}")];
    for accessor in accessors {
        if !is_accessor(accessor) {
            return Err(PolicyError::Name {
                what: "accessor",
                value: (*accessor).to_string(),
            });
        }
        let user = format!("{{{{identity.entity.aliases.{accessor}.metadata.{key}}}}}");
        push_block(
            &mut lines,
            "users",
            "data",
            &format!("{user}/*"),
            &[
                Capability::Create,
                Capability::Read,
                Capability::Update,
                Capability::Patch,
                Capability::Delete,
            ],
        );
        push_block(
            &mut lines,
            "users",
            "metadata",
            &format!("{user}/*"),
            &[Capability::Read, Capability::List, Capability::Delete],
        );
    }
    let mut text = lines.join("\n");
    text.push('\n');
    Ok(text)
}

/// Whether `text` is a policy this operator wrote for `owner`.
pub fn is_owned_by(text: &str, owner: &str) -> bool {
    text.lines().next() == Some(format!("# managed-by: weebo-openbao owner: {owner}").as_str())
}

fn push_block(lines: &mut Vec<String>, mount: &str, kind: &str, path: &str, caps: &[Capability]) {
    if caps.is_empty() {
        return;
    }
    let mut caps = caps.to_vec();
    caps.sort();
    caps.dedup();
    let caps: Vec<String> = caps.iter().map(|c| format!("\"{}\"", c.as_str())).collect();
    lines.push(format!(
        "path \"{mount}/{kind}/{path}\" {{ capabilities = [{}] }}",
        caps.join(", ")
    ));
}

/// `[a-z0-9._-]+`, not `.` or `..`: a literal segment or a mount name.
fn is_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// An organization's `spec.name` (§4.3): `[a-z0-9]`, then up to 38 of
/// `[a-z0-9._-]`, ending on `[a-z0-9]`.
pub fn is_org(s: &str) -> bool {
    let bytes = s.as_bytes();
    let edge = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    (1..=40).contains(&bytes.len())
        && bytes.first().is_some_and(edge)
        && bytes.last().is_some_and(edge)
        && is_name(s)
}

/// An auth accessor as OpenBao prints it: `auth_<type>_<hex>`.
fn is_accessor(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// `<Kind>/<name>`: an ASCII kind, then a Kubernetes object name.
fn is_owner(s: &str) -> bool {
    let Some((kind, name)) = s.split_once('/') else {
        return false;
    };
    !kind.is_empty()
        && kind.bytes().all(|b| b.is_ascii_alphanumeric())
        && !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read() -> Level {
        Level {
            data: vec![Capability::Read],
            metadata: vec![Capability::Read, Capability::List],
            versions: false,
        }
    }

    fn rule(mount: &str, path: &str, metadata_path: Option<&str>, level: Level) -> Rule {
        Rule {
            mount: mount.into(),
            path: RulePath::parse(path).unwrap(),
            metadata_path: metadata_path.map(|p| RulePath::parse(p).unwrap()),
            level,
        }
    }

    fn orgs(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_layout_cell_renders_the_terraform_policy() {
        // vault-spaces.tf, batleforc-org dev in preprod, plus the mark.
        let text = render(
            &[rule("orgs", "{org}/+/*", Some("{org}/*"), read())],
            &Context {
                owner: "OpenbaoOrganization/batleforc-org",
                organizations: &orgs(&["batleforc-org"]),
                accessor: None,
            },
        )
        .unwrap();
        assert_eq!(
            text,
            "# managed-by: weebo-openbao owner: OpenbaoOrganization/batleforc-org\n\
             path \"orgs/data/batleforc-org/+/*\" { capabilities = [\"read\"] }\n\
             path \"orgs/metadata/batleforc-org/*\" { capabilities = [\"read\", \"list\"] }\n"
        );
    }

    /// RFC 0007 §6.P n°5: the `weebo` layout and levels of weebo-si
    /// (`2.argo/helm/vault/spaces/values.yaml`), rendered cell by cell and
    /// put end to end per role, give exactly the paths and capabilities of
    /// `vault_policy.org["batleforc-org_<role>"]` in the Terraform they
    /// replace (weebo-si `c4e62809^:2.terra/auth/terra-map/vault-spaces.tf`),
    /// `orgs-<env>/` becoming `<env>/orgs/`.
    #[test]
    fn the_weebo_layout_renders_the_terraform_org_policies() {
        use Capability::*;
        use std::collections::{BTreeMap, BTreeSet};

        let level = |data: &[Capability], metadata: &[Capability], versions| Level {
            data: data.to_vec(),
            metadata: metadata.to_vec(),
            versions,
        };
        let levels = BTreeMap::from([
            ("read", level(&[Read], &[Read, List], false)),
            (
                "write",
                level(&[Create, Read, Update, Patch], &[Read, List], false),
            ),
            (
                "owner",
                level(
                    &[Create, Read, Update, Patch, Delete],
                    &[Read, List, Delete],
                    true,
                ),
            ),
        ]);
        let layout = [
            (
                "owner",
                &[
                    ("prod", "owner"),
                    ("preprod", "owner"),
                    ("recette", "owner"),
                    ("devenv", "owner"),
                ][..],
            ),
            (
                "maintainer",
                &[
                    ("prod", "write"),
                    ("preprod", "write"),
                    ("recette", "write"),
                    ("devenv", "write"),
                ][..],
            ),
            (
                "dev",
                &[
                    ("preprod", "read"),
                    ("recette", "write"),
                    ("devenv", "write"),
                ][..],
            ),
        ];

        // The Terraform policies, expanded: `<path> <capabilities>`.
        let terraform: BTreeMap<&str, &str> = BTreeMap::from([
            (
                "owner",
                "\
                orgs-prod/data/batleforc-org/+/* create read update patch delete\n\
                orgs-prod/metadata/batleforc-org/* read list delete\n\
                orgs-prod/delete/batleforc-org/+/* update\n\
                orgs-prod/undelete/batleforc-org/+/* update\n\
                orgs-prod/destroy/batleforc-org/+/* update\n\
                orgs-preprod/data/batleforc-org/+/* create read update patch delete\n\
                orgs-preprod/metadata/batleforc-org/* read list delete\n\
                orgs-preprod/delete/batleforc-org/+/* update\n\
                orgs-preprod/undelete/batleforc-org/+/* update\n\
                orgs-preprod/destroy/batleforc-org/+/* update\n\
                orgs-recette/data/batleforc-org/+/* create read update patch delete\n\
                orgs-recette/metadata/batleforc-org/* read list delete\n\
                orgs-recette/delete/batleforc-org/+/* update\n\
                orgs-recette/undelete/batleforc-org/+/* update\n\
                orgs-recette/destroy/batleforc-org/+/* update\n\
                orgs-devenv/data/batleforc-org/+/* create read update patch delete\n\
                orgs-devenv/metadata/batleforc-org/* read list delete\n\
                orgs-devenv/delete/batleforc-org/+/* update\n\
                orgs-devenv/undelete/batleforc-org/+/* update\n\
                orgs-devenv/destroy/batleforc-org/+/* update",
            ),
            (
                "maintainer",
                "\
                orgs-prod/data/batleforc-org/+/* create read update patch\n\
                orgs-prod/metadata/batleforc-org/* read list\n\
                orgs-preprod/data/batleforc-org/+/* create read update patch\n\
                orgs-preprod/metadata/batleforc-org/* read list\n\
                orgs-recette/data/batleforc-org/+/* create read update patch\n\
                orgs-recette/metadata/batleforc-org/* read list\n\
                orgs-devenv/data/batleforc-org/+/* create read update patch\n\
                orgs-devenv/metadata/batleforc-org/* read list",
            ),
            (
                "dev",
                "\
                orgs-preprod/data/batleforc-org/+/* read\n\
                orgs-preprod/metadata/batleforc-org/* read list\n\
                orgs-recette/data/batleforc-org/+/* create read update patch\n\
                orgs-recette/metadata/batleforc-org/* read list\n\
                orgs-devenv/data/batleforc-org/+/* create read update patch\n\
                orgs-devenv/metadata/batleforc-org/* read list",
            ),
        ]);
        let expected = |text: &str| -> BTreeSet<(String, BTreeSet<String>)> {
            text.lines()
                .map(|l| {
                    let mut words = l.split_whitespace();
                    let path = words.next().unwrap();
                    let (mount, rest) = path.split_once('/').unwrap();
                    let env = mount.strip_prefix("orgs-").unwrap();
                    (
                        format!("{env}/orgs/{rest}"),
                        words.map(String::from).collect(),
                    )
                })
                .collect()
        };

        for (role, cells) in layout {
            let mut got = BTreeSet::new();
            for (env, lvl) in cells {
                let text = render(
                    &[rule(
                        "orgs",
                        "{org}/+/*",
                        Some("{org}/*"),
                        levels[lvl].clone(),
                    )],
                    &Context {
                        owner: "OpenbaoOrganization/batleforc-org",
                        organizations: &orgs(&["batleforc-org"]),
                        accessor: None,
                    },
                )
                .unwrap();
                // path "<p>" { capabilities = ["a", "b"] }
                for line in text.lines().filter(|l| l.starts_with("path ")) {
                    let (path, caps) = line
                        .strip_prefix("path \"")
                        .and_then(|l| l.split_once("\" { capabilities = ["))
                        .unwrap();
                    let caps = caps.strip_suffix("] }").unwrap();
                    got.insert((
                        format!("{env}/{path}"),
                        caps.split(", ")
                            .map(|c| c.trim_matches('"').to_string())
                            .collect(),
                    ));
                }
            }
            assert_eq!(got, expected(terraform[role]), "role {role}");
        }
    }

    #[test]
    fn org_expands_once_per_organization_and_versions_add_their_paths() {
        let owner = Level {
            data: vec![Capability::Read, Capability::Create],
            metadata: vec![],
            versions: true,
        };
        let text = render(
            &[rule("orgs", "{org}/ci", None, owner)],
            &Context {
                owner: "OpenbaoAccessGrant/ci",
                organizations: &orgs(&["a", "b"]),
                accessor: None,
            },
        )
        .unwrap();
        assert!(text.contains("path \"orgs/data/a/ci\" { capabilities = [\"create\", \"read\"] }"));
        assert!(text.contains("path \"orgs/data/b/ci\""));
        assert!(text.contains("path \"orgs/destroy/b/ci\" { capabilities = [\"update\"] }"));
        assert!(
            !text.contains("orgs/metadata/"),
            "no metadata capability, no block"
        );
    }

    #[test]
    fn service_account_tokens_template_on_the_accessor() {
        let text = render(
            &[rule("orgs", "batleforc-org/{sa.namespace}/*", None, read())],
            &Context {
                owner: "OpenbaoAccessGrant/repo-workloads-read-own",
                organizations: &[],
                accessor: Some("auth_kubernetes_1a2b"),
            },
        )
        .unwrap();
        assert!(text.contains(
            "path \"orgs/data/batleforc-org/{{identity.entity.aliases.auth_kubernetes_1a2b.metadata.service_account_namespace}}/*\""
        ));
        let no_accessor = render(
            &[rule("orgs", "x/{sa.name}", None, read())],
            &Context {
                owner: "OpenbaoAccessGrant/g",
                organizations: &[],
                accessor: None,
            },
        );
        assert!(matches!(no_accessor, Err(PolicyError::NoAccessor { .. })));
    }

    #[test]
    fn injection_attempts_are_refused_not_escaped() {
        for path in [
            r#"x" { capabilities = ["sudo"] } path "*"#,
            "x\npath \"*\"",
            "x#comment",
            "a b",
            "{org}x",
            "{{identity.entity.id}}",
            "*/x",
            "a//b",
            "/a",
            "a/",
            "..",
            "a/../b",
            "A",
            "",
        ] {
            assert!(RulePath::parse(path).is_err(), "{path:?} accepted");
        }
        let bad_org = render(
            &[rule("orgs", "{org}/*", None, read())],
            &Context {
                owner: "OpenbaoAccessGrant/g",
                organizations: &orgs(&["a\" } path \"*"]),
                accessor: None,
            },
        );
        assert!(matches!(bad_org, Err(PolicyError::Name { .. })));
    }

    #[test]
    fn user_space_templates_on_each_oidc_backend() {
        let text = render_user_space(
            "OpenbaoNamespace/users",
            &["auth_oidc_1", "auth_oidc_2"],
            "username",
        )
        .unwrap();
        assert!(text.contains(
            "path \"users/data/{{identity.entity.aliases.auth_oidc_1.metadata.username}}/*\" { capabilities = [\"create\", \"read\", \"update\", \"patch\", \"delete\"] }"
        ));
        assert!(text.contains("auth_oidc_2"));
        assert!(is_owned_by(&text, "OpenbaoNamespace/users"));
        assert!(!is_owned_by(&text, "OpenbaoNamespace/other"));
        assert!(render_user_space("OpenbaoNamespace/users", &["x}}/*"], "username").is_err());
        assert!(
            render_user_space("OpenbaoNamespace/users", &["auth_oidc_1"], "user name").is_err()
        );
    }

    /// xorshift64: a deterministic stream of bytes for the property below.
    struct Bytes(u64);
    impl Bytes {
        fn next(&mut self) -> u8 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0.to_le_bytes().first().copied().unwrap_or(0)
        }
    }

    /// `rendered_paths_stay_in_spaces` (RFC 0007 T2, decision 17): for
    /// arbitrary bytes, whatever parses renders only lines of the expected
    /// shape, every path under the rule's mount, and nothing else.
    #[test]
    fn rendered_paths_stay_in_spaces() {
        let alphabet = b"abz09._-+*/{}\"#\n \\$[]=org.sa";
        let mut bytes = Bytes(0x9E37_79B9_7F4A_7C15);
        let mut accepted = 0;
        for _ in 0..20_000 {
            let len = usize::from(bytes.next() % 24) + 1;
            let raw: Vec<u8> = (0..len)
                .map(|_| {
                    let i = usize::from(bytes.next()) % alphabet.len();
                    alphabet.get(i).copied().unwrap_or(b'a')
                })
                .collect();
            let Ok(path) = std::str::from_utf8(&raw) else {
                continue;
            };
            let Ok(path) = RulePath::parse(path) else {
                continue;
            };
            accepted += 1;
            let rule = Rule {
                mount: "orgs".into(),
                path,
                metadata_path: None,
                level: read(),
            };
            let text = render(
                &[rule],
                &Context {
                    owner: "OpenbaoAccessGrant/g",
                    organizations: &orgs(&["acme"]),
                    accessor: Some("auth_kubernetes_1"),
                },
            )
            .unwrap();
            for line in text.lines().skip(1) {
                let inner = line
                    .strip_prefix("path \"")
                    .and_then(|l| l.split_once("\" { capabilities = ["))
                    .map(|(p, _)| p)
                    .unwrap_or_else(|| panic!("unexpected line {line:?}"));
                assert!(
                    inner.starts_with("orgs/data/") || inner.starts_with("orgs/metadata/"),
                    "{inner:?}"
                );
                assert!(!inner.contains('"') && !inner.contains('\n'), "{inner:?}");
                assert!(line.ends_with("] }"), "{line:?}");
            }
        }
        assert!(
            accepted > 100,
            "the generator reached the accepted set ({accepted})"
        );
    }
}
