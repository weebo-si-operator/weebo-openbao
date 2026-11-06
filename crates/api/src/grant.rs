//! The machine model (RFC 0007 §6.4): `OpenbaoAccessGrant`.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::refs::NameRef;
use crate::status::Status;

/// Access for workloads: Kubernetes ServiceAccounts (`subjects`) log in
/// to a `kubernetes` backend of an OpenBao namespace and get what `rules`
/// open there. One role per subject, `grant_<name>_<index>`, and one policy
/// `grant_<name>` (decision 18).
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoAccessGrant",
    plural = "openbaoaccessgrants",
    status = "GrantStatus",
    printcolumn = r#"{"name":"Namespace","type":"string","jsonPath":".spec.namespace"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
// `namespace` is a CEL keyword: a field of that name is `__namespace__`
// in the rules (unescaped, it is an unknown of unbounded cost).
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.instanceRef == oldSelf.instanceRef && self.__namespace__ == oldSelf.__namespace__ && self.auth == oldSelf.auth",
     "message": "instanceRef, namespace and auth are immutable: create another grant"},
    {"rule": "!self.subjects.exists(s, has(s.namespaceSelector) || (has(s.__namespace__) && s.__namespace__.contains('*'))) || self.rules.all(r, r.path.contains('{sa.namespace}') && (!has(r.metadataPath) || r.metadataPath.contains('{sa.namespace}')))",
     "message": "a broad subject (a namespace glob or a selector) needs {sa.namespace} in every rule's path and metadataPath"},
]))]
pub struct OpenbaoAccessGrantSpec {
    /// The `OpenbaoInstance` of the namespace.
    pub instance_ref: NameRef,
    /// The `OpenbaoNamespace` the access is in.
    #[schemars(regex(pattern = "^[a-z]([a-z0-9-]{0,14}[a-z0-9])?$"), length(max = 16))]
    pub namespace: String,
    /// The `kubernetes` backend of that namespace the subjects log in to.
    #[schemars(regex(pattern = "^[a-z]([a-z0-9-]{0,14}[a-z0-9])?$"), length(max = 16))]
    pub auth: String,
    /// The ServiceAccounts, one Kubernetes role each.
    #[schemars(length(min = 1, max = 8))]
    pub subjects: Vec<Subject>,
    /// What the subjects get.
    #[schemars(length(min = 1, max = 8))]
    pub rules: Vec<GrantRule>,
    /// Token lifetime of a workload login: 15 min by default, 1 h at most.
    #[serde(default = "default_machine_ttl")]
    #[schemars(range(min = 60, max = 3_600))]
    pub token_ttl_seconds: u32,
}

/// ServiceAccounts by namespace and name (a leading or trailing `*` glob),
/// or by a label selector on their namespaces.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.__namespace__) != has(self.namespaceSelector)",
     "message": "a subject names a namespace or a namespaceSelector, not both"},
]))]
pub struct Subject {
    /// A Kubernetes namespace, `*`, or a glob such as `team-*`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        regex(pattern = r"^(\*|\*?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\*?)$"),
        length(max = 63)
    )]
    pub namespace: Option<String>,
    /// Namespaces whose labels match all of these (never empty: an empty
    /// selector would match every namespace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend(
        "minProperties" = 1,
        "maxProperties" = 8,
        "additionalProperties" = {"type": "string", "maxLength": 63}
    ))]
    pub namespace_selector: Option<BTreeMap<String, String>>,
    /// A ServiceAccount name, `*`, or a glob.
    #[schemars(
        regex(pattern = r"^(\*|\*?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?\*?)$"),
        length(max = 253)
    )]
    pub name: String,
}

/// A level on a path of a mount of the namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "!(self.path.contains('{org}') || (has(self.metadataPath) && self.metadataPath.contains('{org}'))) || (has(self.organizations) && size(self.organizations) > 0)",
     "message": "a rule naming {org} lists its organizations (or [\"*\"])"},
]))]
pub struct GrantRule {
    /// The KV v2 mount: a type of the namespace (`orgs`, `users`).
    #[schemars(regex(pattern = "^(orgs|users)$"), length(max = 5))]
    pub mount: String,
    /// The path under the mount: segments of `[a-z0-9._-]`, `+`, a last
    /// `*`, or a whole token `{org}`, `{sa.namespace}`, `{sa.name}`.
    #[schemars(
        regex(
            pattern = r"^(([a-z0-9._-]+|\+|\{org\}|\{sa\.namespace\}|\{sa\.name\})/)*([a-z0-9._-]+|\+|\*|\{org\}|\{sa\.namespace\}|\{sa\.name\})$"
        ),
        length(max = 256)
    )]
    #[schemars(extend("x-kubernetes-validations" = [
        {"rule": r"!self.matches('(^|/)\\.\\.?(/|$)')", "message": "no `.` or `..` segment"},
    ]))]
    pub path: String,
    /// The metadata path, when it differs from `path`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(
        regex(
            pattern = r"^(([a-z0-9._-]+|\+|\{org\}|\{sa\.namespace\}|\{sa\.name\})/)*([a-z0-9._-]+|\+|\*|\{org\}|\{sa\.namespace\}|\{sa\.name\})$"
        ),
        length(max = 256)
    )]
    pub metadata_path: Option<String>,
    /// The organizations `{org}` expands over; `["*"]`: every organization
    /// of the instance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 32))]
    #[schemars(extend("items" = {"type": "string", "maxLength": 40,
        "pattern": "^(\\*|[a-z0-9]([a-z0-9._-]{0,38}[a-z0-9])?)$"}))]
    pub organizations: Vec<String>,
    /// The `OpenbaoAccessLevel`.
    #[schemars(length(min = 1, max = 253))]
    pub level: String,
}

/// What the grant wrote: its policy and the role of each subject, the
/// names a consumer puts in its `additionalMounts[].auth`.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantStatus {
    #[serde(flatten)]
    pub common: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// `grant_<name>_<index>`, in the order of `subjects`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

fn default_machine_ttl() -> u32 {
    900
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn the_forgejo_grant_of_the_rfc_parses() {
        let spec: OpenbaoAccessGrantSpec = serde_json::from_value(serde_json::json!({
            "instanceRef": {"name": "main"},
            "namespace": "users",
            "auth": "kubernetes",
            "subjects": [{"namespace": "weebo-forgejo", "name": "weebo-forgejo"}],
            "rules": [{"mount": "users", "path": "+/forgejo-token", "level": "token-writer"}],
        }))
        .unwrap();
        assert_eq!(spec.token_ttl_seconds, 900);
        assert!(
            spec.rules
                .first()
                .is_some_and(|r| r.organizations.is_empty())
        );
    }

    #[test]
    fn the_crd_carries_the_broad_subject_rule() {
        let crd = serde_json::to_string(&OpenbaoAccessGrant::crd()).unwrap();
        assert!(
            crd.contains("a broad subject"),
            "the CEL rule is in the schema"
        );
        assert!(crd.contains("one Kubernetes role each"));
    }
}
