use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
pub use weebo_kit_api::LocalSecretKeyRef;

use crate::refs::NameRef;
use crate::status::Status;

/// What the operator found and wrote in the namespace.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceStatus {
    #[serde(flatten)]
    pub common: Status,
    /// The auth backends as OpenBao lists them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<AuthStatus>,
    /// `orgs` or `users` mounts no longer declared, left with their secrets.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphaned_mounts: Vec<String>,
    /// Backends this operator enabled, no longer declared, left enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphaned_auth: Vec<String>,
    /// Policies and groups marked for an organization or a grant that no
    /// longer exists (`policy <name>`, `group <name>`); removed under
    /// `allow-disruptive-update` on the namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub left_over: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// What group aliases and templated policies name the backend by.
    pub accessor: String,
    /// SHA-256 of the client secret last written: the secret can't be read
    /// back, a change of digest rewrites the configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_digest: Option<String>,
}

/// An OpenBao namespace of the spaces, named by `metadata.name`, created
/// by the operator and never deleted by it. Its `types` each get a KV v2
/// mount of that name; its `auth` backends are created and configured, and
/// never disabled by the operator either. The root namespace stays the
/// infrastructure's: it can't be declared here.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoNamespace",
    plural = "openbaonamespaces",
    status = "NamespaceStatus",
    validation = r#"self.metadata.name.matches('^[a-z]([a-z0-9-]{0,14}[a-z0-9])?$')"#,
    validation = r#"!(self.metadata.name in ['root', 'infra', 'sys', 'identity', 'auth', 'cubbyhole'])"#,
    printcolumn = r#"{"name":"Types","type":"string","jsonPath":".spec.types"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.instanceRef == oldSelf.instanceRef", "message": "instanceRef is immutable"},
]))]
pub struct OpenbaoNamespaceSpec {
    /// The `OpenbaoInstance` the namespace lives on.
    pub instance_ref: NameRef,
    /// What the namespace holds, one KV v2 mount per type, named after it.
    #[schemars(length(min = 1, max = 2))]
    #[schemars(extend("x-kubernetes-list-type" = "set"))]
    pub types: Vec<SpaceType>,
    /// The auth backends of the namespace. Empty: nobody logs in (closed).
    #[serde(default)]
    #[schemars(length(max = 4))]
    #[schemars(extend("x-kubernetes-list-type" = "map", "x-kubernetes-list-map-keys" = ["name"]))]
    pub auth: Vec<AuthBackend>,
}

/// A type of space.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum SpaceType {
    /// Organizations' spaces, `orgs/<org>/<repo>/…`.
    Orgs,
    /// Personal spaces, `users/<username>/…`.
    Users,
}

impl SpaceType {
    /// The KV v2 mount of this type.
    pub fn mount(self) -> &'static str {
        match self {
            Self::Orgs => "orgs",
            Self::Users => "users",
        }
    }
}

/// An auth backend of the namespace: exactly one method field.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "(has(self.oidc) ? 1 : 0) + (has(self.kubernetes) ? 1 : 0) == 1",
     "message": "an auth backend sets exactly one method: oidc or kubernetes"},
    {"rule": "!(self.name in ['root', 'infra', 'sys', 'identity', 'auth', 'cubbyhole'])",
     "message": "the backend name is reserved"},
]))]
pub struct AuthBackend {
    /// The backend's mount path in the namespace (`bao login -path=<name>`).
    #[schemars(regex(pattern = "^[a-z]([a-z0-9-]{0,14}[a-z0-9])?$"), length(max = 16))]
    pub name: String,
    /// OpenID Connect, for humans: any OIDC identity provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcAuth>,
    /// Kubernetes ServiceAccounts, for workloads: this cluster's apiserver,
    /// with OpenBao's own CA and token for the TokenReview.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesAuth>,
}

/// An OIDC backend and its `default` role.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.tokenTtlSeconds <= self.tokenMaxTtlSeconds",
     "message": "tokenTtlSeconds is at most tokenMaxTtlSeconds"},
]))]
pub struct OidcAuth {
    /// The provider's issuer, discovered by OpenBao. `https` only.
    #[schemars(regex(pattern = "^https://[^\\s]+$"), length(max = 512))]
    pub discovery_url: String,
    #[schemars(length(min = 1, max = 256))]
    pub client_id: String,
    /// The client secret, in a Secret of the operator's namespace.
    pub client_secret_ref: LocalSecretKeyRef,
    /// Scopes asked for, e.g. `openid`, `profile`, `groups`.
    #[serde(default = "default_scopes")]
    #[schemars(length(max = 16))]
    #[schemars(extend("items" = {"type": "string", "maxLength": 64}))]
    pub scopes: Vec<String>,
    /// The claim identifying a user (`sub` keeps it stable).
    #[serde(default = "default_user_claim")]
    #[schemars(length(min = 1, max = 64))]
    pub user_claim: String,
    /// The claim listing a user's groups, which group aliases match.
    #[serde(default = "default_groups_claim")]
    #[schemars(length(min = 1, max = 64))]
    pub groups_claim: String,
    /// Allowed redirect URIs, compared as exact strings: `https://…`, or
    /// `http://localhost:<port>/…` for the CLI.
    #[schemars(length(min = 1, max = 8))]
    #[schemars(extend("items" = {
        "type": "string", "maxLength": 512,
        "pattern": "^(https://[^\\s]+|http://localhost(:[0-9]+)?/[^\\s]*)$"
    }))]
    pub redirect_uris: Vec<String>,
    /// Token lifetime of a human login: 1 h by default, 24 h at most.
    #[serde(default = "default_human_ttl")]
    #[schemars(range(min = 60, max = 86_400))]
    pub token_ttl_seconds: u32,
    /// Maximum lifetime with renewals: 8 h by default, 24 h at most.
    #[serde(default = "default_human_max_ttl")]
    #[schemars(range(min = 60, max = 86_400))]
    pub token_max_ttl_seconds: u32,
}

/// A Kubernetes backend. No other cluster in v1 (decision 18): OpenBao's
/// own token would be sent to the host named.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesAuth {}

fn default_scopes() -> Vec<String> {
    ["openid", "profile", "groups"].map(String::from).to_vec()
}
fn default_user_claim() -> String {
    "sub".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_human_ttl() -> u32 {
    3_600
}
fn default_human_max_ttl() -> u32 {
    28_800
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn the_crd_refuses_reserved_and_nested_names_at_its_root() {
        let crd = serde_json::to_value(OpenbaoNamespace::crd()).unwrap();
        let rules =
            &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["x-kubernetes-validations"];
        let text = rules.to_string();
        assert!(text.contains("self.metadata.name.matches"), "{text}");
        assert!(text.contains("'infra'"), "{text}");
    }

    #[test]
    fn an_oidc_backend_takes_safe_defaults() {
        let backend: AuthBackend = serde_json::from_value(serde_json::json!({
            "name": "authentik",
            "oidc": {
                "discoveryUrl": "https://auth.example/application/o/openbao/",
                "clientId": "openbao",
                "clientSecretRef": {"name": "openbao-oidc", "key": "client-secret"},
                "redirectUris": ["http://localhost:8250/oidc/callback"],
            }
        }))
        .unwrap();
        let oidc = backend.oidc.unwrap();
        assert_eq!(oidc.token_ttl_seconds, 3_600);
        assert_eq!(oidc.token_max_ttl_seconds, 28_800);
        assert_eq!(oidc.user_claim, "sub");
        assert_eq!(SpaceType::Users.mount(), "users");
    }
}
