use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::SecretKeyRef;

use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::OpenbaoInstance as Instance;
pub use self::OpenbaoInstanceSpec as InstanceSpec;

/// The OpenBao server the spaces live on, and the operator's login there:
/// Kubernetes auth in the root, with the operator's ServiceAccount (no
/// static token). `Ready` tells whether OpenBao answers and accepts the
/// login.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoInstance",
    plural = "openbaoinstances",
    status = "Status",
    printcolumn = r#"{"name":"Address","type":"string","jsonPath":".spec.address"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct OpenbaoInstanceSpec {
    /// OpenBao's address, e.g. `https://openbao.vault:8200`. `https` only.
    #[schemars(regex(pattern = "^https://[^\\s/]+(:[0-9]+)?/?$"), length(max = 256))]
    pub address: String,
    /// The CA of OpenBao's certificate, `None` for the system trust store.
    /// No option turns the verification off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<InstanceTls>,
    /// The operator's login.
    pub auth: InstanceAuth,
    /// The OpenBao namespaces the operator's bootstrap policy lets it write
    /// to: an `OpenbaoNamespace` outside them is refused before any call.
    /// It can't widen anything, the policy stays the bound.
    #[serde(default)]
    pub bounds: Bounds,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceTls {
    /// The PEM bundle, in a key of a Secret.
    pub ca_secret_ref: SecretKeyRef,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InstanceAuth {
    pub kubernetes: KubernetesLogin,
}

/// Kubernetes auth in OpenBao's root namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesLogin {
    #[serde(default = "default_auth_mount")]
    #[schemars(length(min = 1, max = 128))]
    pub mount: String,
    #[schemars(length(min = 1, max = 128))]
    pub role: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Bounds {
    #[serde(default)]
    #[schemars(length(max = 16))]
    #[schemars(extend("items" = {"type": "string", "maxLength": 16,
        "pattern": "^[a-z]([a-z0-9-]{0,14}[a-z0-9])?$"}))]
    pub namespaces: Vec<String>,
}

fn default_auth_mount() -> String {
    "kubernetes".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_instance_parses_with_its_defaults() {
        let spec: InstanceSpec = serde_json::from_value(serde_json::json!({
            "address": "https://openbao.vault:8200",
            "tls": {"caSecretRef": {"namespace": "weebo-openbao", "name": "openbao-tls", "key": "ca.crt"}},
            "auth": {"kubernetes": {"role": "weebo-openbao"}},
            "bounds": {"namespaces": ["devenv", "prod", "users"]},
        }))
        .unwrap();
        assert_eq!(spec.auth.kubernetes.mount, "kubernetes");
        assert_eq!(spec.bounds.namespaces.len(), 3);
    }
}
