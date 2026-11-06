use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::SecretKeyRef;

use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::OpenbaoInstance as Instance;
pub use self::OpenbaoInstanceSpec as InstanceSpec;

/// Connection to one Openbao server. Cluster-scoped: an org-wide piece
/// of infrastructure, not owned by a namespace (a namespace's own server
/// is a `OpenbaoLocalInstance`). `Ready` tells whether the server
/// answers with the token below.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoInstance",
    plural = "openbaoinstances",
    status = "Status",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct OpenbaoInstanceSpec {
    /// Base URL of the Openbao server, e.g. `https://example.com`.
    pub url: String,
    /// The API token the operator authenticates with. Read on every
    /// reconcile: rotating it needs no restart.
    pub token_secret_ref: SecretKeyRef,
}
