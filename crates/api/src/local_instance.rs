use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::{LocalSecretKeyRef, SharedWith};

use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::OpenbaoLocalInstance as LocalInstance;
pub use self::OpenbaoLocalInstanceSpec as LocalInstanceSpec;

/// Connection to one Openbao server, owned by a namespace: its token
/// is that namespace's, and only its objects use it unless `sharedWith`
/// says otherwise. What an operator limited to one namespace uses. `Ready`
/// tells whether the server answers with the token below.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoLocalInstance",
    plural = "openbaolocalinstances",
    namespaced,
    status = "Status",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct OpenbaoLocalInstanceSpec {
    /// Base URL of the Openbao server, e.g. `https://example.com`.
    pub url: String,
    /// The API token the operator authenticates with, in a `Secret` of
    /// this namespace labelled
    /// `openbao.weebo.io/instance-token: "true"` (without the
    /// label the operator doesn't read it). Read on every reconcile:
    /// rotating it needs no restart.
    pub token_secret_ref: LocalSecretKeyRef,
    /// Other namespaces (or cluster-scoped objects) allowed to use this
    /// instance — and its token. Unset: this namespace only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_with: Option<SharedWith>,
}

impl weebo_kit_api::SharesItself for LocalInstance {
    fn shared_with(&self) -> Option<&SharedWith> {
        self.spec.shared_with.as_ref()
    }
}
