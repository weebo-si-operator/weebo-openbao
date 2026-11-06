//! The human model's kinds and the levels both models share (RFC 0007
//! §4.1): `OpenbaoAccessLevel`, `OpenbaoSpaceLayout`, `OpenbaoOrganization`.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::refs::NameRef;
use crate::status::Status;

/// A level of access, named by `metadata.name`, cited by the layout's
/// cells and the grants' rules. Changing it rewrites every policy citing
/// it; it can't be deleted while cited.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoAccessLevel",
    plural = "openbaoaccesslevels",
    status = "Status",
    printcolumn = r#"{"name":"Data","type":"string","jsonPath":".spec.data"}"#,
    printcolumn = r#"{"name":"Metadata","type":"string","jsonPath":".spec.metadata"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "size(self.data) + size(self.metadata) > 0 || self.versions",
     "message": "a level grants at least one capability"},
]))]
pub struct OpenbaoAccessLevelSpec {
    /// Capabilities on the secrets (`<mount>/data/<path>`).
    #[serde(default)]
    #[schemars(length(max = 6))]
    #[schemars(extend("x-kubernetes-list-type" = "set"))]
    pub data: Vec<KvCapability>,
    /// Capabilities on the metadata (`<mount>/metadata/<path>`).
    #[serde(default)]
    #[schemars(length(max = 6))]
    #[schemars(extend("x-kubernetes-list-type" = "set"))]
    pub metadata: Vec<KvCapability>,
    /// Delete, undelete and destroy past versions.
    #[serde(default)]
    pub versions: bool,
}

/// A KV v2 capability. `sudo`, `deny` and `subscribe` are not offered.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum KvCapability {
    Create,
    Read,
    Update,
    Patch,
    Delete,
    List,
}

/// The human model: which role of an organization gets which level in
/// which namespace of type `orgs`, the personal spaces, and the name of
/// the identity provider's groups.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoSpaceLayout",
    plural = "openbaospacelayouts",
    status = "Status",
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.instanceRef == oldSelf.instanceRef", "message": "instanceRef is immutable"},
]))]
pub struct OpenbaoSpaceLayoutSpec {
    /// The `OpenbaoInstance` of the spaces.
    pub instance_ref: NameRef,
    /// The alias of a group at the identity provider, rendered with
    /// `{org}` and `{role}`.
    #[serde(default = "default_alias_template")]
    #[schemars(
        regex(pattern = r"^([a-z0-9._-]|\{org\}|\{role\})+$"),
        length(max = 64)
    )]
    #[schemars(extend("x-kubernetes-validations" = [
        {"rule": "self.contains('{org}') && self.contains('{role}')",
         "message": "groupAliasTemplate names both {org} and {role}"},
    ]))]
    pub group_alias_template: String,
    /// Role → namespace of type `orgs` → `OpenbaoAccessLevel` name. A role
    /// absent has no objects; removing one removes its access, only under
    /// the `allow-disruptive-update` annotation.
    #[schemars(extend(
        "minProperties" = 1,
        "maxProperties" = 16,
        "additionalProperties" = {
            "type": "object", "maxProperties": 8,
            "additionalProperties": {"type": "string", "maxLength": 253}
        }
    ))]
    #[schemars(extend("x-kubernetes-validations" = [
        {"rule": "self.all(r, r.matches('^[a-z]{1,16}$'))",
         "message": "a role is 1 to 16 lowercase letters (no `_`)"},
    ]))]
    pub roles: BTreeMap<String, BTreeMap<String, String>>,
    /// The personal spaces, required as soon as a namespace has the type
    /// `users`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub users: Option<UsersSpaces>,
}

/// How a personal space is named after its user.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UsersSpaces {
    /// The identity provider's claim holding the username.
    #[serde(default = "default_username_claim")]
    #[schemars(length(min = 1, max = 64))]
    pub username_claim: String,
    /// The alias metadata key the claim is mapped to, which the personal
    /// space's policy templates on.
    #[serde(default = "default_metadata_key")]
    #[schemars(regex(pattern = "^[a-z][a-z0-9_]{0,31}$"))]
    pub alias_metadata_key: String,
}

/// An organization: its access follows the layout, its name is the
/// `{org}` of the identity provider's groups.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "openbao.weebo.io",
    version = "v1alpha1",
    kind = "OpenbaoOrganization",
    plural = "openbaoorganizations",
    status = "OrganizationStatus",
    printcolumn = r#"{"name":"Name","type":"string","jsonPath":".spec.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.name == oldSelf.name && self.layoutRef == oldSelf.layoutRef",
     "message": "name and layoutRef are immutable: create another organization"},
]))]
pub struct OpenbaoOrganizationSpec {
    /// The `OpenbaoSpaceLayout` its access follows.
    pub layout_ref: NameRef,
    /// The organization's name, as the identity provider's groups carry
    /// it; also the folder of its secrets, `orgs/<name>/`.
    #[schemars(
        regex(pattern = "^[a-z0-9]([a-z0-9._-]{0,38}[a-z0-9])?$"),
        length(max = 40)
    )]
    pub name: String,
    /// Per role, an alias other than the template's: to follow a group
    /// renamed at the identity provider.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(extend(
        "maxProperties" = 16,
        "additionalProperties" = {"type": "string", "maxLength": 64}
    ))]
    pub alias_names: BTreeMap<String, String>,
}

/// What the organization wrote: the cells, recorded so that the next pass
/// and the finalizer remove exactly them, without listing anything.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationStatus {
    #[serde(flatten)]
    pub common: Status,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cells: Vec<CellStatus>,
}

/// One role × namespace of the layout.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CellStatus {
    pub namespace: String,
    pub role: String,
    pub policy: String,
    /// One external group per OIDC backend of the namespace.
    #[serde(default)]
    pub groups: Vec<CellGroupStatus>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CellGroupStatus {
    pub backend: String,
    pub name: String,
    /// OpenBao's id of the group.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_id: Option<String>,
}

fn default_alias_template() -> String {
    "{org}_{role}".into()
}
fn default_username_claim() -> String {
    "preferred_username".into()
}
fn default_metadata_key() -> String {
    "username".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_layout_reproduces_the_terraform_matrix() {
        let spec: OpenbaoSpaceLayoutSpec = serde_json::from_value(serde_json::json!({
            "instanceRef": {"name": "main"},
            "roles": {
                "owner": {"prod": "owner", "preprod": "owner"},
                "dev": {"preprod": "read", "devenv": "write"},
            },
        }))
        .unwrap();
        assert_eq!(spec.group_alias_template, "{org}_{role}");
        assert_eq!(spec.roles["dev"]["preprod"], "read");
        assert!(spec.users.is_none());
    }

    #[test]
    fn a_level_with_versions_alone_is_a_level() {
        let level: OpenbaoAccessLevelSpec =
            serde_json::from_value(serde_json::json!({"versions": true})).unwrap();
        assert!(level.data.is_empty() && level.versions);
    }
}
