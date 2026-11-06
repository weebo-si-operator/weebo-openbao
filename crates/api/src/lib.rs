//! The CRDs of the operator. Pure types: `serde`/`schemars` derives and
//! the kit's shared field types, no client code. Doc comments become the
//! CRD schema descriptions (`crdgen` → `deploy/crd/`).
//!
//! The kinds' Rust types carry their kind's name (`OpenbaoInstance`, the
//! CRD's title); [`Instance`] is the short name of the instance.

pub mod access;
pub mod grant;
pub mod instance;
pub mod namespace;
pub mod refs;
pub mod status;

/// API group shared by every CRD of this operator.
pub const GROUP: &str = "openbao.weebo.io";

/// The kit's common annotations under [`GROUP`]:
/// `openbao.weebo.io/force-orphan` (release a CR without
/// cleanup), `allow-disruptive-update`, `rotate-secret`, `import-pending`.
pub const ANNOTATIONS: weebo_kit_api::Annotations = weebo_kit_api::Annotations::new(GROUP);

pub use access::{OpenbaoAccessLevel, OpenbaoOrganization, OpenbaoSpaceLayout};
pub use grant::OpenbaoAccessGrant;
pub use instance::Instance;
pub use namespace::OpenbaoNamespace;
pub use status::Status;
