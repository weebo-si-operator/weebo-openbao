//! Port traits: what the use-cases need from the outside world. One
//! [`SpaceAdmin`] per `OpenbaoInstance`, logged in, from the
//! [`SpaceAdminFactory`].

pub use crate::space::{
    Group, GroupAlias, GroupSpec, KubernetesRole, Mounted, OidcConfig, OidcRole, OpenbaoError,
    SpaceAdmin, SpaceAdminFactory, SpaceAdminFactoryError,
};
pub use weebo_kit_application::instances::BoundInstance;
