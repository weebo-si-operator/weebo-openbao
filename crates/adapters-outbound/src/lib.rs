//! Outbound adapters: [`OpenbaoSpaceAdmin`], `application::space::SpaceAdmin`
//! on OpenBao's API, and the factory logging in one per `OpenbaoInstance`.

pub mod admin_factory;
pub mod openbao;

pub use admin_factory::KubeSpaceAdminFactory;
pub use openbao::OpenbaoSpaceAdmin;
