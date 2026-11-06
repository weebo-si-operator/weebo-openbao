//! Test harness of the operator: the kit's envtest control plane with this
//! operator's CRDs, status polling, and an in-memory OpenBao.

pub mod envtest;
pub mod polling;

pub use application::test_support::{FakeSpaceAdmin, StaticAdminFactory};
