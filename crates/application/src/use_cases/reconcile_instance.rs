//! An `OpenbaoInstance` has nothing to write: reconciling it checks that
//! OpenBao answers and accepts the operator's login, which every CR on it
//! depends on.

use crate::ports::SpaceAdmin;
use crate::use_cases::Outcome;

pub async fn reconcile_instance(admin: &dyn SpaceAdmin) -> Outcome {
    match admin.check().await {
        Ok(()) => Outcome::synced(None, "OpenBao answers the operator's login"),
        Err(e) => Outcome::failed(e),
    }
}

#[cfg(test)]
mod tests {
    use domain::error::ReasonCode;

    use super::*;
    use crate::ports::OpenbaoError;
    use crate::test_support::FakeSpaceAdmin;

    #[tokio::test]
    async fn a_reachable_instance_is_ready() {
        let outcome = reconcile_instance(&FakeSpaceAdmin::default()).await;
        assert_eq!(outcome.reason(), ReasonCode::Reconciled);
    }

    #[tokio::test]
    async fn a_sealed_or_refusing_instance_is_not() {
        let admin = FakeSpaceAdmin::default();
        admin.fail_with(Some(OpenbaoError::Sealed("503".into())));
        assert_eq!(
            reconcile_instance(&admin).await.reason(),
            ReasonCode::VaultSealed
        );
        admin.fail_with(Some(OpenbaoError::PermissionDenied("403".into())));
        assert_eq!(
            reconcile_instance(&admin).await.reason(),
            ReasonCode::PermissionDenied
        );
    }
}
