//! `OpenbaoAccessLevel` (cluster-scoped): nothing to write, the policies
//! citing it are the organizations' and grants'. Its `in-use` finalizer
//! holds its deletion while a layout or a grant cites it (decision 21).

use std::sync::Arc;
use std::time::Instant;

use api::OpenbaoAccessLevel;
use application::use_cases::Outcome;
use domain::Failure;
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};

use super::{Ctx, Error, IN_USE_FINALIZER, error_policy};

const KIND: &str = "OpenbaoAccessLevel";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<OpenbaoAccessLevel>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<OpenbaoAccessLevel>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<OpenbaoAccessLevel> = Api::all(ctx.client.clone());
    finalizer(&api, IN_USE_FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(level) => {
                let started = Instant::now();
                let citers = super::in_use::level_citers(&ctx.client, &level.name_any()).await?;
                let outcome = Outcome::synced(None, format!("cited by {} object(s)", citers.len()));
                super::record_reconcile(KIND, started, &outcome);
                super::publish(
                    &api,
                    &ctx.recorder,
                    level.as_ref(),
                    &outcome,
                    serde_json::Map::new(),
                )
                .await?;
                Ok(super::requeue_after(level.as_ref(), &outcome))
            }
            FinalizerEvent::Cleanup(level) => {
                let citers = super::in_use::level_citers(&ctx.client, &level.name_any()).await?;
                let held = async {
                    if citers.is_empty() {
                        Ok(())
                    } else {
                        Err(Error::Cleanup(Failure::new(
                            ReasonCode::InUse,
                            format!("still cited by {}", citers.join(", ")),
                        )))
                    }
                };
                super::finalize(level.as_ref(), &ctx, held).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}
