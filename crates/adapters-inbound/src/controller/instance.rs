//! `OpenbaoInstance` (cluster-scoped): reconciling it checks OpenBao
//! answers the operator's login (`reconcile_instance`). Its `in-use`
//! finalizer (decision 21) holds its deletion while a namespace, a layout
//! or a grant cites it: their finalizers still need to log in.

use std::sync::Arc;
use std::time::Instant;

use api::Instance;
use application::use_cases::Outcome;
use application::use_cases::reconcile_instance::reconcile_instance;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};

use domain::Failure;
use domain::error::ReasonCode;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};

use super::{Ctx, Error, IN_USE_FINALIZER, error_policy};

const KIND: &str = "OpenbaoInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<Instance>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<Instance>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<Instance> = Api::all(ctx.client.clone());
    finalizer(&api, IN_USE_FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(instance) => apply(&api, &instance, &ctx).await,
            FinalizerEvent::Cleanup(instance) => {
                let citers =
                    super::in_use::instance_citers(&ctx.client, &instance.name_any()).await?;
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
                super::finalize(instance.as_ref(), &ctx, held).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

async fn apply(api: &Api<Instance>, obj: &Instance, ctx: &Ctx) -> Result<Action, Error> {
    let started = Instant::now();
    let outcome = match ctx.admins.admin_for(&obj.name_any()).await {
        Ok(admin) => reconcile_instance(admin.as_ref()).await,
        Err(e) => Outcome::failed(e),
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(api, &ctx.recorder, obj, &outcome, serde_json::Map::new()).await?;
    Ok(super::requeue_after(obj, &outcome))
}
