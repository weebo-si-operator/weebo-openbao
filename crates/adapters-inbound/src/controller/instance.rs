//! `OpenbaoInstance` (cluster-scoped): reconciling it checks OpenBao
//! answers the operator's login (`reconcile_instance`). Its `in-use`
//! finalizer (decision 21) comes with the kinds that cite it.

use std::sync::Arc;
use std::time::Instant;

use api::Instance;
use application::use_cases::Outcome;
use application::use_cases::reconcile_instance::reconcile_instance;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};

use super::{Ctx, Error, error_policy};

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
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let api: Api<Instance> = Api::all(ctx.client.clone());
    let started = Instant::now();
    let outcome = match ctx.admins.admin_for(&obj.name_any()).await {
        Ok(admin) => reconcile_instance(admin.as_ref()).await,
        Err(e) => Outcome::failed(e),
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(&api, &ctx.recorder, obj.as_ref(), &outcome).await?;
    Ok(super::requeue_after(obj.as_ref(), &outcome))
}
