//! `OpenbaoSpaceLayout` (cluster-scoped): checks the levels and the
//! namespaces its cells cite, and the `users` block a `users` namespace
//! needs (`check_layout`). Writes nothing to OpenBao.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use api::namespace::SpaceType;
use api::{OpenbaoNamespace, OpenbaoSpaceLayout};
use application::use_cases::check_layout::{LayoutNamespace, check_layout};
use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};

use super::{Ctx, Error, error_policy};

const KIND: &str = "OpenbaoSpaceLayout";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<OpenbaoSpaceLayout>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<OpenbaoSpaceLayout>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let api: Api<OpenbaoSpaceLayout> = Api::all(ctx.client.clone());
    let started = Instant::now();
    let levels: BTreeSet<String> = super::organization::levels(&ctx.client)
        .await?
        .into_keys()
        .collect();
    let namespaces_api: Api<OpenbaoNamespace> = Api::all(ctx.client.clone());
    let namespaces: BTreeMap<String, LayoutNamespace> = namespaces_api
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|n| n.spec.instance_ref.name == obj.spec.instance_ref.name)
        .map(|n| {
            let ns = LayoutNamespace {
                orgs: n.spec.types.contains(&SpaceType::Orgs),
                users: n.spec.types.contains(&SpaceType::Users),
            };
            (n.name_any(), ns)
        })
        .collect();
    let outcome = check_layout(
        &obj.spec.roles,
        &levels,
        &namespaces,
        obj.spec.users.is_some(),
    );
    super::record_reconcile(KIND, started, &outcome);
    super::publish(
        &api,
        &ctx.recorder,
        obj.as_ref(),
        &outcome,
        serde_json::Map::new(),
    )
    .await?;
    Ok(super::requeue_after(obj.as_ref(), &outcome))
}
