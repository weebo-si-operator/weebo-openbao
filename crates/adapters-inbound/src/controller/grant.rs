//! `OpenbaoAccessGrant` (cluster-scoped, RFC 0007 §6.4): its policy and a
//! Kubernetes role per subject (`reconcile_grant`), and on deletion the
//! roles then the policy (finalizer). What it let workloads write stays.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Instant;

use api::{OpenbaoAccessGrant, OpenbaoNamespace, OpenbaoOrganization, OpenbaoSpaceLayout};
use application::ports::BoundInstance;
use application::use_cases::reconcile_grant::{
    GrantInput, GrantNamespace, cleanup_grant, reconcile_grant,
};
use domain::Failure;
use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};

use super::{Ctx, Error, FINALIZER, HasStatus, error_policy};

const KIND: &str = "OpenbaoAccessGrant";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<OpenbaoAccessGrant>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<OpenbaoAccessGrant>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<OpenbaoAccessGrant> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(grant) => apply(&api, &grant, &ctx).await,
            FinalizerEvent::Cleanup(grant) => {
                super::finalize(grant.as_ref(), &ctx, cleanup(&api, &grant, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn ready<K: HasStatus>(obj: &K) -> bool {
    obj.status().is_some_and(|s| {
        s.conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
    })
}

/// The grant's namespace, if declared on its instance.
async fn namespace(
    client: &Client,
    instance: &str,
    name: &str,
) -> Result<Option<GrantNamespace>, kube::Error> {
    let api: Api<OpenbaoNamespace> = Api::all(client.clone());
    Ok(api
        .get_opt(name)
        .await?
        .filter(|n| n.spec.instance_ref.name == instance)
        .map(|n| GrantNamespace {
            ready: ready(&n),
            mounts: n.spec.types.iter().map(|t| t.mount().to_string()).collect(),
            kubernetes: n
                .status
                .iter()
                .flat_map(|s| &s.auth)
                .filter(|a| a.kind == "kubernetes" && !a.accessor.is_empty())
                .map(|a| (a.name.clone(), a.accessor.clone()))
                .collect(),
        }))
}

/// Every organization's name on `instance`, for `organizations: ["*"]`.
async fn organizations(client: &Client, instance: &str) -> Result<Vec<String>, kube::Error> {
    let layouts: Api<OpenbaoSpaceLayout> = Api::all(client.clone());
    let on_instance: BTreeSet<String> = layouts
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|l| l.spec.instance_ref.name == instance)
        .map(|l| l.name_any())
        .collect();
    let orgs: Api<OpenbaoOrganization> = Api::all(client.clone());
    let names: BTreeSet<String> = orgs
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|o| on_instance.contains(&o.spec.layout_ref.name))
        .map(|o| o.spec.name)
        .collect();
    Ok(names.into_iter().collect())
}

async fn apply(
    api: &Api<OpenbaoAccessGrant>,
    grant: &OpenbaoAccessGrant,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let current = api.get(&grant.name_any()).await?;
    let started = Instant::now();
    let instance = current.spec.instance_ref.name.clone();
    let previous: Vec<String> = current
        .status
        .iter()
        .flat_map(|s| s.roles.clone())
        .collect();
    let levels = super::organization::levels(&ctx.client).await?;
    let namespace = namespace(&ctx.client, &instance, &current.spec.namespace).await?;
    let orgs = organizations(&ctx.client, &instance).await?;
    let mut extra = serde_json::Map::new();
    let outcome = match ctx.admins.admin_for(&instance).await {
        Err(e) => application::use_cases::Outcome::failed(e),
        Ok(admin) => {
            let report = reconcile_grant(
                admin.as_ref(),
                &GrantInput {
                    name: &current.name_any(),
                    spec: &current.spec,
                    levels: &levels,
                    organizations: &orgs,
                    namespace: namespace.as_ref(),
                    previous_roles: &previous,
                },
            )
            .await;
            if let Some(policy) = &report.policy {
                extra.insert("policy".into(), policy.clone().into());
            }
            extra.insert(
                "roles".into(),
                serde_json::to_value(&report.roles).map_err(kube::Error::SerdeError)?,
            );
            report.outcome.on(BoundInstance::cluster(instance))
        }
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(api, &ctx.recorder, &current, &outcome, extra).await?;
    Ok(super::requeue_after(&current, &outcome))
}

async fn cleanup(
    api: &Api<OpenbaoAccessGrant>,
    grant: &OpenbaoAccessGrant,
    ctx: &Ctx,
) -> Result<(), Error> {
    let Some(grant) = api.get_opt(&grant.name_any()).await? else {
        return Ok(());
    };
    let Some(status) = &grant.status else {
        return Ok(());
    };
    if status.policy.is_none() && status.roles.is_empty() {
        return Ok(());
    }
    let Some(instance) = grant.bound_instance().map(|b| b.name.clone()) else {
        return Ok(());
    };
    let admin = ctx
        .admins
        .admin_for(&instance)
        .await
        .map_err(|e| Error::Cleanup(Failure::from(e)))?;
    cleanup_grant(
        admin.as_ref(),
        &grant.spec.namespace,
        &grant.spec.auth,
        &grant.name_any(),
        &status.roles,
    )
    .await
    .map_err(|e| Error::Cleanup(Failure::from(e)))?;
    super::metrics().record_write(KIND, domain::RemoteWrite::Deleted);
    Ok(())
}
