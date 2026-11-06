//! `OpenbaoOrganization` (cluster-scoped, RFC 0007 §5.2): its cells
//! (`reconcile_organization`), and on deletion their removal, alias first
//! (finalizer). Its secrets stay in `<ns>/orgs/<org>/`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use api::access::{CellGroupStatus, CellStatus, KvCapability};
use api::namespace::SpaceType;
use api::{OpenbaoAccessLevel, OpenbaoNamespace, OpenbaoOrganization, OpenbaoSpaceLayout};
use application::ports::BoundInstance;
use application::use_cases::Outcome;
use application::use_cases::reconcile_organization::{
    Cell, CellGroup, CellNamespace, OrgInput, cleanup_organization, reconcile_organization,
};
use domain::Failure;
use domain::error::ReasonCode;
use domain::policy::{Capability, Level};
use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, Resource, ResourceExt};
use weebo_kit_runtime::events;

use super::{Ctx, Error, FINALIZER, HasStatus, error_policy};

const KIND: &str = "OpenbaoOrganization";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<OpenbaoOrganization>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<OpenbaoOrganization>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let api: Api<OpenbaoOrganization> = Api::all(ctx.client.clone());
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(org) => apply(&api, &org, &ctx).await,
            FinalizerEvent::Cleanup(org) => {
                super::finalize(org.as_ref(), &ctx, cleanup(&api, &org, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn capability(c: KvCapability) -> Capability {
    match c {
        KvCapability::Create => Capability::Create,
        KvCapability::Read => Capability::Read,
        KvCapability::Update => Capability::Update,
        KvCapability::Patch => Capability::Patch,
        KvCapability::Delete => Capability::Delete,
        KvCapability::List => Capability::List,
    }
}

/// Every `OpenbaoAccessLevel`, as the domain renders them.
pub async fn levels(client: &Client) -> Result<BTreeMap<String, Level>, kube::Error> {
    let api: Api<OpenbaoAccessLevel> = Api::all(client.clone());
    Ok(api
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .map(|l| {
            let level = Level {
                data: l.spec.data.iter().copied().map(capability).collect(),
                metadata: l.spec.metadata.iter().copied().map(capability).collect(),
                versions: l.spec.versions,
            };
            (l.name_any(), level)
        })
        .collect())
}

fn ready<K: HasStatus>(obj: &K) -> bool {
    obj.status().is_some_and(|s| {
        s.conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
    })
}

/// The `orgs` namespaces of `instance`, with their OIDC backends.
async fn namespaces(
    client: &Client,
    instance: &str,
) -> Result<BTreeMap<String, CellNamespace>, kube::Error> {
    let api: Api<OpenbaoNamespace> = Api::all(client.clone());
    Ok(api
        .list(&ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|n| n.spec.instance_ref.name == instance)
        .map(|n| {
            let oidc = n
                .status
                .iter()
                .flat_map(|s| &s.auth)
                .filter(|a| a.kind == "oidc" && !a.accessor.is_empty())
                .map(|a| (a.name.clone(), a.accessor.clone()))
                .collect();
            let cell = CellNamespace {
                ready: ready(&n) && n.spec.types.contains(&SpaceType::Orgs),
                oidc,
            };
            (n.name_any(), cell)
        })
        .collect())
}

fn cells_of(org: &OpenbaoOrganization) -> Vec<Cell> {
    org.status
        .iter()
        .flat_map(|s| &s.cells)
        .map(|c| Cell {
            namespace: c.namespace.clone(),
            role: c.role.clone(),
            policy: c.policy.clone(),
            groups: c
                .groups
                .iter()
                .map(|g| CellGroup {
                    backend: g.backend.clone(),
                    name: g.name.clone(),
                    id: g.id.clone(),
                    alias_id: g.alias_id.clone(),
                })
                .collect(),
        })
        .collect()
}

fn status_of(cells: &[Cell]) -> Vec<CellStatus> {
    cells
        .iter()
        .map(|c| CellStatus {
            namespace: c.namespace.clone(),
            role: c.role.clone(),
            policy: c.policy.clone(),
            groups: c
                .groups
                .iter()
                .map(|g| CellGroupStatus {
                    backend: g.backend.clone(),
                    name: g.name.clone(),
                    id: g.id.clone(),
                    alias_id: g.alias_id.clone(),
                })
                .collect(),
        })
        .collect()
}

async fn apply(
    api: &Api<OpenbaoOrganization>,
    org: &OpenbaoOrganization,
    ctx: &Ctx,
) -> Result<Action, Error> {
    // Fresh from the apiserver: the cells of the last pass must be there.
    let current = api.get(&org.name_any()).await?;
    let started = Instant::now();
    let previous = cells_of(&current);
    let layouts: Api<OpenbaoSpaceLayout> = Api::all(ctx.client.clone());
    let mut extra = serde_json::Map::new();
    let outcome = match layouts.get_opt(&current.spec.layout_ref.name).await? {
        None => Outcome::failed(Failure::new(
            ReasonCode::LayoutNotFound,
            format!(
                "OpenbaoSpaceLayout {} not found",
                current.spec.layout_ref.name
            ),
        )),
        Some(layout) => {
            let instance = layout.spec.instance_ref.name.clone();
            let levels = levels(&ctx.client).await?;
            let namespaces = namespaces(&ctx.client, &instance).await?;
            match ctx.admins.admin_for(&instance).await {
                Err(e) => Outcome::failed(e),
                Ok(admin) => {
                    let report = reconcile_organization(
                        admin.as_ref(),
                        &OrgInput {
                            owner: &format!("OpenbaoOrganization/{}", current.name_any()),
                            org: &current.spec.name,
                            roles: &layout.spec.roles,
                            alias_template: &layout.spec.group_alias_template,
                            alias_names: &current.spec.alias_names,
                            levels: &levels,
                            namespaces: &namespaces,
                            previous: &previous,
                            allow_disruptive: api::ANNOTATIONS
                                .allows_disruptive_update(layout.meta()),
                        },
                    )
                    .await;
                    let cells = serde_json::to_value(status_of(&report.cells))
                        .map_err(kube::Error::SerdeError)?;
                    extra.insert("cells".into(), cells);
                    report.outcome.on(BoundInstance::cluster(instance))
                }
            }
        }
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(api, &ctx.recorder, &current, &outcome, extra).await?;
    Ok(super::requeue_after(&current, &outcome))
}

async fn cleanup(
    api: &Api<OpenbaoOrganization>,
    org: &OpenbaoOrganization,
    ctx: &Ctx,
) -> Result<(), Error> {
    let Some(org) = api.get_opt(&org.name_any()).await? else {
        return Ok(());
    };
    let cells = cells_of(&org);
    if cells.is_empty() {
        return Ok(());
    }
    // The instance recorded at the last pass, not whatever the layout names now.
    let Some(instance) = org.bound_instance().map(|b| b.name.clone()) else {
        return Ok(());
    };
    let admin = ctx
        .admins
        .admin_for(&instance)
        .await
        .map_err(|e| Error::Cleanup(Failure::from(e)))?;
    cleanup_organization(admin.as_ref(), &cells)
        .await
        .map_err(|e| Error::Cleanup(Failure::from(e)))?;
    super::metrics().record_write(KIND, domain::RemoteWrite::Deleted);
    let namespaces: Vec<&str> = cells.iter().map(|c| c.namespace.as_str()).collect();
    events::announce_change(
        &ctx.recorder,
        &org.object_ref(&()),
        ReasonCode::Deleted,
        events::CLEANUP,
        &format!(
            "access of {} removed; its secrets stay in orgs/{}/ of {}",
            org.spec.name,
            org.spec.name,
            namespaces.join(", ")
        ),
    )
    .await;
    Ok(())
}
