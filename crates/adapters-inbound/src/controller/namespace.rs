//! `OpenbaoNamespace` (cluster-scoped, RFC 0007 §4.2): the namespace, its
//! mounts and auth backends (`reconcile_namespace`). No finalizer: the
//! operator never deletes a namespace, a mount or a backend.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use api::namespace::AuthStatus;
use api::{Instance, OpenbaoNamespace, OpenbaoSpaceLayout};
use application::use_cases::Outcome;
use application::use_cases::reconcile_namespace::{NamespaceInput, reconcile_namespace};
use domain::Failure;
use domain::error::ReasonCode;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use sha2::{Digest, Sha256};

use super::{Ctx, Error, error_policy};

const KIND: &str = "OpenbaoNamespace";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = ctx
        .watches
        .controller(ctx.scope.api::<OpenbaoNamespace>(client), &ctx.scope)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

/// The client secrets of the OIDC backends, read in the operator's own
/// namespace (the only one its Role reads Secrets in), with their digest.
async fn client_secrets(
    client: &Client,
    obj: &OpenbaoNamespace,
) -> BTreeMap<String, (String, String)> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), client.default_namespace());
    let mut out = BTreeMap::new();
    for backend in &obj.spec.auth {
        let Some(oidc) = &backend.oidc else { continue };
        let Ok(Some(secret)) = secrets.get_opt(&oidc.client_secret_ref.name).await else {
            continue;
        };
        let value = secret
            .data
            .and_then(|d| d.get(&oidc.client_secret_ref.key).cloned())
            .and_then(|v| String::from_utf8(v.0).ok());
        if let Some(value) = value {
            let digest = format!("sha256:{:x}", Sha256::digest(value.as_bytes()));
            out.insert(backend.name.clone(), (value, digest));
        }
    }
    out
}

async fn reconcile(obj: Arc<OpenbaoNamespace>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if obj.meta().deletion_timestamp.is_some() {
        return Ok(Action::await_change());
    }
    let api: Api<OpenbaoNamespace> = Api::all(ctx.client.clone());
    let started = Instant::now();
    let name = obj.name_any();
    let instance_name = &obj.spec.instance_ref.name;
    let instances: Api<Instance> = Api::all(ctx.client.clone());
    let mut extra = serde_json::Map::new();
    let outcome = match instances.get_opt(instance_name).await? {
        None => Outcome::failed(Failure::new(
            ReasonCode::InstanceNotFound,
            format!("OpenbaoInstance {instance_name} not found"),
        )),
        Some(instance) => {
            let layouts: Api<OpenbaoSpaceLayout> = Api::all(ctx.client.clone());
            let users = layouts
                .list(&ListParams::default())
                .await?
                .items
                .into_iter()
                .filter(|l| &l.spec.instance_ref.name == instance_name)
                .find_map(|l| l.spec.users);
            let secrets = client_secrets(&ctx.client, &obj).await;
            let written: BTreeMap<String, String> = obj
                .status
                .iter()
                .flat_map(|s| &s.auth)
                .filter_map(|a| a.client_secret_digest.clone().map(|d| (a.name.clone(), d)))
                .collect();
            match ctx.admins.admin_for(instance_name).await {
                Err(e) => Outcome::failed(e),
                Ok(admin) => {
                    let report = reconcile_namespace(
                        admin.as_ref(),
                        &NamespaceInput {
                            name: &name,
                            types: &obj.spec.types,
                            auth: &obj.spec.auth,
                            bounds: &instance.spec.bounds.namespaces,
                            client_secrets: &secrets,
                            written_digests: &written,
                            users: users.as_ref(),
                        },
                    )
                    .await;
                    let auth: Vec<AuthStatus> = report
                        .auth
                        .iter()
                        .map(|a| AuthStatus {
                            name: a.name.clone(),
                            kind: a.kind.clone(),
                            accessor: a.accessor.clone(),
                            client_secret_digest: a.client_secret_digest.clone(),
                        })
                        .collect();
                    let value = |v: serde_json::Result<serde_json::Value>| {
                        v.map_err(kube::Error::SerdeError)
                    };
                    extra.insert("auth".into(), value(serde_json::to_value(&auth))?);
                    extra.insert(
                        "orphanedMounts".into(),
                        value(serde_json::to_value(&report.orphaned_mounts))?,
                    );
                    extra.insert(
                        "orphanedAuth".into(),
                        value(serde_json::to_value(&report.orphaned_auth))?,
                    );
                    report.outcome
                }
            }
        }
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(&api, &ctx.recorder, obj.as_ref(), &outcome, extra).await?;
    Ok(super::requeue_after(obj.as_ref(), &outcome))
}
