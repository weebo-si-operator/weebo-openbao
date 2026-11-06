//! Integration test: a real apiserver (envtest), the real controllers of
//! the spaces' kinds, OpenBao swapped for an in-memory one
//! (`testkit::FakeSpaceAdmin`). What only a cluster shows: the status the
//! controllers publish, the finalizers that hold a deletion (decision 21)
//! and revoke an organization's access (alias first).

#![expect(clippy::panic, reason = "test helpers fail the test on purpose")]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use api::access::{
    KvCapability, OpenbaoAccessLevelSpec, OpenbaoOrganizationSpec, OpenbaoSpaceLayoutSpec,
};
use api::instance::{Bounds, InstanceAuth, InstanceSpec, KubernetesLogin};
use api::namespace::{AuthBackend, KubernetesAuth, OpenbaoNamespaceSpec, SpaceType};
use api::refs::NameRef;
use api::{
    Instance, OpenbaoAccessLevel, OpenbaoNamespace, OpenbaoOrganization, OpenbaoSpaceLayout,
};
use kube::Client;
use kube::api::{Api, DeleteParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::{FakeSpaceAdmin, StaticAdminFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(250);

fn ctx(client: Client, admin: Arc<FakeSpaceAdmin>) -> Arc<Ctx> {
    Arc::new(Ctx {
        client: client.clone(),
        admins: Arc::new(StaticAdminFactory {
            admin,
            failure: Default::default(),
        }),
        recorder: Recorder::new(
            client,
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Arc::new(Health::default()),
        scope: WatchScope::cluster(),
        watches: Default::default(),
    })
}

async fn eventually<T>(what: &str, mut check: impl AsyncFnMut() -> Option<T>) -> T {
    tokio::time::timeout(TIMEOUT, async {
        loop {
            if let Some(v) = check().await {
                return v;
            }
            tokio::time::sleep(POLL).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

fn ready_reason(conditions: &[weebo_kit_api::Condition]) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

#[tokio::test]
async fn the_human_model_reconciles_then_finalizers_revoke_and_hold() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let admin = Arc::new(FakeSpaceAdmin::default());
    // The OIDC backend's client secret, in the operator's namespace.
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), client.default_namespace());
    secrets
        .create(
            &PostParams::default(),
            &serde_json::from_value(serde_json::json!({
                "metadata": {"name": "openbao-oidc"},
                "stringData": {"client-secret": "s3cret"},
            }))
            .unwrap(),
        )
        .await
        .expect("secret");
    let ctx = ctx(client.clone(), admin.clone());
    tokio::spawn(controller::instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::namespace::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::level::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::layout::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::organization::run(client.clone(), ctx.clone()));
    let pp = PostParams::default();

    let instances: Api<Instance> = Api::all(client.clone());
    instances
        .create(
            &pp,
            &Instance::new(
                "main",
                InstanceSpec {
                    address: "https://openbao.example:8200".into(),
                    tls: None,
                    auth: InstanceAuth {
                        kubernetes: KubernetesLogin {
                            mount: "kubernetes".into(),
                            role: "weebo-openbao".into(),
                        },
                    },
                    bounds: Bounds {
                        namespaces: vec!["preprod".into()],
                    },
                },
            ),
        )
        .await
        .expect("instance");
    let namespaces: Api<OpenbaoNamespace> = Api::all(client.clone());
    namespaces
        .create(
            &pp,
            &OpenbaoNamespace::new(
                "preprod",
                OpenbaoNamespaceSpec {
                    instance_ref: NameRef::named("main"),
                    types: vec![SpaceType::Orgs],
                    auth: vec![
                        serde_json::from_value(serde_json::json!({
                            "name": "authentik",
                            "oidc": {
                                "discoveryUrl": "https://auth.example/",
                                "clientId": "openbao",
                                "clientSecretRef": {"name": "openbao-oidc", "key": "client-secret"},
                                "redirectUris": ["http://localhost:8250/oidc/callback"],
                            }
                        }))
                        .unwrap(),
                        AuthBackend {
                            name: "kubernetes".into(),
                            oidc: None,
                            kubernetes: Some(KubernetesAuth {}),
                        },
                    ],
                },
            ),
        )
        .await
        .expect("namespace");
    let levels: Api<OpenbaoAccessLevel> = Api::all(client.clone());
    levels
        .create(
            &pp,
            &OpenbaoAccessLevel::new(
                "read",
                OpenbaoAccessLevelSpec {
                    data: vec![KvCapability::Read],
                    metadata: vec![KvCapability::Read, KvCapability::List],
                    versions: false,
                },
            ),
        )
        .await
        .expect("level");
    let layouts: Api<OpenbaoSpaceLayout> = Api::all(client.clone());
    layouts
        .create(
            &pp,
            &OpenbaoSpaceLayout::new(
                "weebo",
                OpenbaoSpaceLayoutSpec {
                    instance_ref: NameRef::named("main"),
                    group_alias_template: "{org}_{role}".into(),
                    roles: BTreeMap::from([(
                        "dev".into(),
                        BTreeMap::from([("preprod".into(), "read".into())]),
                    )]),
                    users: None,
                },
            ),
        )
        .await
        .expect("layout");

    // The namespace becomes Ready, with its backends' accessors in status.
    let ns_status = eventually("the namespace Ready", async || {
        let ns = namespaces.get("preprod").await.ok()?;
        let status = ns.status?;
        (ready_reason(&status.common.conditions)? == ("True".into(), "Reconciled".into()))
            .then_some(status)
    })
    .await;
    assert!(
        ns_status
            .auth
            .iter()
            .any(|a| a.name == "authentik" && a.client_secret_digest.is_some())
    );

    let orgs: Api<OpenbaoOrganization> = Api::all(client.clone());
    orgs.create(
        &pp,
        &OpenbaoOrganization::new(
            "acme",
            OpenbaoOrganizationSpec {
                layout_ref: NameRef::named("weebo"),
                name: "acme".into(),
                alias_names: BTreeMap::new(),
            },
        ),
    )
    .await
    .expect("organization");
    let cells = eventually("the organization's cells", async || {
        let org = orgs.get("acme").await.ok()?;
        let status = org.status?;
        (ready_reason(&status.common.conditions)?.1 == "Reconciled").then_some(status.cells)
    })
    .await;
    assert_eq!(cells.len(), 1);
    let group = admin.namespace("preprod").unwrap().groups["org_acme_dev_authentik"].clone();
    assert_eq!(group.alias.unwrap().name, "acme_dev");

    // The level is cited: its deletion waits.
    levels
        .delete("read", &DeleteParams::default())
        .await
        .expect("delete level");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        levels.get_opt("read").await.unwrap().is_some(),
        "held while cited"
    );

    // Deleting the organization revokes its access, alias first.
    admin.clear_writes();
    orgs.delete("acme", &DeleteParams::default())
        .await
        .expect("delete org");
    eventually("the organization gone", async || {
        orgs.get_opt("acme").await.ok()?.is_none().then_some(())
    })
    .await;
    let writes = admin.writes();
    assert!(
        writes
            .first()
            .is_some_and(|w| w.starts_with("delete alias")),
        "{writes:?}"
    );
    assert!(admin.namespace("preprod").unwrap().groups.is_empty());

    // Once the layout no longer cites it, the level goes.
    layouts
        .delete("weebo", &DeleteParams::default())
        .await
        .expect("delete layout");
    eventually("the level gone", async || {
        levels.get_opt("read").await.ok()?.is_none().then_some(())
    })
    .await;
}
