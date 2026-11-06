//! The `weebo-openbao-operator` binary: wires the adapters into the
//! controllers, then runs them on the kit's runtime (telemetry, health,
//! graceful shutdown, leader election, HTTPS probes).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook;
use adapters_outbound::KubeSpaceAdminFactory;
use api::Instance;
use kube::Client;
use kube::runtime::events::{Recorder, Reporter};
use weebo_kit_runtime::shared::LISTED_TIMEOUT;
use weebo_kit_runtime::{Health, WatchScope, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`. Keep it across releases: old and new pods of a
/// rollout must compete for the same lease.
const DEFAULT_LEASE_NAME: &str = "weebo-openbao-operator-leader";

/// The kit's runtime: `WEEBO_WORKER_THREADS` workers (4 by default), not
/// tokio's one per core (`weebo_kit_runtime::runtime`).
fn main() -> anyhow::Result<()> {
    weebo_kit_runtime::runtime::build()?.block_on(operator())
}

async fn operator() -> anyhow::Result<()> {
    let telemetry = telemetry::init(controller::FIELD_MANAGER)?;
    let result = match std::env::args().nth(1).as_deref() {
        // What the image's smoke run calls: no cluster needed.
        Some("--version") => {
            println!(
                "{} {}",
                controller::FIELD_MANAGER,
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?}")),
        None => run(&telemetry).await,
    };
    if let Err(err) = &result {
        tracing::error!(error = %err, "operator failed");
    }
    telemetry.shutdown();
    result
}

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    // `ring` and `aws-lc-rs` are both linked transitively (`kube`'s rustls
    // vs. reqwest's); rustls refuses to pick a default provider when more
    // than one is present. An `Err` only means one is installed already,
    // which is all rustls needs.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("a rustls crypto provider was already installed");
    }

    telemetry.serve_metrics().await?;
    // `<prefix>_leader`: 1 on the replica holding the lease.
    leader::register_leader_gauge(controller::FIELD_MANAGER, controller::METRIC_PREFIX);

    let client = Client::try_default().await?;
    // The whole cluster, or one namespace (with or without the
    // cluster-scoped kinds) and/or a label selector (the chart's
    // `watch.*`): an invalid value stops the start here, as does a kind
    // the scope can't watch.
    let scope = WatchScope::from_env()?;
    if scope.cluster_kinds() {
        scope.ensure::<Instance>()?;
    }
    tracing::info!(
        namespace = ?scope.watched_namespace(),
        selector = ?scope.selector(),
        cluster_kinds = scope.cluster_kinds(),
        "watch scope"
    );

    // The binary is PID 1 in its container: without a handler, SIGTERM
    // would be ignored and every rollout would wait for the SIGKILL.
    let shutdown = Shutdown::on_termination()?;
    let health = Arc::new(Health::default());

    // One watch per kind, shared by every controller and by the instance
    // reads (every resolution reads the instances: from memory, not a LIST
    // per reconcile). Started before campaigning for the lease: a standby
    // keeps them warm, and the controllers start from stores that already
    // listed.
    let watches = controller::spawn_watches(&client, &scope, &health);
    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        admins: Arc::new(KubeSpaceAdminFactory::new(client.clone())),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: Some(holder_id.clone()),
            },
        ),
        shutdown: shutdown.clone(),
        health: health.clone(),
        scope: scope.clone(),
        watches,
    });

    // The HTTPS server (probes, the scope guard, and an admission webhook
    // once there is one) runs on every replica, before and regardless of leadership: a
    // standby must stay ready, and a leader-only webhook would turn every
    // failover into an outage. On shutdown it keeps answering while
    // endpoints drain.
    let server = webhook_server::spawn(
        webhook::router(health.clone(), scope),
        health,
        shutdown.clone(),
    )
    .await?;

    // The controllers, in contrast, run on one replica at a time: two
    // active reconcilers could both create the same remote object. The
    // replica campaigns once its shared watches listed (their LISTs done
    // before the lease, not in the leader's first minute), or after
    // LISTED_TIMEOUT: a watch that can't list is reported by /livez, not
    // waited for.
    let campaign = async {
        ctx.watches.wait_listed(LISTED_TIMEOUT).await;
        leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME).await
    };
    let leadership = tokio::select! {
        leadership = campaign => leadership,
        () = shutdown.wait() => {
            server.stopped().await;
            return Ok(());
        }
    };

    tracing::info!("starting controllers");
    let cluster_instances = async {
        if ctx.scope.cluster_kinds() {
            tokio::join!(
                controller::instance::run(client.clone(), ctx.clone()),
                controller::namespace::run(client.clone(), ctx.clone()),
            );
        }
    };
    cluster_instances.await;
    // Every controller returns once the shutdown signal arrived and its
    // in-flight reconciles finished: hand the lease over right away
    // instead of making the next leader wait out the TTL.
    leadership.release().await;
    // Bounded: the drain started with the signal, long before.
    if tokio::time::timeout(Duration::from_secs(30), server.stopped())
        .await
        .is_err()
    {
        tracing::warn!("the webhook server was still draining after 30 s; exiting anyway");
    }
    Ok(())
}
