//! What the operator costs a cluster (weebo-kit-perf, RFC 0007 §10.3): the
//! release binary against envtest and a fake OpenBao over HTTPS. The
//! steady state of §10.3: one layout (`owner`/`maintainer` on 4 `orgs`
//! namespaces, `dev` on 3: 11 cells), a `users` namespace, the weebo
//! levels, then a warm-up cycle, an idle baseline and a measured cycle — a
//! burst of `OpenbaoOrganization`s, an idle window with all of them in
//! place, a forced resync of all of them (the steady-state reconcile:
//! reads, zero OpenBao write, both asserted), an alias change on all of them,
//! their deletion (the finalizer revokes) — and a final idle window,
//! checked against the kit's small-cluster budget.
//!
//! The fake OpenBao is the HTTP API the real adapter speaks, over the
//! in-memory `FakeSpaceAdmin` of the controller tests: the operator's own
//! code runs end to end (login, adapter, use-cases), OpenBao's latency and
//! raft do not. Its reads and writes per phase are printed at the end.
//!
//! `task perf` runs it. Tunable: `PERF_OBJECTS` (organizations, default
//! 100), `PERF_IDLE_SECS` (default 30); `WEEBO_PERF_REPORT_ONLY=1` reports
//! without failing; `WEEBO_PERF_BASELINE=<previous json>` adds the change
//! from a previous run. The report lands in `target/perf/`.
#![expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test helpers fail the test on purpose"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use api::{
    Instance, OpenbaoAccessLevel, OpenbaoNamespace, OpenbaoOrganization, OpenbaoSpaceLayout,
};
use application::space::{GroupAlias, GroupSpec, KubernetesRole, OidcConfig, OidcRole, SpaceAdmin};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum_server::tls_rustls::RustlsConfig;
use kube::api::{Api, PostParams};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use testkit::FakeSpaceAdmin;
use weebo_kit_perf::{BASELINE, Budget, FINAL, OperatorMetrics, PerfRun, Workload, names};

const ORGS_NAMESPACES: [&str; 4] = ["prod", "preprod", "recette", "devenv"];

/// The fake OpenBao: the in-memory admin, and its reads.
#[derive(Default)]
struct Bao {
    admin: FakeSpaceAdmin,
    reads: AtomicU64,
}

impl Bao {
    fn writes(&self) -> u64 {
        self.admin.writes().len() as u64
    }
}

fn ok(data: Value) -> Response {
    axum::Json(json!({ "data": data })).into_response()
}

fn found(data: Option<Value>) -> Response {
    data.map_or_else(|| StatusCode::NOT_FOUND.into_response(), ok)
}

fn str_of(v: &Value, key: &str) -> String {
    v[key].as_str().unwrap_or_default().to_string()
}

fn split(v: &Value, key: &str) -> Vec<String> {
    str_of(v, key)
        .split(',')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn map_of(v: &Value, key: &str) -> BTreeMap<String, String> {
    serde_json::from_value(v[key].clone()).unwrap_or_default()
}

fn ttl(v: &Value, key: &str) -> u32 {
    v[key]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or_default()
}

fn owner(description: &str) -> String {
    description
        .strip_prefix("managed-by weebo-openbao owner ")
        .unwrap_or_default()
        .to_string()
}

fn mounted(m: BTreeMap<String, application::space::Mounted>) -> Value {
    m.into_iter()
        .map(|(path, m)| {
            (
                format!("{path}/"),
                json!({"type": m.kind, "accessor": m.accessor, "description": m.description}),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// OpenBao's HTTP API as `adapters_outbound::OpenbaoSpaceAdmin` calls it,
/// answered by the in-memory admin.
async fn openbao(
    State(bao): State<Arc<Bao>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let a = &bao.admin;
    let ns = headers
        .get("X-Vault-Namespace")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let ns = ns.as_str();
    let body: Value = serde_json::from_slice(&body).unwrap_or_default();
    let path = uri.path().trim_start_matches("/v1/").to_string();
    let segments: Vec<&str> = path.split('/').collect();
    let m = method.as_str();
    if matches!(m, "GET" | "LIST") {
        bao.reads.fetch_add(1, Ordering::Relaxed);
    }
    let done = |r: Result<(), _>| {
        r.map_or_else(
            |_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            |()| StatusCode::NO_CONTENT.into_response(),
        )
    };
    match (m, segments.as_slice()) {
        ("POST" | "PUT", ["auth", _, "login"]) => axum::Json(json!({"request_id": "perf", "lease_id": "", "lease_duration": 0, "renewable": false, "data": null, "auth": {
            "client_token": "perf-token", "accessor": "perf", "policies": ["weebo_openbao_operator"],
            "token_policies": ["weebo_openbao_operator"], "metadata": null,
            "lease_duration": 3600, "renewable": true, "entity_id": "", "token_type": "service",
            "orphan": true,
        }}))
        .into_response(),
        ("GET", ["auth", "token", "lookup-self"]) => ok(json!({"id": "perf-token"})),
        ("GET", ["sys", "namespaces", name]) => {
            found(a.namespace_exists(name).await.unwrap().then(|| json!({"path": format!("{name}/")})))
        }
        ("POST", ["sys", "namespaces", name]) => {
            let owner = str_of(&body["custom_metadata"], "owner");
            done(a.create_namespace(name, &owner).await)
        }
        ("GET", ["sys", "mounts"]) => ok(mounted(a.mounts(ns).await.unwrap())),
        ("POST", ["sys", "mounts", mount]) => {
            done(a.enable_kv2(ns, mount, &owner(&str_of(&body, "description"))).await)
        }
        ("GET", ["sys", "auth"]) => ok(mounted(a.auth_backends(ns).await.unwrap())),
        ("POST", ["sys", "auth", backend]) => done(
            a.enable_auth(
                ns,
                backend,
                &str_of(&body, "type"),
                &owner(&str_of(&body, "description")),
            )
            .await,
        ),
        ("POST", ["auth", backend, "config"]) if body.get("oidc_discovery_url").is_some() => done(
            a.write_oidc_config(
                ns,
                backend,
                &OidcConfig {
                    discovery_url: str_of(&body, "oidc_discovery_url"),
                    client_id: str_of(&body, "oidc_client_id"),
                    client_secret: str_of(&body, "oidc_client_secret"),
                    default_role: str_of(&body, "default_role"),
                },
            )
            .await,
        ),
        ("POST", ["auth", backend, "config"]) => done(a.write_kubernetes_config(ns, backend).await),
        ("GET", ["auth", backend, "role", role]) => {
            let kind = a.auth_backends(ns).await.unwrap().get(*backend).map(|b| b.kind.clone());
            if kind.as_deref() == Some("oidc") {
                found(a.read_oidc_role(ns, backend, role).await.unwrap().map(|r| {
                    json!({
                        "user_claim": r.user_claim, "groups_claim": r.groups_claim,
                        "oidc_scopes": r.scopes, "allowed_redirect_uris": r.redirect_uris,
                        "bound_audiences": r.bound_audiences, "claim_mappings": r.claim_mappings,
                        "token_policies": r.token_policy.into_iter().collect::<Vec<_>>(),
                        "token_ttl": r.token_ttl_seconds, "token_max_ttl": r.token_max_ttl_seconds,
                    })
                }))
            } else {
                found(a.read_kubernetes_role(ns, backend, role).await.unwrap().map(|r| {
                    let list = |s: &str| s.split(',').filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>();
                    json!({
                        "bound_service_account_names": list(&r.service_account_names),
                        "bound_service_account_namespaces": list(r.service_account_namespaces.as_deref().unwrap_or_default()),
                        "bound_service_account_namespace_selector": r.namespace_selector.unwrap_or_default(),
                        "token_policies": [r.token_policy], "token_ttl": r.token_ttl_seconds,
                    })
                }))
            }
        }
        ("POST", ["auth", backend, "role", role]) if str_of(&body, "role_type") == "oidc" => done(
            a.write_oidc_role(
                ns,
                backend,
                role,
                &OidcRole {
                    user_claim: str_of(&body, "user_claim"),
                    groups_claim: str_of(&body, "groups_claim"),
                    scopes: split(&body, "oidc_scopes"),
                    redirect_uris: split(&body, "allowed_redirect_uris"),
                    bound_audiences: split(&body, "bound_audiences"),
                    claim_mappings: map_of(&body, "claim_mappings"),
                    token_policy: body["token_policies"].as_str().map(String::from),
                    token_ttl_seconds: ttl(&body, "token_ttl"),
                    token_max_ttl_seconds: ttl(&body, "token_max_ttl"),
                },
            )
            .await,
        ),
        ("POST", ["auth", backend, "role", role]) => done(
            a.write_kubernetes_role(
                ns,
                backend,
                role,
                &KubernetesRole {
                    service_account_names: str_of(&body, "bound_service_account_names"),
                    service_account_namespaces: body["bound_service_account_namespaces"]
                        .as_str()
                        .map(String::from),
                    namespace_selector: body["bound_service_account_namespace_selector"]
                        .as_str()
                        .map(String::from),
                    token_policy: str_of(&body, "token_policies"),
                    token_ttl_seconds: ttl(&body, "token_ttl"),
                },
            )
            .await,
        ),
        ("DELETE", ["auth", backend, "role", role]) => {
            done(a.delete_kubernetes_role(ns, backend, role).await)
        }
        ("LIST", ["sys", "policies", "acl"]) => {
            ok(json!({"keys": a.list_policies(ns).await.unwrap()}))
        }
        ("GET", ["sys", "policies", "acl", name]) => found(
            a.read_policy(ns, name)
                .await
                .unwrap()
                .map(|p| json!({"name": name, "policy": p})),
        ),
        ("PUT" | "POST", ["sys", "policies", "acl", name]) => {
            done(a.write_policy(ns, name, &str_of(&body, "policy")).await)
        }
        ("DELETE", ["sys", "policies", "acl", name]) => done(a.delete_policy(ns, name).await),
        ("LIST", ["identity", "group", "name"]) => {
            ok(json!({"keys": a.list_groups(ns).await.unwrap()}))
        }
        ("GET", ["identity", "group", "name", name]) => {
            found(a.read_group(ns, name).await.unwrap().map(|g| {
                json!({
                    "id": g.id, "name": name, "policies": g.policies, "metadata": g.metadata,
                    "alias": g.alias.map_or_else(|| json!({}), |al| json!({
                        "id": al.id, "name": al.name, "mount_accessor": al.mount_accessor,
                    })),
                })
            }))
        }
        ("POST", ["identity", "group", "name", name]) => {
            let spec = GroupSpec {
                policy: str_of(&body, "policies"),
                metadata: map_of(&body, "metadata"),
            };
            ok(json!({"id": a.write_group(ns, name, &spec).await.unwrap(), "name": name}))
        }
        ("DELETE", ["identity", "group", "name", name]) => done(a.delete_group(ns, name).await),
        ("POST", ["identity", "group-alias", rest @ ..]) => {
            let id = match rest {
                ["id", id] => Some(*id),
                _ => None,
            };
            let alias = GroupAlias {
                id: String::new(),
                name: str_of(&body, "name"),
                mount_accessor: str_of(&body, "mount_accessor"),
            };
            let canonical = str_of(&body, "canonical_id");
            ok(json!({"id": a.write_group_alias(ns, id, &alias, &canonical).await.unwrap()}))
        }
        ("DELETE", ["identity", "group-alias", "id", id]) => {
            done(a.delete_group_alias(ns, id).await)
        }
        _ => {
            eprintln!("fake OpenBao: unhandled {m} {path} (ns {ns:?})");
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
    }
}

/// The fake OpenBao over HTTPS (the instance's address is `https` only):
/// its URL and the certificate's PEM.
async fn fake_openbao(bao: Arc<Bao>) -> (String, String) {
    // Err: a provider is already installed, which is as good.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let pem = cert.cert.pem();
    let tls = RustlsConfig::from_pem(pem.clone().into(), cert.signing_key.serialize_pem().into())
        .await
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = axum::Router::new().fallback(openbao).with_state(bao);
    tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .unwrap()
            .serve(app.into_make_service())
            .await
            .unwrap();
    });
    (format!("https://localhost:{}", addr.port()), pem)
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn object<K: DeserializeOwned>(value: Value) -> K {
    serde_json::from_value(value).unwrap()
}

async fn create<K>(api: Api<K>, value: Value)
where
    K: kube::Resource + Clone + std::fmt::Debug + DeserializeOwned + serde::Serialize,
{
    api.create(&PostParams::default(), &object(value))
        .await
        .unwrap();
}

fn organization(name: &str) -> OpenbaoOrganization {
    object(json!({
        "apiVersion": "openbao.weebo.io/v1alpha1", "kind": "OpenbaoOrganization",
        "metadata": {"name": name},
        "spec": {"layoutRef": {"name": "weebo"}, "name": name},
    }))
}

/// `Ready: True` for the current generation.
fn converged<K: serde::Serialize + kube::Resource>(o: &K) -> bool {
    let status = &serde_json::to_value(o).unwrap()["status"];
    status["observedGeneration"].as_i64() == o.meta().generation
        && status["conditions"].as_array().is_some_and(|c| {
            c.iter()
                .any(|c| c["type"] == "Ready" && c["status"] == "True")
        })
}

async fn burst(
    orgs: &Workload<OpenbaoOrganization>,
    names: &[String],
    timeout: Duration,
) -> Duration {
    let objects: Vec<_> = names.iter().map(|n| organization(n)).collect();
    let started = Instant::now();
    orgs.create(&objects).await;
    orgs.wait_all(names, timeout, converged).await;
    started.elapsed()
}

/// An annotation on every organization: a reconcile with nothing to
/// change. Done once OpenBao's reads rose by one per organization at
/// least, then stopped for a second.
async fn resync(
    orgs: &Workload<OpenbaoOrganization>,
    names: &[String],
    round: u32,
    bao: &Bao,
    timeout: Duration,
) -> Duration {
    let started = Instant::now();
    let before = bao.reads.load(Ordering::Relaxed);
    orgs.patch_all(
        names,
        |_| json!({"metadata": {"annotations": {"perf.weebo.io/resync": round.to_string()}}}),
    )
    .await;
    let mut last = before;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let now = bao.reads.load(Ordering::Relaxed);
        if now >= before + names.len() as u64 && now == last {
            return started.elapsed();
        }
        assert!(
            started.elapsed() < timeout,
            "{} OpenBao reads after the resync of {} organizations",
            now - before,
            names.len()
        );
        last = now;
    }
}

/// Every organization's `dev` group renamed at the identity provider: one
/// alias rewritten per organization and backend.
async fn churn(
    orgs: &Workload<OpenbaoOrganization>,
    names: &[String],
    round: u32,
    timeout: Duration,
) -> Duration {
    let started = Instant::now();
    orgs.patch_all(
        names,
        |n| json!({"spec": {"aliasNames": {"dev": format!("{n}_dev_r{round}")}}}),
    )
    .await;
    orgs.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn delete(
    orgs: &Workload<OpenbaoOrganization>,
    names: &[String],
    timeout: Duration,
) -> Duration {
    let started = Instant::now();
    orgs.delete_all(names).await;
    orgs.wait_gone(names, timeout).await;
    started.elapsed()
}

/// OpenBao reads and writes per phase.
struct Calls {
    bao: Arc<Bao>,
    last: (u64, u64),
    rows: Vec<(String, u64, u64)>,
}

impl Calls {
    fn now(&self) -> (u64, u64) {
        (self.bao.reads.load(Ordering::Relaxed), self.bao.writes())
    }

    fn mark(&mut self) {
        self.last = self.now();
    }

    /// The calls since the last mark, recorded under `phase`: (reads, writes).
    fn record(&mut self, phase: &str) -> (u64, u64) {
        let now = self.now();
        let delta = (now.0 - self.last.0, now.1 - self.last.1);
        self.rows.push((phase.to_string(), delta.0, delta.1));
        self.last = now;
        delta
    }
}

/// Creates every organization, idles with them in place (`loaded`, when
/// `idle` is set: no OpenBao write allowed), renames an alias on each,
/// deletes them all.
#[expect(
    clippy::too_many_arguments,
    reason = "the forgejo perf test's shape, plus the call counter"
)]
async fn cycle(
    run: &mut PerfRun,
    calls: &mut Calls,
    orgs: &Workload<OpenbaoOrganization>,
    all: &[String],
    label: &str,
    round: u32,
    idle: Option<Duration>,
    timeout: Duration,
) {
    let n = all.len();
    let name = format!("{label} burst");
    calls.mark();
    run.load(&name, n, burst(orgs, all, timeout)).await;
    calls.record(&name);
    if let Some(idle) = idle {
        let name = format!("{label} loaded");
        run.idle(&name, idle).await;
        let (_, writes) = calls.record(&name);
        assert_eq!(
            writes,
            0,
            "OpenBao written at rest: {:?}",
            calls.bao.admin.writes().last()
        );
        // The periodic resync doesn't come within the window: one is
        // forced, the steady-state reconcile of §10.3 (reads, no write).
        let name = format!("{label} resync");
        run.load(&name, n, resync(orgs, all, round, &calls.bao, timeout))
            .await;
        let (reads, writes) = calls.record(&name);
        assert_eq!(
            writes,
            0,
            "OpenBao written by a steady-state reconcile: {:?}",
            calls.bao.admin.writes().last()
        );
        assert!(
            reads >= n as u64,
            "{reads} reads: not every organization reconciled"
        );
    }
    let name = format!("{label} churn");
    run.load(&name, n, churn(orgs, all, round, timeout)).await;
    calls.record(&name);
    let name = format!("{label} delete");
    run.load(&name, n, delete(orgs, all, timeout)).await;
    calls.record(&name);
}

#[tokio::test]
#[ignore = "a perf run (minutes, release build): `task perf`"]
async fn the_operator_fits_a_small_cluster() {
    let objects = usize::try_from(env_or("PERF_OBJECTS", 100)).unwrap();
    let idle = Duration::from_secs(env_or("PERF_IDLE_SECS", 30));
    let timeout = Duration::from_secs(300);

    let cluster = testkit::envtest::start().await;
    let bao = Arc::new(Bao::default());
    let (address, ca) = fake_openbao(bao.clone()).await;
    let client = cluster.client();
    let jwt = tempfile_with("perf-sa-token");

    let secrets = Api::<k8s_openapi::api::core::v1::Secret>::namespaced(client.clone(), "default");
    create(
        secrets.clone(),
        json!({"metadata": {"name": "openbao-ca"}, "stringData": {"ca.crt": ca}}),
    )
    .await;
    create(
        secrets,
        json!({"metadata": {"name": "openbao-oidc"}, "stringData": {"client-secret": "s3cret"}}),
    )
    .await;
    let all_namespaces: Vec<&str> = ORGS_NAMESPACES.iter().copied().chain(["users"]).collect();
    create(Api::<Instance>::all(client.clone()), json!({
        "apiVersion": "openbao.weebo.io/v1alpha1", "kind": "OpenbaoInstance",
        "metadata": {"name": "main"},
        "spec": {"address": address,
                 "tls": {"caSecretRef": {"name": "openbao-ca", "namespace": "default", "key": "ca.crt"}},
                 "auth": {"kubernetes": {"mount": "kubernetes", "role": "weebo-openbao"}},
                 "bounds": {"namespaces": all_namespaces}},
    })).await;
    for ns in &all_namespaces {
        let types = if *ns == "users" { "users" } else { "orgs" };
        create(
            Api::<OpenbaoNamespace>::all(client.clone()),
            json!({
                "apiVersion": "openbao.weebo.io/v1alpha1", "kind": "OpenbaoNamespace",
                "metadata": {"name": ns},
                "spec": {"instanceRef": {"name": "main"}, "types": [types],
                         "auth": [{"name": "authentik", "oidc": {
                             "discoveryUrl": "https://auth.example/application/o/openbao/",
                             "clientId": "openbao",
                             "clientSecretRef": {"name": "openbao-oidc", "key": "client-secret"},
                             "redirectUris": ["http://localhost:8250/oidc/callback"]}}]},
            }),
        )
        .await;
    }
    for (level, data, metadata, versions) in [
        ("read", json!(["read"]), json!(["read", "list"]), false),
        (
            "write",
            json!(["create", "read", "update", "patch"]),
            json!(["read", "list"]),
            false,
        ),
        (
            "owner",
            json!(["create", "read", "update", "patch", "delete"]),
            json!(["read", "list", "delete"]),
            true,
        ),
    ] {
        create(
            Api::<OpenbaoAccessLevel>::all(client.clone()),
            json!({
                "apiVersion": "openbao.weebo.io/v1alpha1", "kind": "OpenbaoAccessLevel",
                "metadata": {"name": level},
                "spec": {"data": data, "metadata": metadata, "versions": versions},
            }),
        )
        .await;
    }
    let every = |level: &str| -> BTreeMap<&str, String> {
        ORGS_NAMESPACES
            .iter()
            .map(|ns| (*ns, level.to_string()))
            .collect()
    };
    create(
        Api::<OpenbaoSpaceLayout>::all(client.clone()),
        json!({
            "apiVersion": "openbao.weebo.io/v1alpha1", "kind": "OpenbaoSpaceLayout",
            "metadata": {"name": "weebo"},
            "spec": {"instanceRef": {"name": "main"}, "groupAliasTemplate": "{org}_{role}",
                     "roles": {"owner": every("owner"), "maintainer": every("write"),
                               "dev": {"preprod": "read", "recette": "write", "devenv": "write"}},
                     "users": {}},
        }),
    )
    .await;

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_weebo-openbao-operator"));
    command
        .env("RUST_LOG", "warn")
        .env("VAULT_KUBERNETES_JWT_PATH", &jwt);
    let mut run = PerfRun::start(
        "weebo-openbao",
        &cluster,
        command,
        OperatorMetrics::new("weebo_openbao"),
    )
    .await;
    let mut calls = Calls {
        bao: bao.clone(),
        last: (0, 0),
        rows: Vec::new(),
    };

    // The layout and namespaces Ready before any organization: the steady
    // state's frame, not what the bursts measure.
    ready(Api::<OpenbaoNamespace>::all(client.clone())).await;
    ready(Api::<OpenbaoSpaceLayout>::all(client.clone())).await;
    calls.record("setup");

    let orgs = run.workload(Api::<OpenbaoOrganization>::all(client.clone()));
    run.idle("startup", idle).await;
    calls.record("startup");
    // The warm-up is a whole cycle at full size: the baseline must follow a
    // process that already filled its caches, pools and allocator arenas to
    // what this load needs, or the next cycle's fill reads as a leak.
    let all = names("org", objects);
    cycle(
        &mut run, &mut calls, &orgs, &all, "warm-up", 1, None, timeout,
    )
    .await;
    run.idle(BASELINE, idle).await;
    calls.record(BASELINE);
    cycle(
        &mut run,
        &mut calls,
        &orgs,
        &all,
        "cycle",
        2,
        Some(idle),
        timeout,
    )
    .await;
    run.idle(FINAL, idle).await;
    calls.record(FINAL);

    eprintln!("\nOpenBao calls per phase ({objects} organizations, 11 cells each):");
    eprintln!("{:<16} {:>8} {:>8}", "phase", "reads", "writes");
    for (phase, reads, writes) in &calls.rows {
        eprintln!("{phase:<16} {reads:>8} {writes:>8}");
    }
    run.finish().await.assert_within(&Budget::small_cluster());
}

/// Waits until every object of `api` converged; on a timeout, fails with
/// their statuses.
async fn ready<K>(api: Api<K>)
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + DeserializeOwned
        + serde::Serialize,
{
    let started = Instant::now();
    loop {
        let list = api.list(&Default::default()).await.unwrap();
        if list.items.iter().all(converged) {
            return;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let statuses: Vec<_> = list
                .items
                .iter()
                .map(|o| serde_json::to_value(o).unwrap()["status"].clone())
                .collect();
            panic!("not ready within 60s: {statuses:#?}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// A file holding `content`, kept for the run (the operator's ServiceAccount
/// token: the fake login takes any).
fn tempfile_with(content: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("weebo-openbao-perf-{}.token", std::process::id()));
    std::fs::write(&path, content).unwrap();
    path
}
