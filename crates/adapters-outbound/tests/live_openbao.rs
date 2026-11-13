//! Live contract (RFC 0007 §6.P, §14): the use-cases and the adapter
//! against a real OpenBao 2.7.1 (podman), logged in as the operator with
//! the bootstrap policy of §6.1 loaded as is. Kubernetes auth's
//! TokenReview is answered by a scripted apiserver.
//!
//! Runs only with `OPENBAO_LIVE=1` (`task test:live-openbao`): it needs
//! podman and pulls `docker.io/openbao/openbao:2.7.1`.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test harness: a failure is the test failing"
)]

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use adapters_outbound::OpenbaoSpaceAdmin;
use api::grant::{GrantRule, OpenbaoAccessGrantSpec, Subject};
use api::namespace::{AuthBackend, KubernetesAuth, SpaceType};
use api::refs::NameRef;
use application::space::{OpenbaoError, SpaceAdmin};
use application::use_cases::reconcile_grant::{GrantInput, GrantNamespace, reconcile_grant};
use application::use_cases::reconcile_namespace::{NamespaceInput, reconcile_namespace};
use application::use_cases::reconcile_organization::{
    CellNamespace, OrgInput, reconcile_organization,
};
use domain::error::ReasonCode;
use domain::policy::{Capability, Level};
use serde_json::json;
use weebo_kit_adapters::{VaultLogin, VaultSession};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const IMAGE: &str = "docker.io/openbao/openbao:2.7.1";
const NAMESPACES: [&str; 2] = ["devenv", "users"];

struct Container(String);

impl Drop for Container {
    fn drop(&mut self) {
        if let Err(e) = Command::new("podman").args(["rm", "-f", &self.0]).output() {
            eprintln!("removing the container {}: {e}", self.0);
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `bao` in the container, as root.
fn bao(name: &str, port: u16, args: &[&str], stdin: Option<&str>) -> String {
    let mut cmd = Command::new("podman");
    cmd.args([
        "exec",
        "-i",
        "-e",
        &format!("BAO_ADDR=http://127.0.0.1:{port}"),
        "-e",
        "BAO_TOKEN=root",
        name,
        "bao",
    ]);
    cmd.args(args);
    let out = if let Some(input) = stdin {
        use std::io::Write as _;
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    } else {
        cmd.output().unwrap()
    };
    assert!(
        out.status.success(),
        "bao {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The operator's bootstrap policy, §6.1 (decisions 16 and 20).
fn operator_policy() -> String {
    NAMESPACES
        .iter()
        .map(|ns| {
            format!(
                r#"
path "sys/namespaces/{ns}" {{ capabilities = ["update", "read"] }}
path "{ns}/sys/mounts" {{ capabilities = ["read"] }}
path "{ns}/sys/mounts/orgs" {{ capabilities = ["update", "read"] allowed_parameters = {{ "type" = ["kv-v2"], "*" = [] }} }}
path "{ns}/sys/mounts/users" {{ capabilities = ["update", "read"] allowed_parameters = {{ "type" = ["kv-v2"], "*" = [] }} }}
path "{ns}/sys/auth" {{ capabilities = ["read"] }}
path "{ns}/sys/auth/+" {{ capabilities = ["update", "read", "sudo"] allowed_parameters = {{ "type" = ["oidc", "kubernetes"], "*" = [] }} }}
path "{ns}/auth/+/config" {{ capabilities = ["create", "read", "update"] }}
path "{ns}/auth/+/role/default" {{ capabilities = ["create", "read", "update"] allowed_parameters = {{ "*" = [], "token_policies" = ["user_space"] }} denied_parameters = {{ "policies" = [] }} }}
path "{ns}/auth/+/role/grant_*" {{ capabilities = ["create", "read", "update", "delete"] allowed_parameters = {{ "*" = [], "token_policies" = ["grant_*"] }} denied_parameters = {{ "policies" = [] }} }}
path "{ns}/sys/policies/acl" {{ capabilities = ["list"] }}
path "{ns}/identity/group/name" {{ capabilities = ["list"] }}
path "{ns}/sys/policies/acl/user_space" {{ capabilities = ["create", "read", "update", "delete"] }}
path "{ns}/sys/policies/acl/org_*" {{ capabilities = ["create", "read", "update", "delete"] }}
path "{ns}/sys/policies/acl/grant_*" {{ capabilities = ["create", "read", "update", "delete"] }}
path "{ns}/identity/group/name/org_*" {{ capabilities = ["create", "read", "update", "delete"] allowed_parameters = {{ "type" = ["external"], "policies" = ["org_*"], "metadata" = [] }} }}
path "{ns}/identity/group-alias" {{ capabilities = ["create", "update"] }}
path "{ns}/identity/group-alias/id/*" {{ capabilities = ["read", "update", "delete"] }}
"#
            )
        })
        .collect()
}

fn b64url(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// A ServiceAccount token as OpenBao parses it (claims read, the
/// signature left to the TokenReview).
fn sa_jwt(namespace: &str, name: &str) -> String {
    let header = b64url(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = b64url(
        json!({
            "iss": "kubernetes/serviceaccount",
            "sub": format!("system:serviceaccount:{namespace}:{name}"),
            "kubernetes.io/serviceaccount/namespace": namespace,
            "kubernetes.io/serviceaccount/service-account.name": name,
            "kubernetes.io/serviceaccount/service-account.uid": "uid-1",
        })
        .to_string()
        .as_bytes(),
    );
    format!("{header}.{claims}.{}", b64url(b"signature"))
}

fn levels() -> BTreeMap<String, Level> {
    BTreeMap::from([
        (
            "read".into(),
            Level {
                data: vec![Capability::Read],
                metadata: vec![Capability::Read, Capability::List],
                versions: false,
            },
        ),
        (
            "write".into(),
            Level {
                data: vec![Capability::Create, Capability::Read, Capability::Update],
                metadata: vec![Capability::Read, Capability::List],
                versions: false,
            },
        ),
    ])
}

#[tokio::test]
async fn the_spaces_reconcile_on_a_real_openbao_and_stay_quiet() {
    if std::env::var_os("OPENBAO_LIVE").is_none() {
        eprintln!("skipped: OPENBAO_LIVE unset (task test:live-openbao)");
        return;
    }
    // The apiserver OpenBao asks to review the operator's token.
    let apiserver = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
            "status": {"authenticated": true, "user": {
                "username": "system:serviceaccount:weebo-openbao:weebo-openbao", "uid": "uid-1",
                "groups": ["system:serviceaccounts"]}}
        })))
        .mount(&apiserver)
        .await;

    let port = free_port();
    let name = format!("weebo-openbao-live-{port}");
    // OpenBao's own pod files (CA, token), as Kubernetes mounts them: a
    // namespace's kubernetes backend uses them (disable_local_ca_jwt=false).
    // Any CA: the scripted apiserver is plain http, the CA is never used.
    let dir = std::env::temp_dir().join(format!("weebo-openbao-live-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let ca = dir.join("ca.pem");
    let made = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=live",
        ])
        .arg("-keyout")
        .arg(dir.join("ca.key"))
        .arg("-out")
        .arg(&ca)
        .output()
        .unwrap();
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let ca_pem = std::fs::read_to_string(&ca).unwrap();
    std::fs::copy(&ca, dir.join("ca.crt")).unwrap();
    std::fs::write(dir.join("token"), "reviewer").unwrap();
    let started = Command::new("podman")
        .args([
            "run",
            "-d",
            "--rm",
            "--network",
            "host",
            "--name",
            &name,
            "-e",
            "BAO_DEV_ROOT_TOKEN_ID=root",
        ])
        .arg("-v")
        .arg(format!(
            "{}:/var/run/secrets/kubernetes.io/serviceaccount:ro,Z",
            dir.display()
        ))
        .arg(IMAGE)
        .args([
            "server",
            "-dev",
            &format!("-dev-listen-address=127.0.0.1:{port}"),
        ])
        .output()
        .unwrap();
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let _container = Container(name.clone());
    for _ in 0..50 {
        if Command::new("podman")
            .args([
                "exec",
                "-e",
                &format!("BAO_ADDR=http://127.0.0.1:{port}"),
                &name,
                "bao",
                "status",
            ])
            .output()
            .is_ok_and(|o| o.status.success())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Bootstrap, as Terraform would: Kubernetes auth in the root, the
    // operator's policy and role.
    bao(&name, port, &["auth", "enable", "kubernetes"], None);

    bao(
        &name,
        port,
        &[
            "write",
            "auth/kubernetes/config",
            &format!("kubernetes_host={}", apiserver.uri()),
            "disable_local_ca_jwt=true",
            "token_reviewer_jwt=reviewer",
            "kubernetes_ca_cert=-",
        ],
        Some(&ca_pem),
    );
    bao(
        &name,
        port,
        &["policy", "write", "weebo_openbao_operator", "-"],
        Some(&operator_policy()),
    );
    bao(
        &name,
        port,
        &[
            "write",
            "auth/kubernetes/role/weebo-openbao",
            "bound_service_account_names=weebo-openbao",
            "bound_service_account_namespaces=weebo-openbao",
            "token_policies=weebo_openbao_operator",
            "token_ttl=900",
        ],
        None,
    );

    let session = VaultSession::login(&VaultLogin {
        address: &format!("http://127.0.0.1:{port}"),
        ca_pem: None,
        namespace: None,
        auth_mount: "kubernetes",
        auth_role: "weebo-openbao",
        jwt: &sa_jwt("weebo-openbao", "weebo-openbao"),
    })
    .await
    .unwrap();
    let admin = OpenbaoSpaceAdmin::new(Arc::new(session));
    admin.check().await.unwrap();

    // OpenbaoNamespace devenv: orgs, a kubernetes backend.
    let bounds = NAMESPACES.map(String::from).to_vec();
    let auth = [AuthBackend {
        name: "kubernetes".into(),
        oidc: None,
        kubernetes: Some(KubernetesAuth {}),
    }];
    let none = BTreeMap::new();
    let no_digest = BTreeMap::new();
    let live_owners = std::collections::BTreeSet::new();
    let ns_input = NamespaceInput {
        name: "devenv",
        types: &[SpaceType::Orgs],
        auth: &auth,
        bounds: &bounds,
        client_secrets: &none,
        written_digests: &no_digest,
        users: None,
        live_owners: &live_owners,
        allow_disruptive: false,
    };
    let ns = reconcile_namespace(&admin, &ns_input).await;
    assert_eq!(
        ns.outcome.reason(),
        ReasonCode::Reconciled,
        "{:?}",
        ns.outcome
    );
    let again = reconcile_namespace(&admin, &ns_input).await;
    assert_eq!(again.outcome.write, None, "a second pass writes nothing");
    let k8s_accessor = ns.auth[0].accessor.clone();
    assert!(
        k8s_accessor.starts_with("auth_kubernetes_"),
        "{k8s_accessor}"
    );
    // Out of bounds: refused before any call.
    let autre = reconcile_namespace(
        &admin,
        &NamespaceInput {
            name: "autre",
            ..ns_input
        },
    )
    .await;
    assert_eq!(autre.outcome.reason(), ReasonCode::OutOfBounds);

    // An organization: the IdP's backend enabled by hand here (an OIDC
    // config needs a reachable provider), its accessor read back.
    bao(
        &name,
        port,
        &["auth", "enable", "-ns=devenv", "-path=idp", "oidc"],
        None,
    );
    let backends = admin.auth_backends("devenv").await.unwrap();
    let idp = backends["idp"].accessor.clone();
    let roles = BTreeMap::from([(
        "dev".to_string(),
        BTreeMap::from([("devenv".to_string(), "write".to_string())]),
    )]);
    let levels = levels();
    let namespaces = BTreeMap::from([(
        "devenv".to_string(),
        CellNamespace {
            ready: true,
            oidc: vec![("idp".into(), idp)],
        },
    )]);
    let aliases = BTreeMap::new();
    let org_input = |previous| OrgInput {
        owner: "OpenbaoOrganization/acme",
        org: "acme",
        roles: &roles,
        alias_template: "{org}_{role}",
        alias_names: &aliases,
        levels: &levels,
        namespaces: &namespaces,
        previous,
        allow_disruptive: false,
    };
    let org = reconcile_organization(&admin, &org_input(&[])).await;
    assert_eq!(
        org.outcome.reason(),
        ReasonCode::Reconciled,
        "{:?}",
        org.outcome
    );
    let org_again = reconcile_organization(&admin, &org_input(&org.cells)).await;
    assert_eq!(
        org_again.outcome.write, None,
        "a second pass writes nothing: {:?}",
        org_again.outcome
    );
    let group = admin
        .read_group("devenv", "org_acme_dev_idp")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(group.policies, ["org_acme_dev"]);
    assert_eq!(group.alias.unwrap().name, "acme_dev");

    // A grant: a broad subject bounded by {sa.namespace}.
    let grant = OpenbaoAccessGrantSpec {
        instance_ref: NameRef::named("main"),
        namespace: "devenv".into(),
        auth: "kubernetes".into(),
        subjects: vec![Subject {
            namespace: Some("*".into()),
            namespace_selector: None,
            name: "*".into(),
        }],
        rules: vec![GrantRule {
            mount: "orgs".into(),
            path: "acme/{sa.namespace}/*".into(),
            metadata_path: None,
            organizations: vec![],
            level: "read".into(),
        }],
        token_ttl_seconds: 900,
    };
    let grant_ns = GrantNamespace {
        ready: true,
        mounts: vec!["orgs".into()],
        kubernetes: BTreeMap::from([("kubernetes".into(), k8s_accessor)]),
    };
    let grant_input = |previous: &'static [String]| GrantInput {
        name: "repo-workloads-read-own",
        spec: &grant,
        levels: &levels,
        organizations: &[],
        namespace: Some(&grant_ns),
        previous_roles: previous,
    };
    let granted = reconcile_grant(&admin, &grant_input(&[])).await;
    assert_eq!(
        granted.outcome.reason(),
        ReasonCode::Reconciled,
        "{:?}",
        granted.outcome
    );
    let roles_written: &'static [String] = Box::leak(granted.roles.clone().into_boxed_slice());
    let granted_again = reconcile_grant(&admin, &grant_input(roles_written)).await;
    assert_eq!(
        granted_again.outcome.write, None,
        "a second pass writes nothing: {:?}",
        granted_again.outcome
    );

    // §6.P n°11: sealed, every reconcile stops on VaultSealed and writes
    // nothing; unsealed, the same token passes again with nothing to write.
    bao(&name, port, &["operator", "seal"], None);
    let sealed_ns = reconcile_namespace(&admin, &ns_input).await;
    let sealed_org = reconcile_organization(&admin, &org_input(&org.cells)).await;
    let sealed_grant = reconcile_grant(&admin, &grant_input(roles_written)).await;
    for (what, reason, write) in [
        (
            "namespace",
            sealed_ns.outcome.reason(),
            sealed_ns.outcome.write,
        ),
        (
            "organization",
            sealed_org.outcome.reason(),
            sealed_org.outcome.write,
        ),
        (
            "grant",
            sealed_grant.outcome.reason(),
            sealed_grant.outcome.write,
        ),
    ] {
        assert_eq!(reason, ReasonCode::VaultSealed, "{what}");
        assert_eq!(write, None, "{what}: nothing written while sealed");
    }
    let logs = Command::new("podman")
        .args(["logs", &name])
        .output()
        .unwrap();
    let logs =
        String::from_utf8_lossy(&logs.stdout).into_owned() + &String::from_utf8_lossy(&logs.stderr);
    let key = logs
        .lines()
        .find_map(|l| l.trim().strip_prefix("Unseal Key: "))
        .unwrap()
        .to_string();
    bao(&name, port, &["operator", "unseal", &key], None);
    let unsealed_ns = reconcile_namespace(&admin, &ns_input).await;
    let unsealed_org = reconcile_organization(&admin, &org_input(&org.cells)).await;
    let unsealed_grant = reconcile_grant(&admin, &grant_input(roles_written)).await;
    for (what, reason, write) in [
        (
            "namespace",
            unsealed_ns.outcome.reason(),
            unsealed_ns.outcome.write,
        ),
        (
            "organization",
            unsealed_org.outcome.reason(),
            unsealed_org.outcome.write,
        ),
        (
            "grant",
            unsealed_grant.outcome.reason(),
            unsealed_grant.outcome.write,
        ),
    ] {
        assert_eq!(reason, ReasonCode::Reconciled, "{what} after unseal");
        assert_eq!(write, None, "{what}: nothing had changed, nothing written");
    }

    let policy = admin
        .read_policy("devenv", "grant_repo-workloads-read-own")
        .await
        .unwrap()
        .unwrap();
    assert!(
        policy.contains("metadata.service_account_namespace}}/*"),
        "{policy}"
    );

    // Decision 20: with no live owner, the organization's and the grant's
    // objects are found by name (the operator's two `list` rights), then
    // removed under allow-disruptive-update.
    let reported = reconcile_namespace(&admin, &ns_input).await;
    assert!(
        reported
            .left_over
            .contains(&"group org_acme_dev_idp".to_string()),
        "{:?}",
        reported.left_over
    );
    assert!(
        reported
            .left_over
            .contains(&"policy grant_repo-workloads-read-own".to_string()),
        "{:?}",
        reported.left_over
    );
    let removed = reconcile_namespace(
        &admin,
        &NamespaceInput {
            allow_disruptive: true,
            ..ns_input
        },
    )
    .await;
    assert_eq!(removed.left_over.len(), reported.left_over.len());
    assert!(
        admin
            .read_group("devenv", "org_acme_dev_idp")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        admin
            .read_policy("devenv", "org_acme_dev")
            .await
            .unwrap()
            .is_none()
    );

    // The bootstrap policy's refusals, through the operator's own login.
    let denied = admin
        .write_policy("devenv", "weebo_admin", "path \"*\" {}")
        .await;
    assert!(
        matches!(denied, Err(OpenbaoError::PermissionDenied(_))),
        "{denied:?}"
    );
    let root = admin.read_policy("devenv", "user_space").await;
    assert!(root.is_ok());
}
