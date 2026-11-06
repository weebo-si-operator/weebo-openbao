//! Contract: what `OpenbaoSpaceAdmin` sends to OpenBao, against scripted
//! HTTP. The shapes the operator's bootstrap policy accepts (RFC 0007
//! §6.1, decision 16): one policy as a plain string, no `name` in a
//! group's body, every call in its namespace.

#![expect(clippy::unwrap_used, reason = "test helpers fail the test on purpose")]

use std::collections::BTreeMap;
use std::sync::Arc;

use adapters_outbound::OpenbaoSpaceAdmin;
use application::space::{GroupAlias, GroupSpec, KubernetesRole, OpenbaoError, SpaceAdmin};
use serde_json::json;
use weebo_kit_adapters::{VaultLogin, VaultSession};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn envelope(data: serde_json::Value) -> serde_json::Value {
    json!({
        "request_id": "r", "lease_id": "", "lease_duration": 0, "renewable": false,
        "data": data, "auth": null, "wrap_info": null, "warnings": null,
    })
}

async fn admin(server: &MockServer) -> OpenbaoSpaceAdmin {
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "request_id": "r", "lease_id": "", "lease_duration": 0, "renewable": false,
            "data": null, "wrap_info": null, "warnings": null,
            "auth": {
                "client_token": "op-token", "accessor": "a", "policies": [],
                "token_policies": [], "metadata": {}, "lease_duration": 900,
                "renewable": true, "entity_id": "", "token_type": "service", "orphan": true,
            },
        })))
        .mount(server)
        .await;
    // A valid token: a 403 is the policy's, never a re-login.
    Mock::given(method("GET"))
        .and(path("/v1/auth/token/lookup-self"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(json!({"id": "op-token"}))))
        .mount(server)
        .await;
    let session = VaultSession::login(&VaultLogin {
        address: &server.uri(),
        ca_pem: None,
        namespace: None,
        auth_mount: "kubernetes",
        auth_role: "weebo-openbao",
        jwt: "sa-jwt",
    })
    .await
    .unwrap();
    OpenbaoSpaceAdmin::new(Arc::new(session))
}

#[tokio::test]
async fn a_group_is_written_with_one_policy_as_a_string_and_no_name() {
    let server = MockServer::start().await;
    let admin = admin(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1/identity/group/name/org_acme_dev"))
        .and(header("X-Vault-Namespace", "prod"))
        .and(header("X-Vault-Token", "op-token"))
        .and(body_json(json!({
            "type": "external",
            "policies": "org_acme_dev",
            "metadata": {"managed-by": "weebo-openbao", "owner": "OpenbaoOrganization/acme"},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(json!({"id": "g-1"}))))
        .expect(1)
        .mount(&server)
        .await;
    let id = admin
        .write_group(
            "prod",
            "org_acme_dev",
            &GroupSpec {
                policy: "org_acme_dev".into(),
                metadata: BTreeMap::from([
                    ("managed-by".into(), "weebo-openbao".into()),
                    ("owner".into(), "OpenbaoOrganization/acme".into()),
                ]),
            },
        )
        .await
        .unwrap();
    assert_eq!(id, "g-1");
}

#[tokio::test]
async fn a_kubernetes_role_carries_one_policy_and_one_subject() {
    let server = MockServer::start().await;
    let admin = admin(&server).await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/kubernetes/role/grant_tokens_0"))
        .and(header("X-Vault-Namespace", "users"))
        .and(body_json(json!({
            "bound_service_account_names": "weebo-forgejo",
            "bound_service_account_namespaces": "weebo-forgejo",
            "token_policies": "grant_tokens",
            "token_ttl": 900,
            "token_max_ttl": 900,
        })))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    admin
        .write_kubernetes_role(
            "users",
            "kubernetes",
            "grant_tokens_0",
            &KubernetesRole {
                service_account_names: "weebo-forgejo".into(),
                service_account_namespaces: Some("weebo-forgejo".into()),
                namespace_selector: None,
                token_policy: "grant_tokens".into(),
                token_ttl_seconds: 900,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_group_reads_back_with_its_one_alias() {
    let server = MockServer::start().await;
    let admin = admin(&server).await;
    Mock::given(method("GET"))
        .and(path("/v1/identity/group/name/org_acme_dev"))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope(json!({
            "id": "g-1", "name": "org_acme_dev", "type": "external",
            "policies": ["org_acme_dev"],
            "metadata": {"owner": "OpenbaoOrganization/acme"},
            "alias": {"id": "a-1", "name": "acme_dev", "mount_accessor": "auth_oidc_1"},
        }))))
        .mount(&server)
        .await;
    let group = admin
        .read_group("prod", "org_acme_dev")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        group.alias,
        Some(GroupAlias {
            id: "a-1".into(),
            name: "acme_dev".into(),
            mount_accessor: "auth_oidc_1".into(),
        })
    );
    assert_eq!(group.metadata["owner"], "OpenbaoOrganization/acme");
    assert!(
        admin.read_group("prod", "absent").await.unwrap().is_none(),
        "404 is None"
    );
}

#[tokio::test]
async fn policies_are_listed_with_list_and_written_with_their_text() {
    let server = MockServer::start().await;
    let admin = admin(&server).await;
    Mock::given(method("LIST"))
        .and(path("/v1/sys/policies/acl"))
        .and(header("X-Vault-Namespace", "prod"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(envelope(json!({"keys": ["default", "org_acme_dev"]}))),
        )
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/org_acme_dev"))
        .and(body_json(
            json!({"policy": "path \"orgs/data/acme/+/*\" { capabilities = [\"read\"] }\n"}),
        ))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(
        admin.list_policies("prod").await.unwrap(),
        ["default", "org_acme_dev"]
    );
    admin
        .write_policy(
            "prod",
            "org_acme_dev",
            "path \"orgs/data/acme/+/*\" { capabilities = [\"read\"] }\n",
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn openbao_errors_keep_their_meaning() {
    let server = MockServer::start().await;
    let admin = admin(&server).await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/denied"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(json!({"errors": ["permission denied"]})),
        )
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path("/v1/sys/policies/acl/sealed"))
        .respond_with(
            ResponseTemplate::new(503).set_body_json(json!({"errors": ["Vault is sealed"]})),
        )
        .mount(&server)
        .await;
    let denied = admin.write_policy("prod", "denied", "x").await.unwrap_err();
    assert!(
        matches!(denied, OpenbaoError::PermissionDenied(ref m) if m.contains("permission denied")),
        "{denied}"
    );
    let sealed = admin.write_policy("prod", "sealed", "x").await.unwrap_err();
    assert!(matches!(sealed, OpenbaoError::Sealed(_)), "{sealed}");
    // One login only: a 403 to a valid token never re-logs-in.
    let logins = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/auth/kubernetes/login")
        .count();
    assert_eq!(logins, 1);
}
