//! [`SpaceAdmin`] on OpenBao's HTTP API, through the kit's
//! [`VaultSession`]: its login, its client per namespace (CA, timeout,
//! `X-Vault-Namespace`) and its re-login on a stale token.
//!
//! The calls are raw JSON rather than `vaultrs`' typed requests: those
//! send policies as JSON lists and a group's `name` in its body, which
//! the operator's bootstrap policy refuses (RFC 0007 §6.1, decision 16).

use std::collections::BTreeMap;
use std::sync::Arc;

use application::space::{
    Group, GroupAlias, GroupSpec, KubernetesRole, Mounted, OidcConfig, OidcRole, OpenbaoError,
    SpaceAdmin,
};
use reqwest::Method;
use serde_json::{Value, json};
use vaultrs::client::{Client as _, VaultClient};
use vaultrs::error::ClientError;
use weebo_kit_adapters::VaultSession;

pub struct OpenbaoSpaceAdmin {
    session: Arc<VaultSession>,
}

impl OpenbaoSpaceAdmin {
    pub fn new(session: Arc<VaultSession>) -> Self {
        Self { session }
    }

    /// `method path` in `ns` (`None`: the root), the response's `data`
    /// (`Ok(None)` on a 404 or an empty body).
    async fn call(
        &self,
        ns: Option<&str>,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<Option<Value>, OpenbaoError> {
        let result = self
            .session
            .with_relogin(ns, |client| {
                let method = method.clone();
                let body = body.clone();
                async move { raw(&client, method, path, body).await }
            })
            .await
            .map_err(|e| OpenbaoError::Login(e.0))?;
        match result {
            Ok(value) => Ok(value),
            Err(ClientError::APIError { code: 404, .. }) => Ok(None),
            Err(e) => Err(error(path, e)),
        }
    }

    async fn list(&self, ns: &str, path: &str) -> Result<Vec<String>, OpenbaoError> {
        let data = self
            .call(
                Some(ns),
                Method::from_bytes(b"LIST").unwrap_or(Method::GET),
                path,
                None,
            )
            .await?;
        Ok(strings(data.as_ref().and_then(|d| d.get("keys"))))
    }

    async fn mounted(
        &self,
        ns: &str,
        path: &str,
    ) -> Result<BTreeMap<String, Mounted>, OpenbaoError> {
        let data = self.call(Some(ns), Method::GET, path, None).await?;
        let mut out = BTreeMap::new();
        if let Some(Value::Object(map)) = data {
            for (key, entry) in map {
                let field = |f: &str| {
                    entry
                        .get(f)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string()
                };
                out.insert(
                    key.trim_end_matches('/').to_string(),
                    Mounted {
                        kind: field("type"),
                        accessor: field("accessor"),
                        description: field("description"),
                    },
                );
            }
        }
        Ok(out)
    }
}

/// One request on `client`, as `vaultrs` would send it: Vault's error
/// statuses as [`ClientError::APIError`], so the session tells a stale
/// token (401/403) from the rest.
async fn raw(
    client: &VaultClient,
    method: Method,
    path: &str,
    body: Option<Value>,
) -> Result<Option<Value>, ClientError> {
    let settings = client.settings();
    let url = format!(
        "{}/v1/{path}",
        settings.address.as_str().trim_end_matches('/')
    );
    let mut request = client
        .http()
        .http
        .request(method, url)
        .header("X-Vault-Token", &settings.token);
    if let Some(ns) = &settings.namespace {
        request = request.header("X-Vault-Namespace", ns);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|source| ClientError::RestClientBuildError { source })?;
    let code = response.status().as_u16();
    let text = response
        .text()
        .await
        .map_err(|source| ClientError::RestClientBuildError { source })?;
    let value: Option<Value> = serde_json::from_str(&text).ok();
    if !(200..300).contains(&code) {
        let errors = strings(value.as_ref().and_then(|v| v.get("errors")));
        return Err(ClientError::APIError { code, errors });
    }
    Ok(value
        .and_then(|v| v.get("data").cloned())
        .filter(|d| !d.is_null()))
}

fn error(path: &str, err: ClientError) -> OpenbaoError {
    match err {
        ClientError::APIError { code, errors } => {
            let message = format!("{path}: {}", errors.join("; "));
            match code {
                403 => OpenbaoError::PermissionDenied(message),
                503 => OpenbaoError::Sealed(message),
                400 => OpenbaoError::Rejected(message),
                _ => OpenbaoError::Api(format!("{code} {message}")),
            }
        }
        other => OpenbaoError::Unreachable(format!("{path}: {other}")),
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn str_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn u32_of(value: Option<&Value>) -> u32 {
    value
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or_default()
}

fn first(value: Option<&Value>) -> Option<String> {
    strings(value).into_iter().next()
}

#[async_trait::async_trait]
impl SpaceAdmin for OpenbaoSpaceAdmin {
    async fn check(&self) -> Result<(), OpenbaoError> {
        self.call(None, Method::GET, "auth/token/lookup-self", None)
            .await
            .map(|_| ())
    }

    async fn namespace_exists(&self, ns: &str) -> Result<bool, OpenbaoError> {
        let found = self
            .call(None, Method::GET, &format!("sys/namespaces/{ns}"), None)
            .await;
        match found {
            Ok(data) => Ok(data.is_some()),
            // `read` on another namespace's path: not one of ours.
            Err(OpenbaoError::PermissionDenied(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn create_namespace(&self, ns: &str, owner: &str) -> Result<(), OpenbaoError> {
        let body = json!({"custom_metadata": {"managed-by": "weebo-openbao", "owner": owner}});
        self.call(
            None,
            Method::POST,
            &format!("sys/namespaces/{ns}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn mounts(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError> {
        self.mounted(ns, "sys/mounts").await
    }

    async fn enable_kv2(&self, ns: &str, path: &str, owner: &str) -> Result<(), OpenbaoError> {
        let body = json!({"type": "kv-v2", "description": format!("managed-by weebo-openbao owner {owner}")});
        self.call(
            Some(ns),
            Method::POST,
            &format!("sys/mounts/{path}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn auth_backends(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError> {
        self.mounted(ns, "sys/auth").await
    }

    async fn enable_auth(
        &self,
        ns: &str,
        path: &str,
        kind: &str,
        owner: &str,
    ) -> Result<(), OpenbaoError> {
        let body =
            json!({"type": kind, "description": format!("managed-by weebo-openbao owner {owner}")});
        self.call(
            Some(ns),
            Method::POST,
            &format!("sys/auth/{path}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn write_oidc_config(
        &self,
        ns: &str,
        backend: &str,
        config: &OidcConfig,
    ) -> Result<(), OpenbaoError> {
        let body = json!({
            "oidc_discovery_url": config.discovery_url,
            "oidc_client_id": config.client_id,
            "oidc_client_secret": config.client_secret,
            "default_role": config.default_role,
        });
        self.call(
            Some(ns),
            Method::POST,
            &format!("auth/{backend}/config"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn read_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<OidcRole>, OpenbaoError> {
        let data = self
            .call(
                Some(ns),
                Method::GET,
                &format!("auth/{backend}/role/{role}"),
                None,
            )
            .await?;
        Ok(data.map(|d| OidcRole {
            user_claim: d
                .get("user_claim")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            groups_claim: d
                .get("groups_claim")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            scopes: strings(d.get("oidc_scopes")),
            redirect_uris: strings(d.get("allowed_redirect_uris")),
            bound_audiences: strings(d.get("bound_audiences")),
            claim_mappings: str_map(d.get("claim_mappings")),
            token_policy: first(d.get("token_policies")),
            token_ttl_seconds: u32_of(d.get("token_ttl")),
            token_max_ttl_seconds: u32_of(d.get("token_max_ttl")),
        }))
    }

    async fn write_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &OidcRole,
    ) -> Result<(), OpenbaoError> {
        let mut body = json!({
            "role_type": "oidc",
            "user_claim": spec.user_claim,
            "groups_claim": spec.groups_claim,
            "oidc_scopes": spec.scopes.join(","),
            "allowed_redirect_uris": spec.redirect_uris.join(","),
            "bound_audiences": spec.bound_audiences.join(","),
            "claim_mappings": spec.claim_mappings,
            "token_ttl": spec.token_ttl_seconds,
            "token_max_ttl": spec.token_max_ttl_seconds,
        });
        // One policy, a plain string: `allowed_parameters` checks it whole.
        if let (Some(policy), Some(map)) = (&spec.token_policy, body.as_object_mut()) {
            map.insert("token_policies".into(), Value::String(policy.clone()));
        }
        self.call(
            Some(ns),
            Method::POST,
            &format!("auth/{backend}/role/{role}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn write_kubernetes_config(&self, ns: &str, backend: &str) -> Result<(), OpenbaoError> {
        let body = json!({
            "kubernetes_host": "https://kubernetes.default.svc",
            "disable_local_ca_jwt": false,
        });
        self.call(
            Some(ns),
            Method::POST,
            &format!("auth/{backend}/config"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn read_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<KubernetesRole>, OpenbaoError> {
        let data = self
            .call(
                Some(ns),
                Method::GET,
                &format!("auth/{backend}/role/{role}"),
                None,
            )
            .await?;
        Ok(data.map(|d| KubernetesRole {
            service_account_names: strings(d.get("bound_service_account_names")).join(","),
            service_account_namespaces: Some(
                strings(d.get("bound_service_account_namespaces")).join(","),
            )
            .filter(|s| !s.is_empty()),
            namespace_selector: d
                .get("bound_service_account_namespace_selector")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from),
            token_policy: first(d.get("token_policies")).unwrap_or_default(),
            token_ttl_seconds: u32_of(d.get("token_ttl")),
        }))
    }

    async fn write_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &KubernetesRole,
    ) -> Result<(), OpenbaoError> {
        let mut body = json!({
            "bound_service_account_names": spec.service_account_names,
            "token_policies": spec.token_policy,
            "token_ttl": spec.token_ttl_seconds,
            "token_max_ttl": spec.token_ttl_seconds,
        });
        if let Some(map) = body.as_object_mut() {
            if let Some(namespaces) = &spec.service_account_namespaces {
                map.insert("bound_service_account_namespaces".into(), json!(namespaces));
            }
            if let Some(selector) = &spec.namespace_selector {
                map.insert(
                    "bound_service_account_namespace_selector".into(),
                    json!(selector),
                );
            }
        }
        self.call(
            Some(ns),
            Method::POST,
            &format!("auth/{backend}/role/{role}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn delete_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<(), OpenbaoError> {
        self.call(
            Some(ns),
            Method::DELETE,
            &format!("auth/{backend}/role/{role}"),
            None,
        )
        .await
        .map(|_| ())
    }

    async fn list_policies(&self, ns: &str) -> Result<Vec<String>, OpenbaoError> {
        self.list(ns, "sys/policies/acl").await
    }

    async fn read_policy(&self, ns: &str, name: &str) -> Result<Option<String>, OpenbaoError> {
        let data = self
            .call(
                Some(ns),
                Method::GET,
                &format!("sys/policies/acl/{name}"),
                None,
            )
            .await?;
        Ok(data.and_then(|d| d.get("policy").and_then(Value::as_str).map(String::from)))
    }

    async fn write_policy(&self, ns: &str, name: &str, text: &str) -> Result<(), OpenbaoError> {
        let body = json!({"policy": text});
        self.call(
            Some(ns),
            Method::PUT,
            &format!("sys/policies/acl/{name}"),
            Some(body),
        )
        .await
        .map(|_| ())
    }

    async fn delete_policy(&self, ns: &str, name: &str) -> Result<(), OpenbaoError> {
        self.call(
            Some(ns),
            Method::DELETE,
            &format!("sys/policies/acl/{name}"),
            None,
        )
        .await
        .map(|_| ())
    }

    async fn list_groups(&self, ns: &str) -> Result<Vec<String>, OpenbaoError> {
        self.list(ns, "identity/group/name").await
    }

    async fn read_group(&self, ns: &str, name: &str) -> Result<Option<Group>, OpenbaoError> {
        let data = self
            .call(
                Some(ns),
                Method::GET,
                &format!("identity/group/name/{name}"),
                None,
            )
            .await?;
        Ok(data.map(|d| Group {
            id: d
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            policies: strings(d.get("policies")),
            metadata: str_map(d.get("metadata")),
            alias: d
                .get("alias")
                .filter(|a| a.get("id").is_some())
                .map(|a| GroupAlias {
                    id: a
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                    name: a
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                    mount_accessor: a
                        .get("mount_accessor")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .into(),
                }),
        }))
    }

    async fn write_group(
        &self,
        ns: &str,
        name: &str,
        spec: &GroupSpec,
    ) -> Result<String, OpenbaoError> {
        // No `name` in the body (the path carries it), one policy as a
        // plain string: what the bootstrap policy allows.
        let body = json!({"type": "external", "policies": spec.policy, "metadata": spec.metadata});
        let data = self
            .call(
                Some(ns),
                Method::POST,
                &format!("identity/group/name/{name}"),
                Some(body),
            )
            .await?;
        match data.and_then(|d| d.get("id").and_then(Value::as_str).map(String::from)) {
            Some(id) => Ok(id),
            // An update answers 204: read the id back.
            None => self
                .read_group(ns, name)
                .await?
                .map(|g| g.id)
                .ok_or_else(|| {
                    OpenbaoError::Api(format!("group {name} not found after its write"))
                }),
        }
    }

    async fn delete_group(&self, ns: &str, name: &str) -> Result<(), OpenbaoError> {
        self.call(
            Some(ns),
            Method::DELETE,
            &format!("identity/group/name/{name}"),
            None,
        )
        .await
        .map(|_| ())
    }

    async fn write_group_alias(
        &self,
        ns: &str,
        id: Option<&str>,
        alias: &GroupAlias,
        canonical_id: &str,
    ) -> Result<String, OpenbaoError> {
        let body = json!({
            "name": alias.name,
            "mount_accessor": alias.mount_accessor,
            "canonical_id": canonical_id,
        });
        let path = match id {
            Some(id) => format!("identity/group-alias/id/{id}"),
            None => "identity/group-alias".to_string(),
        };
        let data = self.call(Some(ns), Method::POST, &path, Some(body)).await?;
        Ok(data
            .and_then(|d| d.get("id").and_then(Value::as_str).map(String::from))
            .or_else(|| id.map(String::from))
            .unwrap_or_default())
    }

    async fn delete_group_alias(&self, ns: &str, id: &str) -> Result<(), OpenbaoError> {
        self.call(
            Some(ns),
            Method::DELETE,
            &format!("identity/group-alias/id/{id}"),
            None,
        )
        .await
        .map(|_| ())
    }
}
