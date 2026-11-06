//! The [`SpaceAdmin`] of an `OpenbaoInstance`: its CA read from its
//! Secret, the operator's ServiceAccount token exchanged for an OpenBao
//! token (the kit's [`VaultSession`]), the session kept for 80% of its
//! lease and redone when the instance's connection changes.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use api::Instance;
use application::space::{OpenbaoError, SpaceAdmin, SpaceAdminFactory, SpaceAdminFactoryError};
use kube::{Api, Client};
use tokio::sync::Mutex;
use weebo_kit_adapters::{VaultLogin, VaultSession, read_secret_key};

use crate::openbao::OpenbaoSpaceAdmin;

/// The operator's projected ServiceAccount token. Overridable with
/// `VAULT_KUBERNETES_JWT_PATH`, as the kit's Vault store.
const DEFAULT_JWT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

struct Cached {
    /// What the session was opened with: a change opens another.
    connection: (String, String, String, Option<Vec<u8>>),
    admin: Arc<OpenbaoSpaceAdmin>,
    expires: Instant,
}

pub struct KubeSpaceAdminFactory {
    client: Client,
    jwt_path: PathBuf,
    sessions: Mutex<HashMap<String, Cached>>,
}

impl KubeSpaceAdminFactory {
    pub fn new(client: Client) -> Self {
        let jwt_path = std::env::var("VAULT_KUBERNETES_JWT_PATH")
            .unwrap_or_else(|_| DEFAULT_JWT_PATH.into())
            .into();
        Self {
            client,
            jwt_path,
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl SpaceAdminFactory for KubeSpaceAdminFactory {
    async fn admin_for(
        &self,
        instance: &str,
    ) -> Result<Arc<dyn SpaceAdmin>, SpaceAdminFactoryError> {
        let api: Api<Instance> = Api::all(self.client.clone());
        let spec = api
            .get_opt(instance)
            .await
            .map_err(|e| {
                SpaceAdminFactoryError::Instance(format!("reading OpenbaoInstance {instance}: {e}"))
            })?
            .ok_or_else(|| {
                SpaceAdminFactoryError::Instance(format!("OpenbaoInstance {instance} not found"))
            })?
            .spec;
        let ca = match &spec.tls {
            Some(tls) => Some(
                read_secret_key(&self.client, &tls.ca_secret_ref)
                    .await
                    .map_err(SpaceAdminFactoryError::CaSecret)?
                    .ok_or_else(|| {
                        SpaceAdminFactoryError::CaSecret(format!(
                            "{}/{} has no key {:?}",
                            tls.ca_secret_ref.namespace,
                            tls.ca_secret_ref.name,
                            tls.ca_secret_ref.key
                        ))
                    })?,
            ),
            None => None,
        };
        let connection = (
            spec.address.clone(),
            spec.auth.kubernetes.mount.clone(),
            spec.auth.kubernetes.role.clone(),
            ca,
        );
        let mut sessions = self.sessions.lock().await;
        if let Some(cached) = sessions.get(instance)
            && cached.connection == connection
            && cached.expires > Instant::now()
        {
            return Ok(cached.admin.clone());
        }
        let jwt = std::fs::read_to_string(&self.jwt_path).map_err(|e| {
            OpenbaoError::Login(format!(
                "reading the ServiceAccount token {}: {e}",
                self.jwt_path.display()
            ))
        })?;
        let session = VaultSession::login(&VaultLogin {
            address: &connection.0,
            ca_pem: connection.3.as_deref(),
            namespace: None,
            auth_mount: &connection.1,
            auth_role: &connection.2,
            jwt: &jwt,
        })
        .await
        .map_err(|e| OpenbaoError::Login(e.0))?
        .with_jwt_path(self.jwt_path.clone());
        let expires = session
            .cache_ttl()
            .and_then(|ttl| Instant::now().checked_add(ttl));
        let admin = Arc::new(OpenbaoSpaceAdmin::new(Arc::new(session)));
        match expires {
            Some(expires) => {
                sessions.insert(
                    instance.to_string(),
                    Cached {
                        connection,
                        admin: admin.clone(),
                        expires,
                    },
                );
            }
            None => {
                sessions.remove(instance);
            }
        }
        Ok(admin)
    }
}
