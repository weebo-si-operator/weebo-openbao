//! The port onto one OpenBao instance (RFC 0007 §5.1): what the spaces'
//! use-cases write there. Every method takes the OpenBao namespace first.
//! A policy is always one name, sent as a plain string (decision 16).

use std::collections::BTreeMap;
use std::sync::Arc;

use domain::error::ReasonCode;

/// A failed call to OpenBao.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenbaoError {
    /// No answer: network error, timeout.
    #[error("OpenBao unreachable: {0}")]
    Unreachable(String),
    /// 503: sealed or not ready.
    #[error("OpenBao is sealed or not ready: {0}")]
    Sealed(String),
    /// The operator's own login failed.
    #[error("OpenBao login failed: {0}")]
    Login(String),
    /// 403 with a valid token: the bootstrap policy and the CRs disagree.
    #[error("OpenBao denied the call: {0}")]
    PermissionDenied(String),
    /// 400: OpenBao refused the request (an IdP it can't reach, a path
    /// already in use…).
    #[error("OpenBao refused the request: {0}")]
    Rejected(String),
    #[error("OpenBao API error: {0}")]
    Api(String),
}

impl OpenbaoError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::Unreachable(_) => ReasonCode::InstanceUnreachable,
            Self::Sealed(_) => ReasonCode::VaultSealed,
            Self::Login(_) => ReasonCode::InstanceUnauthorized,
            Self::PermissionDenied(_) => ReasonCode::PermissionDenied,
            Self::Rejected(_) | Self::Api(_) => ReasonCode::RemoteError,
        }
    }
}

/// A mount or an auth backend as listed: its type and accessor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mounted {
    pub kind: String,
    pub accessor: String,
    pub description: String,
}

/// An external group, as written: one policy, and the owner mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSpec {
    pub policy: String,
    pub metadata: BTreeMap<String, String>,
}

/// An external group as read. `alias`: OpenBao gives a group one alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub id: String,
    pub policies: Vec<String>,
    pub metadata: BTreeMap<String, String>,
    pub alias: Option<GroupAlias>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAlias {
    pub id: String,
    pub name: String,
    pub mount_accessor: String,
}

/// The settings of an OIDC backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcConfig {
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub default_role: String,
}

/// An OIDC role. `token_policy`: the one policy the role carries itself
/// (`user_space` in a `users` namespace), none elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcRole {
    pub user_claim: String,
    pub groups_claim: String,
    pub scopes: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub bound_audiences: Vec<String>,
    pub claim_mappings: BTreeMap<String, String>,
    pub token_policy: Option<String>,
    pub token_ttl_seconds: u32,
    pub token_max_ttl_seconds: u32,
}

/// A Kubernetes role: one subject, one policy (decisions 16 and 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubernetesRole {
    pub service_account_names: String,
    pub service_account_namespaces: Option<String>,
    /// A `LabelSelector` with `matchLabels`, rendered as JSON.
    pub namespace_selector: Option<String>,
    pub token_policy: String,
    pub token_ttl_seconds: u32,
}

/// Talks to one OpenBao instance, as the operator's own login. `None` as
/// a namespace is the root.
#[async_trait::async_trait]
pub trait SpaceAdmin: Send + Sync {
    /// Whether OpenBao answers and accepts the operator's login.
    async fn check(&self) -> Result<(), OpenbaoError>;

    async fn namespace_exists(&self, ns: &str) -> Result<bool, OpenbaoError>;
    /// Creates the namespace (never deleted by the operator).
    async fn create_namespace(&self, ns: &str, owner: &str) -> Result<(), OpenbaoError>;

    /// The secrets engines of `ns`, by path without the trailing `/`.
    async fn mounts(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError>;
    /// Enables a KV v2 mount (never disabled by the operator).
    async fn enable_kv2(&self, ns: &str, path: &str, owner: &str) -> Result<(), OpenbaoError>;

    /// The auth backends of `ns`, by path without the trailing `/`.
    async fn auth_backends(&self, ns: &str) -> Result<BTreeMap<String, Mounted>, OpenbaoError>;
    /// Enables an auth backend of `kind` (`oidc`, `kubernetes`).
    async fn enable_auth(
        &self,
        ns: &str,
        path: &str,
        kind: &str,
        owner: &str,
    ) -> Result<(), OpenbaoError>;
    async fn write_oidc_config(
        &self,
        ns: &str,
        backend: &str,
        config: &OidcConfig,
    ) -> Result<(), OpenbaoError>;
    async fn read_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<OidcRole>, OpenbaoError>;
    async fn write_oidc_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &OidcRole,
    ) -> Result<(), OpenbaoError>;
    /// This cluster's apiserver, OpenBao's own CA and token.
    async fn write_kubernetes_config(&self, ns: &str, backend: &str) -> Result<(), OpenbaoError>;
    async fn read_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<Option<KubernetesRole>, OpenbaoError>;
    async fn write_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
        spec: &KubernetesRole,
    ) -> Result<(), OpenbaoError>;
    async fn delete_kubernetes_role(
        &self,
        ns: &str,
        backend: &str,
        role: &str,
    ) -> Result<(), OpenbaoError>;

    async fn list_policies(&self, ns: &str) -> Result<Vec<String>, OpenbaoError>;
    async fn read_policy(&self, ns: &str, name: &str) -> Result<Option<String>, OpenbaoError>;
    async fn write_policy(&self, ns: &str, name: &str, text: &str) -> Result<(), OpenbaoError>;
    async fn delete_policy(&self, ns: &str, name: &str) -> Result<(), OpenbaoError>;

    async fn list_groups(&self, ns: &str) -> Result<Vec<String>, OpenbaoError>;
    async fn read_group(&self, ns: &str, name: &str) -> Result<Option<Group>, OpenbaoError>;
    /// Creates or updates the external group `name`; its id.
    async fn write_group(
        &self,
        ns: &str,
        name: &str,
        spec: &GroupSpec,
    ) -> Result<String, OpenbaoError>;
    async fn delete_group(&self, ns: &str, name: &str) -> Result<(), OpenbaoError>;
    /// Creates (`id: None`) or updates the alias; its id.
    async fn write_group_alias(
        &self,
        ns: &str,
        id: Option<&str>,
        alias: &GroupAlias,
        canonical_id: &str,
    ) -> Result<String, OpenbaoError>;
    async fn delete_group_alias(&self, ns: &str, id: &str) -> Result<(), OpenbaoError>;
}

/// Why no [`SpaceAdmin`] could be built for an instance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpaceAdminFactoryError {
    #[error("{0}")]
    Instance(String),
    #[error("CA secret: {0}")]
    CaSecret(String),
    #[error(transparent)]
    Openbao(#[from] OpenbaoError),
}

impl SpaceAdminFactoryError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            Self::Instance(_) => ReasonCode::InstanceNotFound,
            Self::CaSecret(_) => ReasonCode::TokenSecretMissing,
            Self::Openbao(e) => e.reason(),
        }
    }
}

/// The [`SpaceAdmin`] of an `OpenbaoInstance`, logged in.
#[async_trait::async_trait]
pub trait SpaceAdminFactory: Send + Sync {
    async fn admin_for(
        &self,
        instance: &str,
    ) -> Result<Arc<dyn SpaceAdmin>, SpaceAdminFactoryError>;
}
