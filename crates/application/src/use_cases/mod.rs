//! One `reconcile_*` use-case per CRD. Each returns an [`Outcome`] the
//! controller turns into a status patch and Events — always through a
//! `ReasonCode`, never a free string.

pub mod reconcile_instance;
pub mod reconcile_namespace;

use domain::error::ReasonCode;
use domain::{Advisory, Drift, Failure, RemoteWrite};

use crate::ports::{BoundInstance, OpenbaoError, SpaceAdminFactoryError};

impl From<OpenbaoError> for Failure {
    fn from(err: OpenbaoError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

impl From<SpaceAdminFactoryError> for Failure {
    fn from(err: SpaceAdminFactoryError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

/// What a reconcile ended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The remote object this CR now owns, to record in its status.
    pub remote_id: Option<String>,
    /// The instance the CR was resolved to, to record in its status.
    pub instance: Option<BoundInstance>,
    /// `Ok(message)` for `Ready: True`.
    pub ready: Result<String, Failure>,
    /// The write this reconcile made to Openbao, if any — counted in
    /// `<prefix>_remote_writes_total`. `None` when everything was in sync.
    pub write: Option<RemoteWrite>,
    /// The fields put back in their desired state (a `DriftCorrected`
    /// Event names them).
    pub drift: Drift,
    /// Non-blocking conditions next to `Ready` (an orphaned mount…).
    pub advisories: Vec<Advisory>,
}

impl Outcome {
    pub fn synced(remote_id: Option<String>, message: impl Into<String>) -> Self {
        Self {
            remote_id,
            instance: None,
            ready: Ok(message.into()),
            write: None,
            drift: Drift::default(),
            advisories: Vec::new(),
        }
    }

    pub fn failed(failure: impl Into<Failure>) -> Self {
        Self {
            remote_id: None,
            instance: None,
            ready: Err(failure.into()),
            write: None,
            drift: Drift::default(),
            advisories: Vec::new(),
        }
    }

    /// Records a write to Openbao.
    pub fn wrote(mut self, write: RemoteWrite) -> Self {
        self.write = Some(write);
        self
    }

    /// Records the fields a drift correction wrote.
    pub fn corrected(mut self, drift: Drift) -> Self {
        self.write = Some(RemoteWrite::Drift);
        self.drift = drift;
        self
    }

    /// Adds an advisory.
    pub fn advise(mut self, reason: ReasonCode, message: impl Into<String>) -> Self {
        self.advisories.push(Advisory {
            reason,
            message: message.into(),
        });
        self
    }

    /// Records the instance the CR is bound to.
    pub fn on(mut self, instance: BoundInstance) -> Self {
        self.instance = Some(instance);
        self
    }

    /// The reason `Ready` ends on — what metrics and Events are keyed by.
    pub fn reason(&self) -> ReasonCode {
        match &self.ready {
            Ok(_) => ReasonCode::Reconciled,
            Err(f) => f.reason,
        }
    }
}
