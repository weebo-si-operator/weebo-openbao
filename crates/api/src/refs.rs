//! References shared by the spaces' kinds.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A cluster-scoped object of this operator, by name.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NameRef {
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

impl NameRef {
    pub fn named(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}
