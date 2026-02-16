//! API endpoint configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ApiConfig {
    /// GraphQL endpoint URL
    pub graphql_url: String,

    /// WebSocket endpoint URL
    pub ws_url: String,
}
