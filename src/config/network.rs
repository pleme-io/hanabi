//! TCP/network configuration (listener backlog, socket options)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// HTTP listener backlog size (default: 1024)
    pub http_backlog: i32,

    /// Health check listener backlog size (default: 128)
    pub health_backlog: i32,

    /// Enable SO_REUSEADDR on listeners (default: true)
    pub reuse_address: bool,

    /// Hashed asset regex pattern (for cache control)
    pub hashed_asset_pattern: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            http_backlog: 1024,
            health_backlog: 128,
            reuse_address: true,
            hashed_asset_pattern: r"/assets/.+-[a-f0-9]{8,}\.(js|css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|webp|ico)$".to_string(),
        }
    }
}
