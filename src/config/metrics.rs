//! Metrics configuration (StatsD/Vector integration)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MetricsConfig {
    /// Enable metrics emission (default: true)
    pub enabled: bool,

    /// Vector/StatsD host (default: 127.0.0.1)
    pub vector_host: String,

    /// Vector/StatsD port (default: 8125)
    pub vector_port: u16,

    /// Metrics prefix for all emitted metrics
    pub prefix: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            vector_host: "127.0.0.1".to_string(),
            vector_port: 8125,
            prefix: "web_server".to_string(),
        }
    }
}
