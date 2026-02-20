//! Logging configuration

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log format: "json" or "pretty" (default: json)
    pub format: String,

    /// Global log level (default: info)
    /// Values: trace, debug, info, warn, error
    pub level: String,

    /// Per-module log levels (overrides global level)
    /// Example: { "hanabi::bff": "debug", "tower_http": "warn" }
    pub module_levels: HashMap<String, String>,

    /// Include file/line numbers in logs (default: true for json)
    pub include_location: bool,

    /// Include thread IDs in logs (default: false)
    pub include_thread_ids: bool,

    /// Include timestamps in logs (default: true)
    pub include_timestamps: bool,

    /// Include target (module path) in logs (default: true for debugging)
    pub include_target: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            level: "info".to_string(),
            module_levels: HashMap::new(),
            include_location: true,
            include_thread_ids: false,
            include_timestamps: true,
            include_target: true,
        }
    }
}
