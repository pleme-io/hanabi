//! Feature flags configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FeaturesConfig {
    /// Enable bug report endpoint (default: false in production, true in dev/staging)
    pub enable_bug_reports: Option<bool>,

    /// Enable metrics emission (default: true)
    pub enable_metrics: bool,

    /// Enable detailed health checks (disk, memory) in ready probe (default: true)
    pub enable_detailed_health_checks: bool,

    /// Enable Backend-for-Frontend (BFF) proxy/cache/aggregate (default: false)
    pub enable_bff: bool,
}

impl Default for FeaturesConfig {
    fn default() -> Self {
        Self {
            enable_bug_reports: None, // Auto-detect based on environment
            enable_metrics: true,
            enable_detailed_health_checks: true,
            enable_bff: false, // Disabled by default, enable explicitly
        }
    }
}
