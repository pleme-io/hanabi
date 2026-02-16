//! Health check configuration (disk, memory thresholds)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    /// Disk space warning threshold percentage (default: 10.0)
    pub disk_warn_threshold: f64,

    /// Disk space critical threshold percentage (default: 5.0)
    pub disk_critical_threshold: f64,

    /// Memory warning threshold percentage (default: 10.0)
    pub memory_warn_threshold: f64,

    /// Memory critical threshold percentage (default: 5.0)
    pub memory_critical_threshold: f64,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            disk_warn_threshold: 10.0,
            disk_critical_threshold: 5.0,
            memory_warn_threshold: 10.0,
            memory_critical_threshold: 5.0,
        }
    }
}

/// Configuration for the health aggregator endpoint
///
/// Defines the list of services to poll for direct health checks.
/// When `services` is empty, the health aggregator returns an empty array.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HealthAggregatorConfig {
    /// List of services to monitor via direct health polling
    #[serde(default)]
    pub services: Vec<ServiceHealthConfig>,
}

/// Configuration for a single service health check
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServiceHealthConfig {
    /// Service name (e.g., "auth", "cart")
    pub name: String,

    /// Display name for UI (e.g., "Authentication Service")
    pub display_name: String,

    /// Service category (e.g., "core", "commerce", "content")
    pub category: String,

    /// Base URL for the service (without health path)
    /// e.g., "http://auth.novaskyn-staging.svc.cluster.local:8081"
    pub base_url: String,

    /// Health endpoint path (default: "/health/ready")
    pub health_path: String,
}

impl Default for ServiceHealthConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            display_name: String::new(),
            category: String::new(),
            base_url: String::new(),
            health_path: "/health/ready".to_string(),
        }
    }
}
