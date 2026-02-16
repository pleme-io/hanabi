//! Health check endpoints and runtime monitoring
//!
//! This module implements RFC draft-inadarei-api-health-check-06 compliant
//! health checks for Kubernetes probes.
//!
//! # Kubernetes Probe Types
//! - **Startup** (`/health/startup`): Verify static files exist (runs once at startup)
//! - **Liveness** (`/health/live`): Basic sanity check (process is alive)
//! - **Readiness** (`/health/ready`): Comprehensive checks (disk, memory, files)
//!
//! # Health Response Format
//! Standard health check response with:
//! - Overall status (pass, warn, fail)
//! - Component-level checks with observed values
//! - Service identification (name, version, release ID)
//!
//! # Example Response
//! ```json
//! {
//!   "status": "pass",
//!   "version": "1.0.0",
//!   "checks": {
//!     "disk:storage": [{
//!       "componentId": "disk",
//!       "status": "pass",
//!       "observedValue": 45.2,
//!       "observedUnit": "percent"
//!     }]
//!   }
//! }
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sys_info::{disk_info, mem_info};

use crate::config::AppConfig;
use crate::state::AppState;

/// RFC draft-inadarei-api-health-check-06 compliant health check response
///
/// This response format follows the IETF draft standard for health check APIs,
/// providing structured health information for monitoring systems.
///
/// # Fields
/// - `status`: Overall health status (pass, warn, fail)
/// - `version`: Service version from configuration
/// - `release_id`: Build/release identifier (CARGO_PKG_VERSION)
/// - `notes`: Human-readable description of checks performed
/// - `checks`: Component-level check results
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checks: Option<HashMap<String, Vec<CheckResult>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Health status enumeration
///
/// - **Pass**: All checks successful
/// - **Warn**: Non-critical issues detected (e.g., low disk space)
/// - **Fail**: Critical issues detected (service unhealthy)
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Pass,
    Fail,
    Warn,
}

/// Individual component health check result
///
/// Each check targets a specific component (disk, memory, database, etc.)
/// and reports pass/warn/fail with optional observed values.
#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    #[serde(rename = "componentId")]
    pub component_id: Option<String>,
    #[serde(rename = "componentType")]
    pub component_type: Option<String>,
    pub status: HealthStatus,
    pub time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_unit: Option<String>,
}

impl CheckResult {
    /// Create a passing check result
    pub fn pass(component_id: &str, component_type: &str) -> Self {
        Self {
            component_id: Some(component_id.to_string()),
            component_type: Some(component_type.to_string()),
            status: HealthStatus::Pass,
            time: Utc::now().to_rfc3339(),
            output: None,
            observed_value: None,
            observed_unit: None,
        }
    }

    /// Create a failing check result with error message
    pub fn fail(component_id: &str, component_type: &str, output: &str) -> Self {
        Self {
            component_id: Some(component_id.to_string()),
            component_type: Some(component_type.to_string()),
            status: HealthStatus::Fail,
            time: Utc::now().to_rfc3339(),
            output: Some(output.to_string()),
            observed_value: None,
            observed_unit: None,
        }
    }

    /// Create a warning check result
    pub fn warn(component_id: &str, component_type: &str, output: &str) -> Self {
        Self {
            component_id: Some(component_id.to_string()),
            component_type: Some(component_type.to_string()),
            status: HealthStatus::Warn,
            time: Utc::now().to_rfc3339(),
            output: Some(output.to_string()),
            observed_value: None,
            observed_unit: None,
        }
    }

    /// Add observed value to check result (e.g., disk usage percentage)
    pub fn with_observed(mut self, value: serde_json::Value, unit: &str) -> Self {
        self.observed_value = Some(value);
        self.observed_unit = Some(unit.to_string());
        self
    }
}

/// Runtime health checks performed during server operation
///
/// These checks run on-demand via health endpoints and provide
/// real-time status of system resources and application state.
pub struct RuntimeChecks;

impl RuntimeChecks {
    /// Check disk space availability using configured thresholds
    ///
    /// Compares free disk space percentage against warning and critical thresholds:
    /// - **Pass**: Free space above warning threshold
    /// - **Warn**: Free space below warning threshold but above critical
    /// - **Fail**: Free space below critical threshold
    ///
    /// # Arguments
    /// * `config` - Application configuration with disk thresholds
    ///
    /// # Returns
    /// CheckResult with disk status and free space percentage
    pub fn check_disk_space(config: &AppConfig) -> CheckResult {
        match disk_info() {
            Ok(disk) => {
                let total_gb = disk.total as f64 / 1024.0 / 1024.0;
                let free_gb = disk.free as f64 / 1024.0 / 1024.0;
                let free_percent = (free_gb / total_gb) * 100.0;

                let result = if free_percent < config.health.disk_critical_threshold {
                    CheckResult::fail(
                        "disk",
                        "storage",
                        &format!("Critical: Only {:.1}% disk space remaining", free_percent),
                    )
                } else if free_percent < config.health.disk_warn_threshold {
                    CheckResult::warn(
                        "disk",
                        "storage",
                        &format!("Warning: Only {:.1}% disk space remaining", free_percent),
                    )
                } else {
                    CheckResult::pass("disk", "storage")
                };

                result.with_observed(serde_json::json!(free_percent), "percent")
            }
            Err(e) => CheckResult::fail(
                "disk",
                "storage",
                &format!("Failed to get disk info: {}", e),
            ),
        }
    }

    /// Check memory availability using configured thresholds
    ///
    /// Compares available memory percentage against warning and critical thresholds:
    /// - **Pass**: Available memory above warning threshold
    /// - **Warn**: Available memory below warning threshold but above critical
    /// - **Fail**: Available memory below critical threshold
    ///
    /// # Arguments
    /// * `config` - Application configuration with memory thresholds
    ///
    /// # Returns
    /// CheckResult with memory status and available memory percentage
    pub fn check_memory(config: &AppConfig) -> CheckResult {
        match mem_info() {
            Ok(mem) => {
                let total_mb = mem.total as f64 / 1024.0;
                let avail_mb = mem.avail as f64 / 1024.0;
                let avail_percent = (avail_mb / total_mb) * 100.0;

                let result = if avail_percent < config.health.memory_critical_threshold {
                    CheckResult::fail(
                        "memory",
                        "system",
                        &format!("Critical: Only {:.1}% memory available", avail_percent),
                    )
                } else if avail_percent < config.health.memory_warn_threshold {
                    CheckResult::warn(
                        "memory",
                        "system",
                        &format!("Warning: Only {:.1}% memory available", avail_percent),
                    )
                } else {
                    CheckResult::pass("memory", "system")
                };

                result.with_observed(serde_json::json!(avail_percent), "percent")
            }
            Err(e) => CheckResult::fail(
                "memory",
                "system",
                &format!("Failed to get memory info: {}", e),
            ),
        }
    }

    /// Check critical static files are accessible
    ///
    /// Verifies that all files in config.preflight.critical_files exist
    /// in the static directory. This ensures the React bundle is deployed.
    ///
    /// # Arguments
    /// * `config` - Application configuration
    ///
    /// # Returns
    /// CheckResult with static files status
    pub fn check_static_files(config: &AppConfig) -> CheckResult {
        for file_name in &config.preflight.critical_files {
            let file_path = Path::new(&config.server.static_dir).join(file_name);

            if !file_path.exists() {
                return CheckResult::fail(
                    "static-files",
                    "datastore",
                    &format!("Missing critical file: {}", file_path.display()),
                );
            }
        }

        CheckResult::pass("static-files", "datastore")
    }
}

/// Startup probe endpoint handler
///
/// Kubernetes calls this once during pod startup to verify the application
/// is ready to begin serving traffic. Checks that static files exist.
///
/// # Returns
/// - HTTP 200 with health response (even on failure - K8s checks status field)
pub async fn health_startup(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Emit metrics for endpoint call
    state.incr("health.check", &[("endpoint", "startup")]);

    let mut checks = HashMap::new();

    // Startup check - just verify static files exist
    checks.insert(
        "static-files:datastore".to_string(),
        vec![RuntimeChecks::check_static_files(&state.config)],
    );

    let overall_status = if checks
        .values()
        .all(|c| matches!(c[0].status, HealthStatus::Pass))
    {
        HealthStatus::Pass
    } else {
        HealthStatus::Fail
    };

    // Emit status metric
    let status_value = match overall_status {
        HealthStatus::Pass => 1.0,
        HealthStatus::Warn => 0.5,
        HealthStatus::Fail => 0.0,
    };
    state.gauge("health.status", status_value, &[("endpoint", "startup")]);

    let response = HealthResponse {
        status: overall_status,
        version: state.config.server.service_version.clone(),
        release_id: Some(env!("CARGO_PKG_VERSION").to_string()),
        service_id: Some(state.config.server.service_name.clone()),
        description: Some(format!("{} (Pure Rust)", state.config.server.service_name)),
        notes: Some(vec![
            "Startup probe - validates static files exist".to_string()
        ]),
        output: None,
        checks: Some(checks),
    };

    (StatusCode::OK, Json(response))
}

/// Liveness probe endpoint handler
///
/// Kubernetes calls this periodically to verify the application is still
/// alive. This is a lightweight check that just confirms the process is running.
///
/// If this fails, Kubernetes will restart the pod.
///
/// # Returns
/// - HTTP 200 with pass status (always passes unless process is dead)
pub async fn health_live(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Emit metrics for endpoint call
    state.incr("health.check", &[("endpoint", "live")]);

    let mut checks = HashMap::new();

    // Liveness - basic sanity check
    checks.insert(
        "server:process".to_string(),
        vec![CheckResult::pass("axum-server", "process")],
    );

    let overall_status = HealthStatus::Pass;

    // Emit status metric
    state.gauge("health.status", 1.0, &[("endpoint", "live")]);

    let response = HealthResponse {
        status: overall_status,
        version: state.config.server.service_version.clone(),
        release_id: Some(env!("CARGO_PKG_VERSION").to_string()),
        service_id: Some(state.config.server.service_name.clone()),
        description: Some(format!("{} (Pure Rust)", state.config.server.service_name)),
        notes: Some(vec!["Liveness probe - server is alive".to_string()]),
        output: None,
        checks: Some(checks),
    };

    (StatusCode::OK, Json(response))
}

/// Readiness probe endpoint handler
///
/// Kubernetes calls this periodically to verify the application is ready
/// to serve traffic. Performs comprehensive health checks:
/// - Disk space availability
/// - Memory availability
/// - Static files accessibility
///
/// If this fails, Kubernetes removes the pod from load balancer rotation
/// but does NOT restart it.
///
/// # Returns
/// - HTTP 200 with health response (status field indicates pass/warn/fail)
pub async fn health_ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Emit metrics for endpoint call
    state.incr("health.check", &[("endpoint", "ready")]);

    let mut checks = HashMap::new();

    // Readiness performs comprehensive checks (if enabled)
    if state.config.features.enable_detailed_health_checks {
        checks.insert(
            "disk:storage".to_string(),
            vec![RuntimeChecks::check_disk_space(&state.config)],
        );
        checks.insert(
            "memory:system".to_string(),
            vec![RuntimeChecks::check_memory(&state.config)],
        );
    }
    checks.insert(
        "static-files:datastore".to_string(),
        vec![RuntimeChecks::check_static_files(&state.config)],
    );

    // Determine overall status (fail if any fail, warn if any warn, else pass)
    let has_failures = checks
        .values()
        .any(|c| matches!(c[0].status, HealthStatus::Fail));
    let has_warnings = checks
        .values()
        .any(|c| matches!(c[0].status, HealthStatus::Warn));

    let overall_status = if has_failures {
        HealthStatus::Fail
    } else if has_warnings {
        HealthStatus::Warn
    } else {
        HealthStatus::Pass
    };

    // Emit status metric
    let status_value = match overall_status {
        HealthStatus::Pass => 1.0,
        HealthStatus::Warn => 0.5,
        HealthStatus::Fail => 0.0,
    };
    state.gauge("health.status", status_value, &[("endpoint", "ready")]);

    let response = HealthResponse {
        status: overall_status,
        version: state.config.server.service_version.clone(),
        release_id: Some(env!("CARGO_PKG_VERSION").to_string()),
        service_id: Some(state.config.server.service_name.clone()),
        description: Some(format!("{} (Pure Rust)", state.config.server.service_name)),
        notes: Some(vec![
            "Readiness probe - comprehensive health checks".to_string(),
            "Includes disk, memory, and file checks".to_string(),
        ]),
        output: None,
        checks: Some(checks),
    };

    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_result_pass() {
        let result = CheckResult::pass("test", "component");
        assert!(matches!(result.status, HealthStatus::Pass));
        assert_eq!(result.component_id, Some("test".to_string()));
    }

    #[test]
    fn test_check_result_with_observed() {
        let result = CheckResult::pass("test", "component")
            .with_observed(serde_json::json!(42.5), "percent");
        assert_eq!(result.observed_value, Some(serde_json::json!(42.5)));
        assert_eq!(result.observed_unit, Some("percent".to_string()));
    }

    #[test]
    fn test_health_status_serialization() {
        // Verify lowercase serialization
        let json = serde_json::to_string(&HealthStatus::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
    }
}
