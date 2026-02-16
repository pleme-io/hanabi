//! Telemetry and OpenTelemetry configuration
//!
//! Supports both YAML configuration and OpenTelemetry standard environment variables.
//! Environment variables take precedence over YAML config when set.

use serde::{Deserialize, Serialize};

/// OpenTelemetry configuration
///
/// Environment variables (per OTel spec, checked in order of precedence):
/// - `OTEL_SERVICE_NAME`: Service name for traces (highest priority)
/// - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP collector endpoint
/// - `OTEL_TRACES_SAMPLER_ARG`: Sampling ratio 0.0-1.0
/// - `OTEL_DEPLOYMENT_ENVIRONMENT`: Deployment environment name
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Enable OpenTelemetry tracing (default: false)
    /// Set to true and compile with --features otel to enable
    pub otel_enabled: bool,

    /// Service name for traces (default: hanabi)
    /// Can be overridden by OTEL_SERVICE_NAME env var
    pub service_name: String,

    /// OTLP endpoint URL (default: http://localhost:4317)
    /// Can be overridden by OTEL_EXPORTER_OTLP_ENDPOINT env var
    pub otlp_endpoint: String,

    /// Sampling ratio 0.0 - 1.0 (default: 1.0 = sample all)
    /// Can be overridden by OTEL_TRACES_SAMPLER_ARG env var
    pub sampling_ratio: f64,

    /// Deployment environment (default: production)
    /// Can be overridden by OTEL_DEPLOYMENT_ENVIRONMENT env var
    pub environment: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otel_enabled: false,
            service_name: "hanabi".to_string(),
            otlp_endpoint: "http://localhost:4317".to_string(),
            sampling_ratio: 1.0,
            environment: "production".to_string(),
        }
    }
}

impl TelemetryConfig {
    /// Create an effective config with environment variable overrides applied.
    /// Per OpenTelemetry specification, env vars take precedence over programmatic config.
    /// Only used when `otel` feature is enabled.
    #[allow(dead_code)]
    pub fn with_env_overrides(&self) -> Self {
        Self {
            otel_enabled: self.otel_enabled,
            service_name: std::env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| self.service_name.clone()),
            otlp_endpoint: std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
                .unwrap_or_else(|_| self.otlp_endpoint.clone()),
            sampling_ratio: std::env::var("OTEL_TRACES_SAMPLER_ARG")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(self.sampling_ratio),
            environment: std::env::var("OTEL_DEPLOYMENT_ENVIRONMENT")
                .unwrap_or_else(|_| self.environment.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TelemetryConfig::default();
        assert_eq!(config.service_name, "hanabi");
        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert!((config.sampling_ratio - 1.0).abs() < f64::EPSILON);
        assert_eq!(config.environment, "production");
        assert!(!config.otel_enabled);
    }

    #[test]
    fn test_sampling_ratio_bounds() {
        let config = TelemetryConfig::default();
        assert!(config.sampling_ratio >= 0.0 && config.sampling_ratio <= 1.0);
    }
}
