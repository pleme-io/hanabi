//! Configuration management for Hanabi
//!
//! Loads configuration from YAML files with comprehensive validation.
//! Default path: /etc/hanabi/config.yaml (override with CONFIG_PATH env var)

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{info, warn};

// Module declarations
mod api;
mod bff;
mod cache;
mod compression;
mod features;
mod geolocation;
mod health;
mod logging;
mod metrics;
mod network;
pub mod paths; // Public module for path constants
mod preflight;
mod s3;
mod security;
mod server;
mod telemetry;

// Re-export configuration types used by the main application
pub use api::ApiConfig;
#[allow(unused_imports)]
pub use bff::{
    AuthInterceptionConfig, BffCacheConfig, BffConfig, BffFederationConfig, BffOAuthConfig,
    BffRateLimitConfig, BffSessionConfig, BffWebhooksConfig, FederationPluginsConfig,
    FederationWebSocketConfig, MetaSocialOAuthConfig, MutationMatcher, TokenFieldConfig,
};
pub use cache::CacheConfig;
pub use compression::CompressionConfig;
pub use features::FeaturesConfig;
pub use geolocation::{GeoCity, GeolocationConfig};
pub use health::{HealthAggregatorConfig, HealthCheckConfig, ServiceHealthConfig};
pub use logging::LoggingConfig;
pub use metrics::MetricsConfig;
pub use network::NetworkConfig;
pub use preflight::PreflightConfig;
pub use s3::S3Config;
pub use security::SecurityConfig;
pub use server::ServerConfig;
pub use telemetry::TelemetryConfig;

/// Application Configuration (loaded from YAML file mounted by FluxCD)
/// Default path: /etc/hanabi/config.yaml (override with CONFIG_PATH env var)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AppConfig {
    /// Environment identifier (e.g., "production", "staging", "development")
    #[serde(default = "default_environment")]
    pub environment: String,

    /// Security configuration (CSP, CORS, HSTS, headers)
    #[serde(default)]
    pub security: SecurityConfig,

    /// API endpoints configuration (GraphQL, WebSocket URLs)
    #[serde(default)]
    pub api: ApiConfig,

    /// Backend-for-Frontend (BFF) configuration (proxy, cache, aggregate)
    #[serde(default)]
    pub bff: BffConfig,

    /// Server configuration (ports, timeouts, worker threads, TCP settings)
    #[serde(default)]
    pub server: ServerConfig,

    /// Compression configuration (Brotli, Gzip)
    #[serde(default)]
    pub compression: CompressionConfig,

    /// Cache control configuration (static assets, HTML caching)
    #[serde(default)]
    pub cache: CacheConfig,

    /// Health check configuration (thresholds for disk, memory)
    #[serde(default)]
    pub health: HealthCheckConfig,

    /// Metrics configuration (StatsD/Vector integration)
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Logging configuration (format, level, verbosity)
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Preflight checks configuration (critical files verification)
    #[serde(default)]
    pub preflight: PreflightConfig,

    /// TCP/network configuration (listener backlog, socket options)
    #[serde(default)]
    pub network: NetworkConfig,

    /// Feature flags (enable/disable specific functionality)
    #[serde(default)]
    pub features: FeaturesConfig,

    /// Telemetry and OpenTelemetry configuration
    #[serde(default)]
    pub telemetry: TelemetryConfig,

    /// Geolocation endpoint configuration (IP-based city detection)
    /// When enabled, registers the /api/geolocation route
    #[serde(default)]
    pub geolocation: GeolocationConfig,

    /// Health aggregator configuration (service health polling)
    /// Defines which services to poll for direct health checks
    #[serde(default)]
    pub health_aggregator: HealthAggregatorConfig,

    /// S3 configuration for image proxy
    #[serde(default)]
    pub s3: S3Config,

    /// Pod identifier (loaded from HOSTNAME/POD_NAME env var at startup)
    /// Used for subscription event source tracking in horizontal scaling
    #[serde(default = "default_pod_id")]
    pub pod_id: String,
}

fn default_pod_id() -> String {
    "unknown".to_string()
}

fn default_environment() -> String {
    "development".to_string()
}

impl AppConfig {
    /// Load configuration from YAML file
    /// Default path: /etc/hanabi/config.yaml (override with CONFIG_PATH env var)
    /// Fallback: ./config.yaml (for local development)
    pub fn load() -> Result<Self, String> {
        let config_path =
            std::env::var("CONFIG_PATH").unwrap_or_else(|_| "/etc/hanabi/config.yaml".to_string());

        info!("Loading configuration from: {}", config_path);

        let config_content = fs::read_to_string(&config_path)
            .or_else(|e| {
                warn!("Failed to read primary config path {}: {}", config_path, e);
                warn!("Attempting fallback: ./config.yaml");
                fs::read_to_string("./config.yaml")
            })
            .map_err(|e| {
                format!(
                    "Failed to read config file (tried {} and ./config.yaml): {}",
                    config_path, e
                )
            })?;

        let mut config: AppConfig = serde_yaml::from_str(&config_content)
            .map_err(|e| format!("Failed to parse config YAML: {}", e))?;

        // Auto-configure features based on environment if not explicitly set
        if config.features.enable_bug_reports.is_none() {
            config.features.enable_bug_reports = Some(config.environment != "production");
        }

        // Override Redis session password from environment variable (security best practice)
        // This allows the password to be injected via Kubernetes secret without putting it in ConfigMap
        if let Ok(redis_password) = std::env::var("REDIS_SESSION_PASSWORD") {
            if !redis_password.is_empty() {
                config.bff.session.redis_password = Some(redis_password);
                info!("  Redis session password loaded from REDIS_SESSION_PASSWORD env var");
            }
        }

        // Override HMAC secret from environment variable (security best practice)
        // This allows the secret to be injected via Kubernetes secret without putting it in ConfigMap
        if let Ok(hmac_secret) = std::env::var("HMAC_SECRET") {
            if !hmac_secret.is_empty() {
                config.bff.federation.hmac.secret = hmac_secret;
                info!("  HMAC secret loaded from HMAC_SECRET env var");
            }
        }

        // Override NATS URL from environment variable
        if let Ok(nats_url) = std::env::var("NATS_URL") {
            if !nats_url.is_empty() {
                config.bff.nats_url = Some(nats_url);
                info!("  NATS URL loaded from NATS_URL env var");
            }
        }

        // Override backend GraphQL URL from environment variable
        if let Ok(backend_url) = std::env::var("BACKEND_GRAPHQL_URL") {
            if !backend_url.is_empty() {
                config.bff.backend_graphql_url = Some(backend_url);
                info!("  Backend GraphQL URL loaded from BACKEND_GRAPHQL_URL env var");
            }
        }

        // Load pod ID from environment (Kubernetes injects HOSTNAME, or POD_NAME can be set explicitly)
        // Used for subscription event source tracking in horizontal scaling
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            if !hostname.is_empty() {
                config.pod_id = hostname;
                info!("  Pod ID loaded from HOSTNAME env var: {}", config.pod_id);
            }
        } else if let Ok(pod_name) = std::env::var("POD_NAME") {
            if !pod_name.is_empty() {
                config.pod_id = pod_name;
                info!("  Pod ID loaded from POD_NAME env var: {}", config.pod_id);
            }
        }

        // Validate configuration
        config.validate()?;

        info!(
            "✓ Configuration loaded successfully for environment: {}",
            config.environment
        );
        Ok(config)
    }

    /// Validate configuration values for correctness and security
    fn validate(&self) -> Result<(), String> {
        // Validate ports are in valid range
        if self.server.http_port == 0 {
            return Err("Invalid HTTP port: 0".to_string());
        }
        if self.server.health_port == 0 {
            return Err("Invalid health port: 0".to_string());
        }
        if self.server.http_port == self.server.health_port {
            return Err("HTTP port and health port must be different".to_string());
        }

        // Validate static directory exists
        if !Path::new(&self.server.static_dir).exists() {
            return Err(format!(
                "Static directory does not exist: {}",
                self.server.static_dir
            ));
        }

        // Validate timeouts are reasonable
        if self.server.request_timeout_secs == 0 || self.server.request_timeout_secs > 300 {
            return Err(format!(
                "Invalid request timeout: {} (must be 1-300 seconds)",
                self.server.request_timeout_secs
            ));
        }

        // Validate thresholds
        if self.health.disk_critical_threshold >= self.health.disk_warn_threshold {
            return Err("Disk critical threshold must be less than warning threshold".to_string());
        }
        if self.health.memory_critical_threshold >= self.health.memory_warn_threshold {
            return Err(
                "Memory critical threshold must be less than warning threshold".to_string(),
            );
        }

        // Validate regex pattern compiles
        if let Err(e) = Regex::new(&self.network.hashed_asset_pattern) {
            return Err(format!("Invalid hashed asset regex pattern: {}", e));
        }

        // Validate CORS origins are valid URLs
        for origin in &self.security.cors.allowed_origins {
            if !origin.starts_with("http://") && !origin.starts_with("https://") {
                return Err(format!(
                    "Invalid CORS origin (must start with http:// or https://): {}",
                    origin
                ));
            }
        }

        // Validate server performance settings
        if self.server.max_concurrent_connections == 0 {
            return Err("Invalid max_concurrent_connections: 0 (must be > 0)".to_string());
        }

        // Validate BFF configuration (if BFF enabled)
        if self.features.enable_bff {
            // Validate BFF optimization configuration
            self.bff.optimization.validate()?;

            // Validate BFF HTTP timeout
            if self.bff.http.timeout_secs == 0 || self.bff.http.timeout_secs > 3600 {
                return Err(format!(
                    "Invalid BFF HTTP timeout: {} (must be 1-3600 seconds)",
                    self.bff.http.timeout_secs
                ));
            }

            // Validate WebSocket configuration
            if self.bff.websocket.timeout_secs == 0 {
                return Err("Invalid WebSocket timeout: 0 (must be > 0)".to_string());
            }

            if self.bff.websocket.max_message_size == 0 {
                return Err("Invalid WebSocket max_message_size: 0 (must be > 0)".to_string());
            }

            if self.bff.websocket.memory_percent_limit <= 0.0
                || self.bff.websocket.memory_percent_limit > 1.0
            {
                return Err(format!(
                    "Invalid WebSocket memory_percent_limit: {} (must be > 0.0 and <= 1.0)",
                    self.bff.websocket.memory_percent_limit
                ));
            }

            if self.bff.websocket.memory_per_connection_kb == 0 {
                return Err(
                    "Invalid WebSocket memory_per_connection_kb: 0 (must be > 0)".to_string(),
                );
            }
        }

        info!("✓ Configuration validation passed");
        Ok(())
    }

    /// Build Content Security Policy from configuration
    /// CSP is built dynamically from YAML config to support different environments
    /// All directives are configurable via YAML for maximum flexibility
    pub fn build_csp(&self) -> String {
        // Build connect-src from all configured sources
        let connect_src_parts: Vec<&str> = vec!["'self'"]
            .into_iter()
            .chain(self.security.csp.api_domains.iter().map(|s| s.as_str()))
            .chain(self.security.csp.ws_domains.iter().map(|s| s.as_str()))
            .chain(
                self.security
                    .csp
                    .additional_connect_src
                    .iter()
                    .map(|s| s.as_str()),
            )
            .collect();
        let connect_src = connect_src_parts.join(" ");

        // Build script-src from configured sources
        // Note: https://unpkg.com is required for React CDN (bundler uses external React)
        let script_src_parts: Vec<&str> = vec![
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            "https://unpkg.com", // React/ReactDOM CDN
        ]
        .into_iter()
        .chain(self.security.csp.script_sources.iter().map(|s| s.as_str()))
        .collect();
        let script_src = script_src_parts.join(" ");

        // Build style-src from configured sources
        let style_src_parts: Vec<&str> = vec!["'self'", "'unsafe-inline'"]
            .into_iter()
            .chain(self.security.csp.style_sources.iter().map(|s| s.as_str()))
            .collect();
        let style_src = style_src_parts.join(" ");

        // Build font-src from configured sources
        let font_src_parts: Vec<&str> = vec!["'self'", "data:"]
            .into_iter()
            .chain(self.security.csp.font_sources.iter().map(|s| s.as_str()))
            .collect();
        let font_src = font_src_parts.join(" ");

        // Build img-src from configured sources (has sensible defaults)
        let img_src = self.security.csp.img_sources.join(" ");

        // Build frame-src from configured sources (optional, product-specific)
        let frame_src = if self.security.csp.frame_sources.is_empty() {
            "'none'".to_string()
        } else {
            self.security.csp.frame_sources.join(" ")
        };

        // Build comprehensive CSP with defense-in-depth principles
        // Note: 'unsafe-inline' and 'unsafe-eval' are currently required for React/Vite builds
        // TODO: Implement CSP nonces to remove 'unsafe-inline' and 'unsafe-eval'
        //       This requires runtime nonce generation and injection into HTML templates
        //       See: https://content-security-policy.com/nonce/
        format!(
            "default-src 'self'; \
             script-src {}; \
             style-src {}; \
             style-src-elem {}; \
             img-src {}; \
             font-src {}; \
             connect-src {}; \
             frame-src {}; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action 'self'; \
             upgrade-insecure-requests",
            script_src, style_src, style_src, img_src, font_src, connect_src, frame_src
        )
    }

    /// Build HSTS header value
    pub fn build_hsts(&self) -> String {
        let mut hsts = format!("max-age={}", self.security.hsts.max_age);

        if self.security.hsts.include_subdomains {
            hsts.push_str("; includeSubDomains");
        }

        if self.security.hsts.preload {
            hsts.push_str("; preload");
        }

        hsts
    }
}
