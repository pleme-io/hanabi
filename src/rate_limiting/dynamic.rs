//! Dynamic Rate Limiter with Hot-Reload Capability
//!
//! Provides a rate limiter that can be updated at runtime without restart.
//! Configuration is fetched from the product backend via GraphQL and applied
//! to the governor rate limiters.
//!
//! # Architecture
//!
//! ```text
//! Admin UI → updatePlatformSettings mutation → Backend DB
//!   → NATS publish → Hanabi subscriber (sync module)
//!   → GraphQL query for fresh PlatformSettings
//!   → DynamicRateLimiter.update_config()
//!   → Both BFF layer + Federation layer pick up new values
//! ```

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Dynamic rate limit configuration
///
/// Can be updated at runtime without restart.
#[derive(Debug, Clone)]
pub struct DynamicRateLimitConfig {
    /// BFF HTTP rate limiting enabled
    pub bff_enabled: bool,

    /// BFF requests per second
    pub bff_rps: u32,

    /// BFF burst size
    pub bff_burst: u32,

    /// Federation rate limiting enabled
    pub federation_enabled: bool,

    /// Federation default requests per second
    pub federation_default_rps: u32,

    /// Federation default burst size
    pub federation_default_burst: u32,

    /// Roles exempt from rate limiting
    pub exempt_roles: Vec<String>,

    /// Configuration version (for tracking updates)
    pub version: u64,
}

impl Default for DynamicRateLimitConfig {
    fn default() -> Self {
        Self {
            bff_enabled: true,
            bff_rps: 1000,
            bff_burst: 2000,
            federation_enabled: true,
            federation_default_rps: 1000,
            federation_default_burst: 2000,
            exempt_roles: vec!["superadmin".to_string(), "service".to_string()],
            version: 0,
        }
    }
}

impl DynamicRateLimitConfig {
    /// Check if a role is exempt from rate limiting
    pub fn is_role_exempt(&self, role: &str) -> bool {
        self.exempt_roles.iter().any(|r| r == role)
    }
}

/// Dynamic rate limiter with hot-reload capability
pub struct DynamicRateLimiter {
    /// Current configuration
    config: Arc<RwLock<DynamicRateLimitConfig>>,
}

impl DynamicRateLimiter {
    /// Create a new dynamic rate limiter with initial configuration
    pub fn new(initial_config: DynamicRateLimitConfig) -> Self {
        info!(
            bff_enabled = initial_config.bff_enabled,
            bff_rps = initial_config.bff_rps,
            bff_burst = initial_config.bff_burst,
            federation_enabled = initial_config.federation_enabled,
            federation_rps = initial_config.federation_default_rps,
            exempt_roles = ?initial_config.exempt_roles,
            "DynamicRateLimiter initialized"
        );

        Self {
            config: Arc::new(RwLock::new(initial_config)),
        }
    }

    /// Get the current configuration
    pub async fn config(&self) -> DynamicRateLimitConfig {
        self.config.read().await.clone()
    }

    /// Update the configuration
    ///
    /// This will be called when new settings are received from the backend.
    pub async fn update_config(&self, new_config: DynamicRateLimitConfig) {
        let mut config = self.config.write().await;

        // Check if anything actually changed
        let changed = config.bff_enabled != new_config.bff_enabled
            || config.bff_rps != new_config.bff_rps
            || config.bff_burst != new_config.bff_burst
            || config.federation_enabled != new_config.federation_enabled
            || config.federation_default_rps != new_config.federation_default_rps
            || config.federation_default_burst != new_config.federation_default_burst
            || config.exempt_roles != new_config.exempt_roles;

        if changed {
            info!(
                old_version = config.version,
                new_version = new_config.version,
                bff_enabled = new_config.bff_enabled,
                bff_rps = new_config.bff_rps,
                federation_enabled = new_config.federation_enabled,
                federation_rps = new_config.federation_default_rps,
                "Rate limit configuration updated"
            );

            *config = new_config;
        } else {
            debug!("Rate limit configuration unchanged");
        }
    }

    /// Check if BFF rate limiting is enabled
    pub async fn is_bff_enabled(&self) -> bool {
        self.config.read().await.bff_enabled
    }

    /// Check if federation rate limiting is enabled
    pub async fn is_federation_enabled(&self) -> bool {
        self.config.read().await.federation_enabled
    }

    /// Get BFF rate limit parameters (rps, burst)
    pub async fn bff_limits(&self) -> (u32, u32) {
        let config = self.config.read().await;
        (config.bff_rps, config.bff_burst)
    }

    /// Get federation rate limit parameters (rps, burst)
    pub async fn federation_limits(&self) -> (u32, u32) {
        let config = self.config.read().await;
        (config.federation_default_rps, config.federation_default_burst)
    }

    /// Check if a role is exempt from rate limiting
    pub async fn is_role_exempt(&self, role: &str) -> bool {
        self.config.read().await.is_role_exempt(role)
    }

    /// Check if any of the given roles are exempt
    pub async fn are_roles_exempt(&self, roles: &[String]) -> bool {
        let config = self.config.read().await;
        roles.iter().any(|r| config.is_role_exempt(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_config() {
        let config = DynamicRateLimitConfig::default();
        assert!(config.bff_enabled);
        assert_eq!(config.bff_rps, 1000);
        assert_eq!(config.bff_burst, 2000);
        assert!(config.is_role_exempt("superadmin"));
        assert!(config.is_role_exempt("service"));
        assert!(!config.is_role_exempt("user"));
    }

    #[tokio::test]
    async fn test_dynamic_rate_limiter() {
        let config = DynamicRateLimitConfig::default();
        let limiter = DynamicRateLimiter::new(config);

        assert!(limiter.is_bff_enabled().await);
        assert_eq!(limiter.bff_limits().await, (1000, 2000));
    }

    #[tokio::test]
    async fn test_config_update() {
        let initial = DynamicRateLimitConfig::default();
        let limiter = DynamicRateLimiter::new(initial);

        let new_config = DynamicRateLimitConfig {
            bff_enabled: false,
            bff_rps: 500,
            bff_burst: 1000,
            version: 1,
            ..Default::default()
        };

        limiter.update_config(new_config).await;

        assert!(!limiter.is_bff_enabled().await);
        assert_eq!(limiter.bff_limits().await, (500, 1000));
    }

    #[tokio::test]
    async fn test_role_exemption() {
        let config = DynamicRateLimitConfig {
            exempt_roles: vec!["admin".to_string(), "superadmin".to_string()],
            ..Default::default()
        };
        let limiter = DynamicRateLimiter::new(config);

        assert!(limiter.is_role_exempt("admin").await);
        assert!(limiter.is_role_exempt("superadmin").await);
        assert!(!limiter.is_role_exempt("user").await);
    }
}
