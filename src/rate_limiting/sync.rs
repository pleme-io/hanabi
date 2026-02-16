//! Rate Limit Configuration Sync via NATS
//!
//! Subscribes to rate limit configuration change notifications from the backend.
//! When an admin updates rate limit settings via the admin UI, the backend
//! publishes a notification to NATS. This module receives that notification,
//! queries the backend's GraphQL API for fresh settings, and updates the
//! DynamicRateLimiter in-place.
//!
//! # Architecture
//!
//! ```text
//! Admin UI → updatePlatformSettings mutation → Backend DB
//!   → NATS publish to "{product}.config.ratelimits"
//!   → Hanabi NATS subscriber (this module)
//!   → GraphQL query to backend for fresh PlatformSettings
//!   → DynamicRateLimiter.update_config()
//!   → Both BFF layer + Federation layer pick up new values
//! ```
//!
//! # Debounce
//!
//! A 2-second debounce prevents querying the backend on rapid admin edits
//! (the admin UI auto-saves with 1s debounce already).

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use super::dynamic::{DynamicRateLimitConfig, DynamicRateLimiter};
use crate::metrics::{MetricsClient, MetricsExt};

/// Debounce duration to avoid querying backend on rapid admin edits
const DEBOUNCE_DURATION: Duration = Duration::from_secs(2);

/// GraphQL query to fetch rate limit settings from the backend
const PLATFORM_SETTINGS_QUERY: &str = r#"query {
  platformSettings {
    rateLimitBffEnabled
    rateLimitBffRps
    rateLimitBffBurst
    rateLimitFedEnabled
    rateLimitFedDefaultRps
    rateLimitFedDefaultBurst
    rateLimitExemptRoles
  }
}"#;

/// Response types for the GraphQL query

#[derive(Debug, Deserialize)]
struct GraphQLResponse {
    data: Option<GraphQLData>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphQLData {
    platform_settings: Option<PlatformSettingsResponse>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlatformSettingsResponse {
    rate_limit_bff_enabled: Option<bool>,
    rate_limit_bff_rps: Option<i64>,
    rate_limit_bff_burst: Option<i64>,
    rate_limit_fed_enabled: Option<bool>,
    rate_limit_fed_default_rps: Option<i64>,
    rate_limit_fed_default_burst: Option<i64>,
    rate_limit_exempt_roles: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

impl PlatformSettingsResponse {
    /// Convert to DynamicRateLimitConfig with a new version number
    fn to_dynamic_config(&self, version: u64) -> DynamicRateLimitConfig {
        let defaults = DynamicRateLimitConfig::default();
        DynamicRateLimitConfig {
            bff_enabled: self.rate_limit_bff_enabled.unwrap_or(defaults.bff_enabled),
            bff_rps: self.rate_limit_bff_rps.map(|v| v as u32).unwrap_or(defaults.bff_rps),
            bff_burst: self.rate_limit_bff_burst.map(|v| v as u32).unwrap_or(defaults.bff_burst),
            federation_enabled: self.rate_limit_fed_enabled.unwrap_or(defaults.federation_enabled),
            federation_default_rps: self
                .rate_limit_fed_default_rps
                .map(|v| v as u32)
                .unwrap_or(defaults.federation_default_rps),
            federation_default_burst: self
                .rate_limit_fed_default_burst
                .map(|v| v as u32)
                .unwrap_or(defaults.federation_default_burst),
            exempt_roles: self
                .rate_limit_exempt_roles
                .clone()
                .unwrap_or(defaults.exempt_roles),
            version,
        }
    }
}

/// Fetch platform settings from backend GraphQL API
async fn fetch_platform_settings(
    http_client: &reqwest::Client,
    backend_graphql_url: &str,
) -> Result<PlatformSettingsResponse, String> {
    let body = serde_json::json!({
        "query": PLATFORM_SETTINGS_QUERY,
    });

    let response = http_client
        .post(backend_graphql_url)
        .header("content-type", "application/json")
        .header("x-internal-service", "hanabi")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("HTTP request to backend failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "Backend returned status {}: {}",
            response.status(),
            response
                .text()
                .await
                .unwrap_or_else(|_| "unknown".into())
        ));
    }

    let gql_response: GraphQLResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse GraphQL response: {}", e))?;

    if let Some(errors) = gql_response.errors {
        if !errors.is_empty() {
            let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
            return Err(format!("GraphQL errors: {}", messages.join(", ")));
        }
    }

    gql_response
        .data
        .and_then(|d| d.platform_settings)
        .ok_or_else(|| "No platformSettings in response".to_string())
}

/// Subscribe to rate limit configuration changes from NATS
///
/// Connects to NATS, subscribes to `{product}.config.ratelimits`, and on each
/// notification queries the backend for fresh settings and updates the DynamicRateLimiter.
///
/// Includes a 2-second debounce to avoid rapid backend queries.
pub async fn subscribe_rate_limit_config(
    nats_url: &str,
    product: &str,
    backend_graphql_url: &str,
    http_client: Arc<reqwest::Client>,
    dynamic_limiter: Arc<DynamicRateLimiter>,
    metrics: Option<Arc<MetricsClient>>,
) -> Result<(), String> {
    let subject = format!("{}.config.ratelimits", product.to_uppercase());

    let client = async_nats::connect(nats_url)
        .await
        .map_err(|e| format!("Failed to connect to NATS at {}: {}", nats_url, e))?;

    info!(
        "Connected to NATS at {} for rate limit config updates",
        nats_url
    );

    let mut subscriber = client
        .subscribe(subject.clone())
        .await
        .map_err(|e| format!("Failed to subscribe to {}: {}", subject, e))?;

    info!(
        "Subscribed to {} for rate limit config change notifications",
        subject
    );

    let mut version: u64 = 0;
    let mut last_fetch = Instant::now() - DEBOUNCE_DURATION; // Allow immediate first fetch

    while let Some(message) = subscriber.next().await {
        info!(
            subject = %message.subject,
            payload_len = message.payload.len(),
            "Received rate limit config change notification"
        );

        metrics.incr("rate_limit_sync.notification_received", &[]);

        // Debounce: skip if we fetched too recently
        let since_last = last_fetch.elapsed();
        if since_last < DEBOUNCE_DURATION {
            let wait = DEBOUNCE_DURATION - since_last;
            debug!(
                wait_ms = wait.as_millis(),
                "Debouncing rate limit config fetch"
            );
            tokio::time::sleep(wait).await;
        }

        // Fetch fresh settings from backend
        match fetch_platform_settings(&http_client, backend_graphql_url).await {
            Ok(settings) => {
                version += 1;
                let new_config = settings.to_dynamic_config(version);

                info!(
                    version = version,
                    bff_enabled = new_config.bff_enabled,
                    bff_rps = new_config.bff_rps,
                    federation_enabled = new_config.federation_enabled,
                    federation_rps = new_config.federation_default_rps,
                    "Applying rate limit config from backend"
                );

                dynamic_limiter.update_config(new_config).await;
                metrics.incr("rate_limit_sync.config_applied", &[]);
                last_fetch = Instant::now();
            }
            Err(e) => {
                error!(
                    error = %e,
                    "Failed to fetch platform settings from backend"
                );
                metrics.incr("rate_limit_sync.fetch_error", &[]);
            }
        }
    }

    warn!("NATS rate limit config subscriber disconnected");
    Ok(())
}

/// Spawn the rate limit config subscriber as a background task with reconnect loop
///
/// Follows the same pattern as `session_events::spawn_session_invalidation_subscriber`.
pub fn spawn_rate_limit_config_subscriber(
    nats_url: String,
    product: String,
    backend_graphql_url: String,
    http_client: Arc<reqwest::Client>,
    dynamic_limiter: Arc<DynamicRateLimiter>,
    metrics: Option<Arc<MetricsClient>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match subscribe_rate_limit_config(
                &nats_url,
                &product,
                &backend_graphql_url,
                http_client.clone(),
                dynamic_limiter.clone(),
                metrics.clone(),
            )
            .await
            {
                Ok(()) => {
                    warn!("Rate limit config subscriber exited normally, reconnecting in 5s...");
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Rate limit config subscriber error, reconnecting in 5s..."
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_settings_to_dynamic_config() {
        let settings = PlatformSettingsResponse {
            rate_limit_bff_enabled: Some(false),
            rate_limit_bff_rps: Some(500),
            rate_limit_bff_burst: Some(1000),
            rate_limit_fed_enabled: Some(true),
            rate_limit_fed_default_rps: Some(200),
            rate_limit_fed_default_burst: Some(400),
            rate_limit_exempt_roles: Some(vec!["admin".to_string()]),
        };

        let config = settings.to_dynamic_config(42);

        assert!(!config.bff_enabled);
        assert_eq!(config.bff_rps, 500);
        assert_eq!(config.bff_burst, 1000);
        assert!(config.federation_enabled);
        assert_eq!(config.federation_default_rps, 200);
        assert_eq!(config.federation_default_burst, 400);
        assert_eq!(config.exempt_roles, vec!["admin".to_string()]);
        assert_eq!(config.version, 42);
    }

    #[test]
    fn test_platform_settings_defaults() {
        let settings = PlatformSettingsResponse {
            rate_limit_bff_enabled: None,
            rate_limit_bff_rps: None,
            rate_limit_bff_burst: None,
            rate_limit_fed_enabled: None,
            rate_limit_fed_default_rps: None,
            rate_limit_fed_default_burst: None,
            rate_limit_exempt_roles: None,
        };

        let config = settings.to_dynamic_config(0);
        let defaults = DynamicRateLimitConfig::default();

        assert_eq!(config.bff_enabled, defaults.bff_enabled);
        assert_eq!(config.bff_rps, defaults.bff_rps);
        assert_eq!(config.bff_burst, defaults.bff_burst);
        assert_eq!(config.federation_enabled, defaults.federation_enabled);
        assert_eq!(
            config.federation_default_rps,
            defaults.federation_default_rps
        );
    }

    #[test]
    fn test_graphql_response_deserialization() {
        let json = r#"{
            "data": {
                "platformSettings": {
                    "rateLimitBffEnabled": true,
                    "rateLimitBffRps": 1000,
                    "rateLimitBffBurst": 2000,
                    "rateLimitFedEnabled": true,
                    "rateLimitFedDefaultRps": 1000,
                    "rateLimitFedDefaultBurst": 2000,
                    "rateLimitExemptRoles": ["superadmin", "service"]
                }
            }
        }"#;

        let response: GraphQLResponse = serde_json::from_str(json).unwrap();
        let settings = response.data.unwrap().platform_settings.unwrap();

        assert_eq!(settings.rate_limit_bff_enabled, Some(true));
        assert_eq!(settings.rate_limit_bff_rps, Some(1000));
        assert_eq!(
            settings.rate_limit_exempt_roles,
            Some(vec!["superadmin".to_string(), "service".to_string()])
        );
    }
}
