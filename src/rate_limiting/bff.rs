//! BFF HTTP rate limiter (tower middleware)
//!
//! Uses tower-governor for IP-based rate limiting with configurable limits.
//! Superadmins and API key holders are exempt from rate limiting.
//!
//! # Governor Quota Gotcha
//!
//! `GovernorConfigBuilder::per_second(N)` means "replenish 1 token every N seconds"
//! (NOT "allow N requests per second"). To get the correct RPS we compute the
//! replenish interval in nanoseconds: `1_000_000_000 / rps`.

use axum::http::Request;
use governor::clock::QuantaInstant;
use governor::middleware::NoOpMiddleware;
use std::sync::Arc;
use tower_governor::{governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorLayer};
use tracing::{debug, trace};

use super::exemption::{check_api_key_exemption, check_superadmin_exemption};
use super::ip::extract_client_ip;
use crate::config::BffRateLimitConfig;

/// Custom key extractor that exempts API key holders and superadmins from rate limiting.
///
/// Exemption priority:
/// 1. API key (x-api-key header) — for automated testing, no JWT required
/// 2. Superadmin role in JWT (Authorization header) — for admin operations
/// 3. Falls back to IP-based rate limiting for all other requests
#[derive(Clone)]
pub struct RoleAwareKeyExtractor;

impl KeyExtractor for RoleAwareKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, tower_governor::GovernorError> {
        let headers = req.headers();

        // FIRST: Check for API key exemption
        if let Some(unique_key) = check_api_key_exemption(headers) {
            debug!("Rate limit exempt: API key present (unique key)");
            return Ok(unique_key);
        }

        // SECOND: Check for superadmin role in JWT
        if check_superadmin_exemption(headers) {
            debug!("Rate limit exempt: superadmin user");
            return Ok("__SUPERADMIN_EXEMPT__".to_string());
        }

        // Fall back to unified IP extraction
        let (ip, _source) = extract_client_ip(req);
        trace!("Rate limit key: IP={}", ip);
        Ok(ip)
    }
}

/// Build rate limiting layer for BFF endpoints.
///
/// Creates a tower-governor layer that:
/// - Tracks requests per client (IP address for normal users, exempt key for superadmins)
/// - Enforces requests_per_second quota
/// - Allows burst_size temporary bursts
/// - Returns 429 when quota exceeded (except for superadmins)
///
/// # Parameters
/// - `rate_limit_config`: Rate limit configuration (requests_per_second, burst_size)
/// - `label`: Human-readable label for logging (e.g., "HTTP", "WebSocket")
pub fn build_rate_limit_layer(
    rate_limit_config: &BffRateLimitConfig,
    label: &str,
) -> Result<
    GovernorLayer<RoleAwareKeyExtractor, NoOpMiddleware<QuantaInstant>>,
    Box<dyn std::error::Error>,
> {
    if !rate_limit_config.enabled {
        return Err(format!("Rate limiting not enabled for {}", label).into());
    }

    // GovernorConfigBuilder::per_second(N) means "replenish 1 token every N seconds"
    // (NOT "allow N requests per second"). To get requests_per_second tokens/sec,
    // we need a replenishment interval of 1/requests_per_second seconds.
    // Using per_nanosecond for precision across all RPS values.
    let replenish_interval_ns =
        1_000_000_000u64 / rate_limit_config.requests_per_second.max(1) as u64;

    let governor_conf = GovernorConfigBuilder::default()
        .per_nanosecond(replenish_interval_ns)
        .burst_size(rate_limit_config.burst_size)
        .key_extractor(RoleAwareKeyExtractor)
        .finish()
        .ok_or("Failed to build rate limit config")?;

    Ok(GovernorLayer {
        config: Arc::new(governor_conf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_layer_creation() {
        // Rate limit layer creation is tested through integration tests
        // Unit testing requires valid configuration
    }
}
