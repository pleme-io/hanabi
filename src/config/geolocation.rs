//! Geolocation endpoint configuration

use serde::{Deserialize, Serialize};

/// Configuration for the geolocation endpoint
///
/// When `enabled` is false, the /api/geolocation route is not registered.
/// Cities are defined in the product's YAML config.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct GeolocationConfig {
    /// Enable the geolocation endpoint
    pub enabled: bool,

    /// API URL template for IP geolocation lookups
    /// Use `{ip}` as placeholder for the client IP
    pub api_url_template: String,

    /// Cache TTL in seconds for successful lookups
    pub cache_ttl_secs: u64,

    /// Cache TTL in seconds for failed lookups (shorter to retry sooner)
    pub failed_cache_ttl_secs: u64,

    /// Rate limit: max requests per IP per minute
    pub rate_limit_per_minute: u64,

    /// List of cities for matching IP geolocation results
    pub cities: Vec<GeoCity>,
}

impl Default for GeolocationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_url_template: "http://ip-api.com/json/{ip}?fields=status,city,regionName"
                .to_string(),
            cache_ttl_secs: 86400,          // 24 hours
            failed_cache_ttl_secs: 3600,    // 1 hour
            rate_limit_per_minute: 10,
            cities: Vec::new(),
        }
    }
}

/// A city entry for geolocation matching
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoCity {
    /// URL-friendly slug (e.g., "sao-paulo")
    pub slug: String,
    /// Display name for matching (e.g., "São Paulo")
    pub name: String,
}
