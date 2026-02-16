use serde::{Deserialize, Serialize};

/// HTTP-specific BFF configuration (queries/mutations)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffHttpConfig {
    /// Request timeout for HTTP GraphQL requests (seconds)
    pub timeout_secs: u64,

    /// Rate limiting for HTTP requests
    #[serde(default)]
    pub rate_limit: BffRateLimitConfig,

    /// Enable query result caching (requires Redis)
    #[serde(default)]
    pub enable_caching: bool,
}

impl Default for BffHttpConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 10,
            rate_limit: BffRateLimitConfig::default(),
            enable_caching: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffRateLimitConfig {
    /// Enable rate limiting on BFF endpoints
    #[serde(default)]
    pub enabled: bool,

    /// Requests per second per client
    pub requests_per_second: u64,

    /// Burst size (how many requests can be made at once)
    pub burst_size: u32,
}

impl Default for BffRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 1000,
            burst_size: 2000,
        }
    }
}
