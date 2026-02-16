use super::BffRateLimitConfig;
use serde::{Deserialize, Serialize};

/// WebSocket-specific BFF configuration (subscriptions)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffWebSocketConfig {
    /// Idle timeout for WebSocket connections (seconds)
    /// Connections idle longer than this will be closed
    pub timeout_secs: u64,

    /// Maximum concurrent WebSocket connections
    /// Can be explicitly set or auto-calculated from available memory
    /// If 0, calculated as: (available_memory × memory_percent_limit) / memory_per_connection_kb
    #[serde(default)]
    pub max_connections: usize,

    /// Percentage of available system memory to allocate to WebSocket connections (0.0-1.0)
    /// Used for auto-calculating max_connections if max_connections = 0
    /// Example: 0.25 = 25% of available memory for WebSocket connections
    pub memory_percent_limit: f64,

    /// Estimated memory per WebSocket connection in KB (for capacity planning)
    /// Includes: 2 tokio tasks + message buffers + connection state
    /// Default: 200KB per connection
    pub memory_per_connection_kb: usize,

    /// Rate limiting for WebSocket upgrade requests
    /// Once upgraded, individual messages are not rate-limited
    #[serde(default)]
    pub rate_limit: BffRateLimitConfig,

    /// Maximum message size in bytes (prevents memory exhaustion)
    /// Rejects messages exceeding this size
    pub max_message_size: usize,

    /// Channel buffer size for message forwarding (per-connection)
    /// Bounded channels prevent unbounded memory growth
    /// Memory per connection: buffer_size × average_message_size
    pub channel_buffer_size: usize,

    /// Ping interval to keep connections alive (seconds)
    /// Set to 0 to disable automatic pings
    pub ping_interval_secs: u64,

    /// Enable per-connection message rate limiting (messages per second)
    #[serde(default)]
    pub enable_message_rate_limit: bool,

    /// Messages per second per connection (if message rate limiting enabled)
    pub messages_per_second: u64,
}

impl Default for BffWebSocketConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 3600,
            max_connections: 1000,
            memory_percent_limit: 0.25,
            memory_per_connection_kb: 200,
            rate_limit: BffRateLimitConfig {
                enabled: false, // Don't rate limit WS upgrades by default (HTTP already limited)
                requests_per_second: 1000,
                burst_size: 2000,
            },
            max_message_size: 10 * 1024 * 1024,
            channel_buffer_size: 32,
            ping_interval_secs: 30,
            enable_message_rate_limit: false,
            messages_per_second: 100,
        }
    }
}
