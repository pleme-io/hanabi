use serde::{Deserialize, Serialize};

/// Auto-optimization configuration for runtime resource detection and optimization
///
/// # Design Philosophy
/// All optimization parameters are tunable with excellent defaults based on:
/// - Known algorithmic optimizations (Little's Law, Amdahl's Law, TCP flow control)
/// - Industry best practices (connection pooling, async I/O patterns)
/// - Empirical studies (HTTP keep-alive, buffer sizing)
///
/// # Optimization Algorithms
/// - **Connection Limits**: Safety bounds prevent resource exhaustion
/// - **Pool Sizing**: Based on Little's Law (Little, 1961) and keep-alive studies
/// - **Concurrency**: 10x multiplier for async I/O (Nginx, Node.js best practices)
/// - **Buffer Sizing**: Adaptive based on Van Jacobson's flow control (1988)
/// - **Timeouts**: 3x RTT rule from TCP congestion control (Jacobson, 1988)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffOptimizationConfig {
    // ===== Connection Limits (Safety Bounds) =====
    /// Minimum WebSocket connections (safety lower bound)
    /// Prevents over-conservative resource allocation
    pub min_connections: usize,

    /// Maximum WebSocket connections (safety upper bound)
    /// Prevents memory exhaustion on large instances
    pub max_connections: usize,

    // ===== Pool Sizing (Little's Law + Keep-Alive Studies) =====
    /// HTTP connection pool size multiplier (x CPU cores)
    /// Default: 2.0 based on HTTP keep-alive studies (RFC 7230)
    /// - 1.0: Conservative (single connection per core)
    /// - 2.0: Balanced (handles connection setup latency)
    /// - 4.0: Aggressive (high connection churn workloads)
    pub http_pool_multiplier: f64,

    /// Max concurrent requests multiplier (x CPU cores)
    /// Default: 10.0 for async I/O (Nginx, Node.js best practice)
    /// - Async can handle Nx CPU cores due to non-blocking I/O
    /// - Lower for CPU-bound workloads (1-2x), higher for I/O-bound (10-100x)
    pub concurrency_multiplier: f64,

    // ===== Buffer Sizing (Van Jacobson Flow Control) =====
    /// Channel buffer size when memory pressure is LOW (<50% used)
    /// Default: 128 messages (generous buffering for throughput)
    pub channel_buffer_low_pressure: usize,

    /// Channel buffer size when memory pressure is MEDIUM (50-80% used)
    /// Default: 64 messages (balanced buffering)
    pub channel_buffer_medium_pressure: usize,

    /// Channel buffer size when memory pressure is HIGH (>80% used)
    /// Default: 32 messages (minimal buffering to prevent OOM)
    pub channel_buffer_high_pressure: usize,

    // ===== Network-Aware Optimization (TCP Congestion Control) =====
    /// Base timeout in milliseconds (before network adjustment)
    /// Default: 30000ms (30 seconds) for GraphQL queries
    pub timeout_base_ms: u64,

    /// Timeout multiplier for network latency (x measured RTT)
    /// Default: 3.0 based on TCP retransmission timeout (RTO) calculation
    /// - 1.0: Aggressive (tight timeouts, may timeout on slow networks)
    /// - 3.0: Balanced (3x RTT, TCP standard from RFC 6298)
    /// - 5.0: Conservative (tolerates high jitter)
    pub timeout_latency_multiplier: f64,
}

impl Default for BffOptimizationConfig {
    fn default() -> Self {
        Self {
            min_connections: 100,
            max_connections: 50000,
            http_pool_multiplier: 2.0,
            concurrency_multiplier: 10.0,
            channel_buffer_low_pressure: 128,
            channel_buffer_medium_pressure: 64,
            channel_buffer_high_pressure: 32,
            timeout_base_ms: 30000,
            timeout_latency_multiplier: 3.0,
        }
    }
}

impl BffOptimizationConfig {
    /// Validate configuration values to prevent runtime errors
    /// Returns Err with detailed message if validation fails
    pub fn validate(&self) -> Result<(), String> {
        // Validate connection limits
        if self.min_connections == 0 {
            return Err("BFF optimization: min_connections must be > 0".to_string());
        }
        if self.max_connections == 0 {
            return Err("BFF optimization: max_connections must be > 0".to_string());
        }
        if self.min_connections > self.max_connections {
            return Err(format!(
                "BFF optimization: min_connections ({}) must be <= max_connections ({})",
                self.min_connections, self.max_connections
            ));
        }

        // Validate multipliers (must be positive)
        if self.http_pool_multiplier <= 0.0 {
            return Err(format!(
                "BFF optimization: http_pool_multiplier ({}) must be positive",
                self.http_pool_multiplier
            ));
        }
        if self.concurrency_multiplier <= 0.0 {
            return Err(format!(
                "BFF optimization: concurrency_multiplier ({}) must be positive",
                self.concurrency_multiplier
            ));
        }
        if self.timeout_latency_multiplier <= 0.0 {
            return Err(format!(
                "BFF optimization: timeout_latency_multiplier ({}) must be positive",
                self.timeout_latency_multiplier
            ));
        }

        // Validate buffer sizes (must be positive)
        if self.channel_buffer_low_pressure == 0 {
            return Err("BFF optimization: channel_buffer_low_pressure must be > 0".to_string());
        }
        if self.channel_buffer_medium_pressure == 0 {
            return Err("BFF optimization: channel_buffer_medium_pressure must be > 0".to_string());
        }
        if self.channel_buffer_high_pressure == 0 {
            return Err("BFF optimization: channel_buffer_high_pressure must be > 0".to_string());
        }

        // Validate buffer size ordering (low >= medium >= high makes sense for memory pressure)
        if self.channel_buffer_low_pressure < self.channel_buffer_medium_pressure {
            return Err(format!(
                "BFF optimization: channel_buffer_low_pressure ({}) should be >= channel_buffer_medium_pressure ({})",
                self.channel_buffer_low_pressure, self.channel_buffer_medium_pressure
            ));
        }
        if self.channel_buffer_medium_pressure < self.channel_buffer_high_pressure {
            return Err(format!(
                "BFF optimization: channel_buffer_medium_pressure ({}) should be >= channel_buffer_high_pressure ({})",
                self.channel_buffer_medium_pressure, self.channel_buffer_high_pressure
            ));
        }

        // Validate timeout base
        if self.timeout_base_ms == 0 {
            return Err("BFF optimization: timeout_base_ms must be > 0".to_string());
        }

        Ok(())
    }
}
