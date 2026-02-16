//! Lazy Redis Connection Manager
//!
//! Shared Redis infrastructure for BFF services. This module is independent of
//! auth/state to avoid circular dependencies.
//!
//! Uses redis-rs ConnectionManager for multiplexed async connections:
//! - Cheaply cloneable (wrapped Arc internally)
//! - Automatic reconnection on connection drop
//! - No connection pooling needed for async (multiplexed)
//! - Lazy initialization on first use for resilience
//!
//! # Architectural Decision: ConnectionManager vs Deadpool
//!
//! We use ConnectionManager (not deadpool-redis) because:
//! 1. **Multiplexed connections** - For async Redis, a single multiplexed
//!    connection achieves higher performance than a connection pool
//! 2. **Automatic reconnection** - ConnectionManager handles reconnects
//!    transparently, no manual retry logic needed
//! 3. **Simpler code** - No pool configuration, sizing, or management
//! 4. **Cloneable** - Can be shared across handlers/tasks cheaply
//!
//! When to use deadpool-redis instead:
//! - If using **blocking Redis commands** (BLPOP, BRPOP, etc.)
//! - If connections need **isolation** (pub/sub with dedicated connections)
//! - If you need **connection limits** for resource control
//!
//! References:
//! - https://docs.rs/redis/latest/redis/aio/struct.ConnectionManager.html

use redis::aio::ConnectionManager;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::{error, info, warn};

/// Redis connection configuration
#[derive(Clone, Debug)]
pub struct LazyRedisConfig {
    /// Redis host (e.g., "redis-client.namespace.svc.cluster.local")
    pub host: String,
    /// Redis port (default: 6379)
    pub port: u16,
    /// Redis password for authentication (optional)
    /// If None, connects without authentication
    pub password: Option<String>,
    /// Maximum retry attempts for initial connection
    pub max_retries: u32,
    /// Initial retry delay in milliseconds (doubles each retry)
    pub initial_delay_ms: u64,
    /// Overall timeout for connection initialization in seconds
    /// CRITICAL: Prevents blocking requests for 31+ seconds on Redis failure
    pub connection_timeout_secs: u64,
}

impl Default for LazyRedisConfig {
    fn default() -> Self {
        Self {
            host: "localhost".to_string(),
            port: 6379,
            password: None,             // No auth by default
            max_retries: 3,             // Reduced from 5 to fail faster
            initial_delay_ms: 100,      // Reduced from 1000ms to 100ms
            connection_timeout_secs: 5, // Overall 5s timeout (was 31s!)
        }
    }
}

/// Lazy Redis connection manager
///
/// Wraps ConnectionManager with lazy initialization for resilience during
/// startup (handles Redis not being ready yet).
///
/// # Features
/// - Lazy connect on first use (not at startup)
/// - Retry with exponential backoff on initial connection
/// - Auto-reconnect on connection drop (handled by ConnectionManager)
/// - Cheaply cloneable for sharing across handlers
///
/// # Usage
/// ```ignore
/// let pool = LazyRedisPool::new(config);
///
/// // Get connection (connects if needed)
/// if let Some(conn) = pool.get().await {
///     // Use connection - it's cloneable!
///     let store = SessionStore::new(conn.clone(), session_config);
/// }
/// ```
pub struct LazyRedisPool {
    config: LazyRedisConfig,
    connection: OnceCell<ConnectionManager>,
}

impl LazyRedisPool {
    /// Create a new lazy Redis pool
    ///
    /// Does NOT connect immediately - connection happens on first `get()` call.
    pub fn new(config: LazyRedisConfig) -> Self {
        info!(
            "Redis connection configured (will connect on first use): {}:{}",
            config.host, config.port
        );
        Self {
            config,
            connection: OnceCell::new(),
        }
    }

    /// Get the ConnectionManager, initializing with retries if needed
    ///
    /// Returns `Some(ConnectionManager)` on success, `None` on failure.
    /// The ConnectionManager handles reconnection automatically after initial connect.
    ///
    /// # Behavior
    /// 1. If already connected: returns existing ConnectionManager (fast path)
    /// 2. If not connected: attempts to connect with exponential backoff
    /// 3. On failure after retries OR timeout: returns None (graceful degradation)
    ///
    /// # Timeout
    /// CRITICAL: Overall timeout prevents blocking requests for 31+ seconds
    /// when Redis is unavailable. Defaults to 5 seconds.
    ///
    /// # Non-Blocking Architecture
    /// This method NEVER blocks indefinitely. It either:
    /// - Returns immediately if connected (fast path)
    /// - Times out after connection_timeout_secs if Redis unavailable
    /// - Returns None for graceful degradation (fail-open pattern)
    ///
    /// PERFORMANCE: Inlined for hot path - called on every session operation
    #[inline]
    pub async fn get(&self) -> Option<ConnectionManager> {
        // Fast path: already connected
        if let Some(conn) = self.connection.get() {
            return Some(conn.clone());
        }

        // Slow path: need to initialize with timeout protection
        // CRITICAL: Wrap entire initialization in timeout to prevent blocking!
        let timeout_duration = Duration::from_secs(self.config.connection_timeout_secs);

        match tokio::time::timeout(timeout_duration, self.try_initialize()).await {
            Ok(Some(conn)) => Some(conn),
            Ok(None) => {
                warn!(
                    "Redis connection failed within timeout - graceful degradation (operations will skip Redis)"
                );
                None
            }
            Err(_elapsed) => {
                error!(
                    "Redis connection timed out after {}s - graceful degradation (requests proceed without Redis)",
                    self.config.connection_timeout_secs
                );
                None
            }
        }
    }

    /// Internal initialization with retries (called within timeout wrapper)
    async fn try_initialize(&self) -> Option<ConnectionManager> {
        self.connection
            .get_or_try_init(|| async {
                // Build Redis URL with optional password authentication
                // Format: redis://[:password@]host:port
                let redis_url = match &self.config.password {
                    Some(password) => format!(
                        "redis://:{}@{}:{}",
                        password, self.config.host, self.config.port
                    ),
                    None => format!("redis://{}:{}", self.config.host, self.config.port),
                };

                for attempt in 1..=self.config.max_retries {
                    match redis::Client::open(redis_url.as_str()) {
                        Ok(client) => {
                            match ConnectionManager::new(client).await {
                                Ok(manager) => {
                                    info!(
                                        "✓ Redis connected ({}:{}) [attempt {}/{}]",
                                        self.config.host,
                                        self.config.port,
                                        attempt,
                                        self.config.max_retries
                                    );
                                    return Ok(manager);
                                }
                                Err(e) => {
                                    let delay_ms =
                                        self.config.initial_delay_ms * (1 << (attempt - 1));
                                    if attempt < self.config.max_retries {
                                        warn!(
                                            "⚠ Redis connection failed (attempt {}/{}): {} - retrying in {}ms",
                                            attempt, self.config.max_retries, e, delay_ms
                                        );
                                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                    } else {
                                        error!(
                                            "⚠ Redis connection failed after {} attempts: {}",
                                            self.config.max_retries, e
                                        );
                                        return Err(e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let delay_ms = self.config.initial_delay_ms * (1 << (attempt - 1));
                            if attempt < self.config.max_retries {
                                warn!(
                                    "⚠ Redis client creation failed (attempt {}/{}): {} - retrying in {}ms",
                                    attempt, self.config.max_retries, e, delay_ms
                                );
                                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                            } else {
                                error!(
                                    "⚠ Redis client creation failed after {} attempts: {}",
                                    self.config.max_retries, e
                                );
                                return Err(e);
                            }
                        }
                    }
                }

                // Should not reach here, but handle it gracefully
                error!("Redis connection exhausted all retries");
                Err(redis::RedisError::from((
                    redis::ErrorKind::IoError,
                    "Connection failed after all retries",
                )))
            })
            .await
            .ok()
            .cloned()
    }

    /// Check if a connection has been established
    /// PERFORMANCE: Inlined for fast status checks
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.connection.initialized()
    }

    /// Get connection availability metric (0.0 = unavailable, 1.0 = available)
    /// Used for monitoring and alerting on Redis pool health
    #[inline]
    pub fn availability(&self) -> f64 {
        if self.is_connected() {
            1.0
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lazy_redis_config_default() {
        let config = LazyRedisConfig::default();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 6379);
        assert!(config.password.is_none()); // No auth by default
        assert_eq!(config.max_retries, 3); // Fast fail
        assert_eq!(config.initial_delay_ms, 100); // Fast retry
        assert_eq!(config.connection_timeout_secs, 5); // Overall timeout
    }

    #[test]
    fn test_lazy_redis_pool_creation() {
        let config = LazyRedisConfig {
            host: "redis-test".to_string(),
            port: 6380,
            password: None,
            max_retries: 3,
            initial_delay_ms: 500,
            connection_timeout_secs: 5,
        };
        let pool = LazyRedisPool::new(config);
        // Pool should be created without connecting
        assert!(!pool.is_connected());
    }

    #[test]
    fn test_lazy_redis_pool_with_password() {
        let config = LazyRedisConfig {
            host: "redis-auth".to_string(),
            port: 6379,
            password: Some("secret123".to_string()),
            max_retries: 3,
            initial_delay_ms: 100,
            connection_timeout_secs: 5,
        };
        let pool = LazyRedisPool::new(config);
        assert!(!pool.is_connected());
    }
}
