//! Service mesh primitives — circuit breaker, retry policy, rate limiting.
//!
//! These can be composed as tower middleware layers on the proxy.
//! mTLS is planned for a future phase.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to open the circuit.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Duration to keep the circuit open before half-opening.
    #[serde(default = "default_reset_timeout")]
    pub reset_timeout_secs: u64,

    /// Number of successes in half-open to close the circuit.
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_failure_threshold() -> u32 { 5 }
fn default_reset_timeout() -> u64 { 30 }
fn default_success_threshold() -> u32 { 2 }

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            reset_timeout_secs: default_reset_timeout(),
        }
    }
}

/// Circuit breaker states.
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,
    Open { opened_at: std::time::Instant },
    HalfOpen,
}

/// Per-backend circuit breaker.
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    consecutive_failures: AtomicU64,
    consecutive_successes: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitState::Closed),
            consecutive_failures: AtomicU64::new(0),
            consecutive_successes: AtomicU64::new(0),
        }
    }

    /// Check if a request is allowed through.
    pub async fn allow_request(&self) -> bool {
        let mut state = self.state.write().await;
        match &*state {
            CircuitState::Closed => true,
            CircuitState::Open { opened_at } => {
                let elapsed = opened_at.elapsed();
                if elapsed >= Duration::from_secs(self.config.reset_timeout_secs) {
                    debug!("circuit breaker transitioning to half-open");
                    *state = CircuitState::HalfOpen;
                    self.consecutive_successes.store(0, Ordering::Relaxed);
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub async fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        let successes = self.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

        let mut state = self.state.write().await;
        if *state == CircuitState::HalfOpen
            && successes >= self.config.success_threshold as u64
        {
            debug!("circuit breaker closing");
            *state = CircuitState::Closed;
        }
    }

    /// Record a failed request.
    pub async fn record_failure(&self) {
        self.consecutive_successes.store(0, Ordering::Relaxed);
        let failures = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

        let mut state = self.state.write().await;
        let is_open = matches!(&*state, CircuitState::Open { .. });
        if failures >= self.config.failure_threshold as u64 && !is_open {
            warn!(failures, "circuit breaker opening");
            *state = CircuitState::Open {
                opened_at: std::time::Instant::now(),
            };
        }
    }

    /// Get the current state.
    pub async fn state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

/// Retry policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Initial backoff in milliseconds.
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_ms: u64,

    /// Backoff multiplier.
    #[serde(default = "default_multiplier")]
    pub multiplier: f64,

    /// Maximum backoff in milliseconds.
    #[serde(default = "default_max_backoff")]
    pub max_backoff_ms: u64,
}

fn default_max_retries() -> u32 { 3 }
fn default_initial_backoff() -> u64 { 100 }
fn default_multiplier() -> f64 { 2.0 }
fn default_max_backoff() -> u64 { 5000 }

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_backoff_ms: default_initial_backoff(),
            multiplier: default_multiplier(),
            max_backoff_ms: default_max_backoff(),
        }
    }
}

impl RetryConfig {
    /// Calculate backoff duration for a given attempt.
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let ms = (self.initial_backoff_ms as f64 * self.multiplier.powi(attempt as i32)) as u64;
        Duration::from_millis(ms.min(self.max_backoff_ms))
    }
}

/// Mesh configuration combining circuit breaker and retry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    #[serde(default)]
    pub retry: RetryConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retry_backoff() {
        let config = RetryConfig::default();
        assert_eq!(config.backoff_for(0), Duration::from_millis(100));
        assert_eq!(config.backoff_for(1), Duration::from_millis(200));
        assert_eq!(config.backoff_for(2), Duration::from_millis(400));
        // Should cap at max
        assert!(config.backoff_for(20) <= Duration::from_millis(5000));
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            reset_timeout_secs: 60,
            success_threshold: 2,
        });

        assert!(cb.allow_request().await);
        cb.record_failure().await;
        cb.record_failure().await;
        assert!(cb.allow_request().await); // still closed
        cb.record_failure().await;
        assert!(!cb.allow_request().await); // now open
    }

    #[tokio::test]
    async fn test_circuit_breaker_recovers() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout_secs: 1,
            success_threshold: 1,
        });

        cb.record_failure().await;
        cb.record_failure().await;
        assert!(!cb.allow_request().await); // open

        // Wait for reset timeout
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(cb.allow_request().await); // half-open
        cb.record_success().await;
        assert!(cb.allow_request().await); // closed
    }
}
