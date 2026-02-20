#![allow(dead_code)]
//! Request Deduplication for GraphQL Federation
//!
//! Coalesces concurrent identical queries to reduce subgraph load.
//! When multiple clients request the same query simultaneously,
//! only one request is executed and the result is shared with all waiters.
//!
//! # Architecture
//!
//! ```text
//! Client A ─┐
//!           │  Same Query
//! Client B ─┼────────► [Deduplication Layer]
//!           │                   │
//! Client C ─┘                   │
//!                               │
//!              ┌────────────────┴────────────────┐
//!              │                                 │
//!              ▼                                 ▼
//!     First request?                    Already in-flight?
//!              │                                 │
//!              ▼                                 ▼
//!     Execute query ─────────► Result    Wait for result
//!              │                  │              │
//!              ▼                  │              │
//!     Broadcast to waiters ◄─────┘              │
//!              │                                 │
//!              ▼                                 ▼
//!     Return to Client A            Return to Clients B & C
//! ```
//!
//! # When to Use
//!
//! Deduplication is most effective for:
//! - Read queries (not mutations)
//! - Queries without user-specific data
//! - High-concurrency scenarios (many users viewing same data)
//!
//! # TTL
//!
//! In-flight entries have a short TTL to prevent memory leaks from
//! abandoned requests. The default is 30 seconds.

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::{mapref::entry::Entry, DashMap};
use once_cell::sync::Lazy;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::metrics::{MetricsClient, MetricsExt};

/// PERFORMANCE: Static RandomState for deterministic hashing within process lifetime.
/// Initialized once, reused for all hash operations. ahash is 2-3x faster than DefaultHasher.
static AHASH_STATE: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);

/// Configuration for request deduplication
#[derive(Debug, Clone)]
pub struct DeduplicationConfig {
    /// Enable deduplication
    pub enabled: bool,

    /// Maximum time to wait for an in-flight request (seconds)
    pub max_wait_secs: u64,

    /// Maximum number of waiters per in-flight request
    pub max_waiters: usize,

    /// TTL for abandoned in-flight entries (seconds)
    pub entry_ttl_secs: u64,

    /// Maximum concurrent in-flight requests to track
    pub max_entries: usize,
}

impl Default for DeduplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // CRITICAL: Keep wait time SHORT to fail fast like Hive Router
            // Long waits cause 504 cascades when leader gets stuck
            // 5 seconds is enough for most queries, anything longer should fail
            max_wait_secs: 5,
            max_waiters: 100,
            // TTL should be short - abandoned entries are dead weight
            entry_ttl_secs: 10,
            max_entries: 10_000,
        }
    }
}

/// Result of a deduplication lookup
pub enum DeduplicationResult {
    /// First request - caller should execute and broadcast result
    Leader {
        /// Sender to broadcast result to waiters
        sender: broadcast::Sender<DeduplicatedResult>,
    },
    /// Request is already in-flight - caller should wait
    Waiter {
        /// Receiver to wait for result
        receiver: broadcast::Receiver<DeduplicatedResult>,
    },
}

/// A deduplicated query result
#[derive(Debug, Clone)]
pub struct DeduplicatedResult {
    /// The GraphQL response data
    pub data: serde_json::Value,
    /// Whether the result was from cache
    pub from_cache: bool,
}

/// In-flight query entry
struct InFlightEntry {
    /// Broadcast sender for sharing results
    sender: broadcast::Sender<DeduplicatedResult>,
    /// When this entry was created
    created_at: Instant,
}

/// Request deduplication layer
pub struct RequestDeduplicator {
    /// In-flight queries by hash
    in_flight: DashMap<u64, InFlightEntry>,

    /// Configuration
    config: DeduplicationConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl RequestDeduplicator {
    /// Create a new request deduplicator
    pub fn new(config: DeduplicationConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self {
            in_flight: DashMap::new(),
            config,
            metrics,
        }
    }

    /// Check if deduplication is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Try to deduplicate a query
    ///
    /// Returns `Leader` if this is the first request and caller should execute it.
    /// Returns `Waiter` if the request is already in-flight and caller should wait.
    pub fn deduplicate(&self, key: &DeduplicationKey) -> Option<DeduplicationResult> {
        if !self.config.enabled {
            return None;
        }

        let hash = key.hash();

        // Check if already in-flight
        if let Some(entry) = self.in_flight.get(&hash) {
            // Check if entry is still valid (not expired)
            if entry.created_at.elapsed() < Duration::from_secs(self.config.entry_ttl_secs) {
                // Already in-flight, become a waiter
                let receiver = entry.sender.subscribe();

                self.metrics.incr("bff.federation.dedup.waiter", &[]);

                debug!(
                    operation = ?key.operation_name,
                    hash = hash,
                    "Deduplication: joining as waiter"
                );

                return Some(DeduplicationResult::Waiter { receiver });
            } else {
                // Entry expired, remove it
                drop(entry);
                self.in_flight.remove(&hash);
            }
        }

        // Check if we have capacity for new entries
        if self.in_flight.len() >= self.config.max_entries {
            // Clean up expired entries
            self.cleanup_expired();

            // If still at capacity, skip deduplication
            if self.in_flight.len() >= self.config.max_entries {
                warn!(
                    max_entries = self.config.max_entries,
                    "Deduplication: at capacity, skipping"
                );
                self.metrics.incr("bff.federation.dedup.skip_capacity", &[]);
                return None;
            }
        }

        // Create new in-flight entry
        let (sender, _) = broadcast::channel(self.config.max_waiters);

        let entry = InFlightEntry {
            sender: sender.clone(),
            created_at: Instant::now(),
        };

        // Use entry API to handle race condition
        match self.in_flight.entry(hash) {
            Entry::Occupied(occupied) => {
                // Another thread created the entry, become a waiter
                let receiver = occupied.get().sender.subscribe();

                self.metrics.incr("bff.federation.dedup.waiter", &[]);

                Some(DeduplicationResult::Waiter { receiver })
            }
            Entry::Vacant(vacant) => {
                // We're the leader
                vacant.insert(entry);

                self.metrics.incr("bff.federation.dedup.leader", &[]);
                self.metrics.gauge(
                    "bff.federation.dedup.in_flight",
                    self.in_flight.len() as f64,
                    &[],
                );

                debug!(
                    operation = ?key.operation_name,
                    hash = hash,
                    "Deduplication: becoming leader"
                );

                Some(DeduplicationResult::Leader { sender })
            }
        }
    }

    /// Complete a deduplicated request
    ///
    /// Called by the leader after executing the query to broadcast result.
    pub fn complete(&self, key: &DeduplicationKey, result: DeduplicatedResult) {
        let hash = key.hash();

        if let Some((_, entry)) = self.in_flight.remove(&hash) {
            let waiter_count = entry.sender.receiver_count();

            // Broadcast result to all waiters
            // Ignore send errors (all receivers dropped)
            let _ = entry.sender.send(result);

            self.metrics.incr("bff.federation.dedup.complete", &[]);
            self.metrics.histogram(
                "bff.federation.dedup.waiters_served",
                waiter_count as f64,
                &[],
            );
            self.metrics.gauge(
                "bff.federation.dedup.in_flight",
                self.in_flight.len() as f64,
                &[],
            );

            debug!(
                operation = ?key.operation_name,
                hash = hash,
                waiters = waiter_count,
                "Deduplication: completed, served waiters"
            );
        }
    }

    /// Cancel a deduplicated request (e.g., on error)
    ///
    /// Removes the entry without broadcasting a result.
    /// Waiters will timeout.
    pub fn cancel(&self, key: &DeduplicationKey) {
        let hash = key.hash();

        if self.in_flight.remove(&hash).is_some() {
            self.metrics.incr("bff.federation.dedup.cancel", &[]);
            self.metrics.gauge(
                "bff.federation.dedup.in_flight",
                self.in_flight.len() as f64,
                &[],
            );

            debug!(
                operation = ?key.operation_name,
                hash = hash,
                "Deduplication: cancelled"
            );
        }
    }

    /// Get the maximum wait duration for waiters
    pub fn max_wait_duration(&self) -> Duration {
        Duration::from_secs(self.config.max_wait_secs)
    }

    /// Get current statistics
    pub fn stats(&self) -> DeduplicationStats {
        DeduplicationStats {
            in_flight_count: self.in_flight.len(),
        }
    }

    /// Clean up expired entries
    fn cleanup_expired(&self) {
        let ttl = Duration::from_secs(self.config.entry_ttl_secs);
        let mut expired_count = 0;

        self.in_flight.retain(|_, entry| {
            let keep = entry.created_at.elapsed() < ttl;
            if !keep {
                expired_count += 1;
            }
            keep
        });

        if expired_count > 0 {
            debug!(
                expired_count = expired_count,
                "Deduplication: cleaned up expired entries"
            );

            self.metrics.count("bff.federation.dedup.expired", expired_count as i64, &[]);
        }
    }
}

/// Key for deduplication
#[derive(Debug, Clone)]
pub struct DeduplicationKey {
    /// Operation name (e.g., "getProducts")
    pub operation_name: Option<String>,

    /// Query document
    pub query: String,

    /// Variables (will be sorted for determinism)
    pub variables: Option<serde_json::Value>,

    /// Product scope for multi-tenant isolation
    pub product: String,
}

impl DeduplicationKey {
    /// Create a new deduplication key
    pub fn new(
        operation_name: Option<String>,
        query: String,
        variables: Option<serde_json::Value>,
        product: String,
    ) -> Self {
        Self {
            operation_name,
            query,
            variables,
            product,
        }
    }

    /// Compute hash for this key
    ///
    /// PERFORMANCE: Uses ahash instead of DefaultHasher for 2-3x faster hashing.
    /// ahash leverages AES-NI instructions on modern CPUs for optimal performance.
    /// Uses static RandomState for deterministic hashing within process lifetime.
    #[inline]
    pub fn hash(&self) -> u64 {
        let mut hasher = AHASH_STATE.build_hasher();

        // Hash operation name
        if let Some(ref name) = self.operation_name {
            name.hash(&mut hasher);
        }

        // Hash query (normalized - remove extra whitespace)
        // PERFORMANCE: Avoid String allocation by hashing pieces directly
        for piece in self.query.split_whitespace() {
            piece.hash(&mut hasher);
            // Hash space separator for consistency
            " ".hash(&mut hasher);
        }

        // Hash variables (sorted for determinism)
        if let Some(ref vars) = self.variables {
            let sorted = Self::sort_json_value(vars);
            sorted.to_string().hash(&mut hasher);
        }

        // Hash product scope
        self.product.hash(&mut hasher);

        hasher.finish()
    }

    /// Sort JSON value for deterministic hashing
    fn sort_json_value(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut sorted = Vec::with_capacity(map.len());
                sorted.extend(map.iter());
                sorted.sort_by_key(|(k, _)| *k);
                serde_json::Value::Object(
                    sorted
                        .into_iter()
                        .map(|(k, v)| (k.clone(), Self::sort_json_value(v)))
                        .collect(),
                )
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(Self::sort_json_value).collect())
            }
            _ => value.clone(),
        }
    }
}

/// Deduplication statistics
#[derive(Debug, Clone)]
pub struct DeduplicationStats {
    /// Number of currently in-flight requests
    pub in_flight_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplication_key_hash_deterministic() {
        let key1 = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            Some(serde_json::json!({"limit": 10, "offset": 0})),
            "myapp".to_string(),
        );

        let key2 = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            Some(serde_json::json!({"offset": 0, "limit": 10})), // Different order
            "myapp".to_string(),
        );

        assert_eq!(key1.hash(), key2.hash());
    }

    #[test]
    fn test_deduplication_key_different_products() {
        let key1 = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "myapp".to_string(),
        );

        let key2 = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "test-product".to_string(),
        );

        assert_ne!(key1.hash(), key2.hash());
    }

    #[tokio::test]
    async fn test_leader_waiter_flow() {
        let dedup = RequestDeduplicator::new(DeduplicationConfig::default(), None);

        let key = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "myapp".to_string(),
        );

        // First request should become leader
        let result1 = dedup.deduplicate(&key);
        assert!(matches!(result1, Some(DeduplicationResult::Leader { .. })));

        // Second request should become waiter
        let result2 = dedup.deduplicate(&key);
        assert!(matches!(result2, Some(DeduplicationResult::Waiter { .. })));

        // Complete the request
        if let Some(DeduplicationResult::Leader { sender }) = result1 {
            sender
                .send(DeduplicatedResult {
                    data: serde_json::json!({"data": {"products": []}}),
                    from_cache: false,
                })
                .expect("Leader should be able to send result to waiters");
        }

        // Waiter should receive the result
        if let Some(DeduplicationResult::Waiter { mut receiver }) = result2 {
            let result = receiver
                .recv()
                .await
                .expect("Waiter should receive result from leader (channel not closed)");
            assert!(!result.from_cache);
        }
    }

    #[test]
    fn test_disabled_deduplication() {
        let config = DeduplicationConfig {
            enabled: false,
            ..Default::default()
        };

        let dedup = RequestDeduplicator::new(config, None);

        let key = DeduplicationKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "myapp".to_string(),
        );

        // Should return None when disabled
        assert!(dedup.deduplicate(&key).is_none());
    }
}
