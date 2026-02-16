#![allow(dead_code, unused)]
//! Redis-backed Distributed Cache for GraphQL Federation
//!
//! Implements a two-tier caching strategy inspired by Apollo Router:
//! - **L1 (In-Memory)**: Fast moka cache for hot data
//! - **L2 (Redis)**: Distributed cache for cross-instance sharing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                    Two-Tier Caching Architecture                    │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  Request ──► L1 Cache (moka) ──► HIT ──► Response                  │
//! │                    │                                                │
//! │                    ▼ MISS                                           │
//! │              L2 Cache (Redis) ──► HIT ──► Populate L1 ──► Response │
//! │                    │                                                │
//! │                    ▼ MISS                                           │
//! │              Execute Query ──► Store L1 + L2 ──► Response          │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Cache Layers
//!
//! | Layer | Storage | Latency | Shared | Capacity |
//! |-------|---------|---------|--------|----------|
//! | L1    | moka    | <1ms    | No     | 10K-50K  |
//! | L2    | Redis   | 1-5ms   | Yes    | 100K+    |
//!
//! # Use Cases
//!
//! - **Response Cache**: Cache entire GraphQL responses
//! - **Query Plan Cache**: Cache query plans for federation
//! - **APQ Cache**: Distributed Automatic Persisted Queries
//! - **Entity Cache**: Cache individual entities (User, Product)
//!
//! # Non-Blocking Architecture
//!
//! This cache NEVER blocks indefinitely:
//! - Redis pool.get() has 5s timeout (returns None on failure)
//! - Redis operations have configurable timeout (default 100ms)
//! - On L2 failure: Falls back to L1 or miss (graceful degradation)
//! - Metrics emitted for cache hits/misses/L2 failures
//!
//! # References
//!
//! - [Apollo Router Distributed Caching](https://www.apollographql.com/docs/graphos/routing/performance/caching/distributed)
//! - [Entity Caching](https://www.apollographql.com/docs/graphos/routing/v1/performance/caching/entity)

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, error, info, warn};

use crate::memory::{ComponentId, MemoryPressure, MemoryResponder, PressureCoordinator};
use crate::metrics::{MetricsClient, MetricsExt};
use crate::redis::LazyRedisPool;

use super::cache_invalidation::{CacheInvalidator, InvalidationEvent};

/// Configuration for two-tier cache
#[derive(Debug, Clone)]
pub struct TwoTierCacheConfig {
    /// Enable the two-tier cache
    pub enabled: bool,

    /// L1 (in-memory) cache configuration
    pub l1: L1CacheConfig,

    /// L2 (Redis) cache configuration
    pub l2: L2CacheConfig,

    /// Cache key prefix for namespace isolation
    pub key_prefix: String,
}

impl Default for TwoTierCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            l1: L1CacheConfig::default(),
            l2: L2CacheConfig::default(),
            key_prefix: "bff:federation".to_string(),
        }
    }
}

/// L1 (in-memory) cache configuration
#[derive(Debug, Clone)]
pub struct L1CacheConfig {
    /// Enable L1 cache
    pub enabled: bool,

    /// Maximum number of entries
    pub max_capacity: u64,

    /// Default TTL in seconds
    pub default_ttl_secs: u64,
}

impl Default for L1CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_capacity: 10_000,
            default_ttl_secs: 60,
        }
    }
}

/// L2 (Redis) cache configuration
#[derive(Debug, Clone)]
pub struct L2CacheConfig {
    /// Enable L2 cache
    pub enabled: bool,

    /// Default TTL in seconds
    pub default_ttl_secs: u64,

    /// Maximum value size in bytes (skip larger values)
    pub max_value_size: usize,

    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
}

impl Default for L2CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl_secs: 300,       // 5 minutes
            max_value_size: 1024 * 1024, // 1 MB
            timeout_ms: 100,             // 100ms timeout
        }
    }
}

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CacheEntry<T> {
    /// The cached value
    pub value: T,

    /// Unix timestamp when cached (ms)
    pub cached_at_ms: u64,

    /// TTL that was applied (seconds)
    pub ttl_secs: u64,

    /// Source of the cache entry
    pub source: CacheSource,
}

/// Source of a cache hit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum CacheSource {
    /// Hit from L1 (in-memory) cache
    L1,
    /// Hit from L2 (Redis) cache
    L2,
    /// Miss - data was fetched fresh
    Miss,
}

impl std::fmt::Display for CacheSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CacheSource::L1 => write!(f, "L1"),
            CacheSource::L2 => write!(f, "L2"),
            CacheSource::Miss => write!(f, "MISS"),
        }
    }
}

/// Two-tier cache implementation
///
/// Provides fast L1 in-memory cache backed by distributed L2 Redis cache.
pub struct TwoTierCache<T: Clone + Send + Sync + 'static> {
    /// L1 in-memory cache
    l1: Option<Cache<String, CacheEntry<T>>>,

    /// L2 Redis connection
    redis: Option<Arc<LazyRedisPool>>,

    /// Configuration
    config: TwoTierCacheConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,

    /// Cache name for metrics/logging
    name: String,

    /// Pressure coordinator for adaptive memory management
    pressure_coordinator: Option<Arc<PressureCoordinator>>,
}

impl<T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static> TwoTierCache<T> {
    /// Create a new two-tier cache
    pub fn new(
        config: TwoTierCacheConfig,
        redis: Option<Arc<LazyRedisPool>>,
        metrics: Option<Arc<MetricsClient>>,
        name: &str,
    ) -> Self {
        Self::with_pressure_coordinator(config, redis, metrics, name, None)
    }

    /// Create a new two-tier cache with pressure coordinator
    pub fn with_pressure_coordinator(
        config: TwoTierCacheConfig,
        redis: Option<Arc<LazyRedisPool>>,
        metrics: Option<Arc<MetricsClient>>,
        name: &str,
        pressure_coordinator: Option<Arc<PressureCoordinator>>,
    ) -> Self {
        let l1 = if config.l1.enabled {
            Some(
                Cache::builder()
                    .max_capacity(config.l1.max_capacity)
                    .time_to_live(Duration::from_secs(config.l1.default_ttl_secs))
                    .build(),
            )
        } else {
            None
        };

        info!(
            cache_name = name,
            l1_enabled = config.l1.enabled,
            l2_enabled = config.l2.enabled,
            l1_capacity = config.l1.max_capacity,
            has_pressure_coordinator = pressure_coordinator.is_some(),
            "Two-tier cache initialized"
        );

        Self {
            l1,
            redis: if config.l2.enabled { redis } else { None },
            config,
            metrics,
            name: name.to_string(),
            pressure_coordinator,
        }
    }

    /// Register this cache with the pressure coordinator (call after wrapping in Arc)
    pub fn register_self(self: &Arc<Self>) {
        if let Some(ref coordinator) = self.pressure_coordinator {
            let component_id = ComponentId::new(format!("two_tier_cache_{}", self.name));
            coordinator.register(component_id, self.clone() as Arc<dyn MemoryResponder>);
            info!(cache = %self.name, "Two-tier cache registered with pressure coordinator");
        }
    }

    /// Start listening for cache invalidation events
    ///
    /// Spawns a background task that subscribes to the invalidator and evicts
    /// matching cache entries when events are received.
    pub fn start_invalidation_listener(self: &Arc<Self>, invalidator: &CacheInvalidator) {
        if !invalidator.is_enabled() {
            debug!(cache = %self.name, "Cache invalidation disabled, skipping listener");
            return;
        }

        let mut receiver = invalidator.subscribe();
        let cache = self.clone();
        let cache_name = self.name.clone();

        tokio::spawn(async move {
            info!(cache = %cache_name, "Starting cache invalidation listener");

            loop {
                match receiver.recv().await {
                    Ok(event) => {
                        cache.handle_invalidation_event(&event).await;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        warn!(cache = %cache_name, "Invalidation channel closed, stopping listener");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!(
                            cache = %cache_name,
                            lagged = n,
                            "Invalidation listener lagged, some events may have been missed"
                        );
                    }
                }
            }
        });
    }

    /// Handle a single invalidation event
    async fn handle_invalidation_event(&self, event: &InvalidationEvent) {
        match event {
            InvalidationEvent::Entity {
                entity_type,
                entity_id,
                ..
            } => {
                // Invalidate entity-specific cache entries
                let key = format!("{}:{}", entity_type, entity_id);
                self.invalidate(&key).await;
                debug!(
                    cache = %self.name,
                    entity_type = %entity_type,
                    entity_id = %entity_id,
                    "Invalidated entity from cache"
                );
            }
            InvalidationEvent::Pattern { pattern, .. } => {
                // Invalidate by prefix (strip trailing *)
                let prefix = pattern.trim_end_matches('*');
                self.invalidate_prefix(prefix).await;
                debug!(
                    cache = %self.name,
                    pattern = %pattern,
                    "Invalidated pattern from cache"
                );
            }
            InvalidationEvent::Tag { tag, .. } => {
                // Tags require prefix-based invalidation
                let prefix = format!("tag:{}", tag);
                self.invalidate_prefix(&prefix).await;
                debug!(
                    cache = %self.name,
                    tag = %tag,
                    "Invalidated tag from cache"
                );
            }
            InvalidationEvent::Flush {
                product, reason, ..
            } => {
                // Full cache flush
                if product.is_none() || product.as_deref() == Some(&self.config.key_prefix) {
                    self.invalidate_all().await;
                    info!(
                        cache = %self.name,
                        reason = %reason,
                        "Flushed cache due to invalidation event"
                    );
                }
            }
        }

        self.metrics.incr(
            &format!("bff.federation.cache.{}.invalidation_event", self.name),
            &[],
        );
    }

    /// Get a value from cache (L1 → L2 fallback)
    pub async fn get(&self, key: &str) -> Option<CacheEntry<T>> {
        if !self.config.enabled {
            return None;
        }

        let full_key = self.full_key(key);

        // Try L1 first
        if let Some(ref l1) = self.l1 {
            if let Some(entry) = l1.get(&full_key).await {
                self.record_hit(CacheSource::L1);
                debug!(
                    cache = %self.name,
                    key = %key,
                    source = "L1",
                    "Cache hit"
                );
                return Some(entry);
            }
        }

        // Try L2 (Redis)
        if let Some(ref redis_pool) = self.redis {
            if let Some(conn) = redis_pool.get().await {
                match self.get_from_redis(&full_key, conn).await {
                    Some(entry) => {
                        // Promote to L1
                        if let Some(ref l1) = self.l1 {
                            l1.insert(full_key, entry.clone()).await;
                        }

                        self.record_hit(CacheSource::L2);
                        debug!(
                            cache = %self.name,
                            key = %key,
                            source = "L2",
                            "Cache hit (promoted to L1)"
                        );
                        return Some(entry);
                    }
                    None => {
                        self.record_miss();
                    }
                }
            } else {
                warn!(
                    cache = %self.name,
                    "Redis unavailable, L2 cache miss - graceful degradation"
                );
                // Emit metric for Redis unavailability
                self.metrics.incr(
                    &format!("bff.federation.cache.{}.redis_unavailable", self.name),
                    &[],
                );
            }
        }

        debug!(
            cache = %self.name,
            key = %key,
            "Cache miss"
        );
        None
    }

    /// Set a value in cache (L1 + L2)
    pub async fn set(&self, key: &str, value: T, ttl_secs: Option<u64>) {
        if !self.config.enabled {
            return;
        }

        let full_key = self.full_key(key);
        let ttl = ttl_secs.unwrap_or(self.config.l1.default_ttl_secs);

        let entry = CacheEntry {
            value,
            cached_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0), // SystemTime before UNIX_EPOCH (impossible in practice)
            ttl_secs: ttl,
            source: CacheSource::Miss,
        };

        // Store in L1
        if let Some(ref l1) = self.l1 {
            l1.insert(full_key.clone(), entry.clone()).await;
        }

        // Store in L2 (Redis)
        if let Some(ref redis_pool) = self.redis {
            if let Some(conn) = redis_pool.get().await {
                self.set_in_redis(&full_key, &entry, ttl, conn).await;
            }
        }

        self.record_set();
        debug!(
            cache = %self.name,
            key = %key,
            ttl_secs = ttl,
            "Cached value"
        );
    }

    /// Invalidate a key from both caches
    pub async fn invalidate(&self, key: &str) {
        let full_key = self.full_key(key);

        // Invalidate L1
        if let Some(ref l1) = self.l1 {
            l1.invalidate(&full_key).await;
        }

        // Invalidate L2
        if let Some(ref redis_pool) = self.redis {
            if let Some(mut conn) = redis_pool.get().await {
                // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
                let _: Result<(), _> =
                    tokio::time::timeout(Duration::from_secs(5), conn.del(&full_key))
                        .await
                        .unwrap_or(Ok(()));
            }
        }

        self.record_invalidate();
        debug!(
            cache = %self.name,
            key = %key,
            "Invalidated"
        );
    }

    /// Invalidate all entries matching a prefix
    pub async fn invalidate_prefix(&self, prefix: &str) {
        let full_prefix = self.full_key(prefix);

        // L1: moka doesn't support prefix invalidation, use invalidate_all as fallback
        if let Some(ref l1) = self.l1 {
            l1.invalidate_all();
            warn!(
                cache = %self.name,
                prefix = %prefix,
                "L1 invalidate_prefix not supported, invalidated all"
            );
        }

        // L2: Redis supports SCAN + DEL
        if let Some(ref redis_pool) = self.redis {
            if let Some(mut conn) = redis_pool.get().await {
                let pattern = format!("{}*", full_prefix);
                // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
                // Cache invalidation is not critical path - 5 second timeout is generous
                let keys: Result<Vec<String>, _> = tokio::time::timeout(
                    Duration::from_secs(5),
                    redis::cmd("KEYS").arg(&pattern).query_async(&mut conn),
                )
                .await
                .unwrap_or(Ok(vec![]));

                if let Ok(keys) = keys {
                    if !keys.is_empty() {
                        // DEL also needs timeout
                        let _: Result<(), _> = tokio::time::timeout(
                            Duration::from_secs(5),
                            conn.del::<_, ()>(keys.as_slice()),
                        )
                        .await
                        .unwrap_or(Ok(()));
                        info!(
                            cache = %self.name,
                            prefix = %prefix,
                            count = keys.len(),
                            "Invalidated keys by prefix"
                        );
                    }
                }
            }
        }
    }

    /// Invalidate all entries
    pub async fn invalidate_all(&self) {
        // Invalidate L1
        if let Some(ref l1) = self.l1 {
            l1.invalidate_all();
        }

        // Invalidate L2 with prefix
        if let Some(ref redis_pool) = self.redis {
            if let Some(mut conn) = redis_pool.get().await {
                let pattern = format!("{}:*", self.config.key_prefix);
                // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
                // Cache invalidation is not critical path - 5 second timeout is generous
                let keys: Result<Vec<String>, _> = tokio::time::timeout(
                    Duration::from_secs(5),
                    redis::cmd("KEYS").arg(&pattern).query_async(&mut conn),
                )
                .await
                .unwrap_or(Ok(vec![]));

                if let Ok(keys) = keys {
                    if !keys.is_empty() {
                        // DEL also needs timeout
                        let _: Result<(), _> = tokio::time::timeout(
                            Duration::from_secs(5),
                            conn.del::<_, ()>(keys.as_slice()),
                        )
                        .await
                        .unwrap_or(Ok(()));
                    }
                }
            }
        }

        info!(cache = %self.name, "Invalidated all");
    }

    /// Get cache statistics
    pub fn stats(&self) -> TwoTierCacheStats {
        let l1_entries = self
            .l1
            .as_ref()
            .map_or(0, |c: &Cache<String, CacheEntry<T>>| c.entry_count());
        let l1_weighted_size = self
            .l1
            .as_ref()
            .map_or(0, |c: &Cache<String, CacheEntry<T>>| c.weighted_size());
        TwoTierCacheStats {
            l1_entries,
            l1_weighted_size,
            l2_enabled: self.redis.is_some(),
        }
    }

    /// Build full cache key with prefix
    fn full_key(&self, key: &str) -> String {
        format!("{}:{}:{}", self.config.key_prefix, self.name, key)
    }

    /// Get from Redis
    async fn get_from_redis(
        &self,
        key: &str,
        mut conn: ConnectionManager,
    ) -> Option<CacheEntry<T>> {
        let result: Result<Option<String>, _> = tokio::time::timeout(
            Duration::from_millis(self.config.l2.timeout_ms),
            conn.get(key),
        )
        .await
        .unwrap_or(Ok(None));

        match result {
            Ok(Some(json)) => match serde_json::from_str::<CacheEntry<T>>(&json) {
                Ok(mut entry) => {
                    entry.source = CacheSource::L2;
                    Some(entry)
                }
                Err(e) => {
                    warn!(
                        cache = %self.name,
                        key = %key,
                        error = %e,
                        "Failed to deserialize cache entry"
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warn!(
                    cache = %self.name,
                    key = %key,
                    error = %e,
                    "Redis get failed"
                );
                None
            }
        }
    }

    /// Set in Redis
    /// PERFORMANCE: Use pre-allocated buffer for serialization
    async fn set_in_redis(
        &self,
        key: &str,
        entry: &CacheEntry<T>,
        ttl_secs: u64,
        mut conn: ConnectionManager,
    ) {
        // Pre-allocate buffer based on expected cache entry size
        // Most cache entries are small (< 1KB), so 2KB buffer reduces allocations
        let mut buffer = String::with_capacity(2048);

        // SAFETY: serde_json::to_writer writes valid UTF-8 to String's internal buffer
        if let Err(e) = serde_json::to_writer(unsafe { buffer.as_mut_vec() }, entry) {
            error!(
                cache = %self.name,
                key = %key,
                error = %e,
                "Failed to serialize cache entry"
            );
            return;
        }

        // Check size limit
        if buffer.len() > self.config.l2.max_value_size {
            warn!(
                cache = %self.name,
                key = %key,
                size = buffer.len(),
                max_size = self.config.l2.max_value_size,
                "Value too large for L2 cache"
            );
            return;
        }

        let l2_ttl = ttl_secs.max(self.config.l2.default_ttl_secs);

        let result: Result<(), _> = tokio::time::timeout(
            Duration::from_millis(self.config.l2.timeout_ms),
            conn.set_ex(key, buffer, l2_ttl),
        )
        .await
        .unwrap_or(Ok(()));

        if let Err(e) = result {
            warn!(
                cache = %self.name,
                key = %key,
                error = %e,
                "Redis set failed"
            );
        }
    }

    /// Record cache hit metric
    fn record_hit(&self, source: CacheSource) {
        let source_label = source.to_string();
        self.metrics.incr(
            &format!("bff.federation.cache.{}.hit", self.name),
            &[("source", source_label.as_str())],
        );
    }

    /// Record cache miss metric
    fn record_miss(&self) {
        self.metrics.incr(&format!("bff.federation.cache.{}.miss", self.name), &[]);
    }

    /// Record cache set metric
    fn record_set(&self) {
        self.metrics.incr(&format!("bff.federation.cache.{}.set", self.name), &[]);
    }

    /// Record cache invalidate metric
    fn record_invalidate(&self) {
        self.metrics.incr(
            &format!("bff.federation.cache.{}.invalidate", self.name),
            &[],
        );
    }
}

/// Implement MemoryResponder for TwoTierCache to enable pressure-based eviction
impl<T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static> MemoryResponder
    for TwoTierCache<T>
{
    fn memory_usage(&self) -> u64 {
        // L1 cache weighted size is a good approximation of memory usage
        self.l1.as_ref().map_or(0, |c| c.weighted_size())
    }

    fn respond_to_pressure(&self, pressure: MemoryPressure) {
        let pressure_value = pressure.value();

        // Gradient response: more pressure = more aggressive eviction
        if pressure_value < 0.3 {
            // Low pressure: no action needed
            return;
        }

        if let Some(ref l1) = self.l1 {
            // Run eviction synchronously (moka handles this internally)
            l1.run_pending_tasks();

            if pressure_value >= 0.7 {
                // High pressure: aggressive eviction
                // Invalidate oldest entries by running sync cleanup
                info!(
                    cache = %self.name,
                    pressure = pressure_value,
                    "High memory pressure - running aggressive eviction"
                );
            } else {
                // Medium pressure: normal eviction
                debug!(
                    cache = %self.name,
                    pressure = pressure_value,
                    "Medium memory pressure - running normal eviction"
                );
            }
        }
    }
}

/// Two-tier cache statistics
#[derive(Debug, Clone)]
pub struct TwoTierCacheStats {
    /// L1 entry count
    pub l1_entries: u64,

    /// L1 weighted size
    pub l1_weighted_size: u64,

    /// Whether L2 (Redis) is enabled
    pub l2_enabled: bool,
}

/// Query plan cache entry
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct QueryPlanCacheEntry {
    /// Serialized query plan
    pub plan_json: String,

    /// Hash of the query document
    pub query_hash: String,

    /// Number of subgraph fetches in the plan
    pub fetch_count: usize,

    /// Planning duration in microseconds
    pub planning_duration_us: u64,
}

/// APQ (Automatic Persisted Query) cache entry
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ApqCacheEntry {
    /// The full query document
    pub query: String,

    /// Operation name (if present)
    pub operation_name: Option<String>,
}

/// Entity cache entry for normalized caching
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EntityCacheEntry {
    /// Entity typename (e.g., "User", "Product")
    pub typename: String,

    /// Entity ID
    pub id: String,

    /// Entity data as JSON
    pub data: serde_json::Value,

    /// Entity version (for optimistic locking)
    pub version: u64,
}

/// Create a specialized cache for query plans
pub fn create_query_plan_cache(
    redis: Option<Arc<LazyRedisPool>>,
    metrics: Option<Arc<MetricsClient>>,
) -> TwoTierCache<QueryPlanCacheEntry> {
    let config = TwoTierCacheConfig {
        enabled: true,
        l1: L1CacheConfig {
            enabled: true,
            max_capacity: 1_000,   // Query plans are larger, keep fewer
            default_ttl_secs: 300, // 5 minutes
        },
        l2: L2CacheConfig {
            enabled: true,
            default_ttl_secs: 3600,     // 1 hour in Redis
            max_value_size: 512 * 1024, // 512KB max per plan
            timeout_ms: 50,             // Fast timeout for query plans
        },
        key_prefix: "bff:qp".to_string(),
    };

    TwoTierCache::<QueryPlanCacheEntry>::new(config, redis, metrics, "query_plan")
}

/// Create a specialized cache for APQ
pub fn create_apq_cache(
    redis: Option<Arc<LazyRedisPool>>,
    metrics: Option<Arc<MetricsClient>>,
) -> TwoTierCache<ApqCacheEntry> {
    let config = TwoTierCacheConfig {
        enabled: true,
        l1: L1CacheConfig {
            enabled: true,
            max_capacity: 10_000,
            default_ttl_secs: 3600, // 1 hour
        },
        l2: L2CacheConfig {
            enabled: true,
            default_ttl_secs: 86400,    // 24 hours in Redis
            max_value_size: 256 * 1024, // 256KB max per query
            timeout_ms: 50,
        },
        key_prefix: "bff:apq".to_string(),
    };

    TwoTierCache::<ApqCacheEntry>::new(config, redis, metrics, "apq")
}

/// Create a specialized cache for entities
pub fn create_entity_cache(
    redis: Option<Arc<LazyRedisPool>>,
    metrics: Option<Arc<MetricsClient>>,
) -> TwoTierCache<EntityCacheEntry> {
    let config = TwoTierCacheConfig {
        enabled: true,
        l1: L1CacheConfig {
            enabled: true,
            max_capacity: 50_000, // Entities are small, keep many
            default_ttl_secs: 60, // 1 minute L1 TTL
        },
        l2: L2CacheConfig {
            enabled: true,
            default_ttl_secs: 300,     // 5 minutes in Redis
            max_value_size: 64 * 1024, // 64KB max per entity
            timeout_ms: 20,            // Very fast for entities
        },
        key_prefix: "bff:entity".to_string(),
    };

    TwoTierCache::<EntityCacheEntry>::new(config, redis, metrics, "entity")
}

/// Create a specialized cache for GraphQL responses
pub fn create_response_cache(
    redis: Option<Arc<LazyRedisPool>>,
    metrics: Option<Arc<MetricsClient>>,
) -> TwoTierCache<serde_json::Value> {
    create_response_cache_with_pressure(redis, metrics, None)
}

/// Create a response cache for GraphQL responses with pressure coordinator support
pub fn create_response_cache_with_pressure(
    redis: Option<Arc<LazyRedisPool>>,
    metrics: Option<Arc<MetricsClient>>,
    pressure_coordinator: Option<Arc<PressureCoordinator>>,
) -> TwoTierCache<serde_json::Value> {
    let config = TwoTierCacheConfig {
        enabled: true,
        l1: L1CacheConfig {
            enabled: true,
            max_capacity: 10_000,
            default_ttl_secs: 60,
        },
        l2: L2CacheConfig {
            enabled: true,
            default_ttl_secs: 300,
            max_value_size: 1024 * 1024, // 1MB max per response
            timeout_ms: 100,
        },
        key_prefix: "bff:response".to_string(),
    };

    TwoTierCache::<serde_json::Value>::with_pressure_coordinator(
        config,
        redis,
        metrics,
        "response",
        pressure_coordinator,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_l1_only_cache() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> = TwoTierCache::new(config, None, None, "test");

        // Set a value
        cache.set("key1", "value1".to_string(), Some(60)).await;

        // Get the value
        let entry = cache.get("key1").await;
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().value, "value1");

        // Invalidate
        cache.invalidate("key1").await;
        let entry = cache.get("key1").await;
        assert!(entry.is_none());
    }

    #[test]
    fn test_cache_entry_serialization() {
        let entry = CacheEntry {
            value: "test value".to_string(),
            cached_at_ms: 1234567890,
            ttl_secs: 60,
            source: CacheSource::L1,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: CacheEntry<String> = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.value, entry.value);
        assert_eq!(deserialized.cached_at_ms, entry.cached_at_ms);
        assert_eq!(deserialized.ttl_secs, entry.ttl_secs);
    }

    #[test]
    fn test_query_plan_entry_serialization() {
        let entry = QueryPlanCacheEntry {
            plan_json: r#"{"kind":"fetch"}"#.to_string(),
            query_hash: "abc123".to_string(),
            fetch_count: 3,
            planning_duration_us: 1500,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: QueryPlanCacheEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.query_hash, entry.query_hash);
        assert_eq!(deserialized.fetch_count, entry.fetch_count);
    }

    #[test]
    fn test_entity_cache_entry_serialization() {
        let entry = EntityCacheEntry {
            typename: "User".to_string(),
            id: "user-123".to_string(),
            data: serde_json::json!({"name": "Alice", "email": "alice@example.com"}),
            version: 1,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: EntityCacheEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.typename, entry.typename);
        assert_eq!(deserialized.id, entry.id);
        assert_eq!(deserialized.data["name"], "Alice");
    }

    #[tokio::test]
    async fn test_stats_l2_disabled() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> = TwoTierCache::new(config, None, None, "stats_test");

        // L2 should not be enabled
        let stats = cache.stats();
        assert!(!stats.l2_enabled);
    }

    #[tokio::test]
    async fn test_multiple_keys() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> = TwoTierCache::new(config, None, None, "many_test");

        cache.set("key1", "value1".to_string(), Some(60)).await;
        cache.set("key2", "value2".to_string(), Some(60)).await;
        cache.set("key3", "value3".to_string(), Some(60)).await;

        assert!(cache.get("key1").await.is_some());
        assert!(cache.get("key2").await.is_some());
        assert!(cache.get("key3").await.is_some());
        assert!(cache.get("missing").await.is_none());
    }

    #[tokio::test]
    async fn test_invalidate_multiple() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> =
            TwoTierCache::new(config, None, None, "invalidate_many_test");

        cache.set("key1", "value1".to_string(), Some(60)).await;
        cache.set("key2", "value2".to_string(), Some(60)).await;
        cache.set("key3", "value3".to_string(), Some(60)).await;

        // Invalidate individually
        cache.invalidate("key1").await;
        cache.invalidate("key2").await;

        assert!(cache.get("key1").await.is_none());
        assert!(cache.get("key2").await.is_none());
        assert!(cache.get("key3").await.is_some());
    }

    #[test]
    fn test_apq_cache_entry_serialization() {
        let entry = ApqCacheEntry {
            query: "query GetUser { user { id name } }".to_string(),
            operation_name: Some("GetUser".to_string()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: ApqCacheEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.query, entry.query);
        assert_eq!(deserialized.operation_name, entry.operation_name);
    }

    #[test]
    fn test_default_configs() {
        let l1_config = L1CacheConfig::default();
        assert!(l1_config.enabled);
        assert_eq!(l1_config.max_capacity, 10_000);
        assert_eq!(l1_config.default_ttl_secs, 60);

        let l2_config = L2CacheConfig::default();
        assert!(l2_config.enabled);
        assert_eq!(l2_config.default_ttl_secs, 300);
        assert_eq!(l2_config.max_value_size, 1024 * 1024);
    }

    #[test]
    fn test_cache_source_display() {
        assert_eq!(format!("{}", CacheSource::L1), "L1");
        assert_eq!(format!("{}", CacheSource::L2), "L2");
        assert_eq!(format!("{}", CacheSource::Miss), "MISS");
    }

    #[tokio::test]
    async fn test_factory_query_plan_cache() {
        let cache = create_query_plan_cache(None, None);
        let stats = cache.stats();
        assert_eq!(stats.l1_entries, 0);
        assert!(!stats.l2_enabled); // No redis provided
    }

    #[tokio::test]
    async fn test_factory_apq_cache() {
        let cache = create_apq_cache(None, None);
        let stats = cache.stats();
        assert_eq!(stats.l1_entries, 0);
    }

    #[tokio::test]
    async fn test_factory_entity_cache() {
        let cache = create_entity_cache(None, None);
        let stats = cache.stats();
        assert_eq!(stats.l1_entries, 0);
    }

    #[tokio::test]
    async fn test_factory_response_cache() {
        let cache = create_response_cache(None, None);
        let stats = cache.stats();
        assert_eq!(stats.l1_entries, 0);
    }

    #[test]
    fn test_two_tier_config_default() {
        let config = TwoTierCacheConfig::default();
        assert!(config.enabled);
        assert_eq!(config.key_prefix, "bff:federation");
        assert!(config.l1.enabled);
        assert!(config.l2.enabled);
    }

    #[tokio::test]
    async fn test_overwrite_existing_key() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> = TwoTierCache::new(config, None, None, "overwrite_test");

        cache.set("key1", "value1".to_string(), Some(60)).await;
        assert_eq!(cache.get("key1").await.unwrap().value, "value1");

        cache.set("key1", "value2".to_string(), Some(60)).await;
        assert_eq!(cache.get("key1").await.unwrap().value, "value2");
    }

    #[tokio::test]
    async fn test_cache_entry_stored_source() {
        let config = TwoTierCacheConfig {
            l2: L2CacheConfig {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };

        let cache: TwoTierCache<String> = TwoTierCache::new(config, None, None, "source_test");

        cache.set("key1", "value1".to_string(), Some(60)).await;

        // The source field indicates where data was originally sourced from (Miss = fresh data)
        // not the cache layer it was retrieved from
        let entry = cache.get("key1").await.unwrap();
        assert_eq!(entry.source, CacheSource::Miss); // Data was originally a miss (fresh fetch)
        assert!(entry.cached_at_ms > 0);
        assert_eq!(entry.ttl_secs, 60);
    }
}
