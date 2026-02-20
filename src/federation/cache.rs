#![allow(dead_code, unused)]
//! Response Cache for GraphQL Federation
//!
//! Provides in-memory caching for GraphQL query responses using moka.
//! Reduces subgraph load by caching frequently accessed data.
//!
//! # Architecture
//!
//! ```text
//! GraphQL Request
//!       │
//!       ▼
//! ┌─────────────────┐
//! │  Cache Lookup   │ ──► Cache HIT ──► Return cached response
//! └─────────────────┘
//!       │ Cache MISS
//!       ▼
//! ┌─────────────────┐
//! │ Execute Query   │
//! └─────────────────┘
//!       │
//!       ▼
//! ┌─────────────────┐
//! │  Cache Store    │ (if cacheable)
//! └─────────────────┘
//!       │
//!       ▼
//!    Response
//! ```
//!
//! # Cache Key
//!
//! The cache key is a hash of:
//! - Operation name
//! - Query document (normalized)
//! - Variables (sorted for determinism)
//! - Product scope (for multi-tenant isolation)
//!
//! User-specific data should NOT be cached (or use user-scoped keys).
//!
//! # TTL Strategies
//!
//! TTL can be configured per operation pattern:
//! - `products.*` → 60s (catalog data)
//! - `categories.*` → 300s (rarely changes)
//! - `user.*` → 0s (never cache, user-specific)

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use once_cell::sync::Lazy;

/// PERFORMANCE: Static RandomState for deterministic hashing within process lifetime.
/// Initialized once, reused for all hash operations. ahash is 2-3x faster than DefaultHasher.
static AHASH_STATE: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::memory::{ComponentId, MemoryPressure, MemoryResponder, PressureCoordinator};
use crate::metrics::{MetricsClient, MetricsExt};

/// Configuration for the response cache
#[derive(Debug, Clone)]
pub struct ResponseCacheConfig {
    /// Enable response caching
    pub enabled: bool,

    /// Maximum number of entries in cache
    pub max_capacity: u64,

    /// Default TTL for cached responses (seconds)
    pub default_ttl_secs: u64,

    /// Maximum size per cached entry (bytes)
    pub max_entry_size: usize,

    /// Only cache successful responses (no errors)
    pub cache_only_success: bool,

    /// Operation patterns to cache with custom TTLs
    pub strategies: Vec<CacheStrategy>,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_capacity: 10_000,
            default_ttl_secs: 60,
            max_entry_size: 1024 * 1024, // 1 MB
            cache_only_success: true,
            strategies: vec![],
        }
    }
}

/// Cache strategy for specific operation patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStrategy {
    /// Operation name pattern (e.g., "getProducts", "getCategories")
    /// Supports prefix matching with `*` (e.g., "get*")
    pub operation_pattern: String,

    /// TTL in seconds for this pattern (0 = don't cache)
    pub ttl_secs: u64,

    /// Whether to cache this pattern (false = skip caching)
    pub enabled: bool,
}

/// A cached GraphQL response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResponse {
    /// The GraphQL response data
    pub data: serde_json::Value,

    /// Original operation name
    pub operation_name: Option<String>,

    /// Timestamp when cached (Unix epoch ms)
    pub cached_at: u64,

    /// TTL that was applied
    pub ttl_secs: u64,
}

/// Response cache backed by moka
pub struct ResponseCache {
    /// In-memory cache
    cache: Cache<u64, CachedResponse>,

    /// Configuration
    config: ResponseCacheConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,

    /// Pressure coordinator for adaptive memory management
    pressure_coordinator: Option<Arc<PressureCoordinator>>,
}

impl ResponseCache {
    /// Create a new response cache
    pub fn new(
        config: ResponseCacheConfig,
        metrics: Option<Arc<MetricsClient>>,
        pressure_coordinator: Option<Arc<PressureCoordinator>>,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(Duration::from_secs(config.default_ttl_secs))
            .build();

        info!(
            max_capacity = config.max_capacity,
            default_ttl_secs = config.default_ttl_secs,
            "Response cache initialized"
        );

        let instance = Self {
            cache,
            config,
            metrics,
            pressure_coordinator: pressure_coordinator.clone(),
        };

        // Registration with pressure coordinator happens via register_self()
        // after wrapping in Arc (since we need Arc<Self> to implement MemoryResponder)
        if pressure_coordinator.is_some() {
            info!("Response cache ready for pressure coordinator registration");
        }

        instance
    }

    /// Register this cache with its pressure coordinator (call after wrapping in Arc)
    pub fn register_self(self: &Arc<Self>) {
        if let Some(ref coordinator) = self.pressure_coordinator {
            coordinator.register(
                ComponentId::new("response_cache"),
                self.clone() as Arc<dyn MemoryResponder>,
            );
            info!("Response cache registered with pressure coordinator");
        }
    }

    /// Create from BFF configuration
    pub fn from_bff_config(
        bff_config: &crate::config::BffCacheConfig,
        metrics: Option<Arc<MetricsClient>>,
        pressure_coordinator: Option<Arc<PressureCoordinator>>,
    ) -> Self {
        let strategies: Vec<CacheStrategy> = {
            let mut strategies = Vec::with_capacity(bff_config.strategies.len());
            for s in &bff_config.strategies {
                strategies.push(CacheStrategy {
                    operation_pattern: s.query_pattern.clone(),
                    ttl_secs: s.ttl_secs,
                    enabled: true,
                });
            }
            strategies
        };

        let config = ResponseCacheConfig {
            enabled: bff_config.enabled,
            max_capacity: 10_000, // Default, could be added to BffCacheConfig
            default_ttl_secs: bff_config.default_ttl_secs,
            max_entry_size: bff_config.max_value_size,
            cache_only_success: bff_config.cache_only_success,
            strategies,
        };

        Self::new(config, metrics, pressure_coordinator)
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get a cached response
    pub async fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        if !self.config.enabled {
            return None;
        }

        let hash = key.hash();
        let result: Option<CachedResponse> = self.cache.get(&hash).await;

        if let Some(ref m) = self.metrics {
            if result.is_some() {
                m.increment("bff.federation.cache.hit", &[]);
            } else {
                m.increment("bff.federation.cache.miss", &[]);
            }
        }

        if result.is_some() {
            debug!(
                operation = ?key.operation_name,
                "Cache HIT"
            );
        }

        result
    }

    /// Store a response in cache
    pub async fn set(&self, key: &CacheKey, response: serde_json::Value) {
        if !self.config.enabled {
            return;
        }

        // Check if this operation should be cached
        let ttl = self.get_ttl_for_operation(key.operation_name.as_deref());
        if ttl == 0 {
            debug!(
                operation = ?key.operation_name,
                "Skipping cache (TTL = 0)"
            );
            return;
        }

        // Check if response contains errors (if cache_only_success)
        if self.config.cache_only_success {
            if let Some(errors) = response.get("errors") {
                if let Some(errors_array) = errors.as_array() {
                    if !errors_array.is_empty() {
                        debug!(
                            operation = ?key.operation_name,
                            "Skipping cache (response has errors)"
                        );
                        return;
                    }
                }
            }
        }

        // Check response size
        let response_str = response.to_string();
        if response_str.len() > self.config.max_entry_size {
            warn!(
                operation = ?key.operation_name,
                size = response_str.len(),
                max_size = self.config.max_entry_size,
                "Skipping cache (response too large)"
            );
            self.metrics.incr("bff.federation.cache.skip_too_large", &[]);
            return;
        }

        let cached = CachedResponse {
            data: response,
            operation_name: key.operation_name.clone(),
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0), // SystemTime before UNIX_EPOCH (impossible in practice)
            ttl_secs: ttl,
        };

        let hash = key.hash();

        // Insert with custom TTL if different from default
        if ttl != self.config.default_ttl_secs {
            // Moka doesn't support per-entry TTL directly, so we use the weigher approach
            // For now, use the default TTL (entries will be evicted based on default)
            // TODO: Consider using moka's `expire_after` for variable TTLs
            self.cache.insert(hash, cached).await;
        } else {
            self.cache.insert(hash, cached).await;
        }

        if let Some(ref m) = self.metrics {
            m.increment("bff.federation.cache.set", &[]);
            m.gauge(
                "bff.federation.cache.entries",
                self.cache.entry_count() as f64,
                &[],
            );
        }

        debug!(
            operation = ?key.operation_name,
            ttl_secs = ttl,
            "Cached response"
        );
    }

    /// Invalidate a cached entry
    pub async fn invalidate(&self, key: &CacheKey) {
        let hash = key.hash();
        self.cache.invalidate(&hash).await;

        self.metrics.incr("bff.federation.cache.invalidate", &[]);
    }

    /// Invalidate all entries matching an operation pattern
    pub async fn invalidate_pattern(&self, operation_pattern: &str) {
        // Moka doesn't support pattern-based invalidation directly
        // For full invalidation, use invalidate_all()
        // For pattern-based, we'd need to track keys separately
        warn!(
            pattern = operation_pattern,
            "Pattern-based invalidation not implemented, use invalidate_all()"
        );
    }

    /// Invalidate all cached entries
    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all();

        self.metrics.incr("bff.federation.cache.invalidate_all", &[]);

        info!("Invalidated all cache entries");
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.cache.entry_count(),
            weighted_size: self.cache.weighted_size(),
        }
    }

    /// Get TTL for a specific operation based on configured strategies
    fn get_ttl_for_operation(&self, operation_name: Option<&str>) -> u64 {
        let Some(op_name) = operation_name else {
            return self.config.default_ttl_secs;
        };

        for strategy in &self.config.strategies {
            if !strategy.enabled {
                continue;
            }

            if strategy.operation_pattern.ends_with('*') {
                // Prefix match
                let prefix = &strategy.operation_pattern[..strategy.operation_pattern.len() - 1];
                if op_name.starts_with(prefix) {
                    return strategy.ttl_secs;
                }
            } else if strategy.operation_pattern == op_name {
                // Exact match
                return strategy.ttl_secs;
            }
        }

        self.config.default_ttl_secs
    }
}

impl MemoryResponder for ResponseCache {
    fn memory_usage(&self) -> u64 {
        // Estimate: weighted_size approximates memory usage
        self.cache.weighted_size()
    }

    fn respond_to_pressure(&self, pressure: MemoryPressure) {
        // Gradient response: more aggressive eviction as pressure increases
        if pressure.is_critical() {
            // >90% pressure: invalidate 50% of entries
            // Note: moka doesn't have partial eviction, so we log for now
            warn!(
                pressure = pressure.value(),
                "Critical memory pressure - cache would evict 50%"
            );
        } else if pressure.is_high() {
            // >70% pressure: let entries expire faster (no direct API in moka)
            debug!(
                pressure = pressure.value(),
                "High memory pressure - reducing cache aggressiveness"
            );
        }
    }
}

/// Cache key for GraphQL operations
#[derive(Debug, Clone)]
pub struct CacheKey {
    /// Operation name (e.g., "getProducts")
    pub operation_name: Option<String>,

    /// Query document
    pub query: String,

    /// Variables (will be sorted for determinism)
    pub variables: Option<serde_json::Value>,

    /// Product scope for multi-tenant isolation
    pub product: String,
}

impl CacheKey {
    /// Create a new cache key
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

    /// Compute hash for this cache key
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

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of entries in cache
    pub entry_count: u64,

    /// Total weighted size
    pub weighted_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_hash_deterministic() {
        let key1 = CacheKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            Some(serde_json::json!({"limit": 10, "offset": 0})),
            "myapp".to_string(),
        );

        let key2 = CacheKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            Some(serde_json::json!({"offset": 0, "limit": 10})), // Different order
            "myapp".to_string(),
        );

        assert_eq!(key1.hash(), key2.hash());
    }

    #[test]
    fn test_cache_key_different_products() {
        let key1 = CacheKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "myapp".to_string(),
        );

        let key2 = CacheKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "test-product".to_string(),
        );

        assert_ne!(key1.hash(), key2.hash());
    }

    #[test]
    fn test_ttl_strategy_exact_match() {
        let config = ResponseCacheConfig {
            strategies: vec![CacheStrategy {
                operation_pattern: "getProducts".to_string(),
                ttl_secs: 120,
                enabled: true,
            }],
            default_ttl_secs: 60,
            ..Default::default()
        };

        let cache = ResponseCache::new(config, None, None);

        assert_eq!(cache.get_ttl_for_operation(Some("getProducts")), 120);
        assert_eq!(cache.get_ttl_for_operation(Some("getCategories")), 60);
    }

    #[test]
    fn test_ttl_strategy_prefix_match() {
        let config = ResponseCacheConfig {
            strategies: vec![CacheStrategy {
                operation_pattern: "get*".to_string(),
                ttl_secs: 120,
                enabled: true,
            }],
            default_ttl_secs: 60,
            ..Default::default()
        };

        let cache = ResponseCache::new(config, None, None);

        assert_eq!(cache.get_ttl_for_operation(Some("getProducts")), 120);
        assert_eq!(cache.get_ttl_for_operation(Some("getCategories")), 120);
        assert_eq!(cache.get_ttl_for_operation(Some("createOrder")), 60);
    }

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let config = ResponseCacheConfig::default();
        let cache = ResponseCache::new(config, None, None);

        let key = CacheKey::new(
            Some("getProducts".to_string()),
            "query { products { id } }".to_string(),
            None,
            "myapp".to_string(),
        );

        let response = serde_json::json!({
            "data": {
                "products": [{"id": "1"}, {"id": "2"}]
            }
        });

        cache.set(&key, response.clone()).await;

        let cached = cache.get(&key).await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().data, response);
    }

    // Property-based tests using proptest
    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        // Strategy to generate arbitrary JSON values
        fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
            let leaf = prop_oneof![
                Just(serde_json::Value::Null),
                any::<bool>().prop_map(serde_json::Value::Bool),
                any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
                "[a-zA-Z0-9_]{0,20}".prop_map(serde_json::Value::String),
            ];

            leaf.prop_recursive(
                3,  // depth
                32, // max nodes
                10, // items per collection
                |inner| {
                    prop_oneof![
                        // Array of values
                        prop::collection::vec(inner.clone(), 0..5)
                            .prop_map(serde_json::Value::Array),
                        // Object with string keys
                        prop::collection::hash_map("[a-zA-Z_][a-zA-Z0-9_]{0,10}", inner, 0..5)
                            .prop_map(|map| {
                                serde_json::Value::Object(map.into_iter().collect())
                            }),
                    ]
                },
            )
        }

        proptest! {
            /// Property: Cache key hash is deterministic - same inputs always produce same hash
            #[test]
            fn cache_key_hash_deterministic(
                op_name in proptest::option::of("[a-zA-Z][a-zA-Z0-9]{0,20}"),
                query in "[a-zA-Z ]{1,100}",
                product in "product-a|product-b|product-c"
            ) {
                let key1 = CacheKey::new(
                    op_name.clone(),
                    query.clone(),
                    None,
                    product.clone(),
                );
                let key2 = CacheKey::new(op_name, query, None, product);

                prop_assert_eq!(key1.hash(), key2.hash());
            }

            /// Property: JSON sorting is idempotent - sorting twice gives same result
            #[test]
            fn json_sort_idempotent(value in arb_json_value()) {
                let sorted_once = CacheKey::sort_json_value(&value);
                let sorted_twice = CacheKey::sort_json_value(&sorted_once);

                prop_assert_eq!(sorted_once, sorted_twice);
            }

            /// Property: Variable order doesn't affect hash - object key order is normalized
            #[test]
            fn variable_order_independence(
                key1 in "[a-z]{1,5}",
                key2 in "[a-z]{1,5}",
                val1 in any::<i64>(),
                val2 in any::<i64>()
            ) {
                // Skip if keys are the same (would collapse to single entry)
                prop_assume!(key1 != key2);

                let vars1 = serde_json::json!({ &key1: val1, &key2: val2 });
                let vars2 = serde_json::json!({ &key2: val2, &key1: val1 });

                let cache_key1 = CacheKey::new(
                    Some("op".to_string()),
                    "query".to_string(),
                    Some(vars1),
                    "myapp".to_string(),
                );
                let cache_key2 = CacheKey::new(
                    Some("op".to_string()),
                    "query".to_string(),
                    Some(vars2),
                    "myapp".to_string(),
                );

                prop_assert_eq!(cache_key1.hash(), cache_key2.hash());
            }

            /// Property: Hash never panics regardless of input
            #[test]
            fn hash_never_panics(
                op_name in proptest::option::of(".*"),
                query in ".*",
                variables in proptest::option::of(arb_json_value()),
                product in ".*"
            ) {
                let key = CacheKey::new(op_name, query, variables, product);
                // Should never panic
                let _ = key.hash();
            }

            /// Property: Whitespace normalization - queries with different whitespace but same tokens hash equally
            #[test]
            fn whitespace_normalization(
                tokens in prop::collection::vec("[a-zA-Z]+", 1..5)
            ) {
                let query1 = tokens.join(" ");
                let query2 = tokens.join("  ");  // Double spaces
                let query3 = tokens.join("   "); // Triple spaces

                let key1 = CacheKey::new(None, query1, None, "myapp".to_string());
                let key2 = CacheKey::new(None, query2, None, "myapp".to_string());
                let key3 = CacheKey::new(None, query3, None, "myapp".to_string());

                prop_assert_eq!(key1.hash(), key2.hash());
                prop_assert_eq!(key2.hash(), key3.hash());
            }
        }
    }
}
