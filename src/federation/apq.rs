#![allow(dead_code, unused)]
//! Automatic Persisted Queries (APQ) for GraphQL Federation
//!
//! APQ reduces payload size by allowing clients to send query hashes instead
//! of full query documents. The server maintains a cache of hash → query mappings.
//!
//! # Protocol
//!
//! ```text
//! 1. Client sends: { extensions: { persistedQuery: { sha256Hash: "abc...", version: 1 } } }
//!    (no query field)
//!
//! 2a. Cache HIT: Server uses cached query, executes normally
//!
//! 2b. Cache MISS: Server returns PersistedQueryNotFound error
//!
//! 3. Client retries with full query:
//!    { query: "...", extensions: { persistedQuery: { sha256Hash: "abc...", version: 1 } } }
//!
//! 4. Server caches query, executes normally
//! ```
//!
//! # Benefits
//!
//! - **Reduced payload size**: Hash (64 chars) vs full query (potentially KB)
//! - **Security**: Only registered queries can be executed (when enforced)
//! - **CDN caching**: GET requests with hash are cacheable
//! - **Bandwidth savings**: Especially for mobile clients
//!
//! # Configuration
//!
//! ```yaml
//! bff:
//!   federation:
//!     apq:
//!       enabled: true
//!       max_entries: 10000
//!       ttl_secs: 86400  # 24 hours
//!       require_registration: false  # If true, only pre-registered queries allowed
//! ```

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::memory::{MemoryPressure, MemoryResponder};
use crate::metrics::{MetricsClient, MetricsExt};

/// Configuration for APQ
#[derive(Debug, Clone)]
pub struct ApqConfig {
    /// Enable APQ support
    pub enabled: bool,

    /// Maximum number of cached queries
    pub max_entries: u64,

    /// TTL for cached queries in seconds (0 = no expiry)
    pub ttl_secs: u64,

    /// Require queries to be pre-registered (security mode)
    /// When true, queries without prior registration are rejected
    pub require_registration: bool,

    /// Allow GET requests with persisted queries (for CDN caching)
    pub allow_get_requests: bool,
}

impl Default for ApqConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10_000,
            ttl_secs: 86400, // 24 hours
            require_registration: false,
            allow_get_requests: true,
        }
    }
}

/// Persisted query extension from client request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedQueryExtension {
    /// APQ version (currently only version 1 is supported)
    pub version: u32,

    /// SHA256 hash of the query document
    pub sha256_hash: String,
}

/// Result of APQ lookup
#[derive(Debug)]
pub enum ApqLookupResult {
    /// Query found in cache
    Hit {
        /// The cached query document
        query: String,
    },
    /// Query not found, client should retry with full query
    NotFound,
    /// Query provided, will be cached
    Register {
        /// The query to cache
        query: String,
        /// The hash to use as key
        hash: String,
    },
    /// APQ not used in this request
    NotUsed,
    /// Invalid APQ request (bad hash, version mismatch, etc.)
    Invalid {
        /// Error message
        message: String,
    },
}

/// APQ error response per Apollo spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApqError {
    /// Error message
    pub message: String,

    /// Error extensions
    pub extensions: ApqErrorExtensions,
}

/// APQ error extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct ApqErrorExtensions {
    /// Error code
    pub code: ApqErrorCode,
}

/// APQ error codes per Apollo spec
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApqErrorCode {
    /// Query hash not found in cache
    PersistedQueryNotFound,
    /// Query hash doesn't match provided query
    PersistedQueryHashMismatch,
    /// APQ version not supported
    PersistedQueryVersionNotSupported,
    /// Query registration required but not provided
    PersistedQueryNotRegistered,
}

impl ApqError {
    /// Create a PersistedQueryNotFound error
    pub fn not_found() -> Self {
        Self {
            message: "PersistedQueryNotFound".to_string(),
            extensions: ApqErrorExtensions {
                code: ApqErrorCode::PersistedQueryNotFound,
            },
        }
    }

    /// Create a hash mismatch error
    pub fn hash_mismatch() -> Self {
        Self {
            message: "provided sha256 hash does not match query".to_string(),
            extensions: ApqErrorExtensions {
                code: ApqErrorCode::PersistedQueryHashMismatch,
            },
        }
    }

    /// Create a version not supported error
    pub fn version_not_supported(version: u32) -> Self {
        Self {
            message: format!("APQ version {} is not supported", version),
            extensions: ApqErrorExtensions {
                code: ApqErrorCode::PersistedQueryVersionNotSupported,
            },
        }
    }

    /// Create a not registered error (security mode)
    pub fn not_registered() -> Self {
        Self {
            message: "Query must be pre-registered".to_string(),
            extensions: ApqErrorExtensions {
                code: ApqErrorCode::PersistedQueryNotRegistered,
            },
        }
    }

    /// Convert to GraphQL error response
    pub fn to_graphql_response(&self) -> serde_json::Value {
        serde_json::json!({
            "errors": [{
                "message": self.message,
                "extensions": {
                    "code": self.extensions.code
                }
            }]
        })
    }
}

/// Automatic Persisted Queries cache
pub struct ApqCache {
    /// In-memory cache of hash → query
    cache: Cache<String, String>,

    /// Configuration
    config: ApqConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl ApqCache {
    /// Create a new APQ cache
    pub fn new(config: ApqConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        let cache = if config.ttl_secs > 0 {
            Cache::builder()
                .max_capacity(config.max_entries)
                .time_to_live(Duration::from_secs(config.ttl_secs))
                .build()
        } else {
            Cache::builder().max_capacity(config.max_entries).build()
        };

        info!(
            max_entries = config.max_entries,
            ttl_secs = config.ttl_secs,
            require_registration = config.require_registration,
            "APQ cache initialized"
        );

        Self {
            cache,
            config,
            metrics,
        }
    }

    /// Check if APQ is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Process an APQ request
    ///
    /// Returns the lookup result indicating whether to use cached query,
    /// return error, or proceed with provided query.
    pub async fn lookup(
        &self,
        query: Option<&str>,
        extensions: Option<&serde_json::Value>,
    ) -> ApqLookupResult {
        if !self.config.enabled {
            return ApqLookupResult::NotUsed;
        }

        // Check for persistedQuery extension
        let persisted_query = match Self::extract_persisted_query(extensions) {
            Some(pq) => pq,
            None => return ApqLookupResult::NotUsed,
        };

        // Validate version
        if persisted_query.version != 1 {
            self.metrics.incr("bff.federation.apq.version_unsupported", &[]);
            return ApqLookupResult::Invalid {
                message: format!("APQ version {} is not supported", persisted_query.version),
            };
        }

        let hash = &persisted_query.sha256_hash;

        // Case 1: Query not provided - lookup by hash
        if query.is_none() || query.map(|q| q.is_empty()).unwrap_or(true) {
            if let Some(cached_query) = self.cache.get(hash).await {
                self.metrics.incr("bff.federation.apq.hit", &[]);
                debug!(hash = %hash, "APQ cache hit");
                return ApqLookupResult::Hit {
                    query: cached_query,
                };
            }

            self.metrics.incr("bff.federation.apq.miss", &[]);
            debug!(hash = %hash, "APQ cache miss");
            return ApqLookupResult::NotFound;
        }

        // Case 2: Query provided - verify hash and cache
        // SAFETY: We checked query.is_none() above and returned early
        let query = match query {
            Some(q) => q,
            None => {
                return ApqLookupResult::Invalid {
                    message: "Query is None after is_none check".to_string(),
                }
            }
        };

        // Verify the hash matches
        let computed_hash = Self::compute_hash(query);
        if computed_hash != *hash {
            self.metrics.incr("bff.federation.apq.hash_mismatch", &[]);
            warn!(
                provided_hash = %hash,
                computed_hash = %computed_hash,
                "APQ hash mismatch"
            );
            return ApqLookupResult::Invalid {
                message: "provided sha256 hash does not match query".to_string(),
            };
        }

        // Security mode: reject if require_registration and not cached
        if self.config.require_registration {
            let cached: Option<String> = self.cache.get(hash).await;
            if cached.is_none() {
                self.metrics.incr("bff.federation.apq.not_registered", &[]);
                return ApqLookupResult::Invalid {
                    message: "Query must be pre-registered".to_string(),
                };
            }
        }

        ApqLookupResult::Register {
            query: query.to_string(),
            hash: hash.clone(),
        }
    }

    /// Register a query in the cache
    pub async fn register(&self, hash: &str, query: &str) {
        self.cache.insert(hash.to_string(), query.to_string()).await;

        self.metrics.incr("bff.federation.apq.register", &[]);
        self.metrics.gauge(
            "bff.federation.apq.entries",
            self.cache.entry_count() as f64,
            &[],
        );

        debug!(hash = %hash, query_len = query.len(), "APQ query registered");
    }

    /// Pre-register a query (for security mode)
    ///
    /// Returns the hash that clients should use.
    pub async fn pre_register(&self, query: &str) -> String {
        let hash = Self::compute_hash(query);
        self.cache.insert(hash.clone(), query.to_string()).await;

        self.metrics.incr("bff.federation.apq.pre_register", &[]);

        info!(hash = %hash, "APQ query pre-registered");
        hash
    }

    /// Bulk pre-register queries (for security mode)
    ///
    /// Returns a map of query → hash.
    pub async fn pre_register_bulk(&self, queries: &[&str]) -> Vec<(String, String)> {
        let mut results = Vec::with_capacity(queries.len());

        for &query in queries {
            let hash = self.pre_register(query).await;
            results.push((query.to_string(), hash));
        }

        info!(count = results.len(), "APQ queries bulk pre-registered");
        results
    }

    /// Remove a query from the cache
    pub async fn invalidate(&self, hash: &str) {
        self.cache.invalidate(hash).await;

        self.metrics.incr("bff.federation.apq.invalidate", &[]);
    }

    /// Clear all cached queries
    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all();

        self.metrics.incr("bff.federation.apq.invalidate_all", &[]);

        info!("APQ cache cleared");
    }

    /// Get cache statistics
    pub fn stats(&self) -> ApqStats {
        ApqStats {
            entry_count: self.cache.entry_count(),
            weighted_size: self.cache.weighted_size(),
        }
    }

    /// Compute SHA256 hash of a query
    /// PERFORMANCE: Inline for hot path (called on every APQ query registration)
    #[inline]
    pub fn compute_hash(query: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(query.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Extract persistedQuery extension from request extensions
    fn extract_persisted_query(
        extensions: Option<&serde_json::Value>,
    ) -> Option<PersistedQueryExtension> {
        extensions?
            .get("persistedQuery")
            .and_then(|pq| serde_json::from_value(pq.clone()).ok())
    }
}

/// APQ cache statistics
#[derive(Debug, Clone)]
pub struct ApqStats {
    /// Number of cached queries
    pub entry_count: u64,

    /// Total weighted size of cache
    pub weighted_size: u64,
}

impl MemoryResponder for ApqCache {
    fn memory_usage(&self) -> u64 {
        // Estimate: weighted_size approximates memory usage
        // Each entry is hash (64 bytes) + query string (variable)
        self.cache.weighted_size()
    }

    fn respond_to_pressure(&self, pressure: MemoryPressure) {
        // Gradient response: more aggressive eviction as pressure increases
        if pressure.is_critical() {
            // >90% pressure: invalidate all entries (APQ can be regenerated)
            // This is safe because clients will just re-send the full query
            warn!(
                pressure = pressure.value(),
                entries = self.cache.entry_count(),
                "Critical memory pressure - APQ cache cleared"
            );
            self.cache.invalidate_all();
        } else if pressure.is_high() {
            // >70% pressure: let entries expire naturally (no forced eviction)
            debug!(
                pressure = pressure.value(),
                entries = self.cache.entry_count(),
                "High memory pressure - APQ cache allowing natural expiration"
            );
        }
    }
}

/// Helper to build APQ-enabled GraphQL requests
pub struct ApqRequestBuilder;

impl ApqRequestBuilder {
    /// Build a request with APQ extension (hash only, no query)
    pub fn hash_only(hash: &str, variables: Option<serde_json::Value>) -> serde_json::Value {
        let mut request = serde_json::json!({
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": hash
                }
            }
        });

        if let Some(vars) = variables {
            request["variables"] = vars;
        }

        request
    }

    /// Build a request with APQ extension (full query for registration)
    pub fn with_query(query: &str, variables: Option<serde_json::Value>) -> serde_json::Value {
        let hash = ApqCache::compute_hash(query);

        let mut request = serde_json::json!({
            "query": query,
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": hash
                }
            }
        });

        if let Some(vars) = variables {
            request["variables"] = vars;
        }

        request
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash() {
        let query = "query { users { id name } }";
        let hash = ApqCache::compute_hash(query);

        // SHA256 produces 64 character hex string
        assert_eq!(hash.len(), 64);

        // Same query produces same hash
        let hash2 = ApqCache::compute_hash(query);
        assert_eq!(hash, hash2);

        // Different query produces different hash
        let hash3 = ApqCache::compute_hash("query { posts { id } }");
        assert_ne!(hash, hash3);
    }

    #[tokio::test]
    async fn test_apq_cache_flow() {
        let config = ApqConfig::default();
        let cache = ApqCache::new(config, None);

        let query = "query GetUsers { users { id name email } }";
        let hash = ApqCache::compute_hash(query);

        // First request with hash only - should miss
        let extensions = serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash
            }
        });

        let result = cache.lookup(None, Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::NotFound));

        // Second request with query - should register
        let result = cache.lookup(Some(query), Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::Register { .. }));

        // Register the query
        cache.register(&hash, query).await;

        // Third request with hash only - should hit
        let result = cache.lookup(None, Some(&extensions)).await;
        match result {
            ApqLookupResult::Hit { query: cached } => {
                assert_eq!(cached, query);
            }
            _ => panic!("Expected cache hit"),
        }
    }

    #[tokio::test]
    async fn test_apq_hash_mismatch() {
        let config = ApqConfig::default();
        let cache = ApqCache::new(config, None);

        let query = "query { users { id } }";
        let wrong_hash = "0".repeat(64);

        let extensions = serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": wrong_hash
            }
        });

        let result = cache.lookup(Some(query), Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::Invalid { .. }));
    }

    #[tokio::test]
    async fn test_apq_version_unsupported() {
        let config = ApqConfig::default();
        let cache = ApqCache::new(config, None);

        let extensions = serde_json::json!({
            "persistedQuery": {
                "version": 2,
                "sha256Hash": "abc"
            }
        });

        let result = cache.lookup(None, Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::Invalid { .. }));
    }

    #[tokio::test]
    async fn test_apq_disabled() {
        let config = ApqConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = ApqCache::new(config, None);

        let extensions = serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": "abc"
            }
        });

        let result = cache.lookup(None, Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::NotUsed));
    }

    #[tokio::test]
    async fn test_apq_security_mode() {
        let config = ApqConfig {
            require_registration: true,
            ..Default::default()
        };
        let cache = ApqCache::new(config, None);

        let query = "query { users { id } }";
        let hash = ApqCache::compute_hash(query);

        let extensions = serde_json::json!({
            "persistedQuery": {
                "version": 1,
                "sha256Hash": hash
            }
        });

        // Query not pre-registered - should fail
        let result = cache.lookup(Some(query), Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::Invalid { .. }));

        // Pre-register the query
        cache.pre_register(query).await;

        // Now should succeed
        let result = cache.lookup(Some(query), Some(&extensions)).await;
        assert!(matches!(result, ApqLookupResult::Register { .. }));
    }

    #[test]
    fn test_apq_request_builder() {
        let query = "query { users { id } }";
        let hash = ApqCache::compute_hash(query);

        // Hash only request
        let request = ApqRequestBuilder::hash_only(&hash, None);
        assert!(request.get("query").is_none());
        assert!(
            request["extensions"]["persistedQuery"]["sha256Hash"]
                .as_str()
                .unwrap()
                == hash
        );

        // Full query request
        let request = ApqRequestBuilder::with_query(query, None);
        assert_eq!(request["query"].as_str().unwrap(), query);
        assert!(
            request["extensions"]["persistedQuery"]["sha256Hash"]
                .as_str()
                .unwrap()
                == hash
        );
    }

    #[test]
    fn test_apq_error_responses() {
        let not_found = ApqError::not_found();
        let response = not_found.to_graphql_response();
        assert!(response["errors"][0]["extensions"]["code"]
            .as_str()
            .unwrap()
            .contains("PERSISTED_QUERY_NOT_FOUND"));

        let mismatch = ApqError::hash_mismatch();
        let response = mismatch.to_graphql_response();
        assert!(response["errors"][0]["extensions"]["code"]
            .as_str()
            .unwrap()
            .contains("HASH_MISMATCH"));
    }
}
