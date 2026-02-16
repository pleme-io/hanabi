use serde::{Deserialize, Serialize};

use super::CacheStrategy;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffCacheConfig {
    /// Enable Redis caching for GraphQL responses
    pub enabled: bool,

    /// Redis host
    pub redis_host: String,

    /// Redis port
    pub redis_port: u16,

    /// Redis connection pool size (min connections)
    pub pool_min_size: u32,

    /// Redis connection pool size (max connections)
    pub pool_max_size: u32,

    /// Redis connection timeout (seconds)
    pub connection_timeout_secs: u64,

    /// Redis command timeout (seconds)
    pub command_timeout_secs: u64,

    /// Default TTL for cached responses (seconds)
    pub default_ttl_secs: u64,

    /// Query-specific cache strategies (query pattern → TTL)
    #[serde(default)]
    pub strategies: Vec<CacheStrategy>,

    /// Cache only successful responses (ignore errors)
    pub cache_only_success: bool,

    /// Maximum cached value size in bytes (prevents memory exhaustion)
    pub max_value_size: usize,
}

impl Default for BffCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redis_host: "localhost".to_string(),
            redis_port: 6379,
            pool_min_size: 2,
            pool_max_size: 10,
            connection_timeout_secs: 5,
            command_timeout_secs: 3,
            default_ttl_secs: 60,
            strategies: vec![],
            cache_only_success: true,
            max_value_size: 1024 * 1024, // 1 MB
        }
    }
}

// =============================================================================
// Two-Tier Cache Configuration (Infrastructure for Phase 2 Federation)
// These types are intentionally defined for future integration.
// =============================================================================

/// Two-tier distributed cache configuration
///
/// Implements Apollo Router-style caching with L1 (in-memory) + L2 (Redis):
/// - L1: Fast moka cache for hot data, per-instance
/// - L2: Redis for cross-instance sharing, survives restarts
///
/// # Cache Hierarchy
/// ```text
/// Request → L1 (moka) → L2 (Redis) → Execute Query
///    ↑         HIT         HIT           ↓
///    └─────────┴───────────┴─────────────┘
/// ```
///
/// # Use Cases
/// - **Response Cache**: Full GraphQL response caching
/// - **Query Plan Cache**: Federation query plan caching (saves 1-10s latency)
/// - **APQ Cache**: Distributed Automatic Persisted Queries
/// - **Entity Cache**: Granular entity caching (User, Product, etc.)
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffTwoTierCacheConfig {
    /// Enable two-tier caching
    pub enabled: bool,

    /// L1 (in-memory) cache configuration
    pub l1: BffL1CacheConfig,

    /// L2 (Redis) cache configuration
    pub l2: BffL2CacheConfig,

    /// Query plan cache configuration
    pub query_plan: BffQueryPlanCacheConfig,

    /// APQ cache configuration
    pub apq: BffApqCacheConfig,

    /// Entity cache configuration
    pub entity: BffEntityCacheConfig,

    /// Hot reload configuration changes without restart
    pub hot_reload: bool,
}

impl Default for BffTwoTierCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            l1: BffL1CacheConfig::default(),
            l2: BffL2CacheConfig::default(),
            query_plan: BffQueryPlanCacheConfig::default(),
            apq: BffApqCacheConfig::default(),
            entity: BffEntityCacheConfig::default(),
            hot_reload: true,
        }
    }
}

/// L1 (in-memory) cache configuration
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffL1CacheConfig {
    /// Enable L1 cache
    pub enabled: bool,

    /// Maximum entries in L1 cache
    pub max_capacity: u64,

    /// Default TTL for L1 entries (seconds)
    pub default_ttl_secs: u64,
}

impl Default for BffL1CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_capacity: 10_000,
            default_ttl_secs: 60,
        }
    }
}

/// L2 (Redis) cache configuration
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffL2CacheConfig {
    /// Enable L2 Redis cache
    pub enabled: bool,

    /// Default TTL for L2 entries (seconds)
    pub default_ttl_secs: u64,

    /// Maximum value size in bytes
    pub max_value_size: usize,

    /// Redis operation timeout (milliseconds)
    pub timeout_ms: u64,

    /// Key prefix for namespace isolation
    pub key_prefix: String,
}

impl Default for BffL2CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl_secs: 300,
            max_value_size: 1024 * 1024, // 1 MB
            timeout_ms: 100,
            key_prefix: "bff:federation".to_string(),
        }
    }
}

/// Query plan cache configuration
///
/// Caches federation query plans to avoid expensive re-planning.
/// Can save 1-10 seconds of latency per unique query.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffQueryPlanCacheConfig {
    /// Enable query plan caching
    pub enabled: bool,

    /// L1 capacity for query plans (plans are larger, fewer cached)
    pub l1_capacity: u64,

    /// L1 TTL for query plans (seconds)
    pub l1_ttl_secs: u64,

    /// L2 TTL for query plans (seconds)
    pub l2_ttl_secs: u64,

    /// Maximum plan size in bytes
    pub max_plan_size: usize,
}

impl Default for BffQueryPlanCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            l1_capacity: 1_000,
            l1_ttl_secs: 300,
            l2_ttl_secs: 3600,
            max_plan_size: 512 * 1024, // 512 KB
        }
    }
}

/// APQ (Automatic Persisted Queries) cache configuration
///
/// Distributed APQ cache allows query hash sharing across instances.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffApqCacheConfig {
    /// Enable distributed APQ
    pub enabled: bool,

    /// L1 capacity for APQ entries
    pub l1_capacity: u64,

    /// L1 TTL (seconds)
    pub l1_ttl_secs: u64,

    /// L2 TTL (seconds)
    pub l2_ttl_secs: u64,

    /// Maximum query size in bytes
    pub max_query_size: usize,

    /// Require pre-registration (security mode)
    #[serde(default)]
    pub require_registration: bool,
}

impl Default for BffApqCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            l1_capacity: 10_000,
            l1_ttl_secs: 3600,
            l2_ttl_secs: 86400,
            max_query_size: 256 * 1024, // 256 KB
            require_registration: false,
        }
    }
}

/// Entity cache configuration
///
/// Normalized entity caching for granular cache control.
/// Caches individual entities (User, Product) instead of full responses.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffEntityCacheConfig {
    /// Enable entity caching
    pub enabled: bool,

    /// L1 capacity (entities are small, cache many)
    pub l1_capacity: u64,

    /// L1 TTL (seconds)
    pub l1_ttl_secs: u64,

    /// L2 TTL (seconds)
    pub l2_ttl_secs: u64,

    /// Maximum entity size in bytes
    pub max_entity_size: usize,

    /// Entity types to cache (empty = all)
    #[serde(default)]
    pub cached_types: Vec<String>,

    /// Entity type-specific TTLs
    #[serde(default)]
    pub type_ttls: Vec<EntityTypeTtl>,
}

impl Default for BffEntityCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            l1_capacity: 50_000,
            l1_ttl_secs: 60,
            l2_ttl_secs: 300,
            max_entity_size: 64 * 1024, // 64 KB
            cached_types: vec![],
            type_ttls: vec![],
        }
    }
}

/// Entity type-specific TTL configuration
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntityTypeTtl {
    /// Entity typename (e.g., "User", "Product")
    pub typename: String,

    /// TTL in seconds for this type
    pub ttl_secs: u64,
}
