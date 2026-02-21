use serde::{Deserialize, Serialize};

fn default_subgraph_port() -> u16 {
    8080
}

fn default_subgraph_path() -> String {
    "/graphql".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffFederationConfig {
    /// Enable federation mode
    /// When true, BFF acts as GraphQL federation router
    /// When false (default), BFF proxies to hive_router_url
    pub enabled: bool,

    /// Performance mode - optimizes for minimum latency like Hive Router
    /// When enabled:
    /// - Skips plugin system (no pre/post hooks)
    /// - Skips request deduplication (adds latency for rare savings)
    /// - Skips APQ (persisted queries rarely used)
    /// - Skips depth/complexity validation (trust subgraphs to validate)
    /// - Uses HTTP/2 multiplexing for connection efficiency
    /// - Keeps only essential features: query planning, execution, response caching
    ///
    /// RECOMMENDED: Enable this in production for Hive Router-like performance
    pub performance_mode: bool,

    /// URL to fetch the supergraph schema from
    /// Can be a file path (file://) or HTTP URL
    /// Example: "http://hive-router:4000/supergraph" or "file:///etc/supergraph.graphql"
    pub supergraph_url: String,

    /// Enable hot reload for supergraph schema changes
    /// When true, watches the supergraph file for changes (if file://)
    /// or polls the HTTP endpoint at poll_interval_secs (if http://)
    /// Similar to Apollo Router's --hot-reload flag
    pub hot_reload: bool,

    /// Interval in seconds to poll for supergraph schema updates
    /// Only used when hot_reload is true and supergraph_url is HTTP
    /// Set to 0 to disable polling (file watching still works for file:// URLs)
    pub poll_interval_secs: u64,

    /// Subgraph URL overrides for Kubernetes cluster-local routing
    ///
    /// When running in Kubernetes, subgraph URLs in the supergraph schema may point
    /// to external URLs, but we want to use cluster-local service DNS names for
    /// lower latency and to avoid external network hops.
    ///
    /// Example:
    /// ```yaml
    /// subgraph_url_overrides:
    ///   - name: auth
    ///     url: http://auth:8080/graphql
    ///   - name: booking
    ///     url: http://booking:8080/graphql
    /// ```
    pub subgraph_url_overrides: Vec<SubgraphUrlOverride>,

    /// HMAC configuration for signing requests to subgraphs
    pub hmac: FederationHmacConfig,

    /// HTTP connection pool configuration for subgraph calls
    pub http_pool: FederationHttpPoolConfig,

    /// WebSocket configuration for subscriptions
    pub websocket: FederationWebSocketConfig,

    /// Query plan cache configuration
    pub query_plan_cache: FederationQueryPlanCacheConfig,

    /// Observability configuration
    pub observability: FederationObservabilityConfig,

    /// Response cache configuration
    pub response_cache: FederationResponseCacheConfig,

    /// Request deduplication configuration
    pub deduplication: FederationDeduplicationConfig,

    /// Automatic Persisted Queries (APQ) configuration
    pub apq: FederationApqConfig,

    /// Federation-level rate limiting configuration
    pub rate_limit: FederationRateLimitConfig,

    /// Request batching configuration (DataLoader pattern)
    pub batching: FederationBatchingConfig,

    /// Query planner configuration
    pub query_planner: FederationQueryPlannerConfig,

    /// Plan executor configuration
    pub executor: FederationExecutorConfig,

    /// Security configuration (depth limiting, complexity analysis, introspection)
    pub security: FederationSecurityConfig,

    /// Custom plugins configuration
    pub plugins: FederationPluginsConfig,

    /// Admin API configuration
    pub admin: FederationAdminConfig,

    /// Enable load shedding (Netflix Gradient algorithm + circuit breakers)
    /// When false (default), BFF processes all requests without admission control
    /// Enable only when you need to protect against cascading failures at scale
    pub enable_load_shedding: bool,

    /// Use the Hive query planner (default: true)
    /// Set to false to use the simpler fallback planner
    pub use_hive_planner: bool,

    /// Cache invalidation configuration (event-driven invalidation via Redis pub/sub)
    pub cache_invalidation: FederationCacheInvalidationConfig,

    /// Default port for subgraphs when URL is not in the supergraph schema
    #[serde(default = "default_subgraph_port")]
    pub subgraph_default_port: u16,

    /// Default path for subgraphs when URL is not in the supergraph schema
    #[serde(default = "default_subgraph_path")]
    pub subgraph_default_path: String,
}

impl Default for BffFederationConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Federation mode enabled by default (Phase 2 activation)
            // ENABLED by default for production-like performance
            // This skips non-essential pipeline steps to match Hive Router latency
            performance_mode: true,
            supergraph_url: "file:///etc/supergraph.graphql".to_string(),
            hot_reload: false, // Disabled by default for stability
            poll_interval_secs: 30, // 30 seconds when hot reload is enabled
            subgraph_url_overrides: vec![],
            hmac: FederationHmacConfig::default(),
            http_pool: FederationHttpPoolConfig::default(),
            websocket: FederationWebSocketConfig::default(),
            query_plan_cache: FederationQueryPlanCacheConfig::default(),
            observability: FederationObservabilityConfig::default(),
            response_cache: FederationResponseCacheConfig::default(),
            deduplication: FederationDeduplicationConfig::default(),
            apq: FederationApqConfig::default(),
            rate_limit: FederationRateLimitConfig::default(),
            batching: FederationBatchingConfig::default(),
            query_planner: FederationQueryPlannerConfig::default(),
            executor: FederationExecutorConfig::default(),
            security: FederationSecurityConfig::default(),
            plugins: FederationPluginsConfig::default(),
            admin: FederationAdminConfig::default(),
            enable_load_shedding: false, // Disabled by default - just process all requests
            use_hive_planner: true, // Hive planner enabled by default
            cache_invalidation: FederationCacheInvalidationConfig::default(),
            subgraph_default_port: default_subgraph_port(),
            subgraph_default_path: default_subgraph_path(),
        }
    }
}

/// Subgraph URL override configuration
///
/// Allows overriding the URL for a specific subgraph, typically used
/// to route to Kubernetes cluster-local service DNS names instead of
/// external URLs defined in the supergraph schema.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubgraphUrlOverride {
    /// Subgraph name (must match the name in @join__graph directive)
    pub name: String,

    /// Override URL for this subgraph
    /// Example: "http://auth:8080/graphql" for Kubernetes service
    pub url: String,
}

/// Admin API configuration for federation
///
/// Controls the supergraph reload and status endpoints.
/// Disabled by default for security - use file watcher for hot reload.
/// Enable only when you need programmatic reload from trusted sources.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct FederationAdminConfig {
    /// Enable admin API endpoints
    /// When true, enables POST /admin/reload-supergraph and GET /admin/supergraph-status
    /// Default: false (use file watcher for hot reload instead)
    #[serde(default)]
    pub enabled: bool,
}

/// Cache invalidation configuration
///
/// Enables event-driven cache invalidation across multiple BFF pods using Redis pub/sub.
/// When a mutation modifies an entity, an invalidation event is published to Redis,
/// and all BFF instances evict matching cache entries.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationCacheInvalidationConfig {
    /// Enable cache invalidation via Redis pub/sub
    /// When true, BFF subscribes to invalidation events and publishes on mutations
    pub enabled: bool,

    /// Channel buffer size for local invalidation broadcast
    pub buffer_size: usize,

    /// Automatically publish invalidation events for mutations
    /// When true, BFF extracts entity info from mutation responses and publishes events
    pub auto_publish_on_mutations: bool,

    /// Patterns for extracting entity info from mutation responses
    /// Each pattern specifies how to map a mutation name to entity type and ID
    #[serde(default)]
    pub mutation_patterns: Vec<MutationInvalidationPattern>,
}

impl Default for FederationCacheInvalidationConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default - opt-in feature
            buffer_size: 1000,
            auto_publish_on_mutations: true,
            mutation_patterns: vec![],
        }
    }
}

/// Pattern for extracting entity info from mutation responses
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MutationInvalidationPattern {
    /// Mutation name pattern (supports * wildcard)
    /// Examples: "create*", "update*", "delete*", "updateUser"
    pub pattern: String,

    /// Entity type to invalidate (if empty, extracted from mutation name)
    /// Example: "User", "Product"
    pub entity_type: String,

    /// JSON path to entity ID in response (supports * wildcard)
    /// Examples: "data.createUser.id", "data.*.id"
    pub id_path: String,
}

impl Default for MutationInvalidationPattern {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            entity_type: String::new(),
            id_path: "data.*.id".to_string(),
        }
    }
}

/// HMAC configuration for signing subgraph requests
///
/// Signatures are placed in the GraphQL extensions field as per
/// the hive-gateway-hmac skill pattern. Subgraphs verify signatures
/// to ensure requests come from the trusted gateway.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationHmacConfig {
    /// Enable HMAC signing for subgraph requests
    pub enabled: bool,

    /// HMAC secret for signing requests to subgraphs
    /// Must match the secret configured on subgraphs for request validation
    /// Should be loaded from environment variable (HMAC_SECRET)
    pub secret: String,

    /// HMAC algorithm to use (default: SHA256)
    pub algorithm: String,
}

impl Default for FederationHmacConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            secret: String::new(),
            algorithm: "SHA256".to_string(),
        }
    }
}

/// HTTP connection pool configuration for subgraph calls
///
/// Based on reqwest best practices for connection reuse and pooling.
/// Pool is shared across all subgraph calls for efficiency.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationHttpPoolConfig {
    /// Request timeout for subgraph queries in seconds
    pub timeout_secs: u64,

    /// Connection timeout in seconds
    pub connect_timeout_secs: u64,

    /// Maximum idle connections per host
    /// Keeps connections alive for reuse, reducing connection setup overhead
    pub pool_max_idle_per_host: usize,

    /// Idle connection timeout in seconds
    /// Connections idle longer than this will be closed
    pub pool_idle_timeout_secs: u64,

    /// TCP keep-alive interval in seconds
    /// Keeps connections alive through network equipment
    pub tcp_keepalive_secs: u64,

    /// Enable gzip compression for subgraph responses
    pub gzip_enabled: bool,

    /// Enable HTTP/2 for subgraph connections
    /// HTTP/2 provides request multiplexing over a single TCP connection,
    /// reducing connection overhead and improving latency for concurrent requests.
    /// This is a key optimization: Hive Router uses HTTP/2 by default.
    pub http2_enabled: bool,
}

impl Default for FederationHttpPoolConfig {
    fn default() -> Self {
        Self {
            // CRITICAL: Keep timeout SHORT to fail fast like Hive Router
            // Long timeouts cause 504 cascades when subgraphs are slow
            timeout_secs: 10,
            connect_timeout_secs: 5, // 5 seconds
            // CRITICAL: Must be high enough to handle concurrent requests to same subgraph
            // With 256 max concurrent requests and ~12 subgraphs, we need 64+ connections/host
            // to avoid connection pool exhaustion causing 504/408 timeouts under load.
            // Previous value of 10 caused intermittent timeouts!
            pool_max_idle_per_host: 64,
            pool_idle_timeout_secs: 90, // 90 seconds (reqwest default)
            tcp_keepalive_secs: 60, // 60 seconds
            gzip_enabled: true,
            // HTTP/2 provides request multiplexing, reducing connection overhead.
            // Enabled by default as Hive Router uses HTTP/2 for subgraph connections.
            http2_enabled: true,
        }
    }
}

/// WebSocket configuration for subscription transport
///
/// Manages WebSocket connections to subscription-capable subgraphs.
/// Uses connection multiplexing - multiple subscriptions share connections.
///
/// # Connection Multiplexing
/// Instead of creating one WebSocket per subscription, connections are pooled:
/// - Multiple subscriptions share a single WebSocket per subgraph
/// - Reduces TCP/TLS handshake overhead
/// - Better resource utilization
/// - Connection health monitoring with ping/pong
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationWebSocketConfig {
    /// Enable WebSocket transport for subscriptions to subgraphs
    pub enabled: bool,

    /// WebSocket path on subgraphs for subscription connections
    /// Appended to subgraph base URL (e.g., "/graphql/ws")
    pub path: String,

    /// Connection timeout in seconds for WebSocket connections
    pub connect_timeout_secs: u64,

    /// Maximum concurrent WebSocket connections per subgraph
    /// Each connection can handle max_subscriptions_per_connection subscriptions
    /// Total subscription capacity = connections × subscriptions_per_connection
    pub max_connections_per_subgraph: usize,

    /// Maximum subscriptions per WebSocket connection (multiplexing)
    /// When reached, a new connection is opened to the same subgraph
    /// Lower values = more connections, higher values = more sharing
    pub max_subscriptions_per_connection: usize,

    /// Ping interval in seconds to keep connections alive
    pub ping_interval_secs: u64,

    /// Pong timeout in seconds before considering connection dead
    /// Connection is marked unhealthy if pong not received within this time
    pub pong_timeout_secs: u64,

    /// Idle timeout in seconds before closing an empty connection
    /// Connections with no subscriptions are closed after this time
    pub idle_timeout_secs: u64,

    /// Reconnection delay in milliseconds (with exponential backoff)
    pub reconnect_delay_ms: u64,

    /// Maximum reconnection attempts before giving up
    pub max_reconnect_attempts: u32,

    // ==========================================================================
    // Redis Pub/Sub for Horizontal Scaling
    // ==========================================================================
    /// Enable Redis pub/sub for cross-pod event distribution
    /// When enabled, subscription events are published to Redis so all BFF pods
    /// can forward events to their local WebSocket clients.
    /// Required for horizontal scaling with multiple BFF replicas.
    pub pub_sub_enabled: bool,

    /// Redis URL for pub/sub (separate from session Redis for isolation)
    /// Format: redis://host:port or redis://host:port/db
    pub pub_sub_redis_url: String,

    /// Buffer size for local broadcast channel (per-pod)
    /// Events that can't be delivered are dropped (subscribers are slow)
    pub pub_sub_channel_buffer_size: usize,

    // ==========================================================================
    // SSE (Server-Sent Events) Fallback Transport
    // ==========================================================================
    /// Enable SSE transport as fallback for WebSocket
    /// SSE is firewall-proof (works through corporate proxies that block WebSocket)
    /// Clients can use SSE when WebSocket upgrade fails
    pub sse_enabled: bool,

    /// Keep-alive interval in seconds for SSE connections
    /// Sends ":" comment to prevent proxy/firewall timeouts
    pub sse_keep_alive_secs: u64,

    /// Maximum SSE connection duration in seconds (0 = unlimited)
    /// Use to prevent resource exhaustion from very long-lived connections
    pub sse_max_duration_secs: u64,
}

impl Default for FederationWebSocketConfig {
    fn default() -> Self {
        Self {
            enabled: true, // WebSocket subscriptions enabled by default
            path: "/graphql".to_string(), // Most subgraphs use same path for HTTP and WS
            connect_timeout_secs: 10, // 10 seconds
            max_connections_per_subgraph: 4, // 4 connections per subgraph (with multiplexing, this handles 400 subscriptions)
            max_subscriptions_per_connection: 100, // 100 subscriptions per connection before opening a new one
            ping_interval_secs: 30, // 30 seconds
            pong_timeout_secs: 10, // 10 seconds to respond to ping before connection is unhealthy
            idle_timeout_secs: 300, // 5 minutes of no subscriptions before closing connection
            reconnect_delay_ms: 1000, // 1 second initial delay
            max_reconnect_attempts: 5, // 5 attempts before giving up
            // Redis pub/sub (disabled by default for backwards compatibility)
            pub_sub_enabled: false,
            pub_sub_redis_url: "redis://localhost:6379".to_string(),
            pub_sub_channel_buffer_size: 1000, // 1000 events in buffer before dropping
            // SSE fallback (enabled by default - firewall-proof transport)
            sse_enabled: true, // SSE enabled by default (firewall-proof fallback)
            sse_keep_alive_secs: 30, // 30 seconds - keeps connections alive through proxies
            sse_max_duration_secs: 0, // Unlimited by default
        }
    }
}

/// Query plan cache configuration
///
/// Caches generated query plans by operation hash to skip planning
/// for repeated operations. Based on Apollo Router's query plan caching.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationQueryPlanCacheConfig {
    /// Enable query plan caching
    pub enabled: bool,

    /// Maximum number of plans to cache (LRU eviction)
    pub max_size: usize,

    /// TTL for cached plans in seconds (0 = no expiry)
    pub ttl_secs: u64,
}

impl Default for FederationQueryPlanCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: 1000, // 1000 plans
            ttl_secs: 0, // No expiry (plans are invalidated on schema change)
        }
    }
}

/// Observability configuration for federation
///
/// Provides metrics, tracing, and logging for federation operations.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationObservabilityConfig {
    /// Enable OpenTelemetry tracing
    pub tracing_enabled: bool,

    /// OTLP endpoint for traces
    pub otlp_endpoint: String,

    /// Enable Prometheus metrics
    pub metrics_enabled: bool,

    /// Log subgraph requests (at debug level)
    pub log_subgraph_requests: bool,

    /// Log subgraph response times (at info level)
    pub log_response_times: bool,
}

impl Default for FederationObservabilityConfig {
    fn default() -> Self {
        Self {
            tracing_enabled: false,
            otlp_endpoint: "http://otel-collector:4317".to_string(),
            metrics_enabled: true,
            log_subgraph_requests: false,
            log_response_times: true,
        }
    }
}

/// Response cache configuration for federation
///
/// In-memory cache using moka for caching GraphQL query responses.
/// Reduces subgraph load for frequently accessed data.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationResponseCacheConfig {
    /// Enable response caching
    pub enabled: bool,

    /// Maximum number of cached entries
    pub max_capacity: u64,

    /// Default TTL for cached responses in seconds
    pub default_ttl_secs: u64,

    /// Maximum size per cached entry in bytes
    pub max_entry_size: usize,

    /// Only cache successful responses (no errors)
    pub cache_only_success: bool,

    /// Operation patterns with custom TTLs
    #[serde(default)]
    pub strategies: Vec<FederationCacheStrategy>,
}

impl Default for FederationResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            max_capacity: 10_000, // 10,000 entries
            default_ttl_secs: 60, // 60 seconds
            max_entry_size: 1024 * 1024, // 1 MB
            cache_only_success: true,
            strategies: vec![],
        }
    }
}

/// Cache strategy for specific operation patterns
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FederationCacheStrategy {
    /// Operation name pattern (e.g., "getProducts", "get*")
    pub operation_pattern: String,

    /// TTL in seconds for this pattern (0 = don't cache)
    pub ttl_secs: u64,
}

/// Request deduplication configuration for federation
///
/// Coalesces concurrent identical queries to reduce subgraph load.
/// When multiple clients request the same query simultaneously,
/// only one request is executed and the result is shared.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationDeduplicationConfig {
    /// Enable request deduplication
    pub enabled: bool,

    /// Maximum time to wait for an in-flight request in seconds
    pub max_wait_secs: u64,

    /// Maximum number of waiters per in-flight request
    pub max_waiters: usize,

    /// TTL for in-flight entries in seconds
    pub entry_ttl_secs: u64,

    /// Maximum concurrent in-flight requests to track
    pub max_entries: usize,
}

impl Default for FederationDeduplicationConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            max_wait_secs: 30, // 30 seconds
            max_waiters: 100, // 100 waiters per request
            entry_ttl_secs: 60, // 60 seconds
            max_entries: 10_000, // 10,000 in-flight requests
        }
    }
}

/// Automatic Persisted Queries (APQ) configuration
///
/// APQ reduces request payload size by allowing clients to send
/// query hashes instead of full query strings. On cache miss,
/// the client sends the full query which is then cached.
///
/// # Protocol (Apollo-compatible)
/// 1. Client sends request with `sha256Hash` in `persistedQuery` extension
/// 2. If cached: execute from cache
/// 3. If not cached: return "PersistedQueryNotFound" error
/// 4. Client retries with full query string + hash
/// 5. Server caches query and executes
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationApqConfig {
    /// Enable Automatic Persisted Queries
    pub enabled: bool,

    /// Maximum number of queries to cache
    pub max_entries: u64,

    /// TTL for cached queries in seconds (0 = no expiry)
    pub ttl_secs: u64,

    /// Maximum query size to cache in bytes
    /// Prevents caching extremely large queries
    pub max_query_size: usize,

    /// Require APQ for all requests (security mode)
    /// When true, rejects requests without persistedQuery extension
    pub required: bool,
}

impl Default for FederationApqConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            max_entries: 10_000, // 10,000 queries
            ttl_secs: 86400, // 24 hours
            max_query_size: 1024 * 1024, // 1 MB
            required: false,
        }
    }
}

/// Federation-level rate limiting configuration
///
/// Multi-level rate limiting with per-user, per-operation, and per-subgraph limits.
/// Uses token bucket algorithm for smooth rate limiting without bursts.
///
/// # Rate Limit Levels
/// 1. **User-level**: Limits total requests per user (authenticated or anonymous)
/// 2. **Operation-level**: Limits specific expensive operations (e.g., mutations)
/// 3. **Subgraph-level**: Protects individual subgraphs from overload
///
/// # Role-based Exemptions
/// Certain roles (admin, service accounts) can be exempted from rate limiting.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationRateLimitConfig {
    /// Enable federation rate limiting
    pub enabled: bool,

    /// Default requests per second per user
    pub default_rps: u32,

    /// Default burst size (token bucket capacity)
    pub default_burst: u32,

    /// Per-operation rate limits (operation name → limits)
    #[serde(default)]
    pub operation_limits: Vec<FederationOperationRateLimit>,

    /// Per-subgraph rate limits (subgraph name → limits)
    #[serde(default)]
    pub subgraph_limits: Vec<FederationSubgraphRateLimit>,

    /// Roles exempted from rate limiting (e.g., "admin", "service")
    pub exempt_roles: Vec<String>,

    /// Cleanup interval for stale user limiters in seconds
    pub cleanup_interval_secs: u64,
}

impl Default for FederationRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            default_rps: 1000, // 1000 requests per second per user
            default_burst: 2000, // Allow burst of 2000 requests
            operation_limits: vec![],
            subgraph_limits: vec![],
            exempt_roles: vec!["admin".to_string(), "service".to_string()],
            cleanup_interval_secs: 300, // 5 minutes
        }
    }
}

/// Rate limit for a specific GraphQL operation
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationOperationRateLimit {
    /// Operation name (e.g., "createOrder", "deleteUser")
    pub operation_name: String,

    /// Requests per second for this operation
    pub rps: u32,

    /// Burst size for this operation
    pub burst: u32,
}

impl Default for FederationOperationRateLimit {
    fn default() -> Self {
        Self {
            operation_name: String::new(),
            rps: 0,
            burst: 2000, // Allow burst of 2000 requests
        }
    }
}

/// Rate limit for a specific subgraph
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationSubgraphRateLimit {
    /// Subgraph name (e.g., "products", "orders")
    pub subgraph_name: String,

    /// Requests per second to this subgraph
    pub rps: u32,

    /// Burst size for this subgraph
    pub burst: u32,
}

impl Default for FederationSubgraphRateLimit {
    fn default() -> Self {
        Self {
            subgraph_name: String::new(),
            rps: 0,
            burst: 2000, // Allow burst of 2000 requests
        }
    }
}

/// Request batching configuration (DataLoader pattern)
///
/// Batches multiple entity requests within a time window to solve
/// the N+1 problem and reduce network overhead.
///
/// # How It Works
/// 1. Multiple requests for entities queue up during batch window
/// 2. At window close or max size, single batch request is made
/// 3. Results are distributed to waiting requests
/// 4. Caching prevents re-fetching recently loaded entities
///
/// # Example
/// ```text
/// Without batching: 4 separate HTTP requests
/// query { post1 { author } } → fetch author 1
/// query { post2 { author } } → fetch author 2
/// query { post3 { author } } → fetch author 1 (duplicate!)
/// query { post4 { author } } → fetch author 3
///
/// With batching: 1 batched HTTP request
/// _entities(representations: [author1, author2, author3])
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationBatchingConfig {
    /// Enable request batching
    pub enabled: bool,

    /// Batch window in milliseconds
    /// Requests within this window are batched together
    pub batch_window_ms: u64,

    /// Maximum batch size before forcing execution
    pub max_batch_size: usize,

    /// Enable in-batch caching (deduplicate within batch window)
    pub cache_enabled: bool,

    /// Cache TTL in milliseconds for batched entities
    pub cache_ttl_ms: u64,
}

impl Default for FederationBatchingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            batch_window_ms: 10, // 10ms batch window (good balance between latency and batching efficiency)
            max_batch_size: 100, // Max 100 entities per batch
            cache_enabled: true,
            cache_ttl_ms: 1000, // 1 second cache TTL
        }
    }
}

/// Query planner configuration
///
/// Controls query planning behavior including caching, parsing,
/// and field ownership resolution.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationQueryPlannerConfig {
    /// Enable the query planner
    /// When disabled, queries are proxied to Hive Router unchanged
    pub enabled: bool,

    /// Maximum number of query plans to cache
    pub plan_cache_size: u64,

    /// Enable query plan caching
    pub cache_enabled: bool,
}

impl Default for FederationQueryPlannerConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enable query planner when federation is enabled
            plan_cache_size: 1000, // Cache up to 1000 query plans
            cache_enabled: true,
        }
    }
}

/// Plan executor configuration
///
/// Controls how query plans are executed against subgraphs,
/// including concurrency, timeouts, and retry behavior.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationExecutorConfig {
    /// Request timeout per subgraph call in seconds
    pub timeout_secs: u64,

    /// Maximum concurrent subgraph calls
    pub max_concurrency: usize,

    /// Number of retries for failed fetches
    pub retry_count: usize,

    /// Delay between retries in milliseconds
    pub retry_delay_ms: u64,
}

impl Default for FederationExecutorConfig {
    fn default() -> Self {
        Self {
            // CRITICAL: Keep timeout SHORT to fail fast like Hive Router
            // Long timeouts cause 504 cascades - if subgraph is slow, fail quickly
            // 10 seconds is generous for any well-behaved subgraph
            timeout_secs: 10,
            // CRITICAL: Set high enough to not block under normal load
            // Each GraphQL query may need 3-5+ subgraph calls
            // With 100 concurrent users, that's 300-500 subgraph calls
            // Previous value of 16 caused request queuing and 504 timeouts!
            max_concurrency: 256,
            retry_count: 1, // Retry once on failure
            retry_delay_ms: 100, // 100ms delay between retries
        }
    }
}

/// Security configuration for federation
///
/// Protects against malicious queries with:
/// - Query depth limiting (DoS protection)
/// - Query complexity analysis (cost-based rejection)
/// - Introspection control (disable in production)
///
/// # Security Research
/// According to industry research, 80% of GraphQL APIs are vulnerable to
/// DoS attacks via deeply nested or complex queries. These protections
/// are essential for production deployments.
///
/// # References
/// - [GraphQL Security Best Practices](https://graphql.org/learn/security/)
/// - [Apollo GraphQL Security Checklist](https://www.apollographql.com/blog/9-ways-to-secure-your-graphql-api-security-checklist)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FederationSecurityConfig {
    /// Enable security features
    #[serde(default)]
    pub enabled: bool,

    /// Query depth limiting configuration
    #[serde(default)]
    pub depth_limit: FederationDepthLimitConfig,

    /// Query complexity analysis configuration
    #[serde(default)]
    pub complexity: FederationComplexityConfig,

    /// Introspection control configuration
    #[serde(default)]
    pub introspection: FederationIntrospectionConfig,
}

impl Default for FederationSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            depth_limit: FederationDepthLimitConfig::default(),
            complexity: FederationComplexityConfig::default(),
            introspection: FederationIntrospectionConfig::default(),
        }
    }
}

/// Query depth limiting configuration
///
/// Prevents deeply nested queries that could cause resource exhaustion.
/// The default depth of 10 is suitable for most applications.
/// Introspection queries typically have depth ~13, so they can be
/// allowed to exceed the limit via `allow_introspection_override`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationDepthLimitConfig {
    /// Enable depth limiting
    pub enabled: bool,

    /// Maximum allowed query depth
    pub max_depth: usize,

    /// Allow introspection queries to exceed depth limit
    /// (Introspection queries have depth ~13)
    pub allow_introspection_override: bool,
}

impl Default for FederationDepthLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_depth: 10, // Suitable for most applications
            allow_introspection_override: true, // Allow introspection to exceed depth limit
        }
    }
}

/// Query complexity analysis configuration
///
/// Estimates query cost before execution to prevent expensive queries
/// that could overload the system. Uses a simple cost model:
/// - Each field costs `default_field_cost` (default: 1)
/// - List fields multiply cost by `list_multiplier` (default: 10)
/// - Custom costs can be assigned per field
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationComplexityConfig {
    /// Enable complexity analysis
    pub enabled: bool,

    /// Maximum allowed complexity score
    pub max_complexity: u32,

    /// Default cost per field
    pub default_field_cost: u32,

    /// Cost multiplier for list fields
    pub list_multiplier: u32,

    /// Custom costs per field (field name → cost)
    #[serde(default)]
    pub field_costs: Vec<FederationFieldCost>,
}

impl Default for FederationComplexityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_complexity: 1000, // Suitable for most applications
            default_field_cost: 1, // Each field costs 1 by default
            list_multiplier: 10, // List fields multiply cost by 10
            field_costs: vec![],
        }
    }
}

/// Custom field cost configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FederationFieldCost {
    /// Field name (e.g., "products", "user.orders")
    pub field: String,

    /// Cost for this field
    pub cost: u32,
}

/// Introspection control configuration
///
/// Controls access to introspection queries (`__schema`, `__type`).
/// Recommended to disable in production to prevent schema discovery.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationIntrospectionConfig {
    /// Allow introspection queries (disable in production)
    pub enabled: bool,

    /// Allow introspection from specific IP addresses (e.g., localhost)
    pub allowed_ips: Vec<String>,

    /// Allow introspection for requests with specific headers
    /// Format: [("header-name", "header-value")]
    #[serde(default)]
    pub allowed_headers: Vec<FederationAllowedHeader>,
}

impl Default for FederationIntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for development
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            allowed_headers: vec![],
        }
    }
}

/// Allowed header for introspection access
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FederationAllowedHeader {
    /// Header name
    pub name: String,

    /// Expected header value
    pub value: String,
}

/// Custom plugins configuration
///
/// Enables the Tower-based middleware plugin system for extending
/// federation behavior. Inspired by Apollo Router's plugin architecture.
///
/// # Plugin Lifecycle
/// ```text
/// Request → [Pre-Parse] → [Parse] → [Validate] → [Pre-Execute] → Execute → [Post-Execute] → Response
/// ```
///
/// # Built-in Plugins (Priority Order)
/// - RequestId (1): Request ID generation and propagation
/// - Tracing (5): OpenTelemetry span creation
/// - Security (6): Depth limiting, complexity analysis, introspection control
/// - Timeout (7): Per-operation timeout limits
/// - AllowList (8): Query allow-listing for security
/// - HeaderPropagation (10): Header control between client/subgraphs
/// - Metrics (15): Prometheus metrics recording
/// - Logging (20): Structured request/response logging
/// - Performance (200): Slow query detection
/// - CostTracking (250): Query cost metering
/// - ResponseExtensions (800): Response metadata
/// - Audit (850): Compliance audit logging
/// - ErrorMasking (900): Production error safety
/// - Sanitization (950): Response sanitization
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct FederationPluginsConfig {
    /// Enable the plugin system
    pub enabled: bool,

    /// Whether plugin errors should abort the request (fail-fast)
    /// When false, plugin errors are logged but the request continues
    pub fail_fast: bool,

    /// Enable the built-in security plugin
    /// Uses security config from `security` section
    pub security_plugin: bool,

    /// Enable the built-in tracing plugin
    pub tracing_plugin: bool,

    /// Include query in tracing spans (may expose sensitive data)
    pub tracing_include_query: bool,

    /// Include variables in tracing spans (may expose sensitive data)
    pub tracing_include_variables: bool,

    /// Enable the built-in metrics plugin
    pub metrics_plugin: bool,

    /// Request ID plugin configuration
    pub request_id: PluginRequestIdConfig,

    /// Logging plugin configuration
    pub logging: PluginLoggingConfig,

    /// Error masking plugin configuration
    pub error_masking: PluginErrorMaskingConfig,

    /// Performance monitoring plugin configuration
    pub performance: PluginPerformanceConfig,

    /// Cost tracking plugin configuration
    pub cost_tracking: PluginCostTrackingConfig,

    /// Response extensions plugin configuration
    pub response_extensions: PluginResponseExtensionsConfig,

    /// Audit logging plugin configuration
    pub audit: PluginAuditConfig,

    /// Timeout plugin configuration
    pub timeout: PluginTimeoutConfig,

    /// Header propagation plugin configuration
    pub header_propagation: PluginHeaderPropagationConfig,

    /// Allow list plugin configuration
    pub allow_list: PluginAllowListConfig,

    /// Response sanitization plugin configuration
    pub sanitization: PluginSanitizationConfig,
}

impl Default for FederationPluginsConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for Phase 2
            fail_fast: true, // Abort request on plugin errors
            security_plugin: false,
            tracing_plugin: false,
            tracing_include_query: false,
            tracing_include_variables: false,
            metrics_plugin: true, // Metrics enabled by default when plugins are enabled
            request_id: PluginRequestIdConfig::default(),
            logging: PluginLoggingConfig::default(),
            error_masking: PluginErrorMaskingConfig::default(),
            performance: PluginPerformanceConfig::default(),
            cost_tracking: PluginCostTrackingConfig::default(),
            response_extensions: PluginResponseExtensionsConfig::default(),
            audit: PluginAuditConfig::default(),
            timeout: PluginTimeoutConfig::default(),
            header_propagation: PluginHeaderPropagationConfig::default(),
            allow_list: PluginAllowListConfig::default(),
            sanitization: PluginSanitizationConfig::default(),
        }
    }
}

/// Request ID plugin configuration
///
/// Generates or propagates request IDs for distributed tracing.
/// Request IDs follow existing headers or generate UUIDs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginRequestIdConfig {
    /// Enable request ID plugin
    pub enabled: bool,

    /// Header name to read/write request ID
    pub header_name: String,

    /// Prefix for generated request IDs
    pub prefix: String,

    /// Include request ID in response headers
    pub include_in_response: bool,

    /// Response header name for request ID
    pub response_header_name: String,
}

impl Default for PluginRequestIdConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for traceability
            header_name: "x-request-id".to_string(),
            prefix: "req-".to_string(),
            include_in_response: true,
            response_header_name: "x-request-id".to_string(),
        }
    }
}

/// Logging plugin configuration
///
/// Structured logging for GraphQL requests with configurable verbosity.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginLoggingConfig {
    /// Enable logging plugin
    pub enabled: bool,

    /// Log level: "trace", "debug", "info", "warn", "error"
    pub level: String,

    /// Include query in logs (may expose sensitive data)
    pub include_query: bool,

    /// Include variables in logs (may expose sensitive data)
    pub include_variables: bool,

    /// Include response in logs (may be large)
    pub include_response: bool,

    /// Maximum query length to log (truncates longer queries)
    pub max_query_length: usize,

    /// Log slow queries above threshold
    pub log_slow_queries: bool,

    /// Slow query threshold in milliseconds
    pub slow_query_threshold_ms: u64,

    /// Operations to exclude from logging
    #[serde(default)]
    pub exclude_operations: Vec<String>,
}

impl Default for PluginLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            level: "info".to_string(),
            include_query: false,
            include_variables: false,
            include_response: false,
            max_query_length: 1000,
            log_slow_queries: true,
            slow_query_threshold_ms: 1000, // 1 second
            exclude_operations: vec![],
        }
    }
}

/// Error masking plugin configuration
///
/// Masks internal errors in production to prevent information leakage.
/// Critical for security - internal stack traces should never reach clients.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginErrorMaskingConfig {
    /// Enable error masking plugin
    pub enabled: bool,

    /// Mask internal error messages
    pub mask_internal_errors: bool,

    /// Message to show for masked errors
    pub masked_message: String,

    /// Error codes to pass through unmasked (e.g., UNAUTHENTICATED, FORBIDDEN)
    pub passthrough_codes: Vec<String>,

    /// Include error code in masked response
    pub include_code: bool,

    /// Include request ID in masked response for support reference
    pub include_request_id: bool,
}

impl Default for PluginErrorMaskingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mask_internal_errors: true,
            masked_message: "An internal error occurred. Please try again later.".to_string(),
            passthrough_codes: vec![
                "UNAUTHENTICATED".to_string(),
                "FORBIDDEN".to_string(),
                "BAD_USER_INPUT".to_string(),
                "VALIDATION_ERROR".to_string(),
                "NOT_FOUND".to_string(),
            ],
            include_code: true,
            include_request_id: true,
        }
    }
}

/// Performance monitoring plugin configuration
///
/// Monitors query performance and detects slow queries.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginPerformanceConfig {
    /// Enable performance monitoring plugin
    pub enabled: bool,

    /// Slow query threshold in milliseconds
    pub slow_query_threshold_ms: u64,

    /// Critical query threshold in milliseconds
    pub critical_threshold_ms: u64,

    /// Track performance by operation name
    pub track_by_operation: bool,

    /// Maximum operations to track
    pub max_tracked_operations: usize,

    /// Include optimization hints in response extensions
    pub include_hints: bool,
}

impl Default for PluginPerformanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            slow_query_threshold_ms: 1000, // 1 second
            critical_threshold_ms: 5000, // 5 seconds
            track_by_operation: true,
            max_tracked_operations: 1000,
            include_hints: false,
        }
    }
}

/// Cost tracking plugin configuration
///
/// Tracks query costs for billing, quotas, and rate limiting.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginCostTrackingConfig {
    /// Enable cost tracking plugin
    pub enabled: bool,

    /// Track costs by user
    pub track_by_user: bool,

    /// Track costs by operation
    pub track_by_operation: bool,

    /// Include cost in response extensions
    pub include_in_response: bool,

    /// User hourly cost budget (0 = unlimited)
    pub user_hourly_budget: u32,

    /// Warning threshold percentage (0-100)
    pub budget_warning_threshold: u8,
}

impl Default for PluginCostTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            track_by_user: true,
            track_by_operation: true,
            include_in_response: false,
            user_hourly_budget: 0,
            budget_warning_threshold: 80,
        }
    }
}

/// Response extensions plugin configuration
///
/// Adds metadata to GraphQL response extensions.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginResponseExtensionsConfig {
    /// Enable response extensions plugin
    pub enabled: bool,

    /// Include timing information
    pub include_timing: bool,

    /// Include cache status
    pub include_cache_status: bool,

    /// Include query complexity score
    pub include_complexity: bool,

    /// Include request ID
    pub include_request_id: bool,

    /// Include API version
    pub include_version: bool,

    /// API version string
    pub version: String,
}

impl Default for PluginResponseExtensionsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            include_timing: true,
            include_cache_status: false,
            include_complexity: false,
            include_request_id: true,
            include_version: false,
            version: "1.0.0".to_string(),
        }
    }
}

/// Audit logging plugin configuration
///
/// Logs operations for compliance and security auditing.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginAuditConfig {
    /// Enable audit logging plugin
    pub enabled: bool,

    /// Operations to audit (empty = all operations)
    #[serde(default)]
    pub audited_operations: Vec<String>,

    /// Operations to exclude from auditing
    #[serde(default)]
    pub excluded_operations: Vec<String>,

    /// Only audit mutations (not queries)
    pub mutations_only: bool,

    /// Include query in audit log
    pub include_query: bool,

    /// Include variables in audit log
    pub include_variables: bool,

    /// Include response status in audit log
    pub include_response_status: bool,
}

impl Default for PluginAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audited_operations: vec![],
            excluded_operations: vec![],
            mutations_only: false,
            include_query: false,
            include_variables: false,
            include_response_status: true,
        }
    }
}

/// Timeout plugin configuration
///
/// Enforces per-operation timeout limits.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginTimeoutConfig {
    /// Enable timeout plugin
    pub enabled: bool,

    /// Default timeout in seconds for all operations
    pub default_timeout_secs: u64,

    /// Per-operation timeout overrides
    #[serde(default)]
    pub operation_timeouts: Vec<OperationTimeoutConfig>,

    /// Per-type timeout overrides (query, mutation, subscription)
    pub type_timeouts: OperationTypeTimeouts,
}

impl Default for PluginTimeoutConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_timeout_secs: 30,
            operation_timeouts: vec![],
            type_timeouts: OperationTypeTimeouts::default(),
        }
    }
}

/// Per-operation timeout configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OperationTimeoutConfig {
    /// Operation name
    pub operation: String,

    /// Timeout in seconds
    pub timeout_secs: u64,
}

/// Timeout limits per operation type
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OperationTypeTimeouts {
    /// Query timeout in seconds (0 = use default)
    #[serde(default)]
    pub query_secs: u64,

    /// Mutation timeout in seconds (0 = use default)
    #[serde(default)]
    pub mutation_secs: u64,

    /// Subscription timeout in seconds (0 = use default)
    #[serde(default)]
    pub subscription_secs: u64,
}

/// Header propagation plugin configuration
///
/// Controls which headers are propagated between client and subgraphs.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginHeaderPropagationConfig {
    /// Enable header propagation plugin
    pub enabled: bool,

    /// Headers to propagate from client to subgraphs
    pub propagate_to_subgraphs: Vec<String>,

    /// Headers to propagate from subgraph to client response
    #[serde(default)]
    pub propagate_to_client: Vec<String>,

    /// Headers to strip from subgraph requests
    pub strip_headers: Vec<String>,

    /// Default headers to add to all subgraph requests
    #[serde(default)]
    pub add_headers: Vec<HeaderConfig>,
}

impl Default for PluginHeaderPropagationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            propagate_to_subgraphs: vec![
                "x-request-id".to_string(),
                "x-correlation-id".to_string(),
                "x-user-id".to_string(),
                "x-product".to_string(),
                "accept-language".to_string(),
            ],
            propagate_to_client: vec![],
            strip_headers: vec![
                "host".to_string(),
                "authorization".to_string(), // Re-added by auth middleware
                "cookie".to_string(),
            ],
            add_headers: vec![],
        }
    }
}

/// Header to add to requests
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HeaderConfig {
    /// Header name
    pub name: String,

    /// Header value
    pub value: String,
}

/// Allow list plugin configuration
///
/// Restricts allowed queries for security in production.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginAllowListConfig {
    /// Enable allow list plugin
    pub enabled: bool,

    /// Strict mode: reject all queries not in allow list
    pub strict_mode: bool,

    /// Allowed operation names
    #[serde(default)]
    pub allowed_operations: Vec<String>,

    /// Allowed query hashes (SHA256)
    #[serde(default)]
    pub allowed_hashes: Vec<String>,

    /// Log blocked queries
    pub log_blocked: bool,
}

impl Default for PluginAllowListConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            strict_mode: false,
            allowed_operations: vec![],
            allowed_hashes: vec![],
            log_blocked: true,
        }
    }
}

/// Response sanitization plugin configuration
///
/// Sanitizes responses to remove sensitive data.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PluginSanitizationConfig {
    /// Enable sanitization plugin
    pub enabled: bool,

    /// Remove __typename from responses
    pub remove_typename: bool,

    /// Remove null values from responses
    pub remove_nulls: bool,

    /// Fields to completely remove from responses
    #[serde(default)]
    pub remove_fields: Vec<String>,

    /// Fields to redact (replace with "[REDACTED]")
    pub redact_fields: Vec<String>,
}

impl Default for PluginSanitizationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            remove_typename: false,
            remove_nulls: false,
            remove_fields: vec![],
            redact_fields: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "apiKey".to_string(),
                "api_key".to_string(),
                "creditCard".to_string(),
                "credit_card".to_string(),
                "ssn".to_string(),
            ],
        }
    }
}
