#![allow(dead_code)]
//! Federation Execution Layer
//!
//! This module provides the main entry point for executing federated GraphQL
//! operations directly from the BFF, bypassing Hive Router.
//!
//! # Execution Flow
//!
//! ```text
//! Request
//!    │
//!    ▼
//! ┌─────────────────┐
//! │  Rate Limiter   │ → Check rate limits
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  APQ Lookup     │ → Resolve persisted query hash
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Security       │ → Depth/complexity validation
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Cache Check    │ → L1 → L2 lookup
//! └────────┬────────┘
//!          │ MISS
//!          ▼
//! ┌─────────────────┐
//! │  Query Planner  │ → Create execution plan
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Plan Executor  │ → Execute against subgraphs
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Cache Store    │ → Store in L1 + L2
//! └────────┬────────┘
//!          ▼
//!       Response
//! ```

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderMap, StatusCode};
use once_cell::sync::Lazy;

/// PERFORMANCE: Static RandomState for deterministic hashing within process lifetime.
/// Initialized once, reused for all hash operations. ahash is 2-3x faster than DefaultHasher.
static AHASH_STATE: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);


use axum::response::IntoResponse;
use axum::Json;
use serde_json::{json, Value};
use tracing::{debug, error, info, warn};

use crate::metrics::{MetricsClient, MetricsExt};
use crate::redis::LazyRedisPool;

use super::apq::{ApqCache, ApqConfig, ApqLookupResult};
use super::batch::{BatchConfig, SubgraphBatcherFactory};
use super::deduplication::{
    DeduplicationConfig, DeduplicationKey, DeduplicationResult, RequestDeduplicator,
};
use super::hive_planner::HivePlanner;
use super::plan_executor::{ExecutionContext, ExecutorConfig, GraphQLError, PlanExecutor};
use super::plugins::{
    AllowListConfig,
    AllowListPlugin,
    AuditConfig,
    AuditPlugin,
    CostTrackingConfig,
    CostTrackingPlugin,
    ErrorMaskingConfig,
    // Security plugins
    ErrorMaskingPlugin,
    HeaderPropagationConfig,
    HeaderPropagationPlugin,
    LoggingConfig,
    LoggingPlugin,
    MetricsPlugin,
    PerformanceConfig,
    // Observability plugins
    PerformancePlugin,
    PluginContext,
    PluginRegistry,
    PluginResponse,
    RequestIdConfig,
    // Request handling plugins
    RequestIdPlugin,
    ResponseExtensionsConfig,
    ResponseExtensionsPlugin,
    SanitizationConfig,
    SanitizationPlugin,
    SecurityPlugin,
    TimeoutConfig,
    // Additional plugins (config-driven)
    TimeoutPlugin,
    // Core plugins
    TracingPlugin,
};
use super::query_planner::QueryPlanner;
use crate::rate_limiting::{
    FederationRateLimiter, OperationType, RateLimitConfig, RateLimitContext, RateLimitResult,
};
use super::redis_cache::{create_response_cache_with_pressure, TwoTierCache};
use super::security::{
    ComplexityConfig, DepthLimitConfig, DepthLimiter, IntrospectionConfig, SecurityError,
};
use super::supergraph::Supergraph;
use crate::memory::PressureCoordinator;

use crate::config::FederationPluginsConfig;
use crate::rate_limiting::DynamicRateLimiter;

/// Configuration for the federation executor
#[derive(Debug, Clone)]
pub struct FederationExecutorConfig {
    /// Enable federation execution (vs proxy mode)
    pub enabled: bool,

    /// Enable response caching
    pub cache_enabled: bool,

    /// Enable rate limiting
    pub rate_limit_enabled: bool,

    /// Enable APQ
    pub apq_enabled: bool,

    /// Enable security validation (depth/complexity)
    pub security_enabled: bool,

    /// Enable plugin system
    pub plugins_enabled: bool,

    /// Enable entity batching (N+1 prevention)
    pub batching_enabled: bool,

    /// Enable request deduplication
    /// When disabled (performance mode), identical concurrent queries are NOT deduplicated
    /// This saves latency from dedup coordination overhead
    pub dedup_enabled: bool,

    /// HMAC secret for signing subgraph requests
    /// When set, adds HMAC signature to GraphQL extensions field
    /// Must match the secret configured on subgraphs
    pub hmac_secret: Option<String>,

    /// Use Hive Router query planner instead of custom planner
    /// The Hive planner is production-grade with 189 Federation v2 compliance tests
    /// and handles all edge cases (entity resolution, @requires, @provides, etc.)
    pub use_hive_planner: bool,
}

impl Default for FederationExecutorConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Opt-in for now
            cache_enabled: true,
            rate_limit_enabled: true,
            apq_enabled: true,
            security_enabled: true,
            plugins_enabled: true,
            batching_enabled: true,
            dedup_enabled: true, // Can be disabled in performance mode
            hmac_secret: None,
            use_hive_planner: true, // Use Hive planner by default (more complete)
        }
    }
}

/// The main federation executor that orchestrates all federation features
///
/// # Execution Pipeline
///
/// ```text
/// Request
///    │
///    ▼
/// ┌─────────────────┐
/// │  Rate Limiter   │ → Check rate limits (per-user, per-operation)
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  APQ Lookup     │ → Resolve persisted query hash
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  Security       │ → Depth/complexity validation
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  Deduplication  │ → Coalesce concurrent identical queries
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  Cache Check    │ → L1 → L2 lookup
/// └────────┬────────┘
///          │ MISS
///          ▼
/// ┌─────────────────┐
/// │  Query Planner  │ → Create execution plan
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  Plan Executor  │ → Execute against subgraphs
/// └────────┬────────┘
///          ▼
/// ┌─────────────────┐
/// │  Cache Store    │ → Store in L1 + L2
/// └────────┬────────┘
///          ▼
///       Response
/// ```
pub struct FederationExecutor {
    /// Configuration
    config: FederationExecutorConfig,

    /// Default product identifier for multi-tenant isolation
    /// Set from config.bff.product during construction
    default_product: String,

    /// Supergraph schema
    #[allow(dead_code)]
    supergraph: Arc<Supergraph>,

    /// Query planner (custom implementation)
    query_planner: QueryPlanner,

    /// Hive Router query planner (production-grade Federation v2)
    hive_planner: Option<HivePlanner>,

    /// Plan executor
    plan_executor: PlanExecutor,

    /// Response cache (two-tier: L1 moka + L2 Redis)
    response_cache: Option<TwoTierCache<Value>>,

    /// APQ cache for persisted queries
    apq_cache: Option<ApqCache>,

    /// Rate limiter for request throttling
    rate_limiter: Option<FederationRateLimiter>,

    /// Depth limiter for query validation
    depth_limiter: Option<DepthLimiter>,

    /// Request deduplicator for coalescing identical queries
    deduplicator: Option<RequestDeduplicator>,

    /// Entity batcher factory for N+1 prevention
    #[allow(dead_code)]
    batcher_factory: Option<SubgraphBatcherFactory>,

    /// Plugin registry for extensibility hooks
    plugin_registry: Option<PluginRegistry>,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,

    /// Dynamic rate limiter for runtime config updates from admin settings
    dynamic_rate_limiter: Option<Arc<DynamicRateLimiter>>,
}

/// Default cache size for query plans
const DEFAULT_PLAN_CACHE_SIZE: u64 = 1000;

impl FederationExecutor {
    /// Create a new federation executor
    ///
    /// # Arguments
    /// * `config` - Feature flags for enabling/disabling functionality
    /// * `plugins_config` - Configuration for all plugins (determines which plugins are enabled)
    /// * `supergraph` - The federated supergraph schema
    /// * `redis` - Optional Redis connection for L2 cache (required when cache_enabled)
    /// * `http_client` - HTTP client for subgraph calls (uses properly pooled client from state)
    /// * `metrics` - Optional metrics client for observability
    /// * `pressure_coordinator` - Optional pressure coordinator for memory management
    /// * `default_product` - Default product identifier for multi-tenant isolation (from config.bff.product)
    pub fn new(
        config: FederationExecutorConfig,
        plugins_config: FederationPluginsConfig,
        supergraph: Arc<Supergraph>,
        redis: Option<Arc<LazyRedisPool>>,
        http_client: Option<Arc<reqwest::Client>>,
        metrics: Option<Arc<MetricsClient>>,
        pressure_coordinator: Option<Arc<PressureCoordinator>>,
        default_product: String,
    ) -> Self {
        Self::with_dynamic_rate_limiter(
            config,
            plugins_config,
            supergraph,
            redis,
            http_client,
            metrics,
            pressure_coordinator,
            default_product,
            None,
        )
    }

    /// Create a new federation executor with an optional dynamic rate limiter
    ///
    /// When `dynamic_rate_limiter` is provided, the executor checks it before each
    /// rate limit operation. This enables runtime hot-reload of rate limit config
    /// from admin settings via NATS.
    pub fn with_dynamic_rate_limiter(
        config: FederationExecutorConfig,
        plugins_config: FederationPluginsConfig,
        supergraph: Arc<Supergraph>,
        redis: Option<Arc<LazyRedisPool>>,
        http_client: Option<Arc<reqwest::Client>>,
        metrics: Option<Arc<MetricsClient>>,
        pressure_coordinator: Option<Arc<PressureCoordinator>>,
        default_product: String,
        dynamic_rate_limiter: Option<Arc<DynamicRateLimiter>>,
    ) -> Self {
        // Use provided HTTP client or create fallback with proper pool settings
        // CRITICAL: Default reqwest client has pool_max_idle_per_host=1 which causes
        // connection exhaustion and 504/408 timeouts under load!
        let http_client = http_client.map(|c| (*c).clone()).unwrap_or_else(|| {
            match reqwest::Client::builder()
                // CRITICAL: Keep timeout SHORT to fail fast like Hive Router
                // Long timeouts cause 504 cascades - if subgraph is slow, fail quickly
                .timeout(std::time::Duration::from_secs(10))
                .connect_timeout(std::time::Duration::from_secs(5)) // Fast-fail on unreachable subgraphs
                .pool_max_idle_per_host(64) // Match config default - high enough for concurrent requests!
                .pool_idle_timeout(std::time::Duration::from_secs(90))
                .tcp_keepalive(std::time::Duration::from_secs(60))
                .tcp_nodelay(true) // Disable Nagle's algorithm for lower latency
                .build()
            {
                Ok(client) => client,
                Err(e) => {
                    // Client creation should never fail with these options
                    // Fall back to default client if it does
                    tracing::error!(error = %e, "Failed to create optimized HTTP client, using defaults");
                    reqwest::Client::new()
                }
            }
        });

        let query_planner =
            QueryPlanner::new(supergraph.clone(), DEFAULT_PLAN_CACHE_SIZE, metrics.clone());

        // Initialize Hive planner if enabled
        let hive_planner = if config.use_hive_planner {
            match HivePlanner::new(&supergraph.schema) {
                Ok(planner) => {
                    info!("Federation Hive planner: enabled (production-grade Federation v2)");
                    Some(planner)
                }
                Err(e) => {
                    warn!(
                        "Failed to initialize Hive planner, falling back to custom: {}",
                        e
                    );
                    None
                }
            }
        } else {
            info!("Federation Hive planner: disabled (using custom planner)");
            None
        };

        let plan_executor =
            PlanExecutor::new(http_client, ExecutorConfig::default(), metrics.clone());

        // Initialize response cache if enabled
        // Uses two-tier cache: L1 (moka in-memory) + L2 (Redis distributed)
        // Note: Cache is created with pressure_coordinator reference for adaptive eviction
        let response_cache = if config.cache_enabled {
            if redis.is_some() {
                info!("Federation response cache: L1 (moka) + L2 (Redis)");
            } else {
                info!("Federation response cache: L1 only (no Redis configured)");
            }
            Some(create_response_cache_with_pressure(
                redis,
                metrics.clone(),
                pressure_coordinator.clone(),
            ))
        } else {
            info!("Federation response cache: disabled");
            None
        };

        // Initialize APQ cache if enabled
        let apq_cache = if config.apq_enabled {
            info!("Federation APQ: enabled");
            Some(ApqCache::new(ApqConfig::default(), metrics.clone()))
        } else {
            info!("Federation APQ: disabled");
            None
        };

        // Initialize rate limiter if enabled
        let rate_limiter = if config.rate_limit_enabled {
            info!("Federation rate limiting: enabled");
            Some(FederationRateLimiter::new(
                RateLimitConfig::default(),
                metrics.clone(),
            ))
        } else {
            info!("Federation rate limiting: disabled");
            None
        };

        // Initialize depth limiter if enabled
        let depth_limiter = if config.security_enabled {
            info!("Federation security (depth limiting): enabled");
            Some(DepthLimiter::new(
                DepthLimitConfig::default(),
                metrics.clone(),
            ))
        } else {
            info!("Federation security (depth limiting): disabled");
            None
        };

        // Initialize request deduplicator if enabled
        // In performance mode, deduplication is disabled to reduce coordination overhead
        let deduplicator = if config.dedup_enabled {
            info!("Federation request deduplication: enabled");
            Some(RequestDeduplicator::new(
                DeduplicationConfig::default(),
                metrics.clone(),
            ))
        } else {
            info!("Federation request deduplication: disabled (performance mode)");
            None
        };

        // Initialize entity batcher factory if enabled
        let batcher_factory = if config.batching_enabled {
            info!("Federation entity batching: enabled");
            Some(SubgraphBatcherFactory::new(
                BatchConfig::default(),
                metrics.clone(),
            ))
        } else {
            info!("Federation entity batching: disabled");
            None
        };

        // Initialize plugin registry if enabled
        let plugin_registry = if config.plugins_enabled && plugins_config.enabled {
            info!("Federation plugins: enabled");

            // Create registry and register plugins based on configuration
            // Plugins are registered in priority order (lower = earlier)
            let mut registry = PluginRegistry::new(metrics.clone());

            // Priority 1: RequestIdPlugin - Establishes request ID first
            if plugins_config.request_id.enabled {
                registry = registry.register(Arc::new(RequestIdPlugin::new(RequestIdConfig {
                    header_name: plugins_config.request_id.header_name.clone(),
                    prefix: plugins_config.request_id.prefix.clone(),
                    include_in_response: plugins_config.request_id.include_in_response,
                    response_header_name: plugins_config.request_id.response_header_name.clone(),
                })));
                debug!("  - RequestIdPlugin: enabled");
            }

            // Priority 3: LoggingPlugin - Log request start (after request ID)
            if plugins_config.logging.enabled {
                registry = registry.register(Arc::new(LoggingPlugin::new(LoggingConfig {
                    level: plugins_config.logging.level.clone(),
                    include_query: plugins_config.logging.include_query,
                    include_variables: plugins_config.logging.include_variables,
                    log_slow_queries: plugins_config.logging.log_slow_queries,
                    slow_query_threshold_ms: plugins_config.logging.slow_query_threshold_ms,
                    ..Default::default()
                })));
                debug!("  - LoggingPlugin: enabled");
            }

            // Priority 5: TracingPlugin - OpenTelemetry spans
            if plugins_config.tracing_plugin {
                registry = registry.register(Arc::new(TracingPlugin::new(
                    plugins_config.tracing_include_query,
                    plugins_config.tracing_include_variables,
                )));
                debug!("  - TracingPlugin: enabled");
            }

            // Priority 8: AllowListPlugin - Query allow-list enforcement
            if plugins_config.allow_list.enabled {
                registry = registry.register(Arc::new(AllowListPlugin::new(
                    AllowListConfig {
                        strict_mode: plugins_config.allow_list.strict_mode,
                        allowed_operations: plugins_config.allow_list.allowed_operations.clone(),
                        allowed_hashes: plugins_config.allow_list.allowed_hashes.clone(),
                        log_blocked: plugins_config.allow_list.log_blocked,
                    },
                    metrics.clone(),
                )));
                debug!("  - AllowListPlugin: enabled");
            }

            // Priority 10: SecurityPlugin - Depth, complexity, and introspection control
            if plugins_config.security_plugin {
                registry = registry.register(Arc::new(SecurityPlugin::new(
                    Some(DepthLimitConfig::default()),
                    Some(ComplexityConfig::default()),
                    Some(IntrospectionConfig::default()),
                    metrics.clone(),
                )));
                debug!("  - SecurityPlugin: enabled");
            }

            // Priority 12: TimeoutPlugin - Per-operation timeouts
            if plugins_config.timeout.enabled {
                registry = registry.register(Arc::new(TimeoutPlugin::new(
                    TimeoutConfig {
                        default_timeout_ms: plugins_config.timeout.default_timeout_secs * 1000,
                        operation_timeouts: plugins_config
                            .timeout
                            .operation_timeouts
                            .iter()
                            .map(|ot| (ot.operation.clone(), ot.timeout_secs * 1000))
                            .collect(),
                        include_in_response: false,
                    },
                    metrics.clone(),
                )));
                debug!("  - TimeoutPlugin: enabled");
            }

            // Priority 15: MetricsPlugin - Record metrics
            if plugins_config.metrics_plugin {
                if let Some(ref m) = metrics {
                    registry = registry.register(Arc::new(MetricsPlugin::new(m.clone())));
                    debug!("  - MetricsPlugin: enabled");
                }
            }

            // Priority 20: CostTrackingPlugin - Usage/billing tracking
            if plugins_config.cost_tracking.enabled {
                registry = registry.register(Arc::new(CostTrackingPlugin::new(
                    CostTrackingConfig {
                        track_by_user: plugins_config.cost_tracking.track_by_user,
                        track_by_operation: plugins_config.cost_tracking.track_by_operation,
                        include_in_response: plugins_config.cost_tracking.include_in_response,
                        user_hourly_budget: plugins_config.cost_tracking.user_hourly_budget,
                        budget_warning_threshold: plugins_config
                            .cost_tracking
                            .budget_warning_threshold,
                    },
                    metrics.clone(),
                )));
                debug!("  - CostTrackingPlugin: enabled");
            }

            // Priority 50: HeaderPropagationPlugin - Header forwarding
            if plugins_config.header_propagation.enabled {
                registry = registry.register(Arc::new(HeaderPropagationPlugin::new(
                    HeaderPropagationConfig {
                        propagate_headers: plugins_config
                            .header_propagation
                            .propagate_to_subgraphs
                            .clone(),
                        remove_headers: plugins_config.header_propagation.strip_headers.clone(),
                        response_headers: plugins_config
                            .header_propagation
                            .add_headers
                            .iter()
                            .map(|h| (h.name.clone(), h.value.clone()))
                            .collect(),
                        rename_headers: std::collections::HashMap::new(),
                    },
                )));
                debug!("  - HeaderPropagationPlugin: enabled");
            }

            // Priority 100: AuditPlugin - Compliance audit logging
            if plugins_config.audit.enabled {
                registry = registry.register(Arc::new(AuditPlugin::new(
                    AuditConfig {
                        audited_operations: plugins_config.audit.audited_operations.clone(),
                        excluded_operations: plugins_config.audit.excluded_operations.clone(),
                        mutations_only: plugins_config.audit.mutations_only,
                        include_query: plugins_config.audit.include_query,
                        include_variables: plugins_config.audit.include_variables,
                        include_response_status: plugins_config.audit.include_response_status,
                    },
                    metrics.clone(),
                )));
                debug!("  - AuditPlugin: enabled");
            }

            // Priority 200: PerformancePlugin - Track performance
            if plugins_config.performance.enabled {
                registry = registry.register(Arc::new(PerformancePlugin::new(
                    PerformanceConfig {
                        slow_query_threshold_ms: plugins_config.performance.slow_query_threshold_ms,
                        critical_threshold_ms: plugins_config.performance.critical_threshold_ms,
                        include_hints: plugins_config.performance.include_hints,
                        ..Default::default()
                    },
                    metrics.clone(),
                )));
                debug!("  - PerformancePlugin: enabled");
            }

            // Priority 800: ResponseExtensionsPlugin - Add cache/timing extensions
            if plugins_config.response_extensions.enabled {
                registry = registry.register(Arc::new(ResponseExtensionsPlugin::new(
                    ResponseExtensionsConfig {
                        include_timestamp: plugins_config.response_extensions.include_timing,
                        include_version: plugins_config.response_extensions.include_version,
                        version: plugins_config.response_extensions.version.clone(),
                        include_cache_status: plugins_config
                            .response_extensions
                            .include_cache_status,
                        custom_extensions: std::collections::HashMap::new(),
                    },
                )));
                debug!("  - ResponseExtensionsPlugin: enabled");
            }

            // Priority 850: SanitizationPlugin - Response sanitization
            if plugins_config.sanitization.enabled {
                registry =
                    registry.register(Arc::new(SanitizationPlugin::new(SanitizationConfig {
                        remove_typename: plugins_config.sanitization.remove_typename,
                        remove_nulls: plugins_config.sanitization.remove_nulls,
                        remove_fields: plugins_config.sanitization.remove_fields.clone(),
                        redact_fields: plugins_config.sanitization.redact_fields.clone(),
                    })));
                debug!("  - SanitizationPlugin: enabled");
            }

            // Priority 900: ErrorMaskingPlugin - Mask internal errors last
            if plugins_config.error_masking.enabled {
                registry = registry.register(Arc::new(ErrorMaskingPlugin::new(
                    ErrorMaskingConfig {
                        mask_internal_errors: plugins_config.error_masking.mask_internal_errors,
                        masked_message: plugins_config.error_masking.masked_message.clone(),
                        passthrough_codes: plugins_config.error_masking.passthrough_codes.clone(),
                        include_code: plugins_config.error_masking.include_code,
                        include_request_id: plugins_config.error_masking.include_request_id,
                    },
                    metrics.clone(),
                )));
                debug!("  - ErrorMaskingPlugin: enabled");
            }

            info!(
                plugin_count = registry.plugin_count(),
                "Federation plugins registered"
            );
            Some(registry)
        } else {
            info!("Federation plugins: disabled");
            None
        };

        Self {
            config,
            default_product,
            supergraph,
            query_planner,
            hive_planner,
            plan_executor,
            response_cache,
            apq_cache,
            rate_limiter,
            depth_limiter,
            deduplicator,
            batcher_factory,
            plugin_registry,
            metrics,
            dynamic_rate_limiter,
        }
    }

    /// Execute a federated GraphQL operation
    ///
    /// This is the main entry point for federation execution.
    /// It orchestrates the full Phase 2 pipeline:
    /// 1. Rate limiting
    /// 2. APQ resolution
    /// 3. Security validation (depth limiting)
    /// 4. Request deduplication
    /// 5. Cache lookup
    /// 6. Query planning
    /// 7. Plan execution
    /// 8. Cache storage
    pub async fn execute(&self, request: FederationRequest) -> FederationResponse {
        let start = Instant::now();
        let operation_name = request.operation_name.clone().unwrap_or_default();

        // Create plugin context for hooks with initial request ID
        let mut plugin_ctx = PluginContext::new(
            uuid::Uuid::new_v4().to_string(), // Will be updated by RequestIdPlugin if header present
            request.query.clone().unwrap_or_default(),
            request.operation_name.clone(),
            request.variables.clone(),
            request
                .product
                .clone()
                .unwrap_or_else(|| self.default_product.clone()),
        );
        plugin_ctx.user_id = request.user_id.clone();
        plugin_ctx.user_roles = request.user_roles.clone();
        plugin_ctx.client_ip = request.client_ip.map(|ip| ip.to_string());

        // Copy headers for plugin access
        for (name, value) in request.headers.iter() {
            if let Ok(v) = value.to_str() {
                plugin_ctx.headers.insert(name.to_string(), v.to_string());
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        // Step 0: Plugin pre-parse hooks (RequestIdPlugin, early validation)
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref registry) = self.plugin_registry {
            if let Err(e) = registry.execute_pre_parse(&mut plugin_ctx) {
                warn!(
                    operation = %operation_name,
                    error = %e,
                    "Federation: Plugin pre-parse hook failed"
                );
                return FederationResponse::error(&format!("Plugin error: {}", e));
            }
        }

        // Use request_id from plugin context (may have been set by RequestIdPlugin from header)
        let request_id = plugin_ctx.request_id.clone();

        info!(
            operation = %operation_name,
            request_id = %request_id,
            "Federation: Starting execution"
        );

        // Diagnostic timing for each step
        let step_start = std::time::Instant::now();
        let mut last_step_time = step_start;

        // ═══════════════════════════════════════════════════════════════════
        // Step 1: Rate limiting check
        // ═══════════════════════════════════════════════════════════════════
        // Check dynamic rate limiter first (hot-reloadable from admin settings)
        let federation_rate_limit_enabled = if let Some(ref drl) = self.dynamic_rate_limiter {
            drl.is_federation_enabled().await
        } else {
            self.config.rate_limit_enabled
        };

        if federation_rate_limit_enabled {
            if let Some(ref limiter) = self.rate_limiter {
                // Determine operation type from query if available
                let operation_type = request
                    .query
                    .as_ref()
                    .map(|q| OperationType::from_query(q))
                    .unwrap_or(OperationType::Query);

                let rate_limit_ctx = RateLimitContext {
                    user_id: request.user_id.clone(),
                    user_roles: request.user_roles.clone(),
                    client_ip: request.client_ip,
                    operation_name: request.operation_name.clone(),
                    operation_type,
                    subgraph: None,
                    product: request
                        .product
                        .clone()
                        .unwrap_or_else(|| self.default_product.clone()),
                };

                match limiter.check(&rate_limit_ctx) {
                    RateLimitResult::Allowed => {
                        debug!(operation = %operation_name, "Federation: Rate limit check passed");
                    }
                    RateLimitResult::Limited {
                        retry_after_ms,
                        limiter: limiter_name,
                    } => {
                        let retry_after_secs = (retry_after_ms / 1000).max(1);
                        info!(
                            operation = %operation_name,
                            retry_after_secs = retry_after_secs,
                            limiter = %limiter_name,
                            "Federation: Rate limited"
                        );
                        self.metrics.incr(
                            "federation.rate_limit.rejected",
                            &[("limiter", &limiter_name)],
                        );
                        return FederationResponse::rate_limited(retry_after_secs);
                    }
                    RateLimitResult::Exempt { reason } => {
                        debug!(operation = %operation_name, reason = %reason, "Federation: Rate limit exempt");
                    }
                }
            }
        }

        info!(
            operation = %operation_name,
            step = "rate_limit",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            "Federation: Step 1 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 1.5: Plugin pre-execute hooks
        // ═══════════════════════════════════════════════════════════════════
        if let Some(ref registry) = self.plugin_registry {
            if let Err(e) = registry.execute_pre_execute(&mut plugin_ctx) {
                warn!(
                    operation = %operation_name,
                    error = %e,
                    "Federation: Plugin pre-execute hook failed"
                );
                self.metrics.incr("federation.plugin.pre_execute.error", &[]);
                // Plugin errors may be fatal depending on configuration
                return FederationResponse::error(&format!("Plugin error: {}", e));
            }
        }

        info!(
            operation = %operation_name,
            step = "plugin_pre_execute",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            "Federation: Step 1.5 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 2: APQ (Automatic Persisted Queries) resolution
        // ═══════════════════════════════════════════════════════════════════
        let query = if self.config.apq_enabled {
            if let Some(ref apq) = self.apq_cache {
                // APQ lookup takes query as Option<&str> and extensions as Option<&Value>
                match apq
                    .lookup(request.query.as_deref(), request.extensions.as_ref())
                    .await
                {
                    ApqLookupResult::Hit { query } => {
                        debug!(operation = %operation_name, "Federation: APQ cache hit");
                        self.metrics.incr("federation.apq.hit", &[]);
                        query
                    }
                    ApqLookupResult::NotFound => {
                        debug!(operation = %operation_name, "Federation: APQ cache miss, returning PersistedQueryNotFound");
                        self.metrics.incr("federation.apq.miss", &[]);
                        return FederationResponse::apq_not_found();
                    }
                    ApqLookupResult::Register { query, hash } => {
                        debug!(operation = %operation_name, hash = %hash, "Federation: APQ registering query");
                        apq.register(&hash, &query).await;
                        self.metrics.incr("federation.apq.register", &[]);
                        query
                    }
                    ApqLookupResult::NotUsed => {
                        // Normal request without APQ
                        match &request.query {
                            Some(q) if !q.is_empty() => q.clone(),
                            _ => return FederationResponse::error("No query provided"),
                        }
                    }
                    ApqLookupResult::Invalid { message } => {
                        return FederationResponse::error(&format!("APQ error: {}", message));
                    }
                }
            } else {
                // APQ enabled but not initialized (shouldn't happen)
                match &request.query {
                    Some(q) if !q.is_empty() => q.clone(),
                    _ => return FederationResponse::error("No query provided"),
                }
            }
        } else {
            // APQ disabled, get query from request
            match &request.query {
                Some(q) if !q.is_empty() => q.clone(),
                _ => return FederationResponse::error("No query provided"),
            }
        };

        info!(
            operation = %operation_name,
            step = "apq",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            "Federation: Step 2 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 3: Security validation (depth limiting)
        // ═══════════════════════════════════════════════════════════════════
        if self.config.security_enabled {
            if let Some(ref limiter) = self.depth_limiter {
                match limiter.validate(&query, request.operation_name.as_deref()) {
                    Ok(depth) => {
                        debug!(operation = %operation_name, depth = depth, "Federation: Depth check passed");
                    }
                    Err(SecurityError::DepthLimitExceeded { depth, max_depth }) => {
                        info!(
                            operation = %operation_name,
                            depth = depth,
                            max_depth = max_depth,
                            "Federation: Query depth exceeded"
                        );
                        self.metrics.incr("federation.security.depth_exceeded", &[]);
                        return FederationResponse::depth_exceeded(depth, max_depth);
                    }
                    Err(SecurityError::IntrospectionDisabled) => {
                        return FederationResponse::introspection_blocked();
                    }
                    Err(e) => {
                        return FederationResponse::error(&format!(
                            "Security validation failed: {}",
                            e
                        ));
                    }
                }
            }
        }

        info!(
            operation = %operation_name,
            step = "security",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            "Federation: Step 3 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 4: Request deduplication check
        // ═══════════════════════════════════════════════════════════════════
        let dedup_key = DeduplicationKey::new(
            request.operation_name.clone(),
            query.clone(),
            request.variables.clone(),
            request
                .product
                .clone()
                .unwrap_or_else(|| self.default_product.clone()),
        );
        let dedup_result = if let Some(ref dedup) = self.deduplicator {
            dedup.deduplicate(&dedup_key)
        } else {
            None
        };

        // Handle deduplication result in a single match to avoid partial move
        let (dedup_sender, waiter_receiver) = match dedup_result {
            Some(DeduplicationResult::Leader { sender }) => {
                self.metrics.incr("federation.deduplication.leader", &[]);
                (Some(sender), None)
            }
            Some(DeduplicationResult::Waiter { receiver }) => {
                self.metrics.incr("federation.deduplication.waiter", &[]);
                (None, Some(receiver))
            }
            None => (None, None),
        };

        // If we're a waiter, wait for the leader to complete (with timeout)
        if let Some(mut receiver) = waiter_receiver {
            debug!(operation = %operation_name, "Federation: Waiting for deduplicated result");

            // CRITICAL: Use timeout to prevent indefinite blocking if leader fails
            // Default 30s from DeduplicationConfig::max_wait_secs
            let max_wait = self
                .deduplicator
                .as_ref()
                .map(|d| d.max_wait_duration())
                .unwrap_or(std::time::Duration::from_secs(30));

            match tokio::time::timeout(max_wait, receiver.recv()).await {
                Ok(Ok(result)) => {
                    let elapsed = start.elapsed();
                    info!(
                        operation = %operation_name,
                        elapsed_ms = elapsed.as_millis(),
                        deduplicated = true,
                        "Federation: Execution complete (deduplicated)"
                    );
                    return FederationResponse::success(result.data);
                }
                Ok(Err(_)) => {
                    // Leader failed or channel closed, continue with execution
                    debug!(operation = %operation_name, "Federation: Deduplication leader failed, executing");
                }
                Err(_elapsed) => {
                    // Timeout waiting for leader - execute independently
                    warn!(
                        operation = %operation_name,
                        max_wait_secs = max_wait.as_secs(),
                        "Federation: Deduplication waiter timed out, executing independently"
                    );
                }
            }
        }

        info!(
            operation = %operation_name,
            step = "deduplication",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            is_leader = dedup_sender.is_some(),
            is_waiter = false, // If we're here, we're not a waiter that received a result
            "Federation: Step 4 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 5: Cache lookup
        // ═══════════════════════════════════════════════════════════════════
        let cache_key = compute_cache_key(
            &query,
            request.variables.as_ref(),
            request.operation_name.as_deref(),
        );

        if self.config.cache_enabled {
            if let Some(ref cache) = self.response_cache {
                if let Some(entry) = cache.get(&cache_key).await {
                    info!(
                        operation = %operation_name,
                        source = %entry.source,
                        "Federation: Cache hit"
                    );
                    self.metrics.incr(
                        "federation.cache.hit",
                        &[("source", &entry.source.to_string())],
                    );

                    // Broadcast to any waiters
                    if let Some(sender) = dedup_sender {
                        let _ = sender.send(super::deduplication::DeduplicatedResult {
                            data: entry.value.clone(),
                            from_cache: true,
                        });
                    }

                    return FederationResponse::success(entry.value);
                }
            }
        }

        info!(
            operation = %operation_name,
            step = "cache_lookup",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            cache_miss = true,
            "Federation: Step 5 complete"
        );
        last_step_time = std::time::Instant::now();

        // Prepare variables with default empty object
        let variables = request.variables.clone().unwrap_or(json!({}));

        // ═══════════════════════════════════════════════════════════════════
        // Step 6: Query planning
        // ═══════════════════════════════════════════════════════════════════
        // Use Hive planner if available (production-grade Federation v2)
        // Falls back to custom planner if Hive fails
        let plan = if let Some(ref hive_planner) = self.hive_planner {
            match hive_planner
                .plan_compat(&query, request.operation_name.as_deref(), &variables)
                .await
            {
                Ok(plan) => {
                    debug!(
                        operation = %operation_name,
                        planner = "hive",
                        "Federation: Using Hive planner"
                    );
                    plan
                }
                Err(e) => {
                    // Fall back to custom planner
                    warn!(
                        operation = %operation_name,
                        error = %e,
                        "Federation: Hive planner failed, falling back to custom"
                    );
                    match self
                        .query_planner
                        .plan(&query, request.operation_name.as_deref(), &variables)
                        .await
                    {
                        Ok(plan) => plan,
                        Err(e) => {
                            error!(
                                operation = %operation_name,
                                error = %e,
                                "Federation: Query planning failed (both planners)"
                            );
                            return FederationResponse::error(&format!(
                                "Query planning failed: {}",
                                e
                            ));
                        }
                    }
                }
            }
        } else {
            // Use custom planner
            match self
                .query_planner
                .plan(&query, request.operation_name.as_deref(), &variables)
                .await
            {
                Ok(plan) => plan,
                Err(e) => {
                    error!(
                        operation = %operation_name,
                        error = %e,
                        "Federation: Query planning failed"
                    );
                    return FederationResponse::error(&format!("Query planning failed: {}", e));
                }
            }
        };

        debug!(
            operation = %operation_name,
            fetch_count = plan.fetch_count,
            "Federation: Query planned"
        );

        info!(
            operation = %operation_name,
            step = "query_planning",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            fetch_count = plan.fetch_count,
            "Federation: Step 6 complete"
        );
        last_step_time = std::time::Instant::now();

        // ═══════════════════════════════════════════════════════════════════
        // Step 7: Plan execution
        // ═══════════════════════════════════════════════════════════════════
        // Convert HeaderMap to HashMap<String, String>
        // IMPORTANT: Filter out hop-by-hop headers and headers that would conflict with subgraph requests
        // Content-Length is particularly critical - the original request's Content-Length doesn't match
        // the subgraph request body size, causing truncated reads on the subgraph side

        // PERFORMANCE: Static header names to avoid repeated allocations
        static HOP_BY_HOP_HEADERS: &[&str] = &[
            "content-length",    // CRITICAL: Different body = different length
            "transfer-encoding", // Hop-by-hop header
            "connection",        // Hop-by-hop header
            "keep-alive",        // Hop-by-hop header
            "proxy-connection",  // Hop-by-hop header
            "te",                // Hop-by-hop header
            "trailer",           // Hop-by-hop header
            "upgrade",           // Hop-by-hop header
            "host",              // Would point to wrong host
            "content-type",      // We set our own Content-Type: application/json
            "accept-encoding",   // Subgraph client handles its own encoding
        ];

        // Convert HeaderMap to HashMap, filtering hop-by-hop headers
        let headers: HashMap<String, String> = request
            .headers
            .iter()
            .filter_map(|(name, value)| {
                let name_lower = name.as_str().to_lowercase();
                // Skip hop-by-hop headers and headers we set ourselves
                if HOP_BY_HOP_HEADERS.contains(&name_lower.as_str()) {
                    return None;
                }
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            })
            .collect();

        // Extract authorization header from request headers
        let authorization = request
            .headers
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        // Extract cookies from request headers (forwarded to auth subgraph only)
        let cookies = request
            .headers
            .get(reqwest::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let context = ExecutionContext {
            variables: variables.clone(),
            headers,
            product: request
                .product
                .clone()
                .unwrap_or_else(|| self.default_product.clone()),
            user_id: request.user_id.clone(),
            user_email: request.user_email.clone(),
            user_roles: request.user_roles.clone(),
            user_permissions: request.user_permissions.clone(),
            user_relationships: request.user_relationships.clone(),
            hmac_secret: self.config.hmac_secret.clone(),
            authorization,
            cookies,
        };

        let result = match self.plan_executor.execute(&plan, &query, &context).await {
            Ok(result) => result,
            Err(e) => {
                error!(
                    operation = %operation_name,
                    error = %e,
                    "Federation: Plan execution failed"
                );
                return FederationResponse::error(&format!("Execution failed: {}", e));
            }
        };

        info!(
            operation = %operation_name,
            step = "plan_execution",
            elapsed_ms = last_step_time.elapsed().as_millis(),
            total_elapsed_ms = step_start.elapsed().as_millis(),
            has_errors = !result.errors.is_empty(),
            "Federation: Step 7 complete"
        );

        // ═══════════════════════════════════════════════════════════════════
        // Step 8: Cache storage and deduplication broadcast
        // ═══════════════════════════════════════════════════════════════════
        if self.config.cache_enabled {
            if let Some(ref cache) = self.response_cache {
                if result.errors.is_empty() {
                    if let Some(ref data) = result.data {
                        cache.set(&cache_key, data.clone(), Some(60)).await;
                        debug!(
                            operation = %operation_name,
                            "Federation: Response cached"
                        );
                    }
                }
            }
        }

        // Broadcast result to any waiting deduplication requests
        if let Some(sender) = dedup_sender {
            if let Some(ref data) = result.data {
                let _ = sender.send(super::deduplication::DeduplicatedResult {
                    data: data.clone(),
                    from_cache: false,
                });
            }
        }

        let elapsed = start.elapsed();
        info!(
            operation = %operation_name,
            elapsed_ms = elapsed.as_millis(),
            "Federation: Execution complete"
        );

        self.metrics.histogram(
            "federation.execution.duration_ms",
            elapsed.as_millis() as f64,
            &[],
        );

        // Convert GraphQLError to Value for response
        let errors_json: Option<Vec<Value>> = if result.errors.is_empty() {
            None
        } else {
            Some(
                result
                    .errors
                    .into_iter()
                    .map(graphql_error_to_value)
                    .collect(),
            )
        };

        // ═══════════════════════════════════════════════════════════════════
        // Step 9: Plugin post-execute hooks
        // ═══════════════════════════════════════════════════════════════════
        let mut plugin_response = PluginResponse {
            data: result.data.clone(),
            ..Default::default()
        };

        if let Some(ref registry) = self.plugin_registry {
            if let Err(e) = registry.execute_post_execute(&plugin_ctx, &mut plugin_response) {
                warn!(
                    operation = %operation_name,
                    error = %e,
                    "Federation: Plugin post-execute hook failed"
                );
                self.metrics.incr("federation.plugin.post_execute.error", &[]);
                // Post-execute errors are logged but don't fail the response
            }
        }

        // Merge plugin extensions into response
        let extensions = if plugin_response.extensions.is_empty() {
            None
        } else {
            Some(serde_json::to_value(plugin_response.extensions).ok())
        };

        FederationResponse {
            status: StatusCode::OK,
            data: result.data,
            errors: errors_json,
            extensions: extensions.flatten(),
        }
    }
}

/// Convert GraphQLError to JSON Value
/// PERFORMANCE: Inline for hot path (called for every error in response)
#[inline]
fn graphql_error_to_value(err: GraphQLError) -> Value {
    json!({
        "message": err.message,
        "locations": err.locations.iter().map(|loc| json!({
            "line": loc.line,
            "column": loc.column
        })).collect::<Vec<_>>(),
        "path": err.path,
        "extensions": err.extensions
    })
}

/// Compute a cache key from query, variables, and operation name
///
/// PERFORMANCE: Uses ahash instead of DefaultHasher for 2-3x faster hashing.
/// ahash leverages AES-NI instructions on modern CPUs for optimal performance.
/// Uses static RandomState for deterministic hashing within process lifetime.
/// Inlined for hot path (called on every query).
#[inline]
fn compute_cache_key(
    query: &str,
    variables: Option<&Value>,
    operation_name: Option<&str>,
) -> String {
    let mut hasher = AHASH_STATE.build_hasher();
    query.hash(&mut hasher);
    if let Some(vars) = variables {
        vars.to_string().hash(&mut hasher);
    }
    if let Some(op) = operation_name {
        op.hash(&mut hasher);
    }
    format!("{:x}", hasher.finish())
}

/// Request for federation execution
#[derive(Debug, Clone)]
pub struct FederationRequest {
    /// GraphQL query document
    pub query: Option<String>,

    /// Operation name
    pub operation_name: Option<String>,

    /// Variables
    pub variables: Option<Value>,

    /// Persisted query hash (APQ)
    pub persisted_query_hash: Option<String>,

    /// Extensions (contains APQ data, etc.)
    pub extensions: Option<Value>,

    /// Request headers
    pub headers: HeaderMap,

    /// Product for multi-tenant isolation
    pub product: Option<String>,

    /// User ID (from session)
    pub user_id: Option<String>,

    /// User roles (for rate limit exemption)
    pub user_roles: Vec<String>,

    /// User email (extracted from session/JWT)
    pub user_email: Option<String>,

    /// User permissions (for pleme-rbac authorization)
    pub user_permissions: Vec<String>,

    /// User relationships (for client-provider linking)
    pub user_relationships: Vec<String>,

    /// Client IP address
    pub client_ip: Option<std::net::IpAddr>,
}

impl FederationRequest {
    /// Create from GraphQL JSON body
    pub fn from_json(body: &Value, headers: HeaderMap) -> Self {
        let query = body.get("query").and_then(|v| v.as_str()).map(String::from);
        let operation_name = body
            .get("operationName")
            .and_then(|v| v.as_str())
            .map(String::from);
        let variables = body.get("variables").cloned();
        let extensions = body.get("extensions").cloned();

        // Extract APQ hash from extensions
        let persisted_query_hash = extensions
            .as_ref()
            .and_then(|e| e.get("persistedQuery"))
            .and_then(|p| p.get("sha256Hash"))
            .and_then(|h| h.as_str())
            .map(String::from);

        Self {
            query,
            operation_name,
            variables,
            persisted_query_hash,
            extensions,
            headers,
            product: None,
            user_id: None,
            user_roles: vec![],
            user_email: None,
            user_permissions: vec![],
            user_relationships: vec![],
            client_ip: None,
        }
    }

    /// Set user context from session
    pub fn with_user(
        mut self,
        user_id: Option<String>,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
        relationships: Vec<String>,
    ) -> Self {
        self.user_id = user_id;
        self.user_email = email;
        self.user_roles = roles;
        self.user_permissions = permissions;
        self.user_relationships = relationships;
        self
    }

    /// Set product for multi-tenant isolation
    pub fn with_product(mut self, product: String) -> Self {
        self.product = Some(product);
        self
    }

    /// Set client IP
    pub fn with_client_ip(mut self, ip: Option<std::net::IpAddr>) -> Self {
        self.client_ip = ip;
        self
    }
}

/// Response from federation execution
#[derive(Debug)]
pub struct FederationResponse {
    pub status: StatusCode,
    pub data: Option<Value>,
    pub errors: Option<Vec<Value>>,
    pub extensions: Option<Value>,
}

impl FederationResponse {
    /// Create a successful response
    pub fn success(data: Value) -> Self {
        Self {
            status: StatusCode::OK,
            data: Some(data),
            errors: None,
            extensions: None,
        }
    }

    /// Create an error response
    pub fn error(message: &str) -> Self {
        Self {
            status: StatusCode::OK, // GraphQL errors still return 200
            data: None,
            errors: Some(vec![json!({
                "message": message,
                "extensions": {
                    "code": "INTERNAL_ERROR"
                }
            })]),
            extensions: None,
        }
    }

    /// Rate limited response
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            data: None,
            errors: Some(vec![json!({
                "message": "Rate limit exceeded",
                "extensions": {
                    "code": "RATE_LIMITED",
                    "retryAfter": retry_after_secs
                }
            })]),
            extensions: None,
        }
    }

    /// Check if response has errors
    ///
    /// Returns true if the errors field is Some and non-empty.
    #[inline]
    pub fn has_errors(&self) -> bool {
        self.errors.as_ref().is_some_and(|e| !e.is_empty())
    }

    /// APQ not found response
    pub fn apq_not_found() -> Self {
        Self {
            status: StatusCode::OK,
            data: None,
            errors: Some(vec![json!({
                "message": "PersistedQueryNotFound",
                "extensions": {
                    "code": "PERSISTED_QUERY_NOT_FOUND"
                }
            })]),
            extensions: None,
        }
    }

    /// Depth exceeded response
    pub fn depth_exceeded(depth: usize, max: usize) -> Self {
        Self {
            status: StatusCode::OK,
            data: None,
            errors: Some(vec![json!({
                "message": format!("Query depth {} exceeds maximum allowed {}", depth, max),
                "extensions": {
                    "code": "DEPTH_LIMIT_EXCEEDED",
                    "depth": depth,
                    "maxDepth": max
                }
            })]),
            extensions: None,
        }
    }

    /// Complexity exceeded response
    pub fn complexity_exceeded(complexity: u64, max: u64) -> Self {
        Self {
            status: StatusCode::OK,
            data: None,
            errors: Some(vec![json!({
                "message": format!("Query complexity {} exceeds maximum allowed {}", complexity, max),
                "extensions": {
                    "code": "COMPLEXITY_LIMIT_EXCEEDED",
                    "complexity": complexity,
                    "maxComplexity": max
                }
            })]),
            extensions: None,
        }
    }

    /// Introspection blocked response
    pub fn introspection_blocked() -> Self {
        Self {
            status: StatusCode::OK,
            data: None,
            errors: Some(vec![json!({
                "message": "Introspection is disabled",
                "extensions": {
                    "code": "INTROSPECTION_DISABLED"
                }
            })]),
            extensions: None,
        }
    }
}

impl IntoResponse for FederationResponse {
    fn into_response(self) -> axum::response::Response {
        let body = json!({
            "data": self.data,
            "errors": self.errors,
            "extensions": self.extensions
        });

        (self.status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_federation_request_from_json() {
        let body = json!({
            "query": "query GetUser { user { id } }",
            "operationName": "GetUser",
            "variables": { "id": "123" }
        });

        let request = FederationRequest::from_json(&body, HeaderMap::new());

        assert_eq!(
            request.query.as_deref(),
            Some("query GetUser { user { id } }")
        );
        assert_eq!(request.operation_name.as_deref(), Some("GetUser"));
        assert!(request.variables.is_some());
    }

    #[test]
    fn test_federation_request_with_apq() {
        let body = json!({
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "abc123def456"
                }
            }
        });

        let request = FederationRequest::from_json(&body, HeaderMap::new());

        assert_eq!(
            request.persisted_query_hash.as_deref(),
            Some("abc123def456")
        );
        assert!(request.query.is_none());
    }

    #[test]
    fn test_federation_response_error() {
        let response = FederationResponse::error("Test error");
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.errors.is_some());
    }

    #[test]
    fn test_federation_response_rate_limited() {
        let response = FederationResponse::rate_limited(60);
        assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
    }

    /// Test that hop-by-hop headers are filtered out when forwarding to subgraphs
    /// This is critical - Content-Length in particular caused JSON truncation bugs
    #[test]
    fn test_hop_by_hop_header_filtering() {
        use reqwest::header::{HeaderMap, HeaderValue};

        // Create a header map with headers that should NOT be forwarded
        let mut headers = HeaderMap::new();
        headers.insert("content-length", HeaderValue::from_static("50"));
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.insert("host", HeaderValue::from_static("example.com"));

        // And headers that SHOULD be forwarded
        headers.insert("x-request-id", HeaderValue::from_static("abc123"));
        headers.insert("x-correlation-id", HeaderValue::from_static("corr-456"));
        headers.insert("accept", HeaderValue::from_static("application/json"));
        headers.insert("user-agent", HeaderValue::from_static("TestClient/1.0"));

        // Headers to filter out
        let hop_by_hop_headers = [
            "content-length",
            "transfer-encoding",
            "connection",
            "keep-alive",
            "proxy-connection",
            "te",
            "trailer",
            "upgrade",
            "host",
            "content-type",
            "accept-encoding",
        ];

        // Apply the same filtering logic as in execute()
        let filtered: HashMap<String, String> = headers
            .iter()
            .filter_map(|(name, value)| {
                let name_lower = name.as_str().to_lowercase();
                if hop_by_hop_headers.contains(&name_lower.as_str()) {
                    return None;
                }
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.to_string(), v.to_string()))
            })
            .collect();

        // Verify hop-by-hop headers are NOT in the filtered set
        assert!(
            !filtered.contains_key("content-length"),
            "content-length should be filtered"
        );
        assert!(
            !filtered.contains_key("content-type"),
            "content-type should be filtered"
        );
        assert!(
            !filtered.contains_key("transfer-encoding"),
            "transfer-encoding should be filtered"
        );
        assert!(
            !filtered.contains_key("connection"),
            "connection should be filtered"
        );
        assert!(!filtered.contains_key("host"), "host should be filtered");

        // Verify custom headers ARE in the filtered set
        assert!(
            filtered.contains_key("x-request-id"),
            "x-request-id should be forwarded"
        );
        assert!(
            filtered.contains_key("x-correlation-id"),
            "x-correlation-id should be forwarded"
        );
        assert!(
            filtered.contains_key("accept"),
            "accept should be forwarded"
        );
        assert!(
            filtered.contains_key("user-agent"),
            "user-agent should be forwarded"
        );

        // Verify values are preserved
        assert_eq!(filtered.get("x-request-id").unwrap(), "abc123");
        assert_eq!(filtered.get("x-correlation-id").unwrap(), "corr-456");
    }
}
