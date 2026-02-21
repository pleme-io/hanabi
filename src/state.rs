//! Application state management
//!
//! This module defines the AppState struct that holds shared application state
//! passed to all handlers and middleware via Axum's State extractor.
//!
//! # Architecture
//! The AppState follows the dependency injection pattern:
//! - Configuration loaded from YAML → AppConfig
//! - AppConfig + MetricsClient + Resource Pools wrapped in Arc → AppState
//! - AppState passed to all Axum handlers/middleware via State(Arc<AppState>)
//!
//! This approach provides:
//! - No global statics (easier testing, better encapsulation)
//! - Explicit dependencies (clear what each handler needs)
//! - Thread-safe sharing via Arc (minimal cloning overhead)
//!
//! # Memory Model
//!
//! ## HTTP Use Case (Short-Lived)
//! - **Lifetime**: Milliseconds to seconds
//! - **Memory**: Bounded by max_concurrent_connections × request body size
//! - **Pooling**: Shared HTTP client connection pool (reuses TCP connections)
//! - **Budget**: Limited by tower ConcurrencyLimitLayer
//!
//! ## WebSocket Use Case (Long-Lived)
//! - **Lifetime**: Minutes to hours
//! - **Memory**: Each connection = 2 tokio tasks + message buffers + state
//! - **Pooling**: Per-connection state (NOT shared)
//! - **Budget**: Limited by Semaphore (max_connections) + message size limits
//!
//! ## Shared Resources (Efficient Cross-Use-Case)
//! - HTTP client connection pool (reqwest with keep-alive)
//! - Metrics client (UDP socket, thread-safe)
//! - Configuration (immutable, Arc<AppConfig>)
//!
//! ## Split Resources (Use-Case Specific)
//! - WebSocket connection semaphore (prevents memory exhaustion)
//! - WebSocket message channels (per-connection, bounded)
//! - HTTP request buffers (bounded by body size limits)
//!
//! # Example
//! ```rust
//! async fn handler(State(state): State<Arc<AppState>>) -> Response {
//!     state.incr("handler.called", &[]);
//!     // Use state.config for configuration values
//! }
//! ```

use once_cell::sync::Lazy;
use regex::Regex;
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::rate_limiting::{DynamicRateLimitConfig, DynamicRateLimiter};
use crate::federation::{
    BroadcasterConfig, FederationExecutor, FederationExecutorConfig, HotReloadableSupergraph,
    SubscriptionEventBroadcaster, SubscriptionManager, Supergraph,
};
use crate::images::ImageCache;
use crate::memory::PressureCoordinator;
use crate::metrics::{MetricsClient, MetricsExt};
use crate::redis::{LazyRedisConfig, LazyRedisPool};
use crate::resources::ResourceManager;

// PERFORMANCE: Pre-create static header names for hot path operations
// These headers are used in every request, so we avoid repeated string parsing
#[allow(dead_code)]
static X_REQUEST_ID: Lazy<axum::http::HeaderName> =
    Lazy::new(|| axum::http::HeaderName::from_static("x-request-id"));
#[allow(dead_code)]
static X_USER_ID: Lazy<axum::http::HeaderName> =
    Lazy::new(|| axum::http::HeaderName::from_static("x-user-id"));
#[allow(dead_code)]
static CONTENT_TYPE_JSON: Lazy<axum::http::HeaderValue> =
    Lazy::new(|| axum::http::HeaderValue::from_static("application/json"));

/// Type-erased extension map for product-specific state.
///
/// Products can attach custom state to `AppState` via `ServerBuilder::with_state_extension`.
/// Uses the same pattern as `http::Extensions` / Axum's request extensions.
///
/// # Example
/// ```rust,no_run
/// struct MyProductState { db_pool: PgPool }
/// let server = ServerBuilder::new(config)
///     .with_state_extension(MyProductState { db_pool })
///     .build().await;
/// // In handlers:
/// let my_state = state.extensions.get::<MyProductState>().unwrap();
/// ```
#[derive(Default)]
pub struct Extensions {
    map: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl Extensions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert<T: Send + Sync + 'static>(&mut self, val: T) {
        self.map.insert(TypeId::of::<T>(), Box::new(val));
    }

    pub fn get<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.map
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref())
    }
}

// Extensions is not Clone (type-erased boxes aren't clonable), but AppState wraps it in Arc.
// We need Clone for AppState, so wrap Extensions in Arc at the AppState level.

/// BFF infrastructure (created when features.enable_bff = true)
#[derive(Clone)]
pub struct BffInfra {
    /// HTTP client with connection pooling for BFF proxy
    pub http_client: Arc<reqwest::Client>,
    /// WebSocket connection semaphore for memory budgeting
    pub websocket_semaphore: Arc<Semaphore>,
    /// Resource detection and optimization
    pub resource_manager: Option<Arc<ResourceManager>>,
    /// Lazy Redis connection pool for BFF session storage (only if session.enabled)
    pub session_redis: Option<Arc<LazyRedisPool>>,
    /// Image cache for CDN-like image serving
    pub image_cache: Arc<ImageCache>,
    /// Pre-compiled auth interception rules (built once at startup from config)
    pub compiled_auth: Arc<crate::auth::compiled::CompiledAuthInterception>,
}

/// Federation infrastructure (created when bff.federation.enabled = true)
#[derive(Clone)]
pub struct FederationInfra {
    /// Federation executor for query planning + plan execution
    pub executor: Arc<FederationExecutor>,
    /// Parsed supergraph schema
    pub supergraph: Arc<Supergraph>,
    /// Subscription manager for WebSocket connections
    pub subscription_manager: Arc<SubscriptionManager>,
    /// Hot-reloadable supergraph (if hot_reload is enabled)
    pub hot_reloadable_supergraph: Option<Arc<HotReloadableSupergraph>>,
    /// HTTP client with subgraph-specific pooling
    pub http_client: Arc<reqwest::Client>,
    /// Load shedder for admission control (None if load shedding disabled)
    pub load_shedder: Option<Arc<crate::federation::LoadShedder>>,
}

/// Application state passed to all handlers and middleware
///
/// # Thread Safety
/// AppState is Clone (via Arc cloning) and Send + Sync, making it safe to
/// share across async tasks and worker threads.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration loaded from YAML
    pub config: Arc<AppConfig>,

    /// Metrics client for emitting StatsD metrics to Vector agent
    /// None if metrics are disabled via config.features.enable_metrics
    pub metrics: Option<Arc<MetricsClient>>,

    /// Memory pressure coordinator for adaptive resource management
    #[allow(dead_code)]
    pub pressure_coordinator: Arc<PressureCoordinator>,

    /// BFF infrastructure (None if BFF disabled)
    pub bff: Option<BffInfra>,

    /// Federation infrastructure (None if federation disabled)
    pub federation: Option<FederationInfra>,

    /// PERFORMANCE: Pre-compiled regex for hashed asset detection
    pub hashed_asset_regex: Option<Regex>,

    /// PERFORMANCE: Pre-computed security headers (computed once at startup)
    pub security_headers: Option<SecurityHeaders>,

    /// Dynamic rate limiter with hot-reload capability
    /// Updated at runtime via NATS when admin changes rate limit settings
    pub dynamic_rate_limiter: Arc<DynamicRateLimiter>,

    /// Product-specific state extensions (type-erased map)
    pub extensions: Arc<Extensions>,
}

/// Pre-computed security headers (computed once at startup, cloned per-request)
#[derive(Clone)]
pub struct SecurityHeaders {
    pub csp: axum::http::HeaderValue,
    pub hsts: axum::http::HeaderValue,
    pub x_frame_options: axum::http::HeaderValue,
    pub referrer_policy: axum::http::HeaderValue,
    pub permissions_policy: axum::http::HeaderValue,
}

impl AppState {
    /// Increment a counter metric (no-op if metrics disabled)
    #[inline]
    pub fn incr(&self, name: &str, tags: &[(&str, &str)]) {
        self.metrics.incr(name, tags);
    }

    /// Record a gauge metric (no-op if metrics disabled)
    #[inline]
    pub fn gauge(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        self.metrics.gauge(name, value, tags);
    }

    /// Record a histogram metric (no-op if metrics disabled)
    #[inline]
    pub fn histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        self.metrics.histogram(name, value, tags);
    }

    /// Record a count metric (no-op if metrics disabled)
    #[inline]
    pub fn count(&self, name: &str, count: i64, tags: &[(&str, &str)]) {
        self.metrics.count(name, count, tags);
    }

    /// Access BFF infrastructure (panics if BFF not enabled — safe because
    /// routes that call this are only registered when BFF is enabled)
    #[inline]
    pub fn bff(&self) -> &BffInfra {
        self.bff.as_ref().expect("BFF not enabled")
    }

    /// Access federation infrastructure (panics if federation not enabled — safe because
    /// routes that call this are only registered when federation is enabled)
    #[inline]
    pub fn federation(&self) -> &FederationInfra {
        self.federation.as_ref().expect("Federation not enabled")
    }

    // Backward-compatible field accessors (delegate to infra structs)
    // These smooth the migration: existing code calling `state.http_client` etc. still works.

    /// HTTP client for BFF proxy (None if BFF disabled)
    #[inline]
    pub fn http_client(&self) -> Option<&Arc<reqwest::Client>> {
        self.bff.as_ref().map(|b| &b.http_client)
    }

    /// WebSocket semaphore (None if BFF disabled)
    #[inline]
    pub fn websocket_semaphore(&self) -> Option<&Arc<Semaphore>> {
        self.bff.as_ref().map(|b| &b.websocket_semaphore)
    }

    /// Session Redis pool (None if BFF disabled or sessions disabled)
    #[inline]
    pub fn session_redis(&self) -> Option<&Arc<LazyRedisPool>> {
        self.bff.as_ref().and_then(|b| b.session_redis.as_ref())
    }

    /// Image cache (None if BFF disabled)
    #[inline]
    pub fn image_cache(&self) -> Option<&Arc<ImageCache>> {
        self.bff.as_ref().map(|b| &b.image_cache)
    }

    /// Resource manager (None if BFF disabled or init failed)
    #[inline]
    pub fn resource_manager(&self) -> Option<&Arc<ResourceManager>> {
        self.bff.as_ref().and_then(|b| b.resource_manager.as_ref())
    }

    /// Federation executor (None if federation disabled)
    #[inline]
    pub fn federation_executor(&self) -> Option<&Arc<FederationExecutor>> {
        self.federation.as_ref().map(|f| &f.executor)
    }

    /// Subscription manager (None if federation disabled)
    #[inline]
    pub fn subscription_manager(&self) -> Option<&Arc<SubscriptionManager>> {
        self.federation.as_ref().map(|f| &f.subscription_manager)
    }

    /// Hot-reloadable supergraph (None if federation disabled or hot reload off)
    #[inline]
    pub fn hot_reloadable_supergraph(&self) -> Option<&Arc<HotReloadableSupergraph>> {
        self.federation.as_ref().and_then(|f| f.hot_reloadable_supergraph.as_ref())
    }

    /// Load shedder (None if federation disabled or load shedding off)
    #[inline]
    pub fn load_shedder(&self) -> Option<&Arc<crate::federation::LoadShedder>> {
        self.federation.as_ref().and_then(|f| f.load_shedder.as_ref())
    }

    /// Dynamic rate limiter for runtime config updates
    #[inline]
    pub fn dynamic_rate_limiter(&self) -> &Arc<DynamicRateLimiter> {
        &self.dynamic_rate_limiter
    }

    /// Initialize application state from configuration
    ///
    /// Orchestrates initialization of all subsystems:
    /// 1. Metrics client (StatsD → Vector)
    /// 2. Resource detection + pressure coordinator
    /// 3. BFF infrastructure (HTTP client, WebSocket, Redis, image cache)
    /// 4. Federation infrastructure (supergraph, executor, subscriptions)
    /// 5. Security headers + asset regex
    pub async fn new(config: Arc<AppConfig>) -> Self {
        Self::with_extensions(config, Extensions::new()).await
    }

    /// Initialize application state with product-specific extensions
    pub async fn with_extensions(config: Arc<AppConfig>, extensions: Extensions) -> Self {
        let metrics = Self::init_metrics(&config);
        let (resource_manager, pressure_coordinator) =
            Self::init_resources(&config, &metrics).await;
        let bff = Self::init_bff(&config, &metrics, resource_manager).await;
        let session_redis = bff.as_ref().and_then(|b| b.session_redis.clone());

        // Initialize dynamic rate limiter from YAML config (before federation, so executor gets it)
        let dynamic_rate_limiter = Self::init_dynamic_rate_limiter(&config);

        let federation = Self::init_federation(
            &config,
            &metrics,
            &pressure_coordinator,
            session_redis,
            &dynamic_rate_limiter,
        )
        .await;
        let hashed_asset_regex = Self::init_asset_regex(&config);
        let security_headers = Self::init_security_headers(&config);

        // Spawn NATS rate limit config subscriber if configured
        if config.features.enable_bff {
            Self::spawn_rate_limit_subscriber(
                &config,
                &bff,
                &dynamic_rate_limiter,
                &metrics,
            );
        }

        Self {
            config,
            metrics,
            pressure_coordinator,
            bff,
            federation,
            hashed_asset_regex,
            security_headers,
            dynamic_rate_limiter,
            extensions: Arc::new(extensions),
        }
    }

    /// Initialize metrics client (StatsD over UDP to Vector agent)
    fn init_metrics(config: &AppConfig) -> Option<Arc<MetricsClient>> {
        if !config.features.enable_metrics {
            warn!("⚠ Metrics disabled via configuration");
            return None;
        }

        // Environment variable overrides for Kubernetes hostNetwork deployments
        let host =
            std::env::var("VECTOR_HOST").unwrap_or_else(|_| config.metrics.vector_host.clone());
        let port = std::env::var("VECTOR_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(config.metrics.vector_port);

        match MetricsClient::new(&host, port) {
            Ok(client) => {
                let ns_info = client
                    .namespace()
                    .map(|ns| format!(" [namespace: {}]", ns))
                    .unwrap_or_default();
                info!(
                    "✓ Metrics client initialized ({}:{}) [prefix: {}]{}",
                    host, port, config.metrics.prefix, ns_info
                );
                Some(Arc::new(client))
            }
            Err(e) => {
                warn!("⚠ Metrics client initialization failed: {}", e);
                None
            }
        }
    }

    /// Initialize resource manager and pressure coordinator
    async fn init_resources(
        config: &Arc<AppConfig>,
        metrics: &Option<Arc<MetricsClient>>,
    ) -> (Option<Arc<ResourceManager>>, Arc<PressureCoordinator>) {
        let resource_manager = if config.features.enable_bff {
            match ResourceManager::new(config).await {
                Ok(manager) => {
                    if let Some(ref m) = metrics {
                        manager.emit_metrics(m);
                    }
                    Some(Arc::new(manager))
                }
                Err(e) => {
                    warn!("⚠ Resource manager initialization failed: {}", e);
                    warn!("  BFF will use static configuration instead of optimized values");
                    None
                }
            }
        } else {
            None
        };

        let memory_limit = resource_manager
            .as_ref()
            .map(|rm| rm.resources.available_memory_bytes);
        let pressure_coordinator = Arc::new(PressureCoordinator::new(memory_limit));
        if config.features.enable_bff {
            pressure_coordinator.spawn_monitor();
            info!(
                memory_limit = ?memory_limit,
                "Pressure coordinator initialized with background monitor"
            );
        } else {
            info!("Pressure coordinator initialized (monitor skipped — BFF disabled)");
        }

        (resource_manager, pressure_coordinator)
    }

    /// Initialize BFF infrastructure (HTTP client, WebSocket semaphore, Redis, image cache)
    async fn init_bff(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
        resource_manager: Option<Arc<ResourceManager>>,
    ) -> Option<BffInfra> {
        if !config.features.enable_bff {
            return None;
        }

        // HTTP client with connection pooling
        let pool_size = resource_manager
            .as_ref()
            .map(|rm| rm.optimized.http_pool_size)
            .unwrap_or(32);

        let http_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(config.bff.http.timeout_secs))
            .connect_timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(pool_size)
            .tcp_keepalive(Duration::from_secs(60))
            .tcp_nodelay(true)
            .build()
        {
            Ok(client) => {
                let source = if resource_manager.is_some() {
                    "auto-optimized"
                } else {
                    "static"
                };
                info!(
                    "✓ HTTP client initialized for BFF (timeout: {}s, pool size: {} [{}], keepalive: 60s)",
                    config.bff.http.timeout_secs, pool_size, source
                );
                Arc::new(client)
            }
            Err(e) => {
                warn!("⚠ HTTP client initialization failed: {}", e);
                warn!("  BFF will not function properly without HTTP client");
                return None;
            }
        };

        // WebSocket semaphore for memory budgeting
        let max_connections = resource_manager
            .as_ref()
            .map(|rm| rm.optimized.websocket_max_connections)
            .unwrap_or(config.bff.websocket.max_connections);
        let websocket_semaphore = Arc::new(Semaphore::new(max_connections));
        let memory_budget_mb = resource_manager
            .as_ref()
            .map(|rm| rm.optimized.websocket_memory_budget_bytes / (1024 * 1024))
            .unwrap_or_else(|| {
                (max_connections as u64).saturating_mul(200) / 1024
            });
        info!(
            "✓ WebSocket semaphore initialized (max connections: {}, memory budget: ~{}MB)",
            max_connections, memory_budget_mb
        );

        // Image cache for CDN-like image serving
        info!("✓ Image cache initialized (L1: moka, L2: Redis)");
        let image_cache = Arc::new(ImageCache::new());

        // Lazy Redis for BFF sessions
        let session_redis = if config.bff.session.enabled {
            let redis_config = LazyRedisConfig {
                host: config.bff.session.redis_host.clone(),
                port: config.bff.session.redis_port,
                password: config.bff.session.redis_password.clone(),
                max_retries: 3,
                initial_delay_ms: 100,
                connection_timeout_secs: 5,
            };
            let pool = Arc::new(LazyRedisPool::new(redis_config));
            let auth_status = if config.bff.session.redis_password.is_some() {
                " (with auth)"
            } else {
                ""
            };
            info!(
                "✓ Redis session manager configured ({}:{}){} - will connect on first use",
                config.bff.session.redis_host, config.bff.session.redis_port, auth_status
            );
            metrics.gauge("bff.session.redis_pool.available", pool.availability(), &[]);
            Some(pool)
        } else {
            info!("  BFF sessions disabled - using passthrough auth mode");
            None
        };

        // Spawn NATS session invalidation subscriber if configured
        if let (Some(ref redis_pool), Some(ref nats_url)) =
            (&session_redis, &config.bff.session.nats_url)
        {
            use crate::auth::session_events::spawn_session_invalidation_subscriber;
            let _handle = spawn_session_invalidation_subscriber(
                nats_url.clone(),
                config.bff.product.clone(),
                redis_pool.clone(),
                config.bff.session.clone(),
            );
            info!(
                "✓ NATS session invalidation subscriber spawned ({})",
                nats_url
            );
        } else if config.bff.session.enabled && config.bff.session.nats_url.is_none() {
            info!("  NATS session invalidation: disabled (nats_url not configured)");
        }

        // Pre-compile auth interception rules from config (zero per-request overhead)
        let compiled_auth = Arc::new(
            crate::auth::compiled::CompiledAuthInterception::from_config(
                &config.bff.session.auth_interception,
            ),
        );
        info!("✓ Auth interception rules compiled from configuration");

        Some(BffInfra {
            http_client,
            websocket_semaphore,
            resource_manager,
            session_redis,
            image_cache,
            compiled_auth,
        })
    }

    /// Initialize federation infrastructure (supergraph, executor, subscriptions, load shedder)
    async fn init_federation(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
        pressure_coordinator: &Arc<PressureCoordinator>,
        session_redis: Option<Arc<LazyRedisPool>>,
        dynamic_rate_limiter: &Arc<DynamicRateLimiter>,
    ) -> Option<FederationInfra> {
        if !config.features.enable_bff || !config.bff.federation.enabled {
            if config.features.enable_bff && !config.bff.federation.enabled {
                info!("  Federation mode: disabled (using Hive Router proxy)");
            }
            return None;
        }

        info!("Federation mode: ENABLED");
        info!(
            "  Loading supergraph from: {}",
            config.bff.federation.supergraph_url
        );
        info!(
            "  Hot reload: {}",
            if config.bff.federation.hot_reload {
                "enabled"
            } else {
                "disabled"
            }
        );

        // Federation HTTP client with subgraph-specific pooling
        let pool_cfg = &config.bff.federation.http_pool;
        let federation_http_client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(pool_cfg.timeout_secs))
            .connect_timeout(Duration::from_secs(pool_cfg.connect_timeout_secs))
            .pool_idle_timeout(Duration::from_secs(pool_cfg.pool_idle_timeout_secs))
            .pool_max_idle_per_host(pool_cfg.pool_max_idle_per_host)
            .tcp_keepalive(Duration::from_secs(pool_cfg.tcp_keepalive_secs))
            .tcp_nodelay(true)
            .build()
        {
            Ok(client) => {
                info!(
                    "✓ Federation HTTP client initialized (timeout: {}s, pool: {} per host, keepalive: {}s, nodelay: true)",
                    pool_cfg.timeout_secs,
                    pool_cfg.pool_max_idle_per_host,
                    pool_cfg.tcp_keepalive_secs
                );
                Arc::new(client)
            }
            Err(e) => {
                warn!("⚠ Federation HTTP client initialization failed: {}", e);
                return None;
            }
        };

        // Subscription broadcaster for horizontal scaling (Redis pub/sub)
        let subscription_broadcaster = if config.bff.federation.websocket.enabled
            && config.bff.federation.websocket.pub_sub_enabled
        {
            let broadcaster_config = BroadcasterConfig {
                redis_url: config.bff.federation.websocket.pub_sub_redis_url.clone(),
                product: config.bff.product.clone(),
                channel_buffer_size: config.bff.federation.websocket.pub_sub_channel_buffer_size,
                enabled: true,
                pod_id: config.pod_id.clone(),
            };
            let broadcaster =
                SubscriptionEventBroadcaster::new(broadcaster_config, metrics.clone()).await;
            info!(
                "✓ Subscription broadcaster initialized (Redis pub/sub: {})",
                if broadcaster.is_redis_connected() {
                    "connected"
                } else {
                    "failed, single-pod mode"
                }
            );
            Some(Arc::new(broadcaster))
        } else {
            if config.bff.federation.websocket.enabled {
                info!("  Subscription broadcaster: disabled (pub_sub_enabled = false)");
            }
            None
        };

        // Load supergraph + create subscription manager
        let (supergraph, subscription_manager, hot_reloadable_supergraph) =
            Self::init_supergraph(config, metrics, &federation_http_client, &subscription_broadcaster).await;

        let supergraph = supergraph?;
        let subscription_manager = subscription_manager?;

        // Federation executor
        let executor = Self::init_executor(
            config,
            metrics,
            pressure_coordinator,
            &supergraph,
            &federation_http_client,
            session_redis,
            dynamic_rate_limiter,
        );

        // Load shedder (Netflix Gradient + circuit breakers)
        let load_shedder = Self::init_load_shedder(config, metrics);

        Some(FederationInfra {
            executor: Arc::new(executor),
            supergraph,
            subscription_manager,
            hot_reloadable_supergraph,
            http_client: federation_http_client,
            load_shedder,
        })
    }

    /// Load supergraph schema and create subscription manager
    async fn init_supergraph(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
        federation_http_client: &Arc<reqwest::Client>,
        subscription_broadcaster: &Option<Arc<SubscriptionEventBroadcaster>>,
    ) -> (
        Option<Arc<Supergraph>>,
        Option<Arc<SubscriptionManager>>,
        Option<Arc<HotReloadableSupergraph>>,
    ) {
        if config.bff.federation.hot_reload {
            match HotReloadableSupergraph::new(
                &config.bff.federation,
                metrics.clone(),
                Some(federation_http_client.clone()),
            )
            .await
            {
                Ok(hot_sg) => {
                    let guard = hot_sg.get().await;
                    match guard {
                        Some(ref sg_guard) => {
                            if let Some(ref sg) = **sg_guard {
                                let sg_arc = Arc::new(sg.clone());
                                let pool_config = SubscriptionManager::pool_config_from_bff(
                                    &config.bff.federation.websocket,
                                );
                                let manager = Arc::new(SubscriptionManager::with_pool_config(
                                    sg_arc.clone(),
                                    metrics.clone(),
                                    pool_config,
                                    subscription_broadcaster.clone(),
                                ));

                                info!("✓ Federation initialized with hot reload:");
                                info!("    - {} subgraphs loaded", sg.subgraphs().len() / 2);
                                info!(
                                    "    - {} subscription routes",
                                    sg.subscription_routes.len()
                                );
                                info!(
                                    "    - WebSocket subscriptions: {}",
                                    if config.bff.federation.websocket.enabled {
                                        "enabled"
                                    } else {
                                        "disabled"
                                    }
                                );
                                info!(
                                    "    - Poll interval: {}s",
                                    config.bff.federation.poll_interval_secs
                                );

                                drop(guard);
                                (Some(sg_arc), Some(manager), Some(Arc::new(hot_sg)))
                            } else {
                                error!("✗ HotReloadableSupergraph created but no supergraph loaded");
                                drop(guard);
                                (None, None, None)
                            }
                        }
                        None => {
                            error!(
                                "✗ HotReloadableSupergraph created but no supergraph loaded"
                            );
                            (None, None, None)
                        }
                    }
                }
                Err(e) => {
                    error!("✗ Hot reload initialization failed: {}", e);
                    error!("  Falling back to static supergraph");
                    Self::init_static_supergraph(config, metrics, subscription_broadcaster).await
                }
            }
        } else {
            Self::init_static_supergraph(config, metrics, subscription_broadcaster).await
        }
    }

    /// Load supergraph from URL (static mode, no hot reload)
    async fn init_static_supergraph(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
        subscription_broadcaster: &Option<Arc<SubscriptionEventBroadcaster>>,
    ) -> (
        Option<Arc<Supergraph>>,
        Option<Arc<SubscriptionManager>>,
        Option<Arc<HotReloadableSupergraph>>,
    ) {
        match Supergraph::load(&config.bff.federation.supergraph_url).await {
            Ok(sg) => {
                let sg = Arc::new(sg);
                let pool_config = SubscriptionManager::pool_config_from_bff(
                    &config.bff.federation.websocket,
                );
                let manager = Arc::new(SubscriptionManager::with_pool_config(
                    sg.clone(),
                    metrics.clone(),
                    pool_config,
                    subscription_broadcaster.clone(),
                ));

                info!("✓ Federation initialized:");
                info!("    - {} subgraphs loaded", sg.subgraphs().len() / 2);
                info!("    - {} subscription routes", sg.subscription_routes.len());
                info!(
                    "    - WebSocket subscriptions: {}",
                    if config.bff.federation.websocket.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );

                (Some(sg), Some(manager), None)
            }
            Err(e) => {
                error!("✗ Federation initialization failed: {}", e);
                error!("  Falling back to proxy mode (subscriptions will NOT work)");
                (None, None, None)
            }
        }
    }

    /// Build federation executor configuration and create executor
    fn init_executor(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
        pressure_coordinator: &Arc<PressureCoordinator>,
        supergraph: &Arc<Supergraph>,
        federation_http_client: &Arc<reqwest::Client>,
        session_redis: Option<Arc<LazyRedisPool>>,
        dynamic_rate_limiter: &Arc<DynamicRateLimiter>,
    ) -> FederationExecutor {
        let hmac_secret = if config.bff.federation.hmac.enabled {
            let cfg_secret = &config.bff.federation.hmac.secret;
            if !cfg_secret.is_empty() && !cfg_secret.starts_with("${") {
                Some(cfg_secret.clone())
            } else {
                warn!("HMAC signing enabled but no secret found (check HMAC_SECRET env var)");
                None
            }
        } else {
            None
        };

        let performance_mode = config.bff.federation.performance_mode;

        let executor_config = FederationExecutorConfig {
            enabled: config.bff.federation.enabled,
            cache_enabled: config.bff.federation.response_cache.enabled,
            rate_limit_enabled: !performance_mode && config.bff.federation.rate_limit.enabled,
            apq_enabled: !performance_mode && config.bff.federation.apq.enabled,
            security_enabled: !performance_mode && config.bff.federation.security.enabled,
            plugins_enabled: !performance_mode && config.bff.federation.plugins.enabled,
            batching_enabled: !performance_mode && config.bff.federation.batching.enabled,
            dedup_enabled: !performance_mode && config.bff.federation.deduplication.enabled,
            hmac_secret,
            use_hive_planner: config.bff.federation.use_hive_planner,
            subgraph_default_port: config.bff.federation.subgraph_default_port,
            subgraph_default_path: config.bff.federation.subgraph_default_path.clone(),
        };

        // Log which features are enabled
        let mode_label = if performance_mode {
            "Federation executor config (PERFORMANCE MODE - minimal latency):"
        } else {
            "Federation executor config:"
        };
        info!("{}", mode_label);
        let flag = |enabled| if enabled { "enabled" } else { "disabled" };
        info!("  - Performance mode: {}", if performance_mode { "ENABLED (Hive Router-like)" } else { "disabled" });
        info!("  - Response caching: {}", flag(executor_config.cache_enabled));
        info!("  - Rate limiting: {}", flag(executor_config.rate_limit_enabled));
        info!("  - APQ: {}", flag(executor_config.apq_enabled));
        info!("  - Security: {}", flag(executor_config.security_enabled));
        info!("  - Plugins: {}", flag(executor_config.plugins_enabled));
        info!("  - Batching: {}", flag(executor_config.batching_enabled));
        info!("  - Deduplication: {}", flag(executor_config.dedup_enabled));
        info!("  - HMAC signing: {}", flag(executor_config.hmac_secret.is_some()));
        info!("  - Hive planner: {}", if executor_config.use_hive_planner { "enabled (Federation v2)" } else { "disabled (custom)" });
        if !config.bff.federation.subgraph_url_overrides.is_empty() {
            info!(
                "  - Subgraph URL overrides: {} configured",
                config.bff.federation.subgraph_url_overrides.len()
            );
        }

        let redis_conn = if executor_config.cache_enabled {
            session_redis
        } else {
            None
        };

        let executor = FederationExecutor::with_dynamic_rate_limiter(
            executor_config,
            config.bff.federation.plugins.clone(),
            supergraph.clone(),
            redis_conn,
            Some(federation_http_client.clone()),
            metrics.clone(),
            Some(pressure_coordinator.clone()),
            config.bff.product.clone(),
            Some(dynamic_rate_limiter.clone()),
        );

        info!("✓ Federation executor initialized (query planning + plan execution)");
        executor
    }

    /// Initialize load shedder for admission control (Netflix Gradient + circuit breakers)
    fn init_load_shedder(
        config: &AppConfig,
        metrics: &Option<Arc<MetricsClient>>,
    ) -> Option<Arc<crate::federation::LoadShedder>> {
        if !config.bff.federation.enable_load_shedding {
            info!("ℹ Load shedding disabled - processing all requests without admission control");
            return None;
        }

        use crate::federation::{CircuitBreakerConfig, LoadShedder, LoadSheddingConfig};

        let load_config = LoadSheddingConfig {
            initial_limit: 1000,
            min_limit: 500,
            max_limit: 5000,
            smoothing: 0.1,
            tolerance: 0.3,
            backoff_ratio: 0.95,
            probe_interval: Duration::from_secs(10),
            long_window_size: 200,
            short_window_size: 20,
        };

        let breaker_config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 2,
            recovery_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_requests: 1,
        };

        let shedder = LoadShedder::new(
            load_config,
            breaker_config,
            Duration::from_secs(30),
            metrics.clone(),
        );

        info!("✓ Load shedder initialized (Netflix Gradient + circuit breakers)");
        Some(Arc::new(shedder))
    }

    /// Initialize dynamic rate limiter from YAML config values
    fn init_dynamic_rate_limiter(config: &AppConfig) -> Arc<DynamicRateLimiter> {
        let initial_config = DynamicRateLimitConfig {
            bff_enabled: config.bff.http.rate_limit.enabled,
            bff_rps: config.bff.http.rate_limit.requests_per_second as u32,
            bff_burst: config.bff.http.rate_limit.burst_size,
            federation_enabled: config.bff.federation.rate_limit.enabled,
            federation_default_rps: config.bff.federation.rate_limit.default_rps,
            federation_default_burst: config.bff.federation.rate_limit.default_burst,
            exempt_roles: config
                .bff
                .federation
                .rate_limit
                .exempt_roles
                .clone(),
            version: 0,
        };

        info!(
            bff_enabled = initial_config.bff_enabled,
            bff_rps = initial_config.bff_rps,
            federation_enabled = initial_config.federation_enabled,
            federation_rps = initial_config.federation_default_rps,
            "✓ DynamicRateLimiter initialized from YAML config"
        );

        Arc::new(DynamicRateLimiter::new(initial_config))
    }

    /// Spawn NATS rate limit config subscriber if both nats_url and backend_graphql_url are configured
    fn spawn_rate_limit_subscriber(
        config: &AppConfig,
        bff: &Option<BffInfra>,
        dynamic_rate_limiter: &Arc<DynamicRateLimiter>,
        metrics: &Option<Arc<MetricsClient>>,
    ) {
        if let (Some(ref nats_url), Some(ref backend_url)) =
            (&config.bff.nats_url, &config.bff.backend_graphql_url)
        {
            // Reuse the BFF HTTP client if available, otherwise create a minimal one
            let http_client = bff
                .as_ref()
                .map(|b| b.http_client.clone())
                .unwrap_or_else(|| Arc::new(reqwest::Client::new()));

            use crate::rate_limiting::spawn_rate_limit_config_subscriber;
            let _handle = spawn_rate_limit_config_subscriber(
                nats_url.clone(),
                config.bff.product.clone(),
                backend_url.clone(),
                http_client,
                dynamic_rate_limiter.clone(),
                metrics.clone(),
            );
            info!(
                "✓ NATS rate limit config subscriber spawned ({}, backend: {})",
                nats_url, backend_url
            );
        } else if config.bff.nats_url.is_some() && config.bff.backend_graphql_url.is_none() {
            info!("  NATS rate limit sync: disabled (backend_graphql_url not configured)");
        } else {
            info!("  NATS rate limit sync: disabled (nats_url not configured)");
        }
    }

    /// Pre-compile hashed asset regex for cache_control_headers middleware
    fn init_asset_regex(config: &AppConfig) -> Option<Regex> {
        match Regex::new(&config.network.hashed_asset_pattern) {
            Ok(re) => {
                info!(
                    "✓ Hashed asset regex compiled (pattern: {})",
                    config.network.hashed_asset_pattern
                );
                Some(re)
            }
            Err(e) => {
                warn!("⚠ Failed to compile hashed asset regex: {} - falling back to per-request compilation", e);
                None
            }
        }
    }

    /// Build pre-computed security headers from config
    fn init_security_headers(config: &AppConfig) -> Option<SecurityHeaders> {
        let csp = match axum::http::HeaderValue::from_str(&config.build_csp()) {
            Ok(val) => {
                info!("✓ CSP header pre-computed");
                val
            }
            Err(e) => {
                warn!("⚠ Failed to parse CSP header: {}", e);
                return None;
            }
        };

        let hsts = match axum::http::HeaderValue::from_str(&config.build_hsts()) {
            Ok(val) => {
                info!("✓ HSTS header pre-computed");
                val
            }
            Err(e) => {
                warn!("⚠ Failed to parse HSTS header: {}", e);
                return None;
            }
        };

        let x_frame_options =
            match axum::http::HeaderValue::from_str(&config.security.headers.x_frame_options) {
                Ok(val) => val,
                Err(e) => {
                    warn!("⚠ Failed to parse X-Frame-Options header: {}", e);
                    return None;
                }
            };

        let referrer_policy =
            match axum::http::HeaderValue::from_str(&config.security.headers.referrer_policy) {
                Ok(val) => val,
                Err(e) => {
                    warn!("⚠ Failed to parse Referrer-Policy header: {}", e);
                    return None;
                }
            };

        let permissions_policy =
            match axum::http::HeaderValue::from_str(&config.security.headers.permissions_policy) {
                Ok(val) => val,
                Err(e) => {
                    warn!("⚠ Failed to parse Permissions-Policy header: {}", e);
                    return None;
                }
            };

        info!("✓ All security headers pre-computed for optimal performance");
        Some(SecurityHeaders {
            csp,
            hsts,
            x_frame_options,
            referrer_policy,
            permissions_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        // AppState creation is tested through integration tests
        // Unit testing requires valid configuration which is tested in config module
    }

    #[test]
    fn test_app_state_is_clone() {
        // Verify AppState implements Clone (required for Axum State)
        fn assert_clone<T: Clone>() {}
        assert_clone::<AppState>();
    }

    #[test]
    fn test_app_state_is_send_sync() {
        // Verify AppState is Send + Sync (required for async handlers)
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AppState>();
    }
}
