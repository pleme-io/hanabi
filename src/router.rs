//! Router construction for Hanabi web server
//!
//! Composable router builders that assemble the HTTP and health check routers
//! from the application state and configuration. Extracted from main.rs to
//! keep the binary entry point thin and enable integration testing.
//!
//! # Builder integration
//!
//! [`build_core_app_router`] and [`apply_global_middleware`] are the building
//! blocks used by [`ServerBuilder`](crate::builder::ServerBuilder). The
//! existing [`build_app_router`] delegates to them for backward compatibility.

use std::collections::HashSet;
use std::sync::Arc;

use axum::{
    extract::State,
    middleware as axum_middleware,
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::{
    compression::CompressionLayer, decompression::RequestDecompressionLayer, services::ServeDir,
    timeout::TimeoutLayer, trace::TraceLayer,
};
use tracing::info;

#[cfg(feature = "google-oauth")]
use crate::auth::{
    google_oauth_callback, google_oauth_init, link_oauth_account, restore_oauth_account,
};
#[cfg(feature = "instagram-oauth")]
use crate::auth::{instagram_oauth_callback, instagram_oauth_init};
use crate::auth::session_auth_middleware;
use crate::bff::{admin_reload_supergraph, admin_supergraph_status, graphql_proxy, graphql_ws_proxy};
use crate::config::AppConfig;
use crate::handlers::{
    backend_upload_proxy, bug_reports, simple_health, spa_fallback, telemetry,
};
#[cfg(feature = "geolocation")]
use crate::handlers::geolocation;
use crate::health::{health_live, health_ready, health_startup};
use crate::health_aggregator::direct_service_health;
use crate::middleware::{
    build_cors_layer, cache_control_headers, request_metrics, security_headers, spa_404_fallback,
};
use crate::rate_limiting::build_rate_limit_layer;
use crate::state::AppState;

/// Core middleware layers that can be disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreMiddleware {
    Trace,
    Cors,
    Compression,
    Decompression,
    ConcurrencyLimit,
    Timeout,
    CacheControl,
    SecurityHeaders,
    RequestMetrics,
    SpaFallback,
}

/// Core routes that can be excluded from the application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreRoute {
    /// POST /api/bug-reports
    BugReports,
    /// POST /api/telemetry
    Telemetry,
    /// GET /api/health/direct
    DirectHealth,
    /// POST /api/upload/*path
    Upload,
    /// GET /health
    SimpleHealth,
}

/// Position in the middleware stack for custom middleware injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MiddlewareSlot {
    /// Before all core middleware (outermost on request).
    Outermost,
    /// Between transport-level and application-level core middleware.
    BeforeRouteHandling,
    /// After all core middleware (innermost, closest to handler).
    Innermost,
}

/// Type-erased middleware function. Called once at startup during router construction.
type MiddlewareFn = Box<dyn Fn(Router, &Arc<AppState>) -> Router + Send + Sync>;

/// Customization for the global middleware stack and core routes.
///
/// Default (empty) produces the identical middleware stack as before.
#[derive(Default)]
pub struct MiddlewareCustomization {
    disabled: HashSet<CoreMiddleware>,
    excluded_routes: HashSet<CoreRoute>,
    custom: Vec<(MiddlewareSlot, MiddlewareFn)>,
}

#[allow(dead_code)]
impl MiddlewareCustomization {
    /// Returns `true` if the given core middleware is enabled (not disabled).
    pub fn is_enabled(&self, mw: CoreMiddleware) -> bool {
        !self.disabled.contains(&mw)
    }

    /// Returns `true` if the given core route should be included.
    pub fn is_route_included(&self, route: CoreRoute) -> bool {
        !self.excluded_routes.contains(&route)
    }

    /// Returns an iterator over custom middleware registered at the given slot.
    pub fn custom_at(&self, slot: MiddlewareSlot) -> impl Iterator<Item = &(MiddlewareSlot, MiddlewareFn)> {
        self.custom.iter().filter(move |(s, _)| *s == slot)
    }

    /// Disable a core middleware layer.
    pub fn disable(&mut self, mw: CoreMiddleware) {
        self.disabled.insert(mw);
    }

    /// Exclude a core route.
    pub fn exclude_route(&mut self, route: CoreRoute) {
        self.excluded_routes.insert(route);
    }

    /// Add custom middleware at a specific slot.
    pub fn add_custom<F>(&mut self, slot: MiddlewareSlot, f: F)
    where
        F: Fn(Router, &Arc<AppState>) -> Router + Send + Sync + 'static,
    {
        self.custom.push((slot, Box::new(f)));
    }
}

/// Build the core application router: BFF proxy, admin, static files, bug reports,
/// telemetry, upload proxy. No OAuth, no webhooks, no geolocation, no image proxy.
///
/// Used by [`ServerBuilder`](crate::builder::ServerBuilder) as the base router
/// before merging provider-supplied routes.
pub fn build_core_app_router(
    state: Arc<AppState>,
    config: &AppConfig,
    customization: &MiddlewareCustomization,
) -> Router<Arc<AppState>> {
    let bff_router = build_bff_router(state.clone(), config);
    let admin_router = build_admin_router(state.clone(), config);

    log_websocket_config(&state, config);

    let empty = || Router::new().with_state(state.clone());

    let mut router = Router::new();

    if customization.is_route_included(CoreRoute::BugReports) {
        router = router.route("/api/bug-reports", post(bug_reports));
    }
    if customization.is_route_included(CoreRoute::Telemetry) {
        router = router.route("/api/telemetry", post(telemetry));
    }
    if customization.is_route_included(CoreRoute::DirectHealth) {
        router = router.route("/api/health/direct", get(direct_service_health));
    }
    if customization.is_route_included(CoreRoute::Upload) {
        router = router.route("/api/upload/*path", post(backend_upload_proxy));
    }
    if customization.is_route_included(CoreRoute::SimpleHealth) {
        router = router.route("/health", get(simple_health));
    }

    router
        .merge(admin_router.unwrap_or_else(&empty))
        .merge(bff_router)
        .with_state(state)
}

/// Apply the global middleware stack (CORS, compression, timeout, security headers, etc.)
/// to the given router.
///
/// Also attaches the SPA static-file fallback service.
///
/// Layer application order (Axum layers applied later are outer / execute first on request):
///
/// 1. Innermost custom middleware     (applied first → innermost on request)
/// 2. Application zone core middleware (SpaFallback → RequestMetrics → SecurityHeaders → CacheControl)
/// 3. BeforeRouteHandling custom middleware
/// 4. Transport zone core middleware  (Timeout → ConcurrencyLimit → Decompression → Compression → CORS → Trace)
/// 5. Outermost custom middleware     (applied last → outermost on request)
pub fn apply_global_middleware(
    app: Router<Arc<AppState>>,
    state: Arc<AppState>,
    config: &AppConfig,
    customization: &MiddlewareCustomization,
) -> Router {
    let static_dir = &config.server.static_dir;
    let fallback_state = state.clone();

    let mut router = app
        .fallback_service(
            ServeDir::new(static_dir).not_found_service(tower::service_fn(move |_req| {
                let state = fallback_state.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        spa_fallback(State(state)).await.into_response(),
                    )
                }
            })),
        )
        .with_state(state.clone());

    // === Innermost custom middleware (closest to handler) ===
    for (_, f) in customization.custom_at(MiddlewareSlot::Innermost) {
        router = f(router, &state);
    }

    // === Application zone (innermost core middleware) ===
    if customization.is_enabled(CoreMiddleware::SpaFallback) {
        router = router.layer(axum_middleware::from_fn_with_state(
            state.clone(),
            spa_404_fallback,
        ));
    }
    if customization.is_enabled(CoreMiddleware::RequestMetrics) {
        router = router.layer(axum_middleware::from_fn_with_state(
            state.clone(),
            request_metrics,
        ));
    }
    if customization.is_enabled(CoreMiddleware::SecurityHeaders) {
        router = router.layer(axum_middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ));
    }
    if customization.is_enabled(CoreMiddleware::CacheControl) {
        router = router.layer(axum_middleware::from_fn_with_state(
            state.clone(),
            cache_control_headers,
        ));
    }

    // === BeforeRouteHandling custom middleware ===
    for (_, f) in customization.custom_at(MiddlewareSlot::BeforeRouteHandling) {
        router = f(router, &state);
    }

    // === Transport zone (outermost core middleware) ===
    if customization.is_enabled(CoreMiddleware::Timeout) {
        router = router.layer(TimeoutLayer::new(std::time::Duration::from_secs(
            config.server.request_timeout_secs,
        )));
    }
    if customization.is_enabled(CoreMiddleware::ConcurrencyLimit) {
        router = router.layer(ConcurrencyLimitLayer::new(
            state
                .resource_manager()
                .map(|rm| rm.optimized.max_concurrent_requests)
                .unwrap_or(config.server.max_concurrent_connections),
        ));
    }
    if customization.is_enabled(CoreMiddleware::Decompression) {
        router = router.layer(RequestDecompressionLayer::new());
    }
    if customization.is_enabled(CoreMiddleware::Compression) {
        router = router.layer(
            CompressionLayer::new()
                .br(config.compression.enable_brotli)
                .gzip(config.compression.enable_gzip),
        );
    }
    if customization.is_enabled(CoreMiddleware::Cors) {
        router = router.layer(build_cors_layer(config));
    }
    if customization.is_enabled(CoreMiddleware::Trace) {
        router = router.layer(TraceLayer::new_for_http());
    }

    // === Outermost custom middleware (runs first on request) ===
    for (_, f) in customization.custom_at(MiddlewareSlot::Outermost) {
        router = f(router, &state);
    }

    router
}

/// Build the main HTTP application router with all routes and middleware.
///
/// Backward-compatible entry point — delegates to [`build_core_app_router`],
/// merges hardcoded OAuth/webhook/geolocation/image routers, then applies
/// global middleware via [`apply_global_middleware`].
#[allow(dead_code)]
pub fn build_app_router(state: Arc<AppState>, config: &AppConfig) -> Router {
    let customization = MiddlewareCustomization::default();
    #[allow(unused_mut)]
    let mut app = build_core_app_router(state.clone(), config, &customization);

    // Optional feature routers (hardcoded providers — kept for backward compat)
    #[cfg(feature = "google-oauth")]
    if let Some(r) = build_oauth_router(state.clone(), config) {
        app = app.merge(r);
    }

    #[cfg(feature = "instagram-oauth")]
    if let Some(r) = build_instagram_router(state.clone(), config) {
        app = app.merge(r);
    }

    // When both google-oauth and instagram-oauth are disabled, skip OAuth entirely
    #[cfg(not(any(feature = "google-oauth", feature = "instagram-oauth")))]
    let _ = &state; // suppress unused warning

    #[cfg(feature = "stripe-webhooks")]
    if let Some(r) = build_stripe_webhooks_router(state.clone(), config) {
        app = app.merge(r);
    }

    #[cfg(feature = "meta-webhooks")]
    if let Some(r) = build_meta_webhooks_router(state.clone(), config) {
        app = app.merge(r);
    }

    #[cfg(feature = "geolocation")]
    if let Some(r) = build_geolocation_router(state.clone(), config) {
        app = app.merge(r);
    }

    #[cfg(feature = "image-proxy")]
    {
        app = app.route(
            "/api/images/:product/:user_id/:filename",
            get(crate::images::image_proxy),
        );
    }

    apply_global_middleware(app, state, config, &customization)
}

/// Build the health check router (separate port, minimal middleware)
pub fn build_health_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/startup", get(health_startup))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/metrics", get(prometheus_metrics_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// BFF GraphQL routes with optional session auth and rate limiting
fn build_bff_router(state: Arc<AppState>, config: &AppConfig) -> Router<Arc<AppState>> {
    let mut router = Router::new()
        .route("/graphql", post(graphql_proxy).get(graphql_ws_proxy))
        .route("/api/graphql", post(graphql_proxy).get(graphql_ws_proxy))
        .with_state(state.clone());

    if config.features.enable_bff && config.bff.session.enabled {
        info!("   BFF Sessions: Enabled (Redis session-based auth)");
        router = router.layer(axum_middleware::from_fn_with_state(
            state.clone(),
            session_auth_middleware,
        ));
    } else if config.features.enable_bff {
        info!("   BFF Sessions: Disabled (passthrough auth mode)");
    }

    if config.features.enable_bff && config.bff.http.rate_limit.enabled {
        match build_rate_limit_layer(&config.bff.http.rate_limit, "HTTP") {
            Ok(rate_limit_layer) => {
                info!(
                    "   HTTP Rate Limiting: Enabled ({} req/s per client, burst {})",
                    config.bff.http.rate_limit.requests_per_second,
                    config.bff.http.rate_limit.burst_size
                );
                router = router.layer(rate_limit_layer);
            }
            Err(e) => {
                tracing::warn!("   HTTP Rate Limiting: Failed to initialize - {}", e);
            }
        }
    }

    router
}

/// OAuth routes (Google + account linking) — None if OAuth disabled or Google not configured
#[cfg(feature = "google-oauth")]
#[allow(dead_code)]
fn build_oauth_router(state: Arc<AppState>, config: &AppConfig) -> Option<Router<Arc<AppState>>> {
    if !(config.features.enable_bff && config.bff.oauth.enabled) {
        return None;
    }

    info!("   OAuth: Enabled (BFF handles token exchange)");
    if config.bff.oauth.google.is_some() {
        info!("     - Google OAuth: Configured");
    }

    Some(
        Router::new()
            .route("/api/auth/google", get(google_oauth_init))
            .route("/api/auth/google/callback", get(google_oauth_callback))
            .route("/api/auth/link-oauth-account", post(link_oauth_account))
            .route(
                "/api/auth/restore-oauth-account",
                post(restore_oauth_account),
            )
            .with_state(state),
    )
}

/// Instagram OAuth routes — None if OAuth disabled or Instagram not configured
#[cfg(feature = "instagram-oauth")]
#[allow(dead_code)]
fn build_instagram_router(
    state: Arc<AppState>,
    config: &AppConfig,
) -> Option<Router<Arc<AppState>>> {
    if !(config.features.enable_bff && config.bff.oauth.enabled) {
        return None;
    }

    if config.bff.oauth.instagram.is_some() {
        info!("     - Instagram OAuth: Configured (social integration)");
    }

    Some(
        Router::new()
            .route("/api/social/instagram", get(instagram_oauth_init))
            .route(
                "/api/social/instagram/callback",
                get(instagram_oauth_callback),
            )
            .with_state(state),
    )
}

/// Stripe + PIX webhook routes — None if webhooks disabled
#[cfg(feature = "stripe-webhooks")]
#[allow(dead_code)]
fn build_stripe_webhooks_router(
    state: Arc<AppState>,
    config: &AppConfig,
) -> Option<Router<Arc<AppState>>> {
    if !(config.features.enable_bff && config.bff.webhooks.enabled) {
        return None;
    }

    info!("   Webhooks: Stripe/PIX enabled");
    Some(
        Router::new()
            .route(
                "/webhooks/stripe",
                post(crate::webhooks::stripe::handle_stripe_webhook),
            )
            .route(
                "/webhooks/pix",
                post(crate::webhooks::stripe::handle_pix_webhook),
            )
            .with_state(state),
    )
}

/// Meta webhook routes — None if webhooks disabled
#[cfg(feature = "meta-webhooks")]
#[allow(dead_code)]
fn build_meta_webhooks_router(
    state: Arc<AppState>,
    config: &AppConfig,
) -> Option<Router<Arc<AppState>>> {
    if !(config.features.enable_bff && config.bff.webhooks.enabled) {
        return None;
    }

    info!("   Webhooks: Meta enabled");
    Some(
        Router::new()
            .route(
                "/webhooks/meta",
                post(crate::webhooks::meta::handle_meta_webhook),
            )
            .route(
                "/webhooks/meta",
                get(crate::webhooks::meta::verify_meta_webhook),
            )
            .with_state(state),
    )
}

/// Admin routes for federation management — None if admin disabled
fn build_admin_router(state: Arc<AppState>, config: &AppConfig) -> Option<Router<Arc<AppState>>> {
    if !(config.features.enable_bff
        && config.bff.federation.enabled
        && config.bff.federation.admin.enabled)
    {
        if config.features.enable_bff && config.bff.federation.enabled {
            info!("   Admin API: Disabled (use federation.admin.enabled: true to enable)");
        }
        return None;
    }

    info!("   Admin API: Enabled (/admin/reload-supergraph, /admin/supergraph-status)");
    Some(
        Router::new()
            .route("/admin/reload-supergraph", post(admin_reload_supergraph))
            .route("/admin/supergraph-status", get(admin_supergraph_status))
            .with_state(state),
    )
}

/// Geolocation route — None if geolocation disabled
#[cfg(feature = "geolocation")]
#[allow(dead_code)]
fn build_geolocation_router(
    state: Arc<AppState>,
    config: &AppConfig,
) -> Option<Router<Arc<AppState>>> {
    if !config.geolocation.enabled {
        info!("   Geolocation: Disabled");
        return None;
    }

    info!(
        "   Geolocation: Enabled ({} cities configured)",
        config.geolocation.cities.len()
    );
    Some(
        Router::new()
            .route("/api/geolocation", get(geolocation))
            .with_state(state),
    )
}

/// Log WebSocket configuration details
fn log_websocket_config(state: &AppState, config: &AppConfig) {
    if !config.features.enable_bff {
        return;
    }

    let max_connections = state
        .resource_manager()
        .map(|rm| rm.optimized.websocket_max_connections)
        .unwrap_or(config.bff.websocket.max_connections);

    let source = if state.resource_manager().is_some() {
        "auto-optimized"
    } else {
        "configured"
    };

    info!("   WebSocket Config:");
    info!("     - Max connections: {} ({})", max_connections, source);
    info!("     - Timeout: {}s", config.bff.websocket.timeout_secs);
    info!(
        "     - Max message size: {} MB",
        config.bff.websocket.max_message_size / (1024 * 1024)
    );
    if config.bff.websocket.ping_interval_secs > 0 {
        info!(
            "     - Ping interval: {}s",
            config.bff.websocket.ping_interval_secs
        );
    }
    if config.bff.websocket.enable_message_rate_limit {
        info!(
            "     - Message rate limit: {} msg/s per connection",
            config.bff.websocket.messages_per_second
        );
    }
}

/// Prometheus metrics endpoint handler
async fn prometheus_metrics_handler() -> impl IntoResponse {
    use axum::http::{header, StatusCode};

    let metrics = crate::prometheus::render_metrics();

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics,
    )
}
