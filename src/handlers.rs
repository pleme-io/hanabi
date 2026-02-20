//! HTTP request handlers for application endpoints
//!
//! This module contains Axum handler functions for:
//! - SPA (Single Page Application) fallback
//! - Bug reporting endpoint (non-production only)
//!
//! # Handler Types
//! - **SPA Fallback**: Serves index.html for client-side routing (React Router)
//! - **Bug Reports**: Accepts frontend error reports (staging/dev only)
//!
//! # Example
//! ```rust
//! Router::new()
//!     .route("/api/bug-reports", post(bug_reports))
//!     .fallback(spa_fallback)
//! ```

use std::path::Path;
use std::sync::{Arc, LazyLock};

use axum::{
    body::Bytes,
    extract::{ConnectInfo, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use regex::Regex;
use tracing::{error, info, warn};

use crate::prometheus;
use crate::state::AppState;

// Pre-compiled regexes for path sanitization (used once, kept forever)
static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("Static UUID_REGEX pattern is valid")
});

static NUMERIC_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/\d+").expect("Static NUMERIC_ID_REGEX pattern is valid"));

/// SPA fallback handler - Returns index.html with 200 OK status
///
/// This handler is called when no route matches the request path.
/// It serves the React app's index.html file, enabling client-side routing.
///
/// # Why This Is Needed
/// React Router (and other SPA routers) use the HTML5 History API for routing.
/// When a user navigates to /products/123, the browser sends a request to the server.
/// Without this fallback, the server would return 404 because no route matches.
/// This handler returns index.html instead, allowing React to handle the route.
///
/// # Behavior
/// - Always returns HTTP 200 OK (never 404)
/// - Serves index.html from static directory
/// - Sets Content-Type: text/html; charset=utf-8
/// - Returns 500 if index.html cannot be read
///
/// # Example Routes Handled
/// - /products/123 → index.html (React handles routing)
/// - /checkout/payment → index.html (React handles routing)
/// - /admin/dashboard → index.html (React handles routing)
///
/// # Note
/// Static files (JS, CSS, images) are served by ServeDir middleware
/// and never reach this fallback handler.
pub async fn spa_fallback(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let index_path =
        Path::new(&state.config.server.static_dir).join(&state.config.preflight.index_html_path);

    match tokio::fs::read_to_string(&index_path).await {
        Ok(content) => {
            // Return index.html with proper 200 OK status, content-type, and cache headers
            // CRITICAL: HTML must never be cached to ensure users get fresh version after deployments
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (
                        header::CACHE_CONTROL,
                        "no-cache, no-store, must-revalidate, max-age=0",
                    ),
                ],
                content,
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to read index.html for SPA fallback: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to load application",
            )
                .into_response()
        }
    }
}

/// Bug report endpoint - accepts frontend bug reports
///
/// ONLY enabled for non-production environments (staging, development).
/// Production uses dedicated monitoring services (Sentry, DataDog, etc.)
///
/// # Configuration
/// - Enabled via: config.features.enable_bug_reports
/// - Auto-configured: disabled in production, enabled in dev/staging
/// - Manual override: set explicit boolean in config
///
/// # Request Format
/// Accepts any JSON payload from frontend (no schema validation).
/// Typical fields:
/// - error: Error message
/// - stack: Stack trace
/// - url: Page URL where error occurred
/// - userAgent: Browser user agent
/// - timestamp: Client-side timestamp
///
/// # Response
/// - **200 OK**: Bug report accepted and logged
/// - **403 Forbidden**: Bug reporting disabled (shouldn't happen if frontend checks)
///
/// # Example Request
/// ```json
/// POST /api/bug-reports
/// {
///   "error": "TypeError: Cannot read property 'name' of undefined",
///   "stack": "at ProductCard.tsx:42...",
///   "url": "/products/123",
///   "userAgent": "Mozilla/5.0..."
/// }
/// ```
///
/// # Security
/// This endpoint is intentionally simple and doesn't persist data.
/// Logs are collected by Vector and forwarded to logging infrastructure.
/// Do NOT expose this in production - use proper APM/monitoring instead.
pub async fn bug_reports(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Check if bug reports are enabled (auto-configured based on environment)
    let enabled = state.config.features.enable_bug_reports.unwrap_or(false);

    if !enabled {
        warn!("Bug report endpoint called but disabled - this should not happen!");
        state.incr("bug_reports.rejected", &[("reason", "disabled")]);
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "Bug reporting is disabled",
                "message": "Use dedicated monitoring services for production issues"
            })),
        )
            .into_response();
    }

    // Emit metrics for bug report received
    state.incr(
        "bug_reports.received",
        &[("source", "frontend"), ("env", &state.config.environment)],
    );

    // Log the bug report
    info!(
        "Bug report received ({}): {:?}",
        state.config.environment, payload
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "received",
            "message": "Bug report accepted",
            "environment": state.config.environment
        })),
    )
        .into_response()
}

/// Simple health check endpoint for integration tests
///
/// Returns HTTP 200 OK with version information to identify the specific deployment.
/// This allows integration tests to verify they're testing the correct release.
///
/// # Response Format
/// ```json
/// {
///   "status": "healthy",
///   "service": "my-service",
///   "version": {
///     "app": "1.0.0",           // From package.json
///     "gitSha": "abc123def",    // Git commit hash
///     "buildTime": "2025-11-24T05:40:21.123Z",
///     "server": "0.1.0"         // Web server binary version
///   }
/// }
/// ```
///
/// # Use Case
/// - Integration tests polling `https://staging.example.com/health`
/// - Verifying the correct deployment is running before testing
/// - External monitoring services
/// - Simple uptime checks
///
/// # Note
/// This is separate from the internal Kubernetes health probes which use:
/// - /health/startup (port 8080)
/// - /health/live (port 8080)
/// - /health/ready (port 8080)
///
/// Those internal probes are more comprehensive and check dependencies.
/// This endpoint is intentionally simple and fast.
pub async fn simple_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Read version.json to get build information
    let version_path = Path::new(&state.config.server.static_dir).join("version.json");

    let version_info = match tokio::fs::read_to_string(&version_path).await {
        Ok(content) => {
            match serde_json::from_str::<serde_json::Value>(&content) {
                Ok(mut json) => {
                    // Add server binary version to the version info
                    json["server"] = serde_json::json!(env!("CARGO_PKG_VERSION"));
                    json
                }
                Err(_) => {
                    // If parsing fails, return minimal version info
                    serde_json::json!({
                        "server": env!("CARGO_PKG_VERSION"),
                        "error": "version.json parse error"
                    })
                }
            }
        }
        Err(_) => {
            // If version.json doesn't exist, return minimal version info
            serde_json::json!({
                "server": env!("CARGO_PKG_VERSION"),
                "error": "version.json not found"
            })
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "service": state.config.server.service_name,
            "version": version_info
        })),
    )
        .into_response()
}

// ============================================================================
// FRONTEND TELEMETRY (CNCF-Aligned Observability)
// ============================================================================
//
// This endpoint receives telemetry from frontend applications and routes it to
// the appropriate CNCF observability backends:
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │                        FRONTEND TELEMETRY FLOW                           │
// ├─────────────────────────────────────────────────────────────────────────┤
// │   Browser (Web Vitals, Errors, Events)                                   │
// │            ↓                                                             │
// │   POST /api/telemetry (Hanabi BFF)                                       │
// │            ↓                                                             │
// │   ┌─────────────────────────────────────────────────────────────┐       │
// │   │               TELEMETRY HANDLER                              │       │
// │   │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │       │
// │   │  │   METRICS    │  │    LOGS      │  │   TRACES     │       │       │
// │   │  │ Web Vitals   │  │   Errors     │  │  User Flow   │       │       │
// │   │  │ Counters     │  │   Events     │  │  (Future)    │       │       │
// │   │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘       │       │
// │   │         │                 │                 │                │       │
// │   │         ▼                 ▼                 ▼                │       │
// │   │     StatsD           Structured         OTLP                │       │
// │   │      (UDP)           JSON logs         (gRPC)               │       │
// │   └─────────────────────────────────────────────────────────────┘       │
// │            ↓                 ↓                 ↓                         │
// │        Vector            Vector            Tempo                         │
// │            ↓                 ↓                 ↓                         │
// │       Prometheus          Loki              Tempo                        │
// │            ↓                 ↓                 ↓                         │
// │                         GRAFANA                                          │
// └─────────────────────────────────────────────────────────────────────────┘
//
// NO EXTERNAL SAAS: All observability stays within the Kubernetes cluster.

use serde::Deserialize;

/// Telemetry event from frontend
#[derive(Debug, Deserialize)]
pub struct TelemetryEvent {
    /// Event type: metric, event, error, trace
    #[serde(rename = "type")]
    pub event_type: String,

    /// Event name (e.g., "CLS", "LCP", "button_click", "api_error")
    pub name: String,

    /// Numeric value (for metrics)
    #[serde(default)]
    pub value: Option<f64>,

    /// Rating for Web Vitals: good, needs-improvement, poor
    #[serde(default)]
    pub rating: Option<String>,

    /// Additional properties
    #[serde(default)]
    pub properties: Option<serde_json::Value>,

    /// Client timestamp (milliseconds since epoch)
    pub timestamp: u64,

    /// Session ID for correlation
    #[serde(rename = "sessionId")]
    pub session_id: String,

    /// Page path where event occurred
    pub page: String,
}

/// Telemetry request payload from frontend
#[derive(Debug, Deserialize)]
pub struct TelemetryPayload {
    /// Batch of telemetry events
    pub events: Vec<TelemetryEvent>,
}

/// Frontend telemetry endpoint - receives and routes telemetry to CNCF stack
///
/// This endpoint is the bridge between frontend observability and the Kubernetes
/// observability infrastructure (Prometheus, Loki, Tempo via Vector).
///
/// # Event Types
/// - **metric**: Web Vitals (CLS, LCP, FCP, INP, TTFB) → StatsD → Prometheus
/// - **event**: User interactions (clicks, form submissions) → Structured log → Loki
/// - **error**: Exceptions and errors → Structured log with stack trace → Loki
/// - **trace**: User flow events (page views, navigation) → Structured log → Loki
///
/// # Request Format
/// ```json
/// {
///   "events": [
///     {
///       "type": "metric",
///       "name": "LCP",
///       "value": 2500.5,
///       "rating": "good",
///       "timestamp": 1703123456789,
///       "sessionId": "abc123",
///       "page": "/products"
///     }
///   ]
/// }
/// ```
///
/// # Response
/// - **200 OK**: Telemetry accepted (no body for minimal latency)
/// - **400 Bad Request**: Invalid JSON payload
///
/// # Performance
/// - Async, non-blocking processing
/// - Metrics via UDP (fire-and-forget to Vector)
/// - Logs written synchronously but tracing handles buffering
/// - Typical latency: <5ms
pub async fn telemetry(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<TelemetryPayload>,
) -> impl IntoResponse {
    let event_count = payload.events.len();
    let product = &state.config.bff.product;

    // Process each event
    for event in payload.events {
        match event.event_type.as_str() {
            // ================================================================
            // METRICS: Web Vitals and custom metrics → Prometheus + StatsD
            // ================================================================
            "metric" => {
                if let Some(value) = event.value {
                    let rating = event.rating.as_deref().unwrap_or("unknown");
                    let page = sanitize_page_path(&event.page);

                    // Get namespace from POD_NAMESPACE env var (Kubernetes downward API)
                    let namespace = std::env::var("POD_NAMESPACE")
                        .unwrap_or_else(|_| format!("{}-staging", product));

                    // Record to Prometheus (native histograms with proper buckets)
                    if ["CLS", "LCP", "FCP", "INP", "TTFB"].contains(&event.name.as_str()) {
                        prometheus::record_web_vital(
                            &event.name,
                            value,
                            rating,
                            &namespace,
                            product,
                            &page,
                        );
                    }

                    // Also emit to StatsD → Vector (for backwards compatibility)
                    state.histogram(
                        &format!("frontend.{}", event.name.to_lowercase()),
                        value,
                        &[("product", product), ("rating", rating), ("page", &page)],
                    );

                    // Also emit counter for each rating bucket (for SLO dashboards)
                    if ["CLS", "LCP", "FCP", "INP", "TTFB"].contains(&event.name.as_str()) {
                        state.incr(
                            &format!("frontend.vitals.{}", rating),
                            &[
                                ("product", product),
                                ("metric", &event.name),
                                ("page", &page),
                            ],
                        );
                    }
                }
            }

            // ================================================================
            // EVENTS: User interactions → Prometheus + Loki
            // ================================================================
            "event" => {
                let page = sanitize_page_path(&event.page);
                let namespace = std::env::var("POD_NAMESPACE")
                    .unwrap_or_else(|_| format!("{}-staging", product));

                // Record to Prometheus
                prometheus::record_frontend_event(&namespace, product, &event.name, &page);

                // Log to Loki via structured logging
                info!(
                    telemetry_type = "event",
                    event_name = %event.name,
                    page = %event.page,
                    session_id = %event.session_id,
                    timestamp = event.timestamp,
                    product = %product,
                    properties = ?event.properties,
                    "Frontend event"
                );

                // Also emit to StatsD (backwards compatibility)
                state.incr(
                    "frontend.events",
                    &[
                        ("product", product),
                        ("name", &event.name),
                        ("page", &page),
                    ],
                );
            }

            // ================================================================
            // ERRORS: Exceptions → Prometheus + Loki (with stack)
            // ================================================================
            "error" => {
                let page = sanitize_page_path(&event.page);
                let namespace = std::env::var("POD_NAMESPACE")
                    .unwrap_or_else(|_| format!("{}-staging", product));

                // Record to Prometheus
                prometheus::record_frontend_error(&namespace, product, &event.name, &page);

                // Extract error details from properties
                let message = event
                    .properties
                    .as_ref()
                    .and_then(|p| p.get("message"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown error");

                let stack = event
                    .properties
                    .as_ref()
                    .and_then(|p| p.get("stack"))
                    .and_then(|v| v.as_str());

                // Log error with full context (goes to Loki via Vector)
                error!(
                    telemetry_type = "error",
                    error_name = %event.name,
                    error_message = %message,
                    error_stack = ?stack,
                    page = %event.page,
                    session_id = %event.session_id,
                    timestamp = event.timestamp,
                    product = %product,
                    properties = ?event.properties,
                    "Frontend error"
                );

                // Also emit to StatsD (backwards compatibility)
                state.incr(
                    "frontend.errors",
                    &[
                        ("product", product),
                        ("name", &event.name),
                        ("page", &page),
                    ],
                );
            }

            // ================================================================
            // TRACES: User flow events → Loki via structured logging
            // ================================================================
            "trace" => {
                info!(
                    telemetry_type = "trace",
                    trace_name = %event.name,
                    page = %event.page,
                    session_id = %event.session_id,
                    timestamp = event.timestamp,
                    product = %product,
                    properties = ?event.properties,
                    "Frontend trace"
                );
            }

            // Unknown event types are logged but not processed
            other => {
                warn!(
                    telemetry_type = %other,
                    event_name = %event.name,
                    "Unknown telemetry event type"
                );
            }
        }
    }

    // Get namespace for Prometheus
    let namespace = std::env::var("POD_NAMESPACE")
        .unwrap_or_else(|_| format!("{}-staging", product));

    // Record to Prometheus
    prometheus::record_telemetry_received(&namespace, product, event_count as u64);

    // Also emit to StatsD (backwards compatibility)
    state.count(
        "frontend.telemetry.events_received",
        event_count as i64,
        &[("product", product)],
    );

    // Return 200 OK with minimal body (performance)
    StatusCode::OK
}

/// Sanitize page path for use as a metric tag
///
/// Removes dynamic segments (UUIDs, IDs) to prevent high cardinality.
/// Examples:
/// - /products/123 → /products/:id
/// - /users/abc-def-123 → /users/:id
fn sanitize_page_path(path: &str) -> String {
    // Replace UUIDs using pre-compiled static regex
    let path = UUID_REGEX.replace_all(path, ":id");

    // Replace numeric IDs in paths using pre-compiled static regex
    let path = NUMERIC_ID_REGEX.replace_all(&path, "/:id");

    // Truncate long paths
    if path.len() > 50 {
        format!("{}...", &path[..47])
    } else {
        path.to_string()
    }
}

// ============================================================================
// GEOLOCATION ENDPOINT (IP-based city detection)
// ============================================================================
//
// This endpoint detects the user's city based on their IP address using ip-api.com.
// Used by the city.store.ts on the frontend to auto-select user's city.
//
// Flow:
// 1. Extract client IP from X-Forwarded-For (first IP) or socket address
// 2. Check Redis cache (24h TTL)
// 3. If cache miss, call ip-api.com (free tier: 45 req/min)
// 4. Map city name to CityValue slug (fuzzy match)
// 5. Cache result and return
//
// Response format:
// {
//   "city": "sao-paulo" | null,
//   "confidence": "high" | "medium" | "low" | "none",
//   "source": "ip" | "cached"
// }

/// Geolocation response returned to frontend
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct GeolocationResponse {
    /// City slug matching CityValue from @pleme/brazilian-utils (null if not found)
    pub city: Option<String>,
    /// Confidence level of the detection
    pub confidence: String, // "high", "medium", "low", "none"
    /// Source of the detection
    pub source: String, // "ip", "cached"
}

/// ip-api.com response structure
#[derive(Debug, serde::Deserialize)]
#[allow(dead_code)]
struct IpApiResponse {
    status: String,
    city: Option<String>,
    #[serde(rename = "regionName")]
    region_name: Option<String>,
}

use crate::config::GeoCity;

/// Map city name from ip-api to a city slug using config-driven city list
/// Uses case-insensitive substring matching
#[allow(dead_code)]
fn match_city_to_slug<'a>(city_name: &str, cities: &'a [GeoCity]) -> Option<&'a str> {
    let normalized = city_name.to_lowercase();

    // Try exact match first (normalized)
    for city in cities {
        if normalized == city.name.to_lowercase() {
            return Some(&city.slug);
        }
    }

    // Try contains match (for partial names like "São Paulo" in "São Paulo City")
    for city in cities {
        if normalized.contains(&city.name.to_lowercase()) {
            return Some(&city.slug);
        }
    }

    // Try reverse contains (for shortened names)
    for city in cities {
        if city.name.to_lowercase().contains(&normalized) && normalized.len() >= 4 {
            return Some(&city.slug);
        }
    }

    None
}

/// Geolocation endpoint - detects user's city based on IP address
///
/// GET /api/geolocation
///
/// Uses ip-api.com (free tier, 45 req/min) with Redis caching (24h TTL).
/// Maps detected city to CityValue slug from @pleme/brazilian-utils.
///
/// # Security Features
/// - **IP Validation**: Rejects private/reserved/invalid IPs
/// - **Rate Limiting**: 10 requests per IP per minute (Redis INCR)
/// - **Cache Stampede Protection**: Uses SETNX lock to prevent thundering herd
///
/// # Response
/// - **200 OK**: Geolocation result (city may be null if not detected)
/// - **429 Too Many Requests**: Rate limit exceeded
///
/// # Caching
/// - Redis key: `{product}:geolocation:{ip}`
/// - TTL: 24 hours
/// - Lock key: `{product}:geolocation:lock:{ip}` (10 second TTL)
#[allow(dead_code)]
pub async fn geolocation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
) -> impl IntoResponse {
    // Extract client IP from proxy headers (Cloudflare → X-Real-IP → X-Forwarded-For → socket)
    // Priority order:
    // 1. CF-Connecting-IP: Cloudflare's authoritative header (most trusted)
    // 2. X-Real-IP: Common proxy header (single IP)
    // 3. X-Forwarded-For: Proxy chain (first IP is original client)
    // 4. Socket address: Direct connection fallback
    let (client_ip, ip_source) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| (s.trim().to_string(), "cf-connecting-ip"))
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .map(|s| (s.trim().to_string(), "x-real-ip"))
        })
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| (s.trim().to_string(), "x-forwarded-for"))
        })
        .unwrap_or_else(|| (addr.ip().to_string(), "socket"));

    // Validate IP address format and reject private/reserved IPs
    if !is_valid_public_ip(&client_ip) {
        // Log all relevant headers for debugging proxy/CDN issues
        let cf_ip = headers
            .get("cf-connecting-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>");
        let x_real_ip = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>");
        let x_forwarded_for = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("<missing>");
        warn!(
            "Geolocation rejected invalid/private IP: {} (source: {}). Debug headers: CF-Connecting-IP={}, X-Real-IP={}, X-Forwarded-For={}, socket={}",
            client_ip, ip_source, cf_ip, x_real_ip, x_forwarded_for, addr.ip()
        );
        state.incr("geolocation.invalid_ip", &[]);
        return (
            StatusCode::OK,
            Json(GeolocationResponse {
                city: None,
                confidence: "none".to_string(),
                source: "ip".to_string(),
            }),
        )
            .into_response();
    }

    info!(
        "Geolocation request for IP: {} (source: {})",
        client_ip, ip_source
    );

    // Rate limiting: 10 requests per IP per minute
    let product = &state.config.bff.product;
    let rate_limit_key = format!("{}:geolocation:rate:{}", product, client_ip);
    if let Some(redis_pool) = state.session_redis() {
        match redis_pool.get().await {
            Some(mut conn) => {
                use redis::AsyncCommands;

                // Atomic INCR with expiry
                let count: Result<i64, _> = conn.incr(&rate_limit_key, 1).await;
                match count {
                    Ok(count) => {
                        if count == 1 {
                            // First request in window - set 60 second expiry
                            // Note: Small race window exists between INCR and EXPIRE
                            // Worst case: key persists slightly longer, which is acceptable
                            if let Err(e) = conn.expire::<_, ()>(&rate_limit_key, 60).await {
                                warn!("Failed to set rate limit expiry for {}: {}", client_ip, e);
                            }
                        }

                        if count > state.config.geolocation.rate_limit_per_minute as i64 {
                            warn!(
                                "Geolocation rate limit exceeded for IP: {} ({} requests)",
                                client_ip, count
                            );
                            state.incr("geolocation.rate_limited", &[]);
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(serde_json::json!({
                                    "error": "Rate limit exceeded",
                                    "retry_after": 60
                                })),
                            )
                                .into_response();
                        }
                    }
                    Err(e) => {
                        // Log but don't fail - allow request to proceed without rate limiting
                        warn!("Redis rate limit INCR failed for {}: {}", client_ip, e);
                    }
                }
            }
            None => {
                // Redis connection unavailable - log warning and proceed without rate limiting
                warn!("Redis connection unavailable for rate limiting, proceeding without limits");
            }
        }
    } else {
        // No Redis pool configured - this shouldn't happen in production
        warn!("No Redis pool configured for geolocation rate limiting");
    }

    // Check Redis cache first
    let cache_key = format!("{}:geolocation:{}", product, client_ip);
    let lock_key = format!("{}:geolocation:lock:{}", product, client_ip);

    if let Some(redis_pool) = state.session_redis() {
        match redis_pool.get().await {
            Some(mut conn) => {
                use redis::AsyncCommands;

                // Try to get cached result
                match conn.get::<_, Option<String>>(&cache_key).await {
                    Ok(Some(cached_json)) => {
                        match serde_json::from_str::<GeolocationResponse>(&cached_json) {
                            Ok(cached_response) => {
                                info!(
                                    "Geolocation cache hit for IP {}: {:?}",
                                    client_ip, cached_response.city
                                );

                                state.incr("geolocation.cache_hit", &[]);

                                // Return cached response with source updated to "cached"
                                return (
                                    StatusCode::OK,
                                    Json(GeolocationResponse {
                                        city: cached_response.city,
                                        confidence: cached_response.confidence,
                                        source: "cached".to_string(),
                                    }),
                                )
                                    .into_response();
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to parse cached geolocation for {}: {}",
                                    client_ip, e
                                );
                                // Proceed to fetch fresh data
                            }
                        }
                    }
                    Ok(None) => {
                        // Cache miss - continue to fetch
                    }
                    Err(e) => {
                        warn!("Redis cache read failed for {}: {}", client_ip, e);
                        // Proceed without cache
                    }
                }
            }
            None => {
                warn!("Redis connection unavailable for cache read");
            }
        }
    }

    // Cache miss - try to acquire lock for cache stampede protection
    // This prevents multiple concurrent requests from hitting ip-api.com
    let mut acquired_lock = false;
    if let Some(redis_pool) = state.session_redis() {
        if let Some(mut conn) = redis_pool.get().await {
            use redis::AsyncCommands;

            // Try to set lock with SETNX (set if not exists) + 10 second expiry
            let lock_result: Result<bool, _> = redis::cmd("SET")
                .arg(&lock_key)
                .arg("1")
                .arg("NX") // Only set if not exists
                .arg("EX")
                .arg(10) // 10 second expiry
                .query_async(&mut conn)
                .await;

            if let Ok(true) = lock_result {
                acquired_lock = true;
            } else {
                // Lock is held by another request - wait briefly then check cache again
                info!("Geolocation lock held for IP {}, waiting for result", client_ip);
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                // Check cache again after waiting
                let cached: Result<Option<String>, _> = conn.get(&cache_key).await;
                if let Ok(Some(cached_json)) = cached {
                    if let Ok(cached_response) =
                        serde_json::from_str::<GeolocationResponse>(&cached_json)
                    {
                        state.incr("geolocation.cache_hit_after_wait", &[]);
                        return (
                            StatusCode::OK,
                            Json(GeolocationResponse {
                                city: cached_response.city,
                                confidence: cached_response.confidence,
                                source: "cached".to_string(),
                            }),
                        )
                            .into_response();
                    }
                }
                // If still no result after wait, proceed anyway (lock may have expired)
            }
        }
    }

    info!("Geolocation cache miss for IP: {} (lock: {})", client_ip, acquired_lock);

    state.incr("geolocation.cache_miss", &[]);

    // Use the shared HTTP client
    let client = match state.http_client() {
        Some(c) => c.clone(),
        None => {
            warn!("HTTP client not available for geolocation");
            return (
                StatusCode::OK,
                Json(GeolocationResponse {
                    city: None,
                    confidence: "none".to_string(),
                    source: "ip".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Call geolocation API with timeout
    let api_url = state
        .config
        .geolocation
        .api_url_template
        .replace("{ip}", &client_ip);

    let response = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.get(&api_url).send(),
    )
    .await
    {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            warn!("Geolocation API error: {}", e);
            state.incr("geolocation.api_error", &[]);
            return (
                StatusCode::OK,
                Json(GeolocationResponse {
                    city: None,
                    confidence: "none".to_string(),
                    source: "ip".to_string(),
                }),
            )
                .into_response();
        }
        Err(_) => {
            warn!("Geolocation API timeout");
            state.incr("geolocation.api_timeout", &[]);
            return (
                StatusCode::OK,
                Json(GeolocationResponse {
                    city: None,
                    confidence: "none".to_string(),
                    source: "ip".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Parse response
    let api_response: IpApiResponse = match response.json().await {
        Ok(data) => data,
        Err(e) => {
            warn!("Geolocation API parse error: {}", e);
            return (
                StatusCode::OK,
                Json(GeolocationResponse {
                    city: None,
                    confidence: "none".to_string(),
                    source: "ip".to_string(),
                }),
            )
                .into_response();
        }
    };

    // Check if API succeeded
    if api_response.status != "success" {
        info!("Geolocation API returned non-success status");
        return (
            StatusCode::OK,
            Json(GeolocationResponse {
                city: None,
                confidence: "none".to_string(),
                source: "ip".to_string(),
            }),
        )
            .into_response();
    }

    // Try to match city to slug using config-driven city list
    let cities = &state.config.geolocation.cities;
    let (city_slug, confidence) = if let Some(ref city_name) = api_response.city {
        if let Some(slug) = match_city_to_slug(city_name, cities) {
            info!(
                "Geolocation matched city '{}' to slug '{}'",
                city_name, slug
            );
            (Some(slug.to_string()), "high".to_string())
        } else {
            info!("Geolocation could not match city '{}'", city_name);
            (None, "low".to_string())
        }
    } else {
        (None, "none".to_string())
    };

    let result = GeolocationResponse {
        city: city_slug.clone(),
        confidence: confidence.clone(),
        source: "ip".to_string(),
    };

    // Cache the result in Redis
    // Use shorter TTL for "none" confidence results so we retry failed lookups sooner
    if let Some(redis_pool) = state.session_redis() {
        if let Some(mut conn) = redis_pool.get().await {
            use redis::AsyncCommands;

            match serde_json::to_string(&result) {
                Ok(json) => {
                    // Use config-driven TTLs for cache duration
                    let geo_config = &state.config.geolocation;
                    let ttl_seconds: u64 = if confidence == "none" {
                        geo_config.failed_cache_ttl_secs
                    } else {
                        geo_config.cache_ttl_secs
                    };

                    match conn.set_ex::<_, _, ()>(&cache_key, json, ttl_seconds).await {
                        Ok(()) => {
                            info!(
                                "Geolocation result cached for IP: {} (TTL: {}s, confidence: {})",
                                client_ip, ttl_seconds, confidence
                            );
                        }
                        Err(e) => {
                            warn!(
                                "Failed to cache geolocation result for {}: {}",
                                client_ip, e
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to serialize geolocation result for {}: {}",
                        client_ip, e
                    );
                }
            }

            // Release lock if we acquired it
            if acquired_lock {
                if let Err(e) = conn.del::<_, ()>(&lock_key).await {
                    warn!("Failed to release geolocation lock for {}: {}", client_ip, e);
                }
            }
        } else {
            warn!(
                "Redis connection unavailable for caching geolocation result for {}",
                client_ip
            );
        }
    }

    state.incr(
        "geolocation.success",
        &[
            (
                "has_city",
                if city_slug.is_some() { "true" } else { "false" },
            ),
            ("confidence", &confidence),
        ],
    );

    (StatusCode::OK, Json(result)).into_response()
}

/// Validate that an IP address is a valid public IP (not private/reserved)
///
/// Rejects:
/// - Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - Loopback: 127.0.0.0/8
/// - Link-local: 169.254.0.0/16
/// - Reserved: 0.0.0.0/8, 224.0.0.0/4, 240.0.0.0/4
/// - Invalid format
#[allow(dead_code)]
fn is_valid_public_ip(ip: &str) -> bool {
    use std::net::IpAddr;

    // Parse IP address
    let parsed: IpAddr = match ip.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    match parsed {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();

            // Reject private ranges
            // 10.0.0.0/8
            if octets[0] == 10 {
                return false;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
                return false;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return false;
            }

            // Reject loopback (127.0.0.0/8)
            if octets[0] == 127 {
                return false;
            }

            // Reject link-local (169.254.0.0/16)
            if octets[0] == 169 && octets[1] == 254 {
                return false;
            }

            // Reject 0.0.0.0/8
            if octets[0] == 0 {
                return false;
            }

            // Reject multicast (224.0.0.0/4)
            if octets[0] >= 224 && octets[0] <= 239 {
                return false;
            }

            // Reject reserved (240.0.0.0/4)
            if octets[0] >= 240 {
                return false;
            }

            true
        }
        IpAddr::V6(ipv6) => {
            // Reject loopback (::1)
            if ipv6.is_loopback() {
                return false;
            }

            // Accept other IPv6 addresses (ip-api.com supports them)
            true
        }
    }
}

// ============================================================================
// BACKEND REST PROXY (File Uploads)
// ============================================================================
//
// This endpoint proxies REST API requests to the backend service.
// Used for file uploads since they don't go through GraphQL.
//
// Flow:
// 1. Frontend POSTs multipart form data to /api/upload/{ad_id}
// 2. Hanabi BFF forwards the raw body to backend at backend_rest_url/api/upload/{ad_id}
// 3. Backend processes upload and returns JSON response
// 4. Hanabi forwards the response back to frontend
//
// This keeps the storage (RustFS/S3) internal to the cluster - not exposed to the internet.

/// Backend upload proxy handler
///
/// Proxies file upload requests to the backend REST API.
/// Forwards the request body as-is (including multipart form data).
///
/// Route: POST /api/upload/{*path}
///
/// # Headers Forwarded
/// - Content-Type (critical for multipart parsing)
/// - Content-Length
/// - Authorization (if present from session middleware)
///
/// # Response
/// - Forwards backend response status and body directly
pub async fn backend_upload_proxy(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(path): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if BFF is enabled
    if !state.config.features.enable_bff {
        warn!("Backend upload proxy called but BFF is disabled");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "success": false,
                "error": "BFF is disabled",
                "code": "BFF_DISABLED"
            })),
        )
            .into_response();
    }

    // Get backend REST URL
    let backend_base_url = state.config.bff.get_backend_rest_url();
    let upload_url = format!("{}/api/upload/{}", backend_base_url, path);

    info!(
        "Backend upload proxy: forwarding to {} (path: {}, body_size: {} bytes)",
        upload_url,
        path,
        body.len()
    );

    // Get HTTP client
    let client = match state.http_client() {
        Some(c) => c.clone(),
        None => {
            error!("HTTP client not available for backend upload proxy");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "HTTP client not initialized",
                    "code": "CLIENT_ERROR"
                })),
            )
                .into_response();
        }
    };

    // Build request to backend
    let timeout = std::time::Duration::from_secs(state.config.bff.http.timeout_secs);

    // Send body as bytes (preserves multipart form data exactly)
    let mut request = client.post(&upload_url).timeout(timeout).body(body);

    // Forward critical headers
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(content_length) = headers.get(header::CONTENT_LENGTH) {
        request = request.header(header::CONTENT_LENGTH, content_length);
    }
    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, auth);
    }

    // Set product header for multi-tenant isolation
    request = request.header("x-product", state.config.bff.product.as_str());

    // Send request
    let response = match request.send().await {
        Ok(r) => r,
        Err(e) => {
            error!("Backend upload proxy failed: {} (url: {})", e, upload_url);

            state.incr("bff.upload_proxy.error", &[("reason", "upstream_error")]);

            let status = if e.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else if e.is_connect() {
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::BAD_GATEWAY
            };

            return (
                status,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": format!("Failed to reach backend: {}", e),
                    "code": "UPSTREAM_ERROR"
                })),
            )
                .into_response();
        }
    };

    let status = response.status();
    info!(
        "Backend upload proxy received response: status={}",
        status.as_u16()
    );

    // Parse response body as JSON
    let response_body = match response.json::<serde_json::Value>().await {
        Ok(b) => b,
        Err(e) => {
            error!("Backend upload proxy: failed to parse response: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "success": false,
                    "error": "Failed to parse backend response",
                    "code": "PARSE_ERROR"
                })),
            )
                .into_response();
        }
    };

    state.incr(
        "bff.upload_proxy.success",
        &[("status", &status.as_u16().to_string())],
    );

    // Return the backend response
    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        axum::Json(response_body),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handlers_compile() {
        // Verify handlers are properly structured
        // Integration tests would require full AppState setup
    }

    #[test]
    fn test_sanitize_page_path() {
        assert_eq!(sanitize_page_path("/products"), "/products");
        assert_eq!(sanitize_page_path("/products/123"), "/products/:id");
        assert_eq!(
            sanitize_page_path("/users/abc-def-123-456-789"),
            "/users/abc-def-123-456-789"
        ); // Not a valid UUID
        assert_eq!(
            sanitize_page_path("/users/12345678-1234-1234-1234-123456789012"),
            "/users/:id"
        );
    }

    #[test]
    fn test_match_city_to_slug() {
        let cities = vec![
            GeoCity { slug: "sao-paulo".to_string(), name: "São Paulo".to_string() },
            GeoCity { slug: "rio-de-janeiro".to_string(), name: "Rio de Janeiro".to_string() },
        ];

        // Exact match
        assert_eq!(match_city_to_slug("São Paulo", &cities), Some("sao-paulo"));
        assert_eq!(match_city_to_slug("Rio de Janeiro", &cities), Some("rio-de-janeiro"));

        // Case insensitive
        assert_eq!(match_city_to_slug("SÃO PAULO", &cities), Some("sao-paulo"));
        assert_eq!(match_city_to_slug("são paulo", &cities), Some("sao-paulo"));

        // Partial match
        assert_eq!(match_city_to_slug("São Paulo City", &cities), Some("sao-paulo"));

        // Unknown city
        assert_eq!(match_city_to_slug("Unknown City", &cities), None);
        assert_eq!(match_city_to_slug("New York", &cities), None);
    }

    #[test]
    fn test_is_valid_public_ip() {
        // Valid public IPs
        assert!(is_valid_public_ip("8.8.8.8")); // Google DNS
        assert!(is_valid_public_ip("1.1.1.1")); // Cloudflare
        assert!(is_valid_public_ip("200.201.202.203")); // Brazilian IP
        assert!(is_valid_public_ip("2001:4860:4860::8888")); // Google DNS IPv6

        // Invalid - private ranges
        assert!(!is_valid_public_ip("10.0.0.1")); // 10.0.0.0/8
        assert!(!is_valid_public_ip("10.255.255.255"));
        assert!(!is_valid_public_ip("172.16.0.1")); // 172.16.0.0/12
        assert!(!is_valid_public_ip("172.31.255.255"));
        assert!(!is_valid_public_ip("192.168.0.1")); // 192.168.0.0/16
        assert!(!is_valid_public_ip("192.168.255.255"));

        // Invalid - loopback
        assert!(!is_valid_public_ip("127.0.0.1"));
        assert!(!is_valid_public_ip("127.255.255.255"));
        assert!(!is_valid_public_ip("::1")); // IPv6 loopback

        // Invalid - link-local
        assert!(!is_valid_public_ip("169.254.0.1"));

        // Invalid - reserved
        assert!(!is_valid_public_ip("0.0.0.0"));
        assert!(!is_valid_public_ip("224.0.0.1")); // Multicast
        assert!(!is_valid_public_ip("240.0.0.1")); // Reserved

        // Invalid - malformed
        assert!(!is_valid_public_ip("not-an-ip"));
        assert!(!is_valid_public_ip("256.256.256.256"));
        assert!(!is_valid_public_ip(""));
    }
}
