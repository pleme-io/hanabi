//! Backend-for-Frontend (BFF) Module
//!
//! Provides proxy, caching, aggregation, and **session-based authentication**
//! between the frontend and Hive Router (GraphQL gateway).
//!
//! # BFF Modes
//! - **disabled**: BFF is off, requests go directly to Hive Router
//! - **proxy**: Simple pass-through proxy (no caching)
//! - **cache**: Proxy with Redis caching for GraphQL responses
//! - **aggregate**: Advanced mode with request batching and aggregation
//!
//! # Session Authentication (Option A - GraphQL Response Interception)
//! When `bff.session.enabled = true`:
//! 1. BFF intercepts login mutation responses → creates Redis session → sets httpOnly cookie
//! 2. BFF intercepts logout mutation responses → deletes Redis session → clears cookie
//! 3. Session middleware reads cookie → adds Bearer token from Redis → forwards to Hive Router
//!
//! This keeps tokens server-side (never in browser) while using a simple session cookie.
//!
//! # Configuration
//! ```yaml
//! features:
//!   enable_bff: true
//!
//! bff:
//!   mode: "proxy"
//!   hive_router_url: "http://hive-router:4000/graphql"
//!   session:
//!     enabled: true
//!     redis_host: "redis"
//!     redis_port: 6379
//!     cookie_name: "session"
//!     cookie_secure: true
//!     cookie_same_site: "strict"
//! ```
//!
//! # Example
//! ```rust
//! Router::new()
//!     .route("/graphql", post(graphql_proxy))
//!     .with_state(state.clone())
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::{
    extract::{ws::WebSocketUpgrade, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use futures_util::{SinkExt, StreamExt};
use once_cell::sync::Lazy;
use redis::AsyncCommands;
use serde_json::Value;
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::protocol::{Message as TungsteniteMessage, WebSocketConfig},
};
use tracing::{debug, error, info, trace, warn};
use uuid::Uuid;

use crate::auth::session::Session;
use crate::auth::{
    intercept_auth_response, rewrite_login_query, rewrite_verify_mfa_login_query,
    AuthInterceptResult, ClientInfo,
};
use crate::federation::types::{
    protocol as ws_protocol, ClientMessage as FederationClientMessage, ExecutionContext,
    ServerMessage as FederationServerMessage, SubscribePayload,
};
use crate::federation::{accepts_sse, graphql_sse_handler, FederationRequest};
// JWT decode is no longer used - user context comes from session fields directly
// use crate::rate_limiting::decode_user_claims;
use crate::request_context::RequestContext;
use crate::state::AppState;

// Pre-serialized static JSON responses for WebSocket protocol
static CONNECTION_ACK_JSON: Lazy<String> = Lazy::new(|| {
    serde_json::to_string(&serde_json::json!({"type": "connection_ack"}))
        .expect("Static CONNECTION_ACK JSON serialization")
});

static PONG_JSON: Lazy<String> = Lazy::new(|| {
    serde_json::to_string(&serde_json::json!({"type": "pong"}))
        .expect("Static PONG JSON serialization")
});

// Pre-serialized error responses
#[allow(dead_code)]
static BFF_DISABLED_ERROR_JSON: Lazy<String> = Lazy::new(|| {
    serde_json::to_string(&serde_json::json!({
        "errors": [{
            "message": "BFF is disabled. Configure frontend to use Hive Router directly.",
            "extensions": {
                "code": "BFF_DISABLED"
            }
        }]
    }))
    .expect("Static BFF_DISABLED error JSON serialization")
});

#[allow(dead_code)]
static BFF_MODE_DISABLED_ERROR_JSON: Lazy<String> = Lazy::new(|| {
    serde_json::to_string(&serde_json::json!({
        "errors": [{
            "message": "BFF mode is disabled",
            "extensions": {
                "code": "BFF_MODE_DISABLED"
            }
        }]
    }))
    .expect("Static BFF_MODE_DISABLED error JSON serialization")
});

/// GraphQL WebSocket connection_init message type
/// Used by graphql-transport-ws protocol for authentication
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ConnectionInitMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(default)]
    payload: Option<serde_json::Value>,
}

/// Extract JWT token from connection_init payload
/// Returns the token if found in payload.authorization (with or without "Bearer " prefix)
fn extract_jwt_from_payload(payload: &serde_json::Value) -> Option<String> {
    // Try to get authorization from payload
    let auth = payload.get("authorization")?.as_str()?;

    // Remove "Bearer " prefix if present
    let token = if auth.starts_with("Bearer ") {
        auth.strip_prefix("Bearer ").unwrap_or(auth)
    } else {
        auth
    };

    Some(token.to_string())
}

/// GraphQL proxy handler - routes requests to Hive Router
///
/// # BFF Mode Behavior
/// - **disabled**: Returns 503 Service Unavailable
/// - **proxy**: Forwards request to Hive Router (no caching)
/// - **cache**: Checks Redis cache, then forwards if miss (TODO)
/// - **aggregate**: Batch multiple queries into one (TODO)
///
/// # Rate Limiting
/// Per-client IP-based rate limiting using tower-governor:
/// - Tracks requests_per_second per client IP (via X-Forwarded-For or remote addr)
/// - Honors burst_size configuration for temporary bursts
/// - Returns 429 Too Many Requests when quota exceeded
/// - Configured via config.bff.rate_limit (enabled/disabled dynamically)
///
/// # Request Format
/// Accepts standard GraphQL POST requests:
/// ```json
/// {
///   "query": "query { products { id name } }",
///   "variables": { "limit": 10 },
///   "operationName": "GetProducts"
/// }
/// ```
///
/// # Response
/// - **200 OK**: Successful proxy with GraphQL response
/// - **500 Internal Server Error**: Proxy failed (upstream error)
/// - **503 Service Unavailable**: BFF disabled
/// - **504 Gateway Timeout**: Upstream timeout
///
/// # Performance Optimization
/// Uses `#[inline]` for hot path optimization. This handler is called on EVERY
/// GraphQL request, so reducing function call overhead is critical.
///
/// # IMPORTANT: Request Extraction Order
/// We use `Request` extractor instead of `HeaderMap` to ensure we see headers
/// AFTER the session auth middleware has added the Authorization header.
/// The middleware modifies `request.headers_mut()`, so we must extract headers
/// from the full request, not as a separate extractor parameter.
#[inline]
pub async fn graphql_proxy(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    request: Request,
) -> impl IntoResponse {
    // =========================================================================
    // SSE DISPATCH: Check for SSE subscription requests
    // If Accept header contains text/event-stream, dispatch to SSE handler
    // SSE is firewall-proof fallback for environments blocking WebSocket
    // =========================================================================
    if accepts_sse(request.headers()) {
        // Check if SSE is enabled in federation config
        let sse_enabled = state.config.bff.federation.websocket.sse_enabled;
        if sse_enabled {
            // Extract body for SSE handler
            let (parts, body) = request.into_parts();
            let headers = parts.headers.clone();

            match axum::body::to_bytes(body, 1024 * 1024).await {
                Ok(bytes) => match serde_json::from_slice(&bytes) {
                    Ok(sse_request) => {
                        return graphql_sse_handler(State(state), headers, jar, Json(sse_request))
                            .await
                            .into_response();
                    }
                    Err(e) => {
                        warn!("SSE request parse error: {}", e);
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "errors": [{
                                    "message": format!("Invalid SSE request body: {}", e),
                                    "extensions": {"code": "INVALID_REQUEST"}
                                }]
                            })),
                        )
                            .into_response();
                    }
                },
                Err(e) => {
                    error!("Failed to read SSE request body: {}", e);
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "errors": [{
                                "message": "Failed to read request body",
                                "extensions": {"code": "BODY_READ_ERROR"}
                            }]
                        })),
                    )
                        .into_response();
                }
            }
        } else {
            // SSE disabled - return 501 Not Implemented
            return (
                StatusCode::NOT_IMPLEMENTED,
                Json(serde_json::json!({
                    "errors": [{
                        "message": "SSE transport is disabled. Use WebSocket for subscriptions.",
                        "extensions": {"code": "SSE_DISABLED"}
                    }]
                })),
            )
                .into_response();
        }
    }

    // =========================================================================
    // REQUEST CONTEXT: Create unified context with deadline and cancellation
    // This context flows through ALL operations, ensuring:
    // - Deadline propagation (all operations respect timeout)
    // - Cancellation (child operations cancel when request ends)
    // - Observability (trace ID flows through all operations)
    // =========================================================================

    // Extract trace ID from headers for distributed tracing (W3C Trace Context)
    let trace_id = request
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Create request context with configured timeout
    // All downstream operations use ctx.remaining() for their timeouts
    let ctx = RequestContext::with_details(
        Duration::from_secs(state.config.bff.http.timeout_secs),
        None, // user_id added later after session lookup
        trace_id,
        state.config.bff.product.clone(),
    );

    debug!(
        request_id = %ctx.request_id(),
        timeout_secs = state.config.bff.http.timeout_secs,
        "Request context created"
    );

    // =========================================================================
    // ADMISSION CONTROL: Reject early before consuming resources
    // Uses Netflix Gradient algorithm for adaptive concurrency limiting
    //
    // CRITICAL: The AdmissionGuard ensures cancellation safety. If the client
    // disconnects or the async task is cancelled, the guard's Drop impl will
    // call record_completion() automatically, preventing in_flight counter leak.
    // =========================================================================

    // Hold the admission guard for the lifetime of the request
    // When this guard is dropped (or complete() is called), in_flight decrements
    let _admission_guard = if let Some(load_shedder) = state.load_shedder() {
        use crate::federation::{AdmissionResult, RejectionReason};

        match load_shedder.try_acquire() {
            AdmissionResult::Admitted(guard) => {
                // Request admitted - guard MUST be held until completion
                Some(guard)
            }
            AdmissionResult::Rejected {
                reason,
                retry_after,
            } => {
                // CRITICAL: Return 503 immediately without processing
                // No guard was issued, so no cleanup needed
                warn!(
                    request_id = %ctx.request_id(),
                    reason = %reason,
                    retry_after = ?retry_after,
                    "Load shedding: rejecting request at admission control"
                );

                state.incr("bff.admission.rejected", &[("reason", &reason.to_string())]);

                let retry_header = retry_after
                    .map(|d| d.as_secs().to_string())
                    .unwrap_or_else(|| "1".to_string());

                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [
                        (header::RETRY_AFTER, retry_header),
                        (header::CONTENT_TYPE, "application/json".to_string()),
                    ],
                    Json(serde_json::json!({
                        "errors": [{
                            "message": match reason {
                                RejectionReason::ConcurrencyLimit =>
                                    "Service at capacity. Please retry.",
                                RejectionReason::CircuitOpen =>
                                    "Service temporarily unavailable. Please retry.",
                                RejectionReason::DeadlineExceeded =>
                                    "Request deadline exceeded.",
                                RejectionReason::Overloaded =>
                                    "Service overloaded. Please retry.",
                            },
                            "extensions": {
                                "code": "OVERLOADED",
                                "reason": reason.to_string(),
                            }
                        }]
                    })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    // Extract headers from request AFTER middleware has modified them
    // This is critical - the session middleware adds Authorization header
    let (parts, body) = request.into_parts();
    let headers = parts.headers;

    // Log whether Authorization header is present (added by session middleware)
    let has_auth_from_middleware = headers.get(header::AUTHORIZATION).is_some();
    info!(
        "graphql_proxy: Authorization header present from middleware: {}",
        has_auth_from_middleware
    );
    if has_auth_from_middleware {
        debug!("graphql_proxy: Session middleware successfully injected Authorization header");
    }

    // Parse the body as JSON
    let body: Value = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(e) => {
                error!("Failed to parse request body as JSON: {}", e);
                // Guard will call record_completion(false) on drop
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "errors": [{
                            "message": "Invalid JSON in request body",
                            "extensions": {
                                "code": "INVALID_JSON"
                            }
                        }]
                    })),
                )
                    .into_response();
            }
        },
        Err(e) => {
            error!("Failed to read request body: {}", e);
            // Guard will call record_completion(false) on drop
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "errors": [{
                        "message": "Failed to read request body",
                        "extensions": {
                            "code": "BODY_READ_ERROR"
                        }
                    }]
                })),
            )
                .into_response();
        }
    };
    // Check if BFF is enabled
    if !state.config.features.enable_bff {
        warn!("BFF disabled - GraphQL proxy endpoint called but feature is off");
        state.incr("bff.request.rejected", &[("reason", "disabled")]);
        // Guard will call record_completion(false) on drop
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "errors": [{
                    "message": "BFF is disabled. Configure frontend to use Hive Router directly.",
                    "extensions": {
                        "code": "BFF_DISABLED"
                    }
                }]
            })),
        )
            .into_response();
    }

    // Check BFF mode
    let mode = &state.config.bff.mode;
    if mode == "disabled" {
        warn!("BFF mode is 'disabled' but feature flag is enabled - check configuration");
        state.incr("bff.request.rejected", &[("reason", "mode_disabled")]);
        // Guard will call record_completion(false) on drop
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "errors": [{
                    "message": "BFF mode is disabled",
                    "extensions": {
                        "code": "BFF_MODE_DISABLED"
                    }
                }]
            })),
        )
            .into_response();
    }

    // Emit metrics
    state.incr(
        "bff.request.received",
        &[("mode", mode), ("env", &state.config.environment)],
    );

    // Extract operation name for logging/metrics (convert to owned String)
    let operation_name = body
        .get("operationName")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    info!(
        request_id = %ctx.request_id(),
        operation = %operation_name,
        mode = %mode,
        remaining_ms = ctx.remaining().as_millis(),
        "BFF proxying GraphQL request"
    );

    // Extract session ID from cookie for logout handling
    let session_id = jar
        .get(&state.config.bff.session.cookie_name)
        .and_then(|c| Uuid::parse_str(c.value()).ok());

    // =========================================================================
    // DEADLINE CHECK: Reject if not enough time remaining
    // This prevents starting work we can't finish
    // =========================================================================
    const MIN_PROCESSING_TIME_MS: u64 = 100; // Minimum time to process request
    if !ctx.has_time_for(Duration::from_millis(MIN_PROCESSING_TIME_MS)) {
        warn!(
            request_id = %ctx.request_id(),
            remaining_ms = ctx.remaining().as_millis(),
            "Request deadline exceeded before processing"
        );

        state.incr("bff.request.deadline_exceeded", &[]);

        // Guard will call record_completion(false) on drop
        return (
            StatusCode::GATEWAY_TIMEOUT,
            Json(serde_json::json!({
                "errors": [{
                    "message": "Request deadline exceeded",
                    "extensions": {
                        "code": "DEADLINE_EXCEEDED"
                    }
                }]
            })),
        )
            .into_response();
    }

    // Primary routing: federation.enabled controls whether we use federation executor or proxy
    // When federation is enabled, BFF handles GraphQL federation internally (replaces Hive Router)
    // When federation is disabled, BFF proxies to Hive Router
    if state.config.bff.federation.enabled {
        // Federation mode: BFF acts as GraphQL federation router
        // Handles query planning, subgraph execution, response merging, caching internally
        execute_federation(state, jar, headers, body, &operation_name, session_id, ctx).await
    } else {
        // Proxy mode: Forward to Hive Router
        proxy_to_hive_router(state, jar, headers, body, &operation_name, session_id, ctx).await
    }
}

/// Proxy GraphQL request to Hive Router with auth interception
///
/// Forwards the GraphQL request to Hive Router and intercepts auth responses.
/// Preserves headers for authentication, tracing, etc.
///
/// # Request Context
/// Uses the RequestContext for:
/// - Deadline propagation (remaining time for upstream call)
/// - Request tracing (request_id in logs)
/// - Cancellation (stops work if context is cancelled)
///
/// # Session Management (Option A)
/// After receiving response from Hive Router:
/// - Login mutation success → Create session in Redis, add Set-Cookie header
/// - Logout mutation → Delete session from Redis, clear cookie
/// - Other mutations/queries → Pass through unchanged
///
/// Uses the shared HTTP client from AppState for connection pooling efficiency.
///
/// # Performance Optimization
/// Uses `#[inline]` for hot path optimization. Minimizes allocations by
/// reusing string references where possible.
///
/// # Error Handling
/// - Connection errors → 504 Gateway Timeout
/// - HTTP errors → Pass through status code
/// - Parse errors → 500 Internal Server Error
/// - Deadline exceeded → 504 Gateway Timeout
#[inline]
async fn proxy_to_hive_router(
    state: Arc<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    mut body: Value,
    operation_name: &str,
    session_id: Option<Uuid>,
    ctx: RequestContext,
) -> axum::response::Response {
    // ========================================================================
    // LOGIN QUERY REWRITING (Legacy Token-Based Auth)
    // ========================================================================
    // For backends that return JWT tokens (accessToken, refreshToken, expiresIn),
    // we rewrite login queries to add these fields so the BFF can extract them.
    //
    // For token_free_auth mode (BFF-only pattern), we SKIP this rewriting
    // because the backend doesn't return tokens - it only returns user info,
    // and the BFF generates session tokens internally.
    //
    // This follows the Full BFF pattern (Duende/Curity model) where tokens
    // NEVER reach the browser - see IETF draft-ietf-oauth-browser-based-apps.
    // ========================================================================
    if !state.config.bff.session.token_free_auth {
        // Legacy mode: Inject token fields into login queries
        let compiled_auth = &state.bff().compiled_auth;
        if rewrite_login_query(&mut body, compiled_auth) {
            info!("BFF: Rewrote login query to include session-required fields (tokens will be stripped from response)");
        }

        // Also rewrite verifyMfaLogin mutation to include token fields
        // This is Step 2 of two-step MFA authentication flow
        if rewrite_verify_mfa_login_query(&mut body, compiled_auth) {
            info!("BFF: Rewrote verifyMfaLogin query to include session-required fields (tokens will be stripped from response)");
        }
    } else {
        debug!("BFF: token_free_auth enabled - skipping login query rewriting (backend doesn't return tokens)");
    }

    // Log request entry
    let body_size = serde_json::to_string(&body).unwrap_or_default().len();
    debug!(
        "BFF proxy request starting: operation={}, body_size={} bytes",
        operation_name, body_size
    );

    // Log request body at trace level (for debugging)
    trace!(
        "BFF proxy request body: operation={}, body={}",
        operation_name,
        serde_json::to_string(&body).unwrap_or_else(|_| "INVALID_JSON".to_string())
    );

    // Get HTTP client from AppState (shared connection pool)
    let client = match state.http_client() {
        Some(c) => {
            debug!("HTTP client available for BFF proxy");
            c.clone()
        }
        None => {
            error!("HTTP client not initialized - BFF cannot function without client");
            state.incr("bff.proxy.error", &[("reason", "client_not_initialized")]);
            // Guard in graphql_proxy will call record_completion(false) on drop
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                Json(serde_json::json!({
                    "errors": [{
                        "message": "BFF proxy not properly initialized",
                        "extensions": {
                            "code": "BFF_CLIENT_ERROR"
                        }
                    }]
                })),
            )
                .into_response();
        }
    };

    // Forward request to Hive Router with configured timeout
    let hive_router_url = &state.config.bff.hive_router_url;
    let timeout = std::time::Duration::from_secs(state.config.bff.http.timeout_secs);

    debug!(
        "Building request to Hive Router: url={}, timeout={:?}",
        hive_router_url, timeout
    );

    let mut request = client.post(hive_router_url).timeout(timeout).json(&body);

    // Forward important headers (Authorization, Cookie, tracing headers, etc.)
    let has_auth = headers.get(header::AUTHORIZATION).is_some();
    let has_content_type = headers.get(header::CONTENT_TYPE).is_some();
    let has_cookie = headers.get(header::COOKIE).is_some();

    if let Some(auth) = headers.get(header::AUTHORIZATION) {
        trace!("Forwarding Authorization header (present but not logged for security)");
        request = request.header(header::AUTHORIZATION, auth);
    }
    // NOTE: Do NOT forward Content-Type header here!
    // The .json(&body) call above already sets Content-Type: application/json.
    // Forwarding the incoming Content-Type creates duplicate headers, which
    // causes Envoy/Istio to return 400 Bad Request with non-JSON body.
    if has_content_type {
        trace!("Incoming Content-Type header present but not forwarded (already set by .json())");
    }
    // CRITICAL: Forward Cookie header for HttpOnly refresh token authentication
    // The browser sends cookies automatically, but we must forward them to Hive Router
    if let Some(cookie) = headers.get(header::COOKIE) {
        debug!("Forwarding Cookie header (contains HttpOnly refresh token)");
        request = request.header(header::COOKIE, cookie);
    }

    // CRITICAL: Set x-product header for multi-tenant isolation
    // The BFF is product-specific, serving the product identified by config.bff.product
    // This ensures all downstream services know the product context
    // Services use pleme-rbac::AuthzContext::from_headers() which requires x-product
    let product = &state.config.bff.product;
    request = request.header("x-product", product.as_str());
    debug!("Setting x-product header: {}", product);

    // CRITICAL: Forward x-user-* headers from session middleware
    // These headers are injected by session_auth_middleware and enable the BFF-only
    // session pattern where backend services read user context from headers via pleme-rbac.
    // Required for: proxy mode (no federation), single backend architecture
    let user_headers = [
        "x-user-id",
        "x-user-email",
        "x-user-roles",
        "x-user-permissions",
        "x-user-staff-role",
        "x-user-relationships",
    ];
    for header_name in &user_headers {
        if let Some(value) = headers.get(*header_name) {
            request = request.header(*header_name, value);
            debug!("Forwarding {} header", header_name);
        }
    }

    debug!(
        "Sending request to Hive Router: has_auth={}, has_content_type={}, has_cookie={}, product={}",
        has_auth, has_content_type, has_cookie, product
    );

    // Send request
    let response = match request.send().await {
        Ok(r) => {
            debug!(
                request_id = %ctx.request_id(),
                status = %r.status(),
                elapsed_ms = ctx.elapsed().as_millis(),
                "Received response from Hive Router"
            );
            r
        }
        Err(e) => {
            let elapsed = ctx.elapsed();
            error!(
                request_id = %ctx.request_id(),
                error = %e,
                url = %hive_router_url,
                operation = %operation_name,
                body_size = body_size,
                elapsed_ms = elapsed.as_millis(),
                is_timeout = e.is_timeout(),
                is_connect = e.is_connect(),
                is_request = e.is_request(),
                "BFF proxy failed"
            );

            state.incr("bff.proxy.error", &[("reason", "upstream_error")]);
            state.histogram(
                "bff.proxy.latency",
                elapsed.as_millis() as f64,
                &[("status", "error"), ("operation", operation_name)],
            );

            // Guard in graphql_proxy will call record_completion(false) on drop

            // Determine if timeout or connection error
            let status = if e.is_timeout() {
                warn!(
                    request_id = %ctx.request_id(),
                    elapsed_ms = elapsed.as_millis(),
                    timeout_secs = timeout.as_secs(),
                    "Request timeout"
                );
                StatusCode::GATEWAY_TIMEOUT
            } else if e.is_connect() {
                warn!(
                    request_id = %ctx.request_id(),
                    url = %hive_router_url,
                    "Connection error to Hive Router"
                );
                StatusCode::BAD_GATEWAY
            } else {
                StatusCode::BAD_GATEWAY
            };

            return (
                status,
                jar,
                Json(serde_json::json!({
                    "errors": [{
                        "message": format!("Failed to reach Hive Router: {}", e),
                        "extensions": {
                            "code": "BFF_UPSTREAM_ERROR"
                        }
                    }]
                })),
            )
                .into_response();
        }
    };

    let status = response.status();

    // CRITICAL: Extract Set-Cookie headers BEFORE consuming response body
    // This enables cookie-based authentication (HttpOnly refresh tokens)
    let set_cookie_headers: Vec<String> = response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect();

    if !set_cookie_headers.is_empty() {
        debug!(
            "BFF proxy forwarding {} Set-Cookie header(s) from Hive Router",
            set_cookie_headers.len()
        );
    }

    debug!(
        request_id = %ctx.request_id(),
        status = %status,
        elapsed_ms = ctx.elapsed().as_millis(),
        "Parsing Hive Router response"
    );

    // Parse response body
    let response_body = match response.json::<Value>().await {
        Ok(b) => {
            debug!(
                request_id = %ctx.request_id(),
                status = %status,
                elapsed_ms = ctx.elapsed().as_millis(),
                "Successfully parsed response"
            );

            // Log response at trace level for debugging
            trace!(
                "BFF proxy response body: operation={}, status={}, body={}",
                operation_name,
                status,
                serde_json::to_string(&b).unwrap_or_else(|_| "INVALID_JSON".to_string())
            );

            b
        }
        Err(e) => {
            let elapsed = ctx.elapsed();
            error!(
                request_id = %ctx.request_id(),
                error = %e,
                status = %status,
                operation = %operation_name,
                elapsed_ms = elapsed.as_millis(),
                "Failed to parse Hive Router response"
            );

            state.incr("bff.proxy.error", &[("reason", "parse_failed")]);
            state.histogram(
                "bff.proxy.latency",
                elapsed.as_millis() as f64,
                &[("status", "error"), ("operation", operation_name)],
            );

            // Guard in graphql_proxy will call record_completion(false) on drop

            return (
                StatusCode::BAD_GATEWAY,
                jar,
                Json(serde_json::json!({
                    "errors": [{
                        "message": "Failed to parse upstream response",
                        "extensions": {
                            "code": "BFF_PARSE_ERROR"
                        }
                    }]
                })),
            )
                .into_response();
        }
    };

    // Emit success metrics
    state.incr(
        "bff.proxy.success",
        &[
            ("status", &status.as_u16().to_string()),
            ("operation", operation_name),
        ],
    );
    state.histogram(
        "bff.proxy.latency",
        ctx.elapsed().as_millis() as f64,
        &[
            ("status", &status.as_u16().to_string()),
            ("operation", operation_name),
        ],
    );

    info!(
        request_id = %ctx.request_id(),
        operation = %operation_name,
        status = %status,
        elapsed_ms = ctx.elapsed().as_millis(),
        cookies_forwarded = set_cookie_headers.len(),
        "BFF proxy success"
    );

    // ========================================================================
    // AUTH INTERCEPTION (Option A - GraphQL Response Interception)
    // ========================================================================
    // Intercept login/logout responses to manage sessions
    let (intercept_result, final_response_body) = if state.config.bff.session.enabled {
        // Extract client IP from headers (X-Forwarded-For, X-Real-IP, or fallback)
        let client_ip = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next()) // First IP in chain is client
            .map(|s| s.trim().to_string())
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "0.0.0.0".to_string());

        // Extract User-Agent from headers
        let user_agent = headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let client_info = ClientInfo {
            ip_address: client_ip,
            user_agent,
        };

        intercept_auth_response(
            &body,
            response_body,
            state.session_redis().cloned(),
            &state.config.bff.session,
            session_id,
            client_info,
            &state.bff().compiled_auth,
        )
        .await
    } else {
        (AuthInterceptResult::PassThrough, response_body)
    };

    // Build response based on interception result
    let mut jar = jar;
    let final_body = match intercept_result {
        AuthInterceptResult::LoginSuccess {
            session_cookie,
            modified_response,
        } => {
            info!("Auth intercept: Login success - setting session cookie");
            jar = jar.add(session_cookie);
            modified_response
        }
        AuthInterceptResult::LogoutSuccess { clear_cookie } => {
            info!("Auth intercept: Logout success - clearing session cookie");
            jar = jar.add(clear_cookie);
            final_response_body
        }
        AuthInterceptResult::PassThrough => final_response_body,
    };

    // Build response with Set-Cookie headers
    let mut response = (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        jar,
        Json(final_body),
    )
        .into_response();

    // Forward Set-Cookie headers from Hive Router to client (for non-auth cookies)
    for cookie in set_cookie_headers {
        if let Ok(header_value) = axum::http::HeaderValue::from_str(&cookie) {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, header_value);
            debug!("BFF proxy: Added Set-Cookie header to response");
        } else {
            warn!("BFF proxy: Failed to parse Set-Cookie header value");
        }
    }

    // NOTE: record_completion() is now handled by AdmissionGuard in graphql_proxy
    // The guard ensures cancellation safety - if the client disconnects mid-request,
    // the guard's Drop impl will still decrement the in_flight counter.
    // This was previously a bug where cancelled requests would leak in_flight counts.

    response
}

/// WebSocket proxy handler - routes WebSocket connections to Hive Router
///
/// Provides bidirectional GraphQL subscription proxying:
/// - Client WebSocket ↔ BFF ↔ Hive Router WebSocket
/// - Transparent message forwarding in both directions
/// - Automatic reconnection handling
///
/// # BFF Mode Behavior
/// - **disabled**: Returns 503 Service Unavailable
/// - **proxy/cache/aggregate**: Forwards WebSocket to Hive Router
///
/// # Rate Limiting
/// WebSocket upgrades are subject to the same per-client IP rate limiting as HTTP requests.
/// Once the WebSocket is established, messages are not rate-limited (subscriptions are long-lived).
///
/// # Authentication (BFF Pattern)
/// BFF Pattern: Tokens NEVER reach the browser. Instead:
/// 1. Browser sends session cookie with WebSocket upgrade request
/// 2. BFF looks up session in Redis to get access token
/// 3. BFF forwards access token to Hive Router in Authorization header
///
/// This is the ONLY correct approach for BFF architecture - the frontend
/// CANNOT send JWT in connection_init because it doesn't have the token.
///
/// # Error Handling
/// - BFF disabled → 503 Service Unavailable
/// - Session not found → 401 Unauthorized
/// - Upstream connection failed → Closes client WebSocket with error message
/// - Message forwarding errors → Logs error and closes connection
pub async fn graphql_ws_proxy(
    State(state): State<Arc<AppState>>,
    _headers: HeaderMap,
    jar: CookieJar,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Check if BFF is enabled
    if !state.config.features.enable_bff {
        warn!("BFF disabled - GraphQL WebSocket proxy endpoint called but feature is off");
        state.incr("bff.ws.request.rejected", &[("reason", "disabled")]);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "errors": [{
                    "message": "BFF is disabled. Configure frontend to use Hive Router directly.",
                    "extensions": {
                        "code": "BFF_DISABLED"
                    }
                }]
            })),
        )
            .into_response();
    }

    // Check BFF mode
    let mode = &state.config.bff.mode;
    if mode == "disabled" {
        warn!("BFF mode is 'disabled' but feature flag is enabled - check configuration");
        state.incr("bff.ws.request.rejected", &[("reason", "mode_disabled")]);
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "errors": [{
                    "message": "BFF mode is disabled",
                    "extensions": {
                        "code": "BFF_MODE_DISABLED"
                    }
                }]
            })),
        )
            .into_response();
    }

    // Emit metrics
    state.incr(
        "bff.ws.request.received",
        &[("mode", mode), ("env", &state.config.environment)],
    );

    info!("BFF proxying GraphQL WebSocket connection: mode={}", mode);

    // ========================================================================
    // BFF PATTERN: Extract session from cookie, look up tokens in Redis
    // ========================================================================
    // The frontend does NOT have JWT (tokens never reach browser).
    // Instead, we extract the session cookie, look up the session in Redis,
    // and use the stored access_token for authentication.
    // ========================================================================

    let jwt_token = if state.config.bff.session.enabled {
        // Extract session ID from cookie
        let session_id = jar
            .get(&state.config.bff.session.cookie_name)
            .and_then(|c| Uuid::parse_str(c.value()).ok());

        match session_id {
            Some(sid) => {
                // Look up session in Redis
                if let Some(redis_pool) = state.session_redis() {
                    let mut conn = match redis_pool.get().await {
                        Some(c) => c,
                        None => {
                            error!("WebSocket: Failed to get Redis connection from pool");
                            return (
                                StatusCode::SERVICE_UNAVAILABLE,
                                Json(serde_json::json!({
                                    "errors": [{
                                        "message": "Session service unavailable",
                                        "extensions": { "code": "SESSION_SERVICE_ERROR" }
                                    }]
                                })),
                            )
                                .into_response();
                        }
                    };

                    let key = format!("{}{}", state.config.bff.session.key_prefix, sid);
                    // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
                    let session_json: Option<String> = match tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        conn.get(&key),
                    )
                    .await
                    {
                        Ok(Ok(v)) => v,
                        Ok(Err(e)) => {
                            error!("WebSocket: Failed to get session from Redis: {}", e);
                            None
                        }
                        Err(_) => {
                            error!("WebSocket: Redis operation timed out after 2s");
                            None
                        }
                    };

                    match session_json {
                        Some(json) => {
                            match serde_json::from_str::<crate::auth::session::Session>(&json) {
                                Ok(session) => {
                                    info!(
                                        "WebSocket: Retrieved session for user {} from Redis",
                                        session.user_id
                                    );
                                    Some(session.access_token)
                                }
                                Err(e) => {
                                    error!("WebSocket: Failed to parse session JSON: {}", e);
                                    None
                                }
                            }
                        }
                        None => {
                            warn!("WebSocket: Session {} not found in Redis - user may need to re-login", sid);
                            None
                        }
                    }
                } else {
                    warn!("WebSocket: Session Redis not configured - cannot authenticate");
                    None
                }
            }
            None => {
                debug!("WebSocket: No session cookie present - unauthenticated connection");
                None
            }
        }
    } else {
        debug!("WebSocket: BFF session management disabled");
        None
    };

    if jwt_token.is_some() {
        info!("WebSocket: Will forward authenticated connection (token from session)");
    } else {
        warn!("WebSocket: Will forward unauthenticated connection (no session found)");
    }

    // Check if federation mode is enabled for subscriptions
    // When federation is enabled, we route subscriptions directly to subgraphs
    // instead of proxying through Hive Router
    let use_federation = state.config.bff.federation.enabled
        && state.config.bff.federation.websocket.enabled
        && state.subscription_manager().is_some();

    if use_federation {
        info!("WebSocket: Using federation mode for direct subgraph subscriptions");
    }

    // Upgrade to WebSocket with GraphQL subprotocol support
    // Support both graphql-transport-ws (new) and graphql-ws (legacy)
    ws.protocols(["graphql-transport-ws", "graphql-ws"])
        .on_upgrade(move |socket| async move {
            if use_federation {
                handle_federation_websocket(socket, state, jwt_token).await
            } else {
                handle_websocket_proxy(socket, state, jwt_token).await
            }
        })
        .into_response()
}

/// Handle WebSocket proxy connection
///
/// Establishes bidirectional message forwarding between client and Hive Router:
/// 1. Acquire semaphore permit (limits concurrent connections for memory budgeting)
/// 2. Wait for connection_init from client
/// 3. Connect to Hive Router WebSocket endpoint with JWT in Authorization header
/// 4. Forward connection_init to Hive Router
/// 5. Wait for connection_ack from Hive Router and forward to client
/// 6. Split both WebSocket connections into read/write halves
/// 7. Spawn two tasks for bidirectional message forwarding
/// 8. Close both connections when either side disconnects
/// 9. Release semaphore permit (frees memory budget)
///
/// # Authentication Flow (BFF Pattern)
/// - BFF extracts session cookie from WebSocket upgrade request
/// - BFF looks up session in Redis to get access_token (tokens NEVER reach browser)
/// - BFF connects to Hive Router with `Authorization: Bearer TOKEN` header
/// - BFF forwards connection_init to Hive Router
/// - Hive Router validates JWT and responds with connection_ack
/// - BFF forwards connection_ack to client
/// - Normal subscription messages flow
///
/// # Memory Management
/// - Semaphore permit: Limits concurrent connections
/// - Message size validation: Rejects messages exceeding max_message_size
/// - Each connection: ~200KB (2 tokio tasks + channel buffers + connection state)
async fn handle_websocket_proxy(
    client_ws: WebSocket,
    state: Arc<AppState>,
    jwt_token: Option<String>,
) {
    // Acquire semaphore permit to limit concurrent connections (memory budgeting)
    // CRITICAL: Reject connection if semaphore not initialized (memory exhaustion vulnerability)
    let semaphore = match state.websocket_semaphore() {
        Some(sem) => sem,
        None => {
            error!("WebSocket semaphore not initialized - rejecting connection to prevent memory exhaustion");
            state.incr(
                "bff.ws.proxy.error",
                &[("reason", "semaphore_not_initialized")],
            );
            return;
        }
    };

    // Track semaphore pressure before attempting acquisition
    state.gauge("bff.ws.semaphore.available", semaphore.available_permits() as f64, &[]);

    let _permit = match semaphore.clone().try_acquire_owned() {
        Ok(permit) => {
            info!("WebSocket semaphore permit acquired (active connections within limit)");
            permit
        }
        Err(_) => {
            warn!("WebSocket connection rejected: max connections reached");
            state.incr(
                "bff.ws.proxy.error",
                &[("reason", "max_connections_reached")],
            );
            state.incr("bff.ws.semaphore.rejections", &[]);
            return;
        }
    };

    // STEP 1: Split client WebSocket to read connection_init
    let (mut client_tx, mut client_rx) = client_ws.split();
    info!("Client WebSocket connected - waiting for connection_init");

    // STEP 2: Wait for connection_init message from client
    // NOTE: In BFF pattern, we already have the JWT from session lookup.
    // We just need to wait for connection_init to forward it to Hive Router.
    let first_msg = match client_rx.next().await {
        Some(Ok(Message::Text(text))) => {
            // Try to parse as connection_init for logging
            match serde_json::from_str::<ConnectionInitMessage>(&text) {
                Ok(conn_init) => {
                    info!(
                        "Received connection_init message type: {}",
                        conn_init.msg_type
                    );
                    // BFF Pattern: We DON'T extract JWT from payload - frontend doesn't have it!
                    // JWT was already retrieved from Redis session in graphql_ws_proxy()
                    if conn_init
                        .payload
                        .as_ref()
                        .and_then(extract_jwt_from_payload)
                        .is_some()
                    {
                        warn!("Client sent JWT in connection_init but BFF pattern doesn't use it - using session token instead");
                    }
                }
                Err(e) => {
                    warn!("Failed to parse connection_init: {} - forwarding anyway", e);
                }
            }
            text
        }
        Some(Ok(msg)) => {
            error!("Unexpected non-text first message: {:?}", msg);
            state.incr("bff.ws.proxy.error", &[("reason", "invalid_first_message")]);
            return;
        }
        Some(Err(e)) => {
            error!("Error receiving first message from client: {}", e);
            state.incr("bff.ws.proxy.error", &[("reason", "first_message_error")]);
            return;
        }
        None => {
            warn!("Client closed connection before sending connection_init");
            state.incr("bff.ws.proxy.error", &[("reason", "client_closed_early")]);
            return;
        }
    };

    // STEP 3: Now connect to Hive Router WITH the JWT in Authorization header
    // Use get_hive_router_ws_url() which allows explicit WebSocket URL configuration
    // (e.g., when backend expects /graphql/ws instead of /graphql for WebSocket)
    let hive_ws_url = state.config.bff.get_hive_router_ws_url();

    info!("Connecting to Hive Router WebSocket: {}", hive_ws_url);

    let ws_config = WebSocketConfig {
        max_message_size: Some(state.config.bff.websocket.max_message_size),
        max_frame_size: Some(16 << 20), // 16MB
        ..Default::default()
    };

    // Build WebSocket request with proper handshake headers
    // Generate Sec-WebSocket-Key (base64-encoded random 16 bytes)
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use rand::RngCore;

    let mut key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let ws_key = BASE64.encode(key_bytes);

    // Extract host:port from WebSocket URL for proper Host header (RFC 7230)
    // Non-standard ports MUST be included in Host header
    let host_header = {
        let url_str = hive_ws_url.as_str();
        // Simple URL parsing without external crate
        // Format: scheme://host[:port]/path
        let without_scheme = url_str
            .strip_prefix("ws://")
            .or_else(|| url_str.strip_prefix("wss://"))
            .unwrap_or(url_str);

        // Extract host[:port] part (before first /)
        let host_port = without_scheme.split('/').next().unwrap_or("localhost:4000");

        host_port.to_string()
    };
    debug!("WebSocket Host header: {}", host_header);

    let mut request_builder = http::Request::builder()
        .method("GET")
        .uri(&hive_ws_url)
        .header("Host", &host_header)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key)
        .header("Sec-WebSocket-Protocol", "graphql-transport-ws");

    // CRITICAL: Add JWT to Authorization header if extracted from connection_init
    if let Some(ref token) = jwt_token {
        info!("Adding extracted JWT to upstream Authorization header");
        request_builder = request_builder.header("Authorization", format!("Bearer {}", token));
    } else {
        warn!("No JWT to forward - Hive Router may reject unauthenticated WebSocket");
    }

    let request = match request_builder.body(()) {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to build WebSocket request: {}", e);
            state.incr("bff.ws.proxy.error", &[("reason", "request_build_failed")]);
            return;
        }
    };

    // STEP 4: Connect to Hive Router
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let client_request = match request.into_client_request() {
        Ok(req) => req,
        Err(e) => {
            error!("Failed to convert to WebSocket client request: {}", e);
            state.incr("bff.ws.proxy.error", &[("reason", "client_request_failed")]);
            return;
        }
    };
    let upstream_ws = match connect_async_with_config(client_request, Some(ws_config), false).await
    {
        Ok((ws_stream, response)) => {
            if let Some(protocol) = response.headers().get("sec-websocket-protocol") {
                info!("Hive Router accepted protocol: {:?}", protocol);
            }
            info!("WebSocket connection to Hive Router established successfully");
            ws_stream
        }
        Err(e) => {
            // Extract detailed error information for debugging
            let error_details = match &e {
                tokio_tungstenite::tungstenite::Error::Http(response) => {
                    let status = response.status();
                    let body = response.body().as_ref().map(|b| {
                        String::from_utf8_lossy(b)
                            .chars()
                            .take(500)
                            .collect::<String>()
                    });
                    format!("HTTP {} - body: {:?}", status, body)
                }
                tokio_tungstenite::tungstenite::Error::HttpFormat(e) => {
                    format!("HTTP format error: {}", e)
                }
                tokio_tungstenite::tungstenite::Error::Url(e) => format!("URL error: {}", e),
                tokio_tungstenite::tungstenite::Error::Io(e) => format!("IO error: {}", e),
                tokio_tungstenite::tungstenite::Error::Protocol(e) => {
                    format!("Protocol error: {}", e)
                }
                _ => format!("{}", e),
            };
            error!(
                "Failed to connect to Hive Router WebSocket: {} - URL: {} - Host header: {} - Details: {}",
                e, hive_ws_url, host_header, error_details
            );
            state.incr(
                "bff.ws.proxy.error",
                &[("reason", "upstream_connection_failed")],
            );
            // Inform client of connection failure with more details
            let reason = format!(
                "Failed to connect to upstream GraphQL server: {}",
                error_details.chars().take(100).collect::<String>()
            );
            let _ = client_tx
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 1011, // Internal error
                    reason: reason.into(),
                })))
                .await;
            return;
        }
    };

    state.incr("bff.ws.proxy.connected", &[]);

    info!("Connected to Hive Router - forwarding connection_init");

    // STEP 5: Split upstream connection and forward connection_init
    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

    if let Err(e) = upstream_tx.send(TungsteniteMessage::Text(first_msg)).await {
        error!("Failed to forward connection_init to Hive Router: {}", e);
        state.incr(
            "bff.ws.proxy.error",
            &[("reason", "forward_connection_init_failed")],
        );
        return;
    }

    // STEP 6: Wait for connection_ack from Hive Router
    match upstream_rx.next().await {
        Some(Ok(TungsteniteMessage::Text(ack_msg))) => {
            info!("Received connection_ack from Hive Router - authentication successful");
            // Forward to client
            if let Err(e) = client_tx.send(Message::Text(ack_msg)).await {
                error!("Failed to forward connection_ack to client: {}", e);
                state.incr(
                    "bff.ws.proxy.error",
                    &[("reason", "forward_connection_ack_failed")],
                );
                return;
            }
        }
        Some(Ok(msg)) => {
            warn!("Unexpected message type as connection_ack: {:?}", msg);
        }
        Some(Err(e)) => {
            error!("Error receiving connection_ack from Hive Router: {}", e);
            state.incr("bff.ws.proxy.error", &[("reason", "connection_ack_error")]);
            return;
        }
        None => {
            error!("Hive Router closed connection before sending connection_ack - likely authentication failed");
            state.incr("bff.ws.proxy.error", &[("reason", "upstream_closed_early")]);
            // Inform client
            let _ = client_tx
                .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                    code: 4401, // Custom: Unauthorized
                    reason: "GraphQL server rejected connection - authentication failed".into(),
                })))
                .await;
            return;
        }
    }

    info!("WebSocket authentication handshake completed - starting bidirectional forwarding");

    // STEP 7: Start bidirectional message forwarding
    let max_message_size = state.config.bff.websocket.max_message_size;
    let state_ws = state.clone();

    // Spawn task to forward client messages to upstream
    let client_to_upstream = tokio::spawn(async move {
        while let Some(msg) = client_rx.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    // Validate message size to prevent memory exhaustion
                    if text.len() > max_message_size {
                        warn!(
                            "Client message size {} exceeds limit {} - closing connection",
                            text.len(),
                            max_message_size
                        );
                        state_ws.incr(
                            "bff.ws.proxy.error",
                            &[("reason", "message_too_large")],
                        );
                        state_ws.histogram(
                            "bff.ws.message.size_rejected",
                            text.len() as f64,
                            &[],
                        );
                        let _ = upstream_tx.send(TungsteniteMessage::Close(Some(
                            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                                reason: "Message too large".into(),
                            }
                        ))).await;
                        break;
                    }

                    state_ws.incr(
                        "bff.ws.messages.forwarded",
                        &[("direction", "client_to_upstream")],
                    );
                    state_ws.histogram(
                        "bff.ws.message.size",
                        text.len() as f64,
                        &[("direction", "client_to_upstream")],
                    );

                    if let Err(e) = upstream_tx.send(TungsteniteMessage::Text(text)).await {
                        error!("Failed to forward client message to upstream: {}", e);
                        state_ws.incr(
                            "bff.ws.forward.error",
                            &[("direction", "client_to_upstream")],
                        );
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    // Validate binary message size
                    if data.len() > max_message_size {
                        warn!(
                            "Client binary message size {} exceeds limit {} - closing connection",
                            data.len(),
                            max_message_size
                        );
                        state_ws.incr(
                            "bff.ws.proxy.error",
                            &[("reason", "message_too_large")],
                        );
                        state_ws.histogram(
                            "bff.ws.message.size_rejected",
                            data.len() as f64,
                            &[],
                        );
                        let _ = upstream_tx.send(TungsteniteMessage::Close(Some(
                            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Size,
                                reason: "Message too large".into(),
                            }
                        ))).await;
                        break;
                    }

                    state_ws.incr(
                        "bff.ws.messages.forwarded",
                        &[("direction", "client_to_upstream")],
                    );
                    state_ws.histogram(
                        "bff.ws.message.size",
                        data.len() as f64,
                        &[("direction", "client_to_upstream")],
                    );

                    if let Err(e) = upstream_tx.send(TungsteniteMessage::Binary(data)).await {
                        error!("Failed to forward client binary to upstream: {}", e);
                        state_ws.incr(
                            "bff.ws.forward.error",
                            &[("direction", "client_to_upstream")],
                        );
                        break;
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("Client closed WebSocket connection");
                    let _ = upstream_tx.send(TungsteniteMessage::Close(None)).await;
                    break;
                }
                Ok(Message::Ping(data)) => {
                    if let Err(e) = upstream_tx.send(TungsteniteMessage::Ping(data)).await {
                        error!("Failed to forward client ping to upstream: {}", e);
                        state_ws.incr(
                            "bff.ws.forward.error",
                            &[("direction", "client_to_upstream"), ("type", "ping")],
                        );
                        break;
                    }
                }
                Ok(Message::Pong(data)) => {
                    if let Err(e) = upstream_tx.send(TungsteniteMessage::Pong(data)).await {
                        error!("Failed to forward client pong to upstream: {}", e);
                        state_ws.incr(
                            "bff.ws.forward.error",
                            &[("direction", "client_to_upstream"), ("type", "pong")],
                        );
                        break;
                    }
                }
                Err(e) => {
                    error!("Error receiving from client WebSocket: {}", e);
                    state_ws.incr("bff.ws.proxy.error", &[("reason", "client_read_error")]);
                    break;
                }
            }
        }
    });

    // Clone state for upstream task (need separate clone for each spawned task)
    let max_message_size_upstream = state.config.bff.websocket.max_message_size;
    let state_upstream = state.clone();

    // Spawn task to forward upstream messages to client
    let upstream_to_client = tokio::spawn(async move {
        while let Some(msg) = upstream_rx.next().await {
            match msg {
                Ok(TungsteniteMessage::Text(text)) => {
                    // Validate upstream message size (protect client from large messages)
                    if text.len() > max_message_size_upstream {
                        warn!(
                            "Upstream message size {} exceeds limit {} - closing connection",
                            text.len(),
                            max_message_size_upstream
                        );
                        state_upstream.incr(
                            "bff.ws.proxy.error",
                            &[("reason", "upstream_message_too_large")],
                        );
                        state_upstream.histogram(
                            "bff.ws.message.size_rejected",
                            text.len() as f64,
                            &[],
                        );
                        let _ = client_tx
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1009, // Message too big
                                reason: "Upstream message too large".into(),
                            })))
                            .await;
                        break;
                    }

                    state_upstream.incr(
                        "bff.ws.messages.forwarded",
                        &[("direction", "upstream_to_client")],
                    );
                    state_upstream.histogram(
                        "bff.ws.message.size",
                        text.len() as f64,
                        &[("direction", "upstream_to_client")],
                    );

                    if let Err(e) = client_tx.send(Message::Text(text)).await {
                        error!("Failed to forward upstream message to client: {}", e);
                        state_upstream.incr(
                            "bff.ws.forward.error",
                            &[("direction", "upstream_to_client")],
                        );
                        break;
                    }
                }
                Ok(TungsteniteMessage::Binary(data)) => {
                    // Validate upstream binary message size
                    if data.len() > max_message_size_upstream {
                        warn!(
                            "Upstream binary message size {} exceeds limit {} - closing connection",
                            data.len(),
                            max_message_size_upstream
                        );
                        state_upstream.incr(
                            "bff.ws.proxy.error",
                            &[("reason", "upstream_message_too_large")],
                        );
                        state_upstream.histogram(
                            "bff.ws.message.size_rejected",
                            data.len() as f64,
                            &[],
                        );
                        let _ = client_tx
                            .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                                code: 1009, // Message too big
                                reason: "Upstream message too large".into(),
                            })))
                            .await;
                        break;
                    }

                    state_upstream.incr(
                        "bff.ws.messages.forwarded",
                        &[("direction", "upstream_to_client")],
                    );
                    state_upstream.histogram(
                        "bff.ws.message.size",
                        data.len() as f64,
                        &[("direction", "upstream_to_client")],
                    );

                    if let Err(e) = client_tx.send(Message::Binary(data)).await {
                        error!("Failed to forward upstream binary to client: {}", e);
                        state_upstream.incr(
                            "bff.ws.forward.error",
                            &[("direction", "upstream_to_client")],
                        );
                        break;
                    }
                }
                Ok(TungsteniteMessage::Close(_)) => {
                    info!("Upstream closed WebSocket connection");
                    let _ = client_tx.send(Message::Close(None)).await;
                    break;
                }
                Ok(TungsteniteMessage::Ping(data)) => {
                    if let Err(e) = client_tx.send(Message::Ping(data)).await {
                        error!("Failed to forward upstream ping to client: {}", e);
                        state_upstream.incr(
                            "bff.ws.forward.error",
                            &[("direction", "upstream_to_client"), ("type", "ping")],
                        );
                        break;
                    }
                }
                Ok(TungsteniteMessage::Pong(data)) => {
                    if let Err(e) = client_tx.send(Message::Pong(data)).await {
                        error!("Failed to forward upstream pong to client: {}", e);
                        state_upstream.incr(
                            "bff.ws.forward.error",
                            &[("direction", "upstream_to_client"), ("type", "pong")],
                        );
                        break;
                    }
                }
                Ok(TungsteniteMessage::Frame(_)) => {
                    // Raw frames are not exposed in high-level API
                }
                Err(e) => {
                    error!("Error receiving from upstream WebSocket: {}", e);
                    state_upstream
                        .incr("bff.ws.proxy.error", &[("reason", "upstream_read_error")]);
                    break;
                }
            }
        }
    });

    // Wait for either task to complete (connection closed)
    // Important: tokio::select! automatically cancels the non-selected branch
    // This ensures both tasks are cleaned up when one completes
    tokio::select! {
        result = client_to_upstream => {
            info!("Client-to-upstream WebSocket proxy task completed");
            // The upstream_to_client task is automatically cancelled here
            if let Err(e) = result {
                warn!("Client-to-upstream task panicked: {:?}", e);
            }
        }
        result = upstream_to_client => {
            info!("Upstream-to-client WebSocket proxy task completed");
            // The client_to_upstream task is automatically cancelled here
            if let Err(e) = result {
                warn!("Upstream-to-client task panicked: {:?}", e);
            }
        }
    }

    state.incr("bff.ws.proxy.disconnected", &[]);

    info!("WebSocket proxy connection closed (both tasks cleaned up)");
}

/// Handle WebSocket connection with federation mode (direct subgraph routing)
///
/// Instead of proxying to Hive Router, this handler routes subscriptions
/// directly to the owning subgraph using the SubscriptionManager.
///
/// # Protocol Flow
/// 1. Client sends `connection_init` → BFF sends `connection_ack`
/// 2. Client sends `subscribe` → BFF routes to subgraph via SubscriptionManager
/// 3. Subgraph sends `next` → BFF forwards to client
/// 4. Client sends `complete` or disconnects → BFF cleans up
///
/// # Benefits
/// - No Hive Router involved for subscriptions (solves transportEntries issues)
/// - Lower latency (one less network hop)
/// - Better control over connection lifecycle
async fn handle_federation_websocket(
    client_ws: WebSocket,
    state: Arc<AppState>,
    jwt_token: Option<String>,
) {
    // Acquire semaphore permit for memory budgeting
    let semaphore = match state.websocket_semaphore() {
        Some(sem) => sem,
        None => {
            error!("Federation WebSocket: Semaphore not initialized");
            return;
        }
    };

    let _permit = match semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            warn!("Federation WebSocket: Connection rejected - max connections reached");
            state.incr(
                "bff.federation.ws.rejected",
                &[("reason", "max_connections")],
            );
            return;
        }
    };

    // Get subscription manager (we already checked it exists in graphql_ws_proxy)
    let subscription_manager = match state.subscription_manager() {
        Some(manager) => manager.clone(),
        None => {
            error!("Federation WebSocket: SubscriptionManager not available");
            return;
        }
    };

    let (mut client_tx, mut client_rx) = client_ws.split();

    info!("Federation WebSocket: Client connected, waiting for connection_init");

    state.incr("bff.federation.ws.connected", &[]);

    // Step 1: Wait for connection_init from client with timeout
    // The graphql-ws protocol expects connection_init within a reasonable time.
    // This prevents clients from holding connections open without initializing.
    const CONNECTION_INIT_TIMEOUT_SECS: u64 = 10;
    let init_timeout = std::time::Duration::from_secs(CONNECTION_INIT_TIMEOUT_SECS);

    let connection_params = match tokio::time::timeout(init_timeout, client_rx.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            match serde_json::from_str::<FederationClientMessage>(&text) {
                Ok(msg) if msg.msg_type == ws_protocol::CONNECTION_INIT => {
                    debug!("Federation WebSocket: Received connection_init");
                    msg.payload
                }
                Ok(msg) => {
                    error!(
                        "Federation WebSocket: Expected connection_init, got {}",
                        msg.msg_type
                    );
                    return;
                }
                Err(e) => {
                    error!(
                        "Federation WebSocket: Failed to parse connection_init: {}",
                        e
                    );
                    return;
                }
            }
        }
        Ok(Some(Ok(_))) => {
            error!("Federation WebSocket: Expected text message for connection_init");
            return;
        }
        Ok(Some(Err(e))) => {
            error!(
                "Federation WebSocket: Error receiving connection_init: {}",
                e
            );
            return;
        }
        Ok(None) => {
            warn!("Federation WebSocket: Client closed before connection_init");
            return;
        }
        Err(_) => {
            warn!(
                timeout_secs = CONNECTION_INIT_TIMEOUT_SECS,
                "Federation WebSocket: connection_init timeout - client did not initialize"
            );
            state.incr("bff.federation.ws.init_timeout", &[]);
            return;
        }
    };

    // Step 2: Send connection_ack (use pre-serialized JSON for performance)
    if let Err(e) = client_tx
        .send(Message::Text(CONNECTION_ACK_JSON.clone()))
        .await
    {
        error!("Federation WebSocket: Failed to send connection_ack: {}", e);
        return;
    }

    info!("Federation WebSocket: Connection established, ready for subscriptions");

    // Build execution context from JWT token
    let context = build_execution_context(&state, jwt_token.as_deref(), connection_params.as_ref());

    // Track active subscriptions for this connection
    let mut active_subscription_ids: Vec<String> = Vec::new();

    // Create a channel to receive messages from subscription tasks
    // This allows multiple subscription tasks to send messages to the client
    let (outgoing_tx, mut outgoing_rx) = tokio::sync::mpsc::channel::<FederationServerMessage>(64);

    // IDLE TIMEOUT: Close connection if no activity for configured duration
    // This prevents zombie connections from consuming resources indefinitely.
    // The timeout resets on every message (client or server), so active
    // connections are not affected. Default: 60 seconds (bff.websocket.timeout_secs)
    let idle_timeout = std::time::Duration::from_secs(state.config.bff.websocket.timeout_secs);

    // Step 3: Main message loop
    loop {
        tokio::select! {
            // IDLE TIMEOUT BRANCH: Closes connection if no activity
            // The sleep is cancelled and restarted on each loop iteration,
            // so this only fires when BOTH channels are quiet for the full duration.
            _ = tokio::time::sleep(idle_timeout) => {
                info!(
                    idle_secs = state.config.bff.websocket.timeout_secs,
                    active_subscriptions = active_subscription_ids.len(),
                    "Federation WebSocket: Connection idle timeout - closing"
                );
                state.incr("bff.federation.ws.idle_timeout", &[]);
                break;
            }
            // Forward messages from subscription tasks to client
            Some(server_msg) = outgoing_rx.recv() => {
                let msg_json = match serde_json::to_string(&server_msg) {
                    Ok(json) => json,
                    Err(e) => {
                        error!("Federation WebSocket: Failed to serialize message: {}", e);
                        continue;
                    }
                };

                if let Err(e) = client_tx.send(Message::Text(msg_json)).await {
                    debug!("Federation WebSocket: Failed to send to client: {}", e);
                    break;
                }

                state.incr("bff.federation.ws.events_forwarded", &[]);
            }

            // Handle messages from client
            client_msg = client_rx.next() => {
                match client_msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<FederationClientMessage>(&text) {
                            Ok(msg) => {
                                match msg.msg_type.as_str() {
                                    ws_protocol::SUBSCRIBE => {
                                        if let (Some(id), Some(payload)) = (msg.id.clone(), msg.payload) {
                                            match serde_json::from_value::<SubscribePayload>(payload) {
                                                Ok(subscribe_payload) => {
                                                    info!("Federation WebSocket: Subscribe request for id={}", id);

                                                    // Start subscription via manager
                                                    match subscription_manager.subscribe(
                                                        id.clone(),
                                                        subscribe_payload,
                                                        context.clone(),
                                                    ).await {
                                                        Ok(mut rx) => {
                                                            active_subscription_ids.push(id.clone());

                                                            // Spawn task to forward subscription events through our channel
                                                            let outgoing_tx_clone = outgoing_tx.clone();
                                                            let _metrics_clone = state.metrics.clone();
                                                            let sub_id = id.clone();

                                                            tokio::spawn(async move {
                                                                while let Some(server_msg) = rx.recv().await {
                                                                    // Non-blocking send - drop message if client buffer full
                                                                    match outgoing_tx_clone.try_send(server_msg) {
                                                                        Ok(()) => {}
                                                                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                                                            // Client is slow, drop message to prevent blocking
                                                                            debug!(
                                                                                subscription_id = %sub_id,
                                                                                "Client buffer full, dropping subscription event"
                                                                            );
                                                                        }
                                                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                                                            debug!("Federation WebSocket: Outgoing channel closed for sub {}", sub_id);
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                                debug!("Federation WebSocket: Subscription {} ended", sub_id);
                                                            });

                                                            state.incr("bff.federation.ws.subscriptions.started", &[]);
                                                        }
                                                        Err(e) => {
                                                            error!("Federation WebSocket: Subscribe failed for {}: {}", id, e);

                                                            // Send error to client
                                                            let error_msg = FederationServerMessage::error(
                                                                &id,
                                                                vec![serde_json::json!({"message": e.to_string()})],
                                                            );
                                                            let error_json = serde_json::to_string(&error_msg).unwrap_or_default();
                                                            let _ = client_tx.send(Message::Text(error_json)).await;

                                                            state.incr("bff.federation.ws.subscriptions.failed", &[]);
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Federation WebSocket: Invalid subscribe payload: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    ws_protocol::COMPLETE => {
                                        if let Some(id) = msg.id {
                                            info!("Federation WebSocket: Client completed subscription {}", id);
                                            subscription_manager.unsubscribe(&id).await;
                                            active_subscription_ids.retain(|x| x != &id);

                                            state.incr("bff.federation.ws.subscriptions.completed", &[]);
                                        }
                                    }
                                    ws_protocol::PING => {
                                        // Respond with pong (use pre-serialized JSON for performance)
                                        let _ = client_tx.send(Message::Text(PONG_JSON.clone())).await;
                                    }
                                    _ => {
                                        debug!("Federation WebSocket: Ignoring message type {}", msg.msg_type);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Federation WebSocket: Failed to parse client message: {}", e);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        info!("Federation WebSocket: Client closed connection");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = client_tx.send(Message::Pong(data)).await;
                    }
                    Some(Err(e)) => {
                        error!("Federation WebSocket: Error from client: {}", e);
                        break;
                    }
                    None => {
                        info!("Federation WebSocket: Client stream ended");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup: Unsubscribe all active subscriptions
    info!(
        "Federation WebSocket: Cleaning up {} active subscriptions",
        active_subscription_ids.len()
    );
    for id in active_subscription_ids {
        subscription_manager.unsubscribe(&id).await;
    }

    state.incr("bff.federation.ws.disconnected", &[]);

    info!("Federation WebSocket: Connection closed");
}

/// Execute GraphQL request using federation executor (Phase 2)
///
/// This bypasses Hive Router and executes directly against subgraphs:
/// 1. Query planning - determines which subgraphs to call
/// 2. Plan execution - calls subgraphs in parallel/sequence as needed
/// 3. Response caching - stores responses in two-tier cache
///
/// # Request Context
/// Uses the RequestContext for:
/// - Deadline propagation (remaining time for subgraph calls)
/// - Request tracing (request_id in logs)
/// - Cancellation (stops work if context is cancelled)
///
/// Falls back to proxy mode if federation executor is not available.
async fn execute_federation(
    state: Arc<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    body: Value,
    operation_name: &str,
    session_id: Option<Uuid>,
    ctx: RequestContext,
) -> axum::response::Response {
    // Check if federation executor is available
    let Some(executor) = state.federation_executor() else {
        warn!(
            request_id = %ctx.request_id(),
            "Federation executor not available, falling back to proxy mode"
        );
        return proxy_to_hive_router(state, jar, headers, body, operation_name, session_id, ctx)
            .await;
    };

    // Create federation request from body
    let mut request = FederationRequest::from_json(&body, headers.clone())
        .with_product(state.config.bff.product.clone());

    // Extract user info from session if available
    if let Some(session_redis) = state.session_redis() {
        if let Some(sid) = session_id {
            if let Some(mut conn) = session_redis.get().await {
                let session_key = format!("session:{}", sid);
                // CRITICAL: Use timeout to prevent blocking on slow Redis
                // 2 seconds is generous for a simple GET operation
                let session_data: Option<String> = match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    redis::cmd("GET")
                        .arg(&session_key)
                        .query_async::<String>(&mut conn),
                )
                .await
                {
                    Ok(Ok(data)) => Some(data),
                    Ok(Err(_)) | Err(_) => {
                        // Redis error or timeout - continue without session context
                        // The request will still work, just without user context
                        debug!(session_id = %sid, "Federation: Session lookup timed out or failed");
                        None
                    }
                };

                if let Some(data) = session_data {
                    // Deserialize as Session struct
                    if let Ok(session) = serde_json::from_str::<Session>(&data) {
                        let user_id = Some(session.user_id.to_string());

                        // Use session fields directly - this is the canonical BFF pattern
                        // User context (email, roles, permissions) is stored in the session
                        // during login intercept, extracted from the login response.
                        // No JWT decode fallback - sessions MUST have user context populated.
                        debug!(
                            user_id = ?user_id,
                            email = ?session.user_email,
                            roles = ?session.roles,
                            permissions_count = session.permissions.len(),
                            permissions_preview = ?session.permissions.iter().take(5).collect::<Vec<_>>(),
                            staff_role = ?session.staff_role,
                            "Federation: Using session-stored user context"
                        );

                        request = request.with_user(
                            user_id,
                            session.user_email.clone(),
                            session.roles.clone(),
                            session.permissions.clone(),
                            session.relationships.clone(),
                        );
                    }
                }
            }
        }
    }

    // Execute via federation executor
    let response = executor.execute(request).await;

    info!(
        request_id = %ctx.request_id(),
        operation = %operation_name,
        elapsed_ms = ctx.elapsed().as_millis(),
        "Federation execution complete"
    );

    state.histogram(
        "bff.federation.execution.duration_ms",
        ctx.elapsed().as_millis() as f64,
        &[("operation", operation_name)],
    );

    // NOTE: record_completion() is now handled by AdmissionGuard in graphql_proxy
    // The guard ensures cancellation safety - if the client disconnects mid-request,
    // the guard's Drop impl will still decrement the in_flight counter.
    // This was previously a bug where cancelled requests would leak in_flight counts.

    // Convert FederationResponse to axum Response
    response.into_response()
}

/// Build execution context from JWT token and connection params
fn build_execution_context(
    state: &AppState,
    jwt_token: Option<&str>,
    connection_params: Option<&serde_json::Value>,
) -> ExecutionContext {
    let mut context = ExecutionContext {
        product: state.config.bff.product.clone(),
        ..Default::default()
    };

    // Try to extract user info from JWT token
    if let Some(token) = jwt_token {
        // Decode JWT to extract claims (without verification - already validated by session)
        if let Ok(parts) = jsonwebtoken::decode_header(token) {
            debug!("JWT algorithm: {:?}", parts.alg);
        }

        // For now, just store the token - subgraphs will validate
        context.token = Some(token.to_string());
    }

    // Also check connection_params for any user info passed by client
    if let Some(params) = connection_params {
        if let Some(user_id) = params.get("x-user-id").and_then(|v| v.as_str()) {
            context.user_id = Some(user_id.to_string());
        }
        if let Some(email) = params.get("x-user-email").and_then(|v| v.as_str()) {
            context.user_email = Some(email.to_string());
        }
        if let Some(roles) = params.get("x-user-roles").and_then(|v| v.as_str()) {
            context.user_roles = Some(roles.to_string());
        }
        if let Some(permissions) = params.get("x-user-permissions").and_then(|v| v.as_str()) {
            context.user_permissions = Some(permissions.to_string());
        }
        if let Some(product) = params.get("x-product").and_then(|v| v.as_str()) {
            context.product = product.to_string();
        }
    }

    context
}

// ============================================================================
// Admin API Endpoints
// ============================================================================

/// Admin endpoint to force reload the supergraph
///
/// POST /admin/reload-supergraph
///
/// This endpoint triggers an immediate reload of the supergraph from the configured
/// source (file:// or http://). Used by the release pipeline to ensure the new
/// supergraph is picked up immediately without waiting for the polling interval.
///
/// # Response
/// Returns JSON with:
/// - `success`: boolean indicating if reload succeeded
/// - `hash`: SHA-256 hash (first 16 chars) of the new supergraph
/// - `subgraph_count`: number of subgraphs in the loaded schema
/// - `subscription_route_count`: number of subscription routes
/// - `source`: URL the supergraph was loaded from
/// - `error`: optional error message if reload failed
///
/// # Security
/// This endpoint should be protected and only accessible internally
/// (e.g., from the release pipeline or admin network).
pub async fn admin_reload_supergraph(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use crate::federation::SupergraphReloadResult;

    // Check if federation is enabled
    if !state.config.features.enable_bff || !state.config.bff.federation.enabled {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SupergraphReloadResult {
                success: false,
                hash: String::new(),
                subgraph_count: 0,
                subscription_route_count: 0,
                source: String::new(),
                error: Some("Federation is not enabled".to_string()),
            }),
        );
    }

    // Get the hot-reloadable supergraph from state
    let supergraph = match state.hot_reloadable_supergraph() {
        Some(sg) => sg,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SupergraphReloadResult {
                    success: false,
                    hash: String::new(),
                    subgraph_count: 0,
                    subscription_route_count: 0,
                    source: String::new(),
                    error: Some("Hot-reloadable supergraph not initialized".to_string()),
                }),
            );
        }
    };

    // Force reload the supergraph
    match supergraph
        .force_reload(&state.config.bff.federation, state.metrics.as_ref())
        .await
    {
        Ok(result) => {
            if result.success {
                info!(
                    hash = %result.hash,
                    subgraphs = result.subgraph_count,
                    "Admin: Supergraph force reload successful"
                );
                (StatusCode::OK, Json(result))
            } else {
                warn!(
                    error = result.error.as_deref().unwrap_or("unknown"),
                    "Admin: Supergraph force reload failed"
                );
                (StatusCode::INTERNAL_SERVER_ERROR, Json(result))
            }
        }
        Err(e) => {
            error!(error = %e, "Admin: Supergraph force reload error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(SupergraphReloadResult {
                    success: false,
                    hash: String::new(),
                    subgraph_count: 0,
                    subscription_route_count: 0,
                    source: state.config.bff.federation.supergraph_url.clone(),
                    error: Some(format!("Reload error: {}", e)),
                }),
            )
        }
    }
}

/// Admin endpoint to get current supergraph status
///
/// GET /admin/supergraph-status
///
/// Returns information about the currently loaded supergraph without reloading.
pub async fn admin_supergraph_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    use serde::Serialize;

    #[derive(Serialize)]
    struct SupergraphStatus {
        enabled: bool,
        loaded: bool,
        source: String,
        hot_reload: bool,
        poll_interval_secs: u64,
        subgraph_count: Option<usize>,
    }

    // Check if federation is enabled
    if !state.config.features.enable_bff || !state.config.bff.federation.enabled {
        return Json(SupergraphStatus {
            enabled: false,
            loaded: false,
            source: String::new(),
            hot_reload: false,
            poll_interval_secs: 0,
            subgraph_count: None,
        });
    }

    let loaded = state.hot_reloadable_supergraph().is_some();
    let subgraph_count = if let Some(sg) = state.hot_reloadable_supergraph() {
        if let Some(guard) = sg.get().await {
            guard.as_ref().map(|s| s.subgraphs().len() / 2)
        } else {
            None
        }
    } else {
        None
    };

    Json(SupergraphStatus {
        enabled: true,
        loaded,
        source: state.config.bff.federation.supergraph_url.clone(),
        hot_reload: state.config.bff.federation.hot_reload,
        poll_interval_secs: state.config.bff.federation.poll_interval_secs,
        subgraph_count,
    })
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_bff_module_compiles() {
        // Basic compilation test
        // Integration tests require full AppState setup
    }
}
