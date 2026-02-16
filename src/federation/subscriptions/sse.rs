//! Server-Sent Events (SSE) Transport for GraphQL Subscriptions
//!
//! Provides firewall-proof subscription transport following the graphql-sse protocol.
//! SSE works through corporate firewalls that block WebSocket upgrade requests.
//!
//! # Protocol
//!
//! Follows the [graphql-sse](https://github.com/enisdenjo/graphql-sse) "distinct connections mode":
//! - Client sends POST with `Accept: text/event-stream` header
//! - Server streams events in SSE format: `event: next\ndata: {...}\n\n`
//!
//! # Event Types
//!
//! - `next`: GraphQL data event (equivalent to WebSocket "next")
//! - `error`: GraphQL error event (equivalent to WebSocket "error")
//! - `complete`: Subscription completed (equivalent to WebSocket "complete")
//!
//! # Architecture
//!
//! ```text
//! Client POST /graphql (Accept: text/event-stream)
//!     │
//!     ├── Parse subscription from body
//!     ├── Route to subgraph (SubscriptionRouter)
//!     ├── Get connection (SubgraphConnectionPool)
//!     └── Stream SSE events until complete
//! ```
//!
//! # HTTP/1.1 Limitation
//!
//! SSE inherits HTTP/1.1's ~6 connections per browser limitation.
//! Use HTTP/2 for production deployments to enable multiplexing.
//!
//! # Module Structure
//!
//! The SSE handler is co-located with subscription types for cohesion.
//!
//! ## Architectural Note (Layering Exception)
//!
//! This module imports `AppState` from `state.rs`, creating a bidirectional dependency
//! between `federation` and `state`. This is intentional:
//! - Handler code requires access to application state (subscription manager, config, metrics)
//! - Co-locating SSE handler with subscription types improves maintainability
//! - This pattern matches how auth/middleware handlers access state
//!
//! Alternative: Move handler to `bff.rs` (increases file size, reduces subscription cohesion)

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::CookieJar;
use futures_util::stream::Stream;
use pin_project_lite::pin_project;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::manager::SubscriptionError;
use crate::auth::session::Session;
use crate::federation::types::{ExecutionContext, ServerMessage, SubscribePayload};
use crate::state::AppState;

/// SSE-specific errors
#[derive(Debug, Error)]
pub enum SseError {
    /// SSE transport is disabled in configuration
    #[error("SSE transport is disabled")]
    Disabled,

    /// Invalid Accept header (must be text/event-stream)
    #[error("Invalid Accept header: expected text/event-stream")]
    InvalidAcceptHeader,

    /// Missing or invalid subscription query
    #[error("Invalid subscription request: {0}")]
    InvalidRequest(String),

    /// Subscription routing error
    #[error("Subscription error: {0}")]
    SubscriptionError(#[from] SubscriptionError),

    /// Session retrieval error (reserved for strict session validation)
    #[error("Session error: {0}")]
    #[allow(dead_code)] // Reserved for future use when session validation is required
    SessionError(String),
}

impl SseError {
    /// Get the error category for recovery action
    pub fn category(&self) -> SseErrorCategory {
        match self {
            Self::Disabled => SseErrorCategory::Permanent,
            Self::InvalidAcceptHeader => SseErrorCategory::Permanent,
            Self::InvalidRequest(_) => SseErrorCategory::Permanent,
            Self::SubscriptionError(_) => SseErrorCategory::Transient,
            Self::SessionError(_) => SseErrorCategory::Transient,
        }
    }
}

/// Error category for recovery action decisions
#[derive(Debug, Clone, Copy)]
pub enum SseErrorCategory {
    /// Retryable errors (network, temporary failures)
    Transient,
    /// Non-retryable errors (bad request, disabled)
    Permanent,
}

/// GraphQL subscription request body for SSE transport
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SseSubscriptionRequest {
    /// GraphQL subscription query
    pub query: String,

    /// GraphQL variables (optional)
    #[serde(default)]
    pub variables: Option<serde_json::Value>,

    /// Operation name (optional, for multi-operation documents)
    #[serde(rename = "operationName")]
    pub operation_name: Option<String>,

    /// Extensions (optional, for APQ hash etc.)
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

/// GraphQL error response for SSE error events
#[derive(Debug, Clone, Serialize)]
struct GraphQLError {
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    extensions: Option<serde_json::Value>,
}

/// SSE configuration (mirrors FederationWebSocketConfig.sse_* fields)
#[derive(Debug, Clone)]
pub struct SseConfig {
    /// Enable SSE transport
    pub enabled: bool,

    /// Keep-alive interval in seconds
    pub keep_alive_secs: u64,

    /// Maximum subscription duration in seconds (0 = unlimited)
    #[allow(dead_code)] // Reserved for future max-duration enforcement
    pub max_duration_secs: u64,

    /// Timeout for Redis session lookups in seconds
    #[allow(dead_code)] // Used in get_session_from_cookie
    pub session_timeout_secs: u64,
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_alive_secs: 30,
            max_duration_secs: 0, // Unlimited
            session_timeout_secs: 2,
        }
    }
}

impl SseConfig {
    /// Create SseConfig from FederationWebSocketConfig
    pub fn from_federation_config(ws_config: &crate::config::FederationWebSocketConfig) -> Self {
        Self {
            enabled: ws_config.sse_enabled,
            keep_alive_secs: ws_config.sse_keep_alive_secs,
            max_duration_secs: ws_config.sse_max_duration_secs,
            session_timeout_secs: 2, // Could be made configurable
        }
    }
}

/// Check if the request accepts SSE (text/event-stream)
///
/// # Arguments
/// * `headers` - Request headers to check
///
/// # Returns
/// `true` if the Accept header includes text/event-stream
#[inline]
pub fn accepts_sse(headers: &HeaderMap) -> bool {
    headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false)
}

/// Handle GraphQL subscription request via SSE transport
///
/// This handler is invoked when:
/// 1. Request is a POST to /graphql
/// 2. Accept header contains text/event-stream
/// 3. Body contains a GraphQL subscription operation
///
/// # Protocol
///
/// Follows graphql-sse "distinct connections mode":
/// - Each subscription gets its own SSE connection
/// - Events streamed as: `event: {type}\ndata: {json}\n\n`
/// - Connection closed after `complete` event
///
/// # Example Request
///
/// ```http
/// POST /graphql HTTP/1.1
/// Accept: text/event-stream
/// Content-Type: application/json
///
/// {
///   "query": "subscription { jobsUpdated { id status } }"
/// }
/// ```
///
/// # Example Response
///
/// ```text
/// event: next
/// data: {"data":{"jobsUpdated":{"id":"123","status":"RUNNING"}}}
///
/// event: complete
/// data:
/// ```
pub async fn graphql_sse_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(request): Json<SseSubscriptionRequest>,
) -> impl IntoResponse {
    // Get SSE config from federation configuration
    let sse_config = SseConfig::from_federation_config(&state.config.bff.federation.websocket);

    // Check if SSE is enabled
    if !sse_config.enabled {
        return SseErrorResponse::from(SseError::Disabled).into_response();
    }

    // Verify Accept header (should already be verified by routing, but double-check)
    if !accepts_sse(&headers) {
        return SseErrorResponse::from(SseError::InvalidAcceptHeader).into_response();
    }

    // Get subscription manager
    let subscription_manager = match state.subscription_manager() {
        Some(manager) => manager.clone(),
        None => {
            error!("SSE handler: SubscriptionManager not available");
            return SseErrorResponse::from(SseError::InvalidRequest(
                "Subscriptions not available".to_string(),
            ))
            .into_response();
        }
    };

    // Build execution context from session (same as WebSocket)
    let context = match build_execution_context(&state, &jar).await {
        Ok(ctx) => ctx,
        Err(e) => {
            warn!("SSE handler: Failed to build execution context: {}", e);
            return SseErrorResponse::from(e).into_response();
        }
    };

    // Generate unique subscription ID
    let subscription_id = uuid::Uuid::new_v4().to_string();

    // Create subscribe payload
    let payload = SubscribePayload {
        query: request.query,
        variables: request.variables.unwrap_or(serde_json::Value::Null),
        operation_name: request.operation_name,
        extensions: request.extensions.unwrap_or(serde_json::Value::Null),
    };

    info!(
        subscription_id = %subscription_id,
        product = %context.product,
        user_id = ?context.user_id,
        "SSE subscription started"
    );

    // Emit metrics
    state.incr(
        "bff.federation.sse.subscription_started",
        &[("product", &context.product)],
    );

    // Subscribe through the subscription manager (reuses existing infrastructure)
    let receiver = match subscription_manager
        .subscribe(subscription_id.clone(), payload, context.clone())
        .await
    {
        Ok(rx) => rx,
        Err(e) => {
            error!(
                subscription_id = %subscription_id,
                error = %e,
                "SSE subscription failed"
            );
            state.incr(
                "bff.federation.sse.subscription_error",
                &[("product", &context.product)],
            );
            return SseErrorResponse::from(SseError::SubscriptionError(e)).into_response();
        }
    };

    // Create SSE stream from subscription events
    let stream = create_sse_stream(
        receiver,
        subscription_id.clone(),
        context.product.clone(),
        state.clone(),
    );

    // Return SSE response with keep-alive
    let keep_alive = KeepAlive::new()
        .interval(Duration::from_secs(sse_config.keep_alive_secs))
        .text(":");

    Sse::new(stream).keep_alive(keep_alive).into_response()
}

// Custom stream wrapper for SSE events
pin_project! {
    /// Stream that converts subscription messages to SSE events
    struct SseEventStream {
        receiver: mpsc::Receiver<ServerMessage>,
        subscription_id: String,
        product: String,
        state: Arc<AppState>,
        completed: bool,
    }
}

impl Stream for SseEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();

        if *this.completed {
            return Poll::Ready(None);
        }

        match Pin::new(this.receiver).poll_recv(cx) {
            Poll::Ready(Some(msg)) => {
                match msg.msg_type.as_str() {
                    "next" => {
                        if let Some(payload) = msg.payload {
                            let data = serde_json::to_string(&payload).unwrap_or_default();
                            debug!(
                                subscription_id = %this.subscription_id,
                                "SSE: sending next event"
                            );
                            Poll::Ready(Some(Ok(Event::default().event("next").data(data))))
                        } else {
                            // No payload, poll again
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    "error" => {
                        if let Some(payload) = msg.payload {
                            let data = serde_json::to_string(&payload).unwrap_or_default();
                            warn!(
                                subscription_id = %this.subscription_id,
                                "SSE: sending error event"
                            );
                            this.state.incr(
                                "bff.federation.sse.error_event",
                                &[("product", this.product.as_str())],
                            );
                            *this.completed = true;
                            Poll::Ready(Some(Ok(Event::default().event("error").data(data))))
                        } else {
                            *this.completed = true;
                            Poll::Ready(None)
                        }
                    }
                    "complete" => {
                        debug!(
                            subscription_id = %this.subscription_id,
                            "SSE: sending complete event"
                        );
                        this.state.incr(
                            "bff.federation.sse.subscription_completed",
                            &[("product", this.product.as_str()), ("completed", "true")],
                        );
                        *this.completed = true;
                        Poll::Ready(Some(Ok(Event::default().event("complete").data(""))))
                    }
                    _ => {
                        warn!(
                            subscription_id = %this.subscription_id,
                            msg_type = %msg.msg_type,
                            "SSE: ignoring unknown message type"
                        );
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(None) => {
                // Channel closed
                info!(
                    subscription_id = %this.subscription_id,
                    completed = *this.completed,
                    "SSE subscription ended (channel closed)"
                );
                if !*this.completed {
                    this.state.incr(
                        "bff.federation.sse.subscription_completed",
                        &[("product", this.product.as_str()), ("completed", "false")],
                    );
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Create SSE event stream from subscription message receiver
fn create_sse_stream(
    receiver: mpsc::Receiver<ServerMessage>,
    subscription_id: String,
    product: String,
    state: Arc<AppState>,
) -> impl Stream<Item = Result<Event, Infallible>> {
    SseEventStream {
        receiver,
        subscription_id,
        product,
        state,
        completed: false,
    }
}

/// Build execution context from session cookie (same logic as WebSocket)
async fn build_execution_context(
    state: &AppState,
    jar: &CookieJar,
) -> Result<ExecutionContext, SseError> {
    // Try to get session from cookie
    let session = get_session_from_cookie(state, jar).await;

    // Build context similar to how bff.rs does it
    let mut context = ExecutionContext {
        product: state.config.bff.product.clone(),
        ..Default::default()
    };

    // Add user info and token from session
    if let Some(s) = session {
        context.user_id = Some(s.user_id.to_string());
        context.token = Some(s.access_token.clone());
    }

    Ok(context)
}

/// Get session from cookie (mirrors WebSocket logic in bff.rs)
async fn get_session_from_cookie(state: &AppState, jar: &CookieJar) -> Option<Session> {
    // Check if sessions are enabled
    if !state.config.bff.session.enabled {
        return None;
    }

    // Get session Redis pool
    let session_redis = state.session_redis()?;

    // Get session ID from cookie
    let cookie_name = &state.config.bff.session.cookie_name;
    let session_cookie = jar.get(cookie_name)?;
    let session_id = session_cookie.value();

    // Get connection from lazy pool
    let mut conn = session_redis.get().await?;

    // Fetch session from Redis with timeout (mirrors bff.rs pattern)
    let session_key = format!("{}{}", state.config.bff.session.key_prefix, session_id);

    let session_data: Option<String> = match tokio::time::timeout(
        Duration::from_secs(2),
        redis::cmd("GET")
            .arg(&session_key)
            .query_async::<String>(&mut conn),
    )
    .await
    {
        Ok(Ok(data)) => Some(data),
        Ok(Err(e)) => {
            warn!("SSE: Redis error fetching session: {}", e);
            None
        }
        Err(_) => {
            warn!("SSE: Redis timeout fetching session");
            None
        }
    };

    // Parse session JSON
    match session_data {
        Some(json) => match serde_json::from_str::<Session>(&json) {
            Ok(session) => Some(session),
            Err(e) => {
                warn!("SSE: Failed to parse session: {}", e);
                None
            }
        },
        None => {
            debug!("SSE: No session found for ID: {}", session_id);
            None
        }
    }
}

/// Error response wrapper for SSE errors
struct SseErrorResponse {
    status: StatusCode,
    error: GraphQLError,
}

impl From<SseError> for SseErrorResponse {
    fn from(e: SseError) -> Self {
        let (status, code) = match &e {
            SseError::Disabled => (StatusCode::NOT_IMPLEMENTED, "SSE_DISABLED"),
            SseError::InvalidAcceptHeader => (StatusCode::NOT_ACCEPTABLE, "INVALID_ACCEPT"),
            SseError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            SseError::SubscriptionError(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "SUBSCRIPTION_ERROR")
            }
            SseError::SessionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "SESSION_ERROR"),
        };

        SseErrorResponse {
            status,
            error: GraphQLError {
                message: e.to_string(),
                extensions: Some(serde_json::json!({
                    "code": code,
                    "category": format!("{:?}", e.category()),
                })),
            },
        }
    }
}

impl IntoResponse for SseErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({
                "errors": [self.error]
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_accepts_sse_valid() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("text/event-stream"));
        assert!(accepts_sse(&headers));
    }

    #[test]
    fn test_accepts_sse_with_other_types() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            HeaderValue::from_static("text/event-stream, application/json"),
        );
        assert!(accepts_sse(&headers));
    }

    #[test]
    fn test_accepts_sse_invalid() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", HeaderValue::from_static("application/json"));
        assert!(!accepts_sse(&headers));
    }

    #[test]
    fn test_accepts_sse_missing() {
        let headers = HeaderMap::new();
        assert!(!accepts_sse(&headers));
    }

    #[test]
    fn test_sse_request_deserialization() {
        let json = r#"{
            "query": "subscription { test }",
            "variables": {"foo": "bar"},
            "operationName": "TestSubscription"
        }"#;

        let request: SseSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "subscription { test }");
        assert!(request.variables.is_some());
        assert_eq!(request.operation_name.as_deref(), Some("TestSubscription"));
    }

    #[test]
    fn test_sse_request_minimal() {
        let json = r#"{"query": "subscription { test }"}"#;
        let request: SseSubscriptionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.query, "subscription { test }");
        assert!(request.variables.is_none());
        assert!(request.operation_name.is_none());
    }

    #[test]
    fn test_sse_error_category() {
        assert!(matches!(
            SseError::Disabled.category(),
            SseErrorCategory::Permanent
        ));
        assert!(matches!(
            SseError::InvalidAcceptHeader.category(),
            SseErrorCategory::Permanent
        ));
        assert!(matches!(
            SseError::InvalidRequest("test".to_string()).category(),
            SseErrorCategory::Permanent
        ));
        assert!(matches!(
            SseError::SessionError("test".to_string()).category(),
            SseErrorCategory::Transient
        ));
    }

    #[test]
    fn test_sse_config_defaults() {
        let config = SseConfig::default();
        assert!(config.enabled);
        assert_eq!(config.keep_alive_secs, 30);
        assert_eq!(config.max_duration_secs, 0);
        assert_eq!(config.session_timeout_secs, 2);
    }

    #[test]
    fn test_sse_config_from_federation_config() {
        use crate::config::FederationWebSocketConfig;

        let ws_config = FederationWebSocketConfig::default();
        let sse_config = SseConfig::from_federation_config(&ws_config);

        // Should match federation config values
        assert_eq!(sse_config.enabled, ws_config.sse_enabled);
        assert_eq!(sse_config.keep_alive_secs, ws_config.sse_keep_alive_secs);
        assert_eq!(
            sse_config.max_duration_secs,
            ws_config.sse_max_duration_secs
        );
    }

    #[test]
    fn test_graphql_error_serialization() {
        let error = GraphQLError {
            message: "Test error".to_string(),
            extensions: Some(serde_json::json!({"code": "TEST"})),
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Test error"));
        assert!(json.contains("TEST"));
    }

    #[test]
    fn test_graphql_error_without_extensions() {
        let error = GraphQLError {
            message: "Test error".to_string(),
            extensions: None,
        };

        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("Test error"));
        assert!(!json.contains("extensions"));
    }
}
