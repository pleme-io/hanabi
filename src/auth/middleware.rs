//! Session authentication middleware for BFF
//!
//! This middleware:
//! 1. Extracts session ID from cookie
//! 2. Looks up session in Redis
//! 3. Auto-refreshes tokens if needed (transparent to frontend)
//! 4. Injects Authorization header AND x-user-* headers into request
//!
//! The x-user-* headers enable the BFF-only session pattern where:
//! - BFF is the SINGLE source of truth for sessions
//! - Backend services read user context from headers (via pleme-rbac)
//! - Backend services do NOT maintain their own session stores
//!
//! Used for /api/graphql endpoint to authenticate requests before proxying to backend.
//!
//! # Non-Blocking Architecture
//!
//! This middleware NEVER blocks indefinitely:
//! - Redis pool.get() has 5s timeout (returns None on failure)
//! - Token refresh has 5s HTTP timeout
//! - On any failure: graceful degradation (pass through without auth)
//! - Metrics emitted for pool exhaustion/unavailability
//!
//! Failure modes:
//! 1. Redis unavailable → Pass through (401 from auth service)
//! 2. Session not found → Pass through (401 from auth service)
//! 3. Token refresh fails → Continue with old token (may get 401)
//!
//! # Performance Optimizations
//! - `#[inline]` on hot path functions (runs on EVERY request)
//! - Static GraphQL mutation string (no per-request allocation)
//! - &str instead of String where possible
//! - Reuse ConnectionManager (no clone needed)

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header,
    middleware::Next,
    response::Response,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{Duration, Utc};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::session::{Session, SessionError, SessionStore};
use crate::state::AppState;

/// GraphQL mutation for token refresh (static to avoid per-request allocation)
const REFRESH_MUTATION: &str = r#"
    mutation RefreshToken($refreshToken: String!) {
        refreshToken(refreshToken: $refreshToken) {
            accessToken
            refreshToken
            expiresIn
        }
    }
"#;

/// Error message constants for session failures
const ERR_HTTP_CLIENT_UNAVAILABLE: &str = "HTTP client not available";
const ERR_NO_REFRESH_DATA: &str = "No refresh data in response";
const ERR_NO_ACCESS_TOKEN: &str = "No access token";
const ERR_NO_REFRESH_TOKEN: &str = "No refresh token";
const ERR_NO_EXPIRES_IN: &str = "No expires_in";
const ERR_UNKNOWN: &str = "Unknown error";

/// Session authentication middleware
///
/// For requests with a valid session cookie:
/// - Validates session exists in Redis
/// - Auto-refreshes tokens if expired (transparent refresh)
/// - Adds Authorization header to request
///
/// For requests without session cookie:
/// - Passes through without Authorization header (some queries are public)
///
/// The Hive Router/Auth Service will return UNAUTHENTICATED for protected queries.
///
/// # Performance
/// Hot path - runs on EVERY GraphQL request. Optimizations:
/// - Inlined for zero-cost abstraction
/// - Minimal allocations (reuses ConnectionManager)
/// - Early returns to skip unnecessary work
#[inline]
pub async fn session_auth_middleware(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    mut request: Request,
    next: Next,
) -> Response {
    // If BFF sessions are not enabled, pass through (legacy mode)
    if !state.config.bff.session.enabled {
        return next.run(request).await;
    }

    // Need Redis for session management
    if state.session_redis().is_none() {
        return next.run(request).await;
    }

    // Extract session ID from cookie
    let session_id = match extract_session_id(&jar, &state.config.bff.session.cookie_name) {
        Some(id) => id,
        None => {
            // No session cookie - check if client is sending Bearer token directly
            // This supports API clients, tests, and M2M authentication
            if request.headers().get(header::AUTHORIZATION).is_some() {
                debug!("No session cookie but Authorization header present - passing through");
                return next.run(request).await;
            }
            // No session cookie and no Authorization header - pass through (public query)
            // Log at info level to help debug cookie issues
            info!(
                "No session cookie '{}' found - passing through without auth",
                state.config.bff.session.cookie_name
            );
            return next.run(request).await;
        }
    };

    info!(
        "Session middleware: found cookie, checking session {}",
        session_id
    );

    // Get Redis connection lazily (connects on first use, retries with backoff)
    // Safety: session_redis is guaranteed to be Some due to early return on line 90
    let redis_pool = match state.session_redis() {
        Some(pool) => pool.clone(),
        None => {
            // This should never happen due to early return, but handle gracefully
            warn!("session_redis unexpectedly None in session middleware");
            return next.run(request).await;
        }
    };
    let redis = match redis_pool.get().await {
        Some(conn) => conn,
        None => {
            warn!("Failed to get Redis connection for session middleware - graceful degradation");
            // Emit metric for pool exhaustion/unavailability
            state.incr(
                "bff.session.redis_unavailable",
                &[("middleware", "session_auth")],
            );
            // Pass through without auth - upstream will handle
            return next.run(request).await;
        }
    };
    // No clone needed - ConnectionManager is cheaply cloneable (Arc internally)
    let mut store = SessionStore::new(redis, state.config.bff.session.clone());

    let (mut session, needs_refresh) = match store.get_with_refresh_check(&session_id).await {
        Ok(result) => result,
        Err(SessionError::NotFound) => {
            debug!("Session not found: {}", session_id);
            // Session expired or invalid - pass through without auth
            // The upstream will return UNAUTHENTICATED if needed
            return next.run(request).await;
        }
        Err(e) => {
            error!("Session lookup error for {}: {}", session_id, e);
            // On Redis error, pass through to allow degraded operation
            return next.run(request).await;
        }
    };

    // Auto-refresh tokens if needed
    if needs_refresh {
        info!("Auto-refreshing tokens for session {}", session_id);

        match refresh_tokens(&state, &session).await {
            Ok((new_access_token, new_refresh_token, expires_in)) => {
                let token_expires_at = Utc::now() + Duration::seconds(expires_in);
                session.update_tokens(new_access_token, new_refresh_token, token_expires_at);

                // Update session in Redis
                if let Err(e) = store.update(&session).await {
                    error!("Failed to update session after refresh: {}", e);
                    // Continue with old token - it might still work
                }

                info!("Token refresh successful for session {}", session_id);
            }
            Err(e) => {
                warn!("Token refresh failed for session {}: {}", session_id, e);
                // Continue with existing token - it might still work for a bit
                // Or the upstream will return UNAUTHENTICATED
            }
        }
    }

    // Add Authorization header to request
    let auth_value = format!("Bearer {}", session.access_token);
    let header_value = match auth_value.parse() {
        Ok(value) => value,
        Err(e) => {
            error!("Failed to parse Authorization header value: {} - token may contain invalid characters", e);
            // Pass through without auth - upstream will handle
            return next.run(request).await;
        }
    };
    request
        .headers_mut()
        .insert(header::AUTHORIZATION, header_value);

    // Inject x-user-* headers for BFF-only session pattern
    // These headers allow backend services to read user context without
    // maintaining their own session stores (pleme-rbac pattern)
    inject_user_headers(&mut request, &session);

    // Inject x-product header for product isolation (required by pleme-rbac)
    // This identifies which product this BFF serves (e.g., "novaskyn", "myapp")
    if let Ok(value) = state.config.bff.product.parse() {
        request.headers_mut().insert("x-product", value);
    }

    info!(
        "Session middleware: added Authorization + x-user-* headers for session {} (user: {}, product: {}, permissions: {})",
        session_id, session.user_id, state.config.bff.product, session.permissions.len()
    );

    next.run(request).await
}

/// Inject x-user-* headers from session into request
///
/// These headers enable the BFF-only session pattern where backend services
/// read user context from headers instead of maintaining separate sessions.
///
/// Headers injected:
/// - x-user-id: User UUID
/// - x-user-email: User email (if available)
/// - x-user-roles: Comma-separated roles
/// - x-user-permissions: Comma-separated permissions
/// - x-user-staff-role: Staff role (if available)
#[inline]
fn inject_user_headers(request: &mut Request, session: &Session) {
    let headers = request.headers_mut();

    // Always inject user_id
    if let Ok(value) = session.user_id.to_string().parse() {
        headers.insert("x-user-id", value);
    }

    // Inject email if available
    if let Some(ref email) = session.user_email {
        if let Ok(value) = email.parse() {
            headers.insert("x-user-email", value);
        }
    }

    // Inject roles as comma-separated list
    if !session.roles.is_empty() {
        if let Ok(value) = session.roles.join(",").parse() {
            headers.insert("x-user-roles", value);
        }
    }

    // Inject permissions as comma-separated list
    if !session.permissions.is_empty() {
        if let Ok(value) = session.permissions.join(",").parse() {
            headers.insert("x-user-permissions", value);
        }
    }

    // Inject staff role if available
    if let Some(ref staff_role) = session.staff_role {
        if let Ok(value) = staff_role.parse() {
            headers.insert("x-user-staff-role", value);
        }
    }

    // Inject relationships if available
    if !session.relationships.is_empty() {
        if let Ok(value) = session.relationships.join(",").parse() {
            headers.insert("x-user-relationships", value);
        }
    }
}

/// Refresh tokens using the Auth Service
///
/// # Performance
/// Uses static REFRESH_MUTATION constant to avoid per-request allocation
#[inline]
async fn refresh_tokens(
    state: &AppState,
    session: &Session,
) -> Result<(String, String, i64), SessionError> {
    let http_client = match state.http_client() {
        Some(client) => client.clone(),
        None => {
            return Err(SessionError::RefreshFailed(
                ERR_HTTP_CLIENT_UNAVAILABLE.to_string(),
            ));
        }
    };

    let graphql_request = serde_json::json!({
        "query": REFRESH_MUTATION,
        "variables": {
            "refreshToken": session.refresh_token
        }
    });

    // CRITICAL: Token refresh must have timeout to prevent blocking requests
    // 5 seconds is generous for auth service response
    let response = http_client
        .post(&state.config.bff.auth_service_url)
        .json(&graphql_request)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| SessionError::RefreshFailed(e.to_string()))?;

    let json: serde_json::Value = response
        .json()
        .await
        .map_err(|e| SessionError::RefreshFailed(e.to_string()))?;

    // Check for errors
    if let Some(errors) = json.get("errors") {
        if let Some(first_error) = errors.as_array().and_then(|a| a.first()) {
            let message = first_error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or(ERR_UNKNOWN);
            return Err(SessionError::RefreshFailed(message.to_string()));
        }
    }

    // Extract refresh result
    let data = json
        .get("data")
        .and_then(|d| d.get("refreshToken"))
        .ok_or_else(|| SessionError::RefreshFailed(ERR_NO_REFRESH_DATA.to_string()))?;

    let access_token = data
        .get("accessToken")
        .and_then(|t| t.as_str())
        .ok_or_else(|| SessionError::RefreshFailed(ERR_NO_ACCESS_TOKEN.to_string()))?
        .to_string();

    let refresh_token = data
        .get("refreshToken")
        .and_then(|t| t.as_str())
        .ok_or_else(|| SessionError::RefreshFailed(ERR_NO_REFRESH_TOKEN.to_string()))?
        .to_string();

    let expires_in = data
        .get("expiresIn")
        .and_then(|e| e.as_i64())
        .ok_or_else(|| SessionError::RefreshFailed(ERR_NO_EXPIRES_IN.to_string()))?;

    Ok((access_token, refresh_token, expires_in))
}

/// Extract session ID from cookie jar
///
/// # Performance
/// Inlined to avoid function call overhead on hot path
#[inline]
fn extract_session_id(jar: &CookieJar, cookie_name: &str) -> Option<Uuid> {
    jar.get(cookie_name)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
}
