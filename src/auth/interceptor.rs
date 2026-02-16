//! GraphQL Response Interceptor for Authentication
//!
//! Intercepts login/logout GraphQL mutation responses to manage sessions:
//! - On login success: Extract tokens, create Redis session, return cookie to set
//! - On login MFA required: Pass through MFA challenge to frontend (no session yet)
//! - On verifyMfaLogin success: Extract tokens, create Redis session, return cookie
//! - On logout: Delete Redis session, return cookie to clear
//!
//! This implements Option A (GraphQL Response Interception) for the BFF pattern,
//! which aligns with the GraphQL-first architecture.

use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{Duration, Utc};
use redis::aio::ConnectionManager;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::compiled::CompiledAuthInterception;
use super::redis_pool::LazyRedisPool;
use super::session::{Session, SessionStore, UserContext};
use crate::config::BffSessionConfig;

/// Result of intercepting an auth-related GraphQL response
#[derive(Debug)]
pub enum AuthInterceptResult {
    /// Login successful - session created, cookie to set
    LoginSuccess {
        session_cookie: Cookie<'static>,
        modified_response: Value,
    },
    /// Logout successful - session deleted, cookie to clear
    LogoutSuccess { clear_cookie: Cookie<'static> },
    /// Not an auth mutation or auth failed - pass through unchanged
    PassThrough,
}

/// Client request metadata for session creation
#[derive(Debug, Clone)]
pub struct ClientInfo {
    /// Client IP address (from X-Forwarded-For, X-Real-IP, or socket)
    pub ip_address: String,
    /// Client User-Agent header
    pub user_agent: String,
}

impl Default for ClientInfo {
    fn default() -> Self {
        Self {
            ip_address: "0.0.0.0".to_string(),
            user_agent: "Unknown".to_string(),
        }
    }
}

/// Intercept GraphQL response for auth mutations
///
/// This function examines the GraphQL response to detect login/logout mutations
/// and handles session management accordingly.
///
/// # Arguments
/// * `request_body` - The original GraphQL request body
/// * `response_body` - The GraphQL response from Hive Router
/// * `redis` - Redis connection manager for session storage
/// * `config` - BFF session configuration
/// * `session_id_from_cookie` - Existing session ID from cookie (for logout)
/// * `client_info` - Client IP and User-Agent for session audit logging
///
/// # Returns
/// * `AuthInterceptResult::LoginSuccess` - Login succeeded, includes cookie to set
/// * `AuthInterceptResult::LogoutSuccess` - Logout succeeded, includes cookie to clear
/// * `AuthInterceptResult::PassThrough` - Not an auth mutation, pass through
pub async fn intercept_auth_response(
    request_body: &Value,
    response_body: Value,
    redis_pool: Option<Arc<LazyRedisPool>>,
    config: &BffSessionConfig,
    session_id_from_cookie: Option<Uuid>,
    client_info: ClientInfo,
    compiled_auth: &CompiledAuthInterception,
) -> (AuthInterceptResult, Value) {
    // If sessions are disabled, pass through
    if !config.enabled {
        return (AuthInterceptResult::PassThrough, response_body);
    }

    // Extract operation name from request
    let operation_name = request_body
        .get("operationName")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Also check the query string for mutation names
    let query = request_body
        .get("query")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Check if Redis pool is configured
    let pool = match redis_pool {
        Some(p) => p,
        None => {
            warn!("Redis pool not configured for auth interception");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Get Redis connection lazily (connects on first use, retries with backoff)
    let redis = match pool.get().await {
        Some(conn) => conn,
        None => {
            warn!("Failed to get Redis connection for auth interception (after retries)");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Detect mutations using pre-compiled config-driven matchers
    let is_login = compiled_auth.login.matches(operation_name, query);
    let is_logout = compiled_auth.logout.matches(operation_name, query);
    let is_verify_mfa_login = compiled_auth.mfa_verify.matches(operation_name, query);
    let is_verify_magic_link = compiled_auth.magic_link.matches(operation_name, query);
    let is_start_profile = compiled_auth.start_profile.matches(operation_name, query);

    if is_login {
        debug!("Detected login mutation response");
        return handle_login_response(response_body, redis, config, &client_info).await;
    }

    if is_verify_mfa_login {
        debug!("Detected verifyMfaLogin mutation response");
        return handle_verify_mfa_login_response(response_body, redis, config, &client_info).await;
    }

    if is_verify_magic_link {
        debug!("Detected verifyMagicLink mutation response (provider onboarding)");
        return handle_verify_magic_link_response(response_body, redis, config, &client_info).await;
    }

    if is_start_profile {
        debug!("Detected startProfile mutation response (provider onboarding)");
        return handle_start_profile_response(response_body, redis, config, &client_info).await;
    }

    if is_logout {
        debug!("Detected logout mutation response");
        return handle_logout_response(response_body, redis, config, session_id_from_cookie).await;
    }

    // Not an auth mutation - pass through
    (AuthInterceptResult::PassThrough, response_body)
}

/// Handle login mutation response
///
/// Extracts tokens from the response, creates a session in Redis,
/// and returns a modified response with tokens stripped.
///
/// Two-Step MFA Flow: If the response indicates MFA is required (mfaRequired: true),
/// the BFF passes through the MFA challenge to the frontend without creating a session.
/// The session is created later when verifyMfaLogin succeeds.
async fn handle_login_response(
    response_body: Value,
    redis: ConnectionManager,
    config: &BffSessionConfig,
    client_info: &ClientInfo,
) -> (AuthInterceptResult, Value) {
    // Check for GraphQL errors first
    if let Some(errors) = response_body.get("errors") {
        if let Some(arr) = errors.as_array() {
            if !arr.is_empty() {
                debug!("Login response has errors - passing through");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        }
    }

    // Extract login data from response
    // Handle various field names:
    // - { data: { login: { ... } } } - standard login
    // - { data: { loginWithGoogle: { ... } } } - Google OAuth
    // - { data: { loginWithFacebook: { ... } } } - Facebook OAuth
    let data = match response_body.get("data") {
        Some(d) => d,
        None => {
            debug!("No data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Try each login field variant
    let login_data = data
        .get("login")
        .or_else(|| data.get("loginWithGoogle"))
        .or_else(|| data.get("loginWithFacebook"))
        .or_else(|| data.get("loginWithOAuthProvider"));

    let login_data = match login_data {
        Some(data) => data,
        None => {
            debug!("No login data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Check for MFA challenge response (two-step auth flow)
    // MFA challenge returns: { mfaRequired: true, mfaChallengeToken: "...", maskedEmail: "..." }
    // No tokens are returned in this case - pass through to frontend
    if let Some(mfa_required) = login_data.get("mfaRequired").and_then(|v| v.as_bool()) {
        if mfa_required {
            info!("Login returned MFA challenge - passing through to frontend (no session created yet)");
            // MFA challenge response should be passed through unchanged
            // Frontend will call verifyMfaLogin with the TOTP code
            return (AuthInterceptResult::PassThrough, response_body);
        }
    }

    // Extract user object from response
    let user_obj = login_data.get("user");

    // Extract user ID (required for all modes)
    let user_id = match user_obj
        .and_then(|u| u.get("id"))
        .and_then(|id| id.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            warn!("No valid user ID in login response");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract user context from login response
    // This is CRITICAL for session-based auth (token-free mode) where the access_token is NOT a JWT
    let user_context = extract_user_context(user_obj);

    debug!(
        user_id = %user_id,
        email = ?user_context.email,
        roles = ?user_context.roles,
        permissions_count = user_context.permissions.len(),
        staff_role = ?user_context.staff_role,
        "Login interceptor: extracted user context from response"
    );

    // Token handling depends on auth mode
    let (access_token, refresh_token, expires_in) = if config.token_free_auth {
        // Token-free auth mode (BFF-only pattern)
        // Backend doesn't return tokens - generate session tokens internally
        debug!("Token-free auth mode: generating session tokens internally");
        let access_token = Uuid::new_v4().to_string();
        let refresh_token = Uuid::new_v4().to_string();
        // Use session TTL from config (converted to seconds)
        let expires_in = config.ttl_secs as i64;
        (access_token, refresh_token, expires_in)
    } else {
        // Legacy token mode - extract tokens from response
        let access_token = match login_data.get("accessToken").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                warn!("No accessToken in login response");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        };

        let refresh_token = match login_data.get("refreshToken").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                warn!("No refreshToken in login response");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        };

        let expires_in = login_data
            .get("expiresIn")
            .and_then(|v| v.as_i64())
            .unwrap_or(900); // Default 15 minutes

        (access_token, refresh_token, expires_in)
    };

    // Calculate token expiry
    let token_expires_at = Utc::now() + Duration::seconds(expires_in);

    // Create session with user context
    let session = Session::with_context(
        user_id,
        access_token,
        refresh_token,
        token_expires_at,
        client_info.ip_address.clone(),
        client_info.user_agent.clone(),
        user_context,
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis, config.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session: {}", e);
        return (AuthInterceptResult::PassThrough, response_body);
    }

    info!(
        "Login intercepted: created session {} for user {}",
        session.id, user_id
    );

    // Build session cookie
    let cookie = build_session_cookie(config, session.id);

    // Modify response to strip tokens (security: tokens stay server-side)
    let modified_response = strip_tokens_from_response(response_body);

    (
        AuthInterceptResult::LoginSuccess {
            session_cookie: cookie,
            modified_response: modified_response.clone(),
        },
        modified_response,
    )
}

/// Handle verifyMfaLogin mutation response
///
/// This is Step 2 of the two-step MFA authentication flow.
/// After the user enters their TOTP code, this function extracts tokens
/// from the response, creates a session in Redis, and returns a cookie.
async fn handle_verify_mfa_login_response(
    response_body: Value,
    redis: ConnectionManager,
    config: &BffSessionConfig,
    client_info: &ClientInfo,
) -> (AuthInterceptResult, Value) {
    // Check for GraphQL errors first
    if let Some(errors) = response_body.get("errors") {
        if let Some(arr) = errors.as_array() {
            if !arr.is_empty() {
                debug!("verifyMfaLogin response has errors - passing through");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        }
    }

    // Extract verifyMfaLogin data from response
    let data = match response_body.get("data") {
        Some(d) => d,
        None => {
            debug!("No data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    let mfa_login_data = match data.get("verifyMfaLogin") {
        Some(data) => data,
        None => {
            debug!("No verifyMfaLogin data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract user object from response
    let user_obj = mfa_login_data.get("user");

    // Extract user ID (required for all modes)
    let user_id = match user_obj
        .and_then(|u| u.get("id"))
        .and_then(|id| id.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            warn!("No valid user ID in verifyMfaLogin response");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract user context from login response
    let user_context = extract_user_context(user_obj);

    debug!(
        user_id = %user_id,
        email = ?user_context.email,
        permissions_count = user_context.permissions.len(),
        staff_role = ?user_context.staff_role,
        "MFA verification interceptor: extracted user context from response"
    );

    // Token handling depends on auth mode
    let (access_token, refresh_token, expires_in) = if config.token_free_auth {
        // Token-free auth mode (BFF-only pattern)
        debug!("Token-free auth mode: generating session tokens internally for MFA verification");
        let access_token = Uuid::new_v4().to_string();
        let refresh_token = Uuid::new_v4().to_string();
        let expires_in = config.ttl_secs as i64;
        (access_token, refresh_token, expires_in)
    } else {
        // Legacy token mode - extract tokens from response
        let access_token = match mfa_login_data.get("accessToken").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                warn!("No accessToken in verifyMfaLogin response");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        };

        let refresh_token = match mfa_login_data.get("refreshToken").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                warn!("No refreshToken in verifyMfaLogin response");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        };

        let expires_in = mfa_login_data
            .get("expiresIn")
            .and_then(|v| v.as_i64())
            .unwrap_or(900); // Default 15 minutes

        (access_token, refresh_token, expires_in)
    };

    // Calculate token expiry
    let token_expires_at = Utc::now() + Duration::seconds(expires_in);

    // Create session with user context
    let session = Session::with_context(
        user_id,
        access_token,
        refresh_token,
        token_expires_at,
        client_info.ip_address.clone(),
        client_info.user_agent.clone(),
        user_context,
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis, config.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session after MFA verification: {}", e);
        return (AuthInterceptResult::PassThrough, response_body);
    }

    info!(
        "MFA verification intercepted: created session {} for user {}",
        session.id, user_id
    );

    // Build session cookie
    let cookie = build_session_cookie(config, session.id);

    // Modify response to strip tokens (security: tokens stay server-side)
    let modified_response = strip_tokens_from_verify_mfa_response(response_body);

    (
        AuthInterceptResult::LoginSuccess {
            session_cookie: cookie,
            modified_response: modified_response.clone(),
        },
        modified_response,
    )
}

/// Handle logout mutation response
///
/// Deletes the session from Redis and returns a cookie to clear.
async fn handle_logout_response(
    response_body: Value,
    redis: ConnectionManager,
    config: &BffSessionConfig,
    session_id: Option<Uuid>,
) -> (AuthInterceptResult, Value) {
    // Delete session if we have one
    if let Some(id) = session_id {
        let mut store = SessionStore::new(redis, config.clone());
        if let Err(e) = store.delete(&id).await {
            warn!("Failed to delete session {}: {}", id, e);
            // Continue anyway - clear the cookie
        } else {
            info!("Logout intercepted: deleted session {}", id);
        }
    } else {
        debug!("Logout without session cookie - clearing anyway");
    }

    // Build clear cookie
    let clear_cookie = build_clear_cookie(config);

    (
        AuthInterceptResult::LogoutSuccess { clear_cookie },
        response_body,
    )
}

/// Handle verifyMagicLink mutation response (provider onboarding)
///
/// This is the entry point for provider authentication after email verification.
/// Creates a BFF session to enable subsequent authenticated mutations during
/// onboarding (setUsername, updateProfile, etc.).
///
/// # Response Structure
///
/// ```json
/// {
///   "data": {
///     "verifyMagicLink": {
///       "isNewProfile": true,
///       "userId": "user-uuid",
///       "profile": {
///         "id": "profile-uuid",
///         "email": "provider@example.com",
///         ...
///       }
///     }
///   }
/// }
/// ```
async fn handle_verify_magic_link_response(
    response_body: Value,
    redis: ConnectionManager,
    config: &BffSessionConfig,
    client_info: &ClientInfo,
) -> (AuthInterceptResult, Value) {
    // Check for GraphQL errors first
    if let Some(errors) = response_body.get("errors") {
        if let Some(arr) = errors.as_array() {
            if !arr.is_empty() {
                debug!("verifyMagicLink response has errors - passing through");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        }
    }

    // Extract verifyMagicLink data from response
    let data = match response_body.get("data") {
        Some(d) => d,
        None => {
            debug!("No data in verifyMagicLink response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    let magic_link_data = match data.get("verifyMagicLink") {
        Some(data) => data,
        None => {
            debug!("No verifyMagicLink data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract userId (required for session creation)
    // This is the user_id from the users table, NOT the profile_id
    let user_id = match magic_link_data
        .get("userId")
        .and_then(|id| id.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            warn!("No valid userId in verifyMagicLink response - cannot create session");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract email from profile for user context
    let email = magic_link_data
        .get("profile")
        .and_then(|p| p.get("email"))
        .and_then(|e| e.as_str())
        .map(String::from);

    // Build minimal user context for providers
    // Providers have the "provider" role, no special permissions during onboarding
    let user_context = UserContext {
        email,
        roles: vec!["provider".to_string()],
        permissions: vec![],
        relationships: vec![],
        staff_role: None,
    };

    debug!(
        user_id = %user_id,
        email = ?user_context.email,
        "verifyMagicLink interceptor: creating session for provider"
    );

    // Generate session tokens (token-free auth mode)
    // Provider auth doesn't use JWTs - session is the only auth mechanism
    let access_token = Uuid::new_v4().to_string();
    let refresh_token = Uuid::new_v4().to_string();
    let token_expires_at = Utc::now() + Duration::seconds(config.ttl_secs as i64);

    // Create session with user context
    let session = Session::with_context(
        user_id,
        access_token,
        refresh_token,
        token_expires_at,
        client_info.ip_address.clone(),
        client_info.user_agent.clone(),
        user_context,
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis, config.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session after magic link verification: {}", e);
        return (AuthInterceptResult::PassThrough, response_body);
    }

    info!(
        session_id = %session.id,
        user_id = %user_id,
        "verifyMagicLink intercepted: created session for provider onboarding"
    );

    // Build session cookie
    let cookie = build_session_cookie(config, session.id);

    // Response is passed through unchanged (no tokens to strip)
    (
        AuthInterceptResult::LoginSuccess {
            session_cookie: cookie,
            modified_response: response_body.clone(),
        },
        response_body,
    )
}

/// Handle startProfile mutation response (provider onboarding)
///
/// When `alreadyVerified: true`, the frontend skips the verifyMagicLink step
/// and proceeds directly to the contact step. This means no session would be
/// created via the normal flow.
///
/// This handler creates a session immediately when alreadyVerified is true,
/// enabling authenticated mutations (setUsername, updateProfile, etc.) during
/// the onboarding flow.
///
/// # Expected Response Structure
///
/// ```json
/// {
///   "data": {
///     "startProfile": {
///       "sent": false,
///       "emailMasked": "u***@example.com",
///       "retryAfterSeconds": null,
///       "profileId": "uuid",
///       "isNewProfile": false,
///       "alreadyVerified": true,
///       "userId": "uuid"
///     }
///   }
/// }
/// ```
async fn handle_start_profile_response(
    response_body: Value,
    redis: ConnectionManager,
    config: &BffSessionConfig,
    client_info: &ClientInfo,
) -> (AuthInterceptResult, Value) {
    // Check for GraphQL errors first
    if let Some(errors) = response_body.get("errors") {
        if let Some(arr) = errors.as_array() {
            if !arr.is_empty() {
                debug!("startProfile response has errors - passing through");
                return (AuthInterceptResult::PassThrough, response_body);
            }
        }
    }

    // Extract startProfile data from response
    let data = match response_body.get("data") {
        Some(d) => d,
        None => {
            debug!("No data in startProfile response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    let start_profile_data = match data.get("startProfile") {
        Some(data) => data,
        None => {
            debug!("No startProfile data in response - passing through");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Check if alreadyVerified is true - only then do we need to create a session
    let already_verified = start_profile_data
        .get("alreadyVerified")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !already_verified {
        // Normal flow: user needs to click magic link, verifyMagicLink will create session
        debug!("startProfile: alreadyVerified=false, passing through (session will be created on verifyMagicLink)");
        return (AuthInterceptResult::PassThrough, response_body);
    }

    // alreadyVerified=true: create session now since verifyMagicLink won't be called
    debug!("startProfile: alreadyVerified=true, creating session immediately");

    // Extract userId (required for session creation)
    let user_id = match start_profile_data
        .get("userId")
        .and_then(|id| id.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            warn!("No valid userId in startProfile response with alreadyVerified=true - cannot create session");
            return (AuthInterceptResult::PassThrough, response_body);
        }
    };

    // Extract email from emailMasked for user context (not ideal but it's what we have)
    let email = start_profile_data
        .get("emailMasked")
        .and_then(|e| e.as_str())
        .map(String::from);

    // Build minimal user context for providers
    let user_context = UserContext {
        email,
        roles: vec!["provider".to_string()],
        permissions: vec![],
        relationships: vec![],
        staff_role: None,
    };

    debug!(
        user_id = %user_id,
        email = ?user_context.email,
        "startProfile interceptor: creating session for provider (alreadyVerified=true)"
    );

    // Generate session tokens (token-free auth mode)
    let access_token = Uuid::new_v4().to_string();
    let refresh_token = Uuid::new_v4().to_string();
    let token_expires_at = Utc::now() + Duration::seconds(config.ttl_secs as i64);

    // Create session with user context
    let session = Session::with_context(
        user_id,
        access_token,
        refresh_token,
        token_expires_at,
        client_info.ip_address.clone(),
        client_info.user_agent.clone(),
        user_context,
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis, config.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session after startProfile (alreadyVerified=true): {}", e);
        return (AuthInterceptResult::PassThrough, response_body);
    }

    info!(
        session_id = %session.id,
        user_id = %user_id,
        "startProfile intercepted: created session for provider (alreadyVerified=true, onboarding continues)"
    );

    // Build session cookie
    let cookie = build_session_cookie(config, session.id);

    // Response is passed through unchanged
    (
        AuthInterceptResult::LoginSuccess {
            session_cookie: cookie,
            modified_response: response_body.clone(),
        },
        response_body,
    )
}

/// Extract user context from the user object in login response
///
/// This extracts email, roles, permissions, and staffRole from the user object.
/// These fields are CRITICAL for session-based auth (token-free mode) where the
/// access_token is NOT a JWT with embedded claims.
///
/// # Expected User Object Structure
///
/// ```json
/// {
///   "id": "uuid",
///   "email": "user@example.com",
///   "roles": ["user", "staff"],
///   "permissions": ["dashboard.read", "ads.moderate"],
///   "staffRole": "admin"
/// }
/// ```
fn extract_user_context(user_obj: Option<&Value>) -> UserContext {
    let Some(user) = user_obj else {
        return UserContext::default();
    };

    // Extract email
    let email = user.get("email").and_then(|v| v.as_str()).map(String::from);

    // Extract roles (array of strings)
    let roles = user
        .get("roles")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Extract permissions (array of strings)
    // These are computed from staffRole on the backend via StaffRole::default_permissions()
    let permissions = user
        .get("permissions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Extract relationships (array of strings like "products:owner:uuid")
    let relationships = user
        .get("relationships")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Extract staffRole (single string like "admin", "moderator", "support", "superadmin")
    let staff_role = user
        .get("staffRole")
        .and_then(|v| v.as_str())
        .map(String::from);

    UserContext {
        email,
        roles,
        permissions,
        relationships,
        staff_role,
    }
}

/// Strip tokens from login response
///
/// Removes accessToken and refreshToken from the response so they never
/// reach the browser. The frontend only needs user info.
fn strip_tokens_from_response(mut response: Value) -> Value {
    if let Some(data) = response.get_mut("data") {
        // Handle all login field variants
        for field_name in [
            "login",
            "loginWithGoogle",
            "loginWithFacebook",
            "loginWithOAuthProvider",
        ] {
            if let Some(login) = data.get_mut(field_name) {
                if let Some(obj) = login.as_object_mut() {
                    obj.remove("accessToken");
                    obj.remove("refreshToken");
                    // Keep user, expiresIn (for frontend session awareness)
                    debug!("Stripped tokens from {} response", field_name);
                    break; // Only one login field should be present
                }
            }
        }
    }
    response
}

/// Strip tokens from verifyMfaLogin response
///
/// Removes accessToken and refreshToken from the MFA verification response
/// so they never reach the browser.
fn strip_tokens_from_verify_mfa_response(mut response: Value) -> Value {
    if let Some(data) = response.get_mut("data") {
        if let Some(verify_mfa) = data.get_mut("verifyMfaLogin") {
            if let Some(obj) = verify_mfa.as_object_mut() {
                obj.remove("accessToken");
                obj.remove("refreshToken");
                // Keep user, expiresIn (for frontend session awareness)
                debug!("Stripped tokens from verifyMfaLogin response");
            }
        }
    }
    response
}

/// Build a session cookie with proper security settings
fn build_session_cookie(config: &BffSessionConfig, session_id: Uuid) -> Cookie<'static> {
    let same_site = match config.cookie_same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "lax" => SameSite::Lax,
        "none" => SameSite::None,
        _ => SameSite::Strict,
    };

    let mut cookie = Cookie::build((config.cookie_name.clone(), session_id.to_string()))
        .http_only(true)
        .secure(config.cookie_secure)
        .same_site(same_site)
        .path(config.cookie_path.clone())
        .max_age(time::Duration::seconds(config.ttl_secs as i64))
        .build();

    if !config.cookie_domain.is_empty() {
        cookie.set_domain(config.cookie_domain.clone());
    }

    cookie
}

/// Build a cookie that clears the session
fn build_clear_cookie(config: &BffSessionConfig) -> Cookie<'static> {
    Cookie::build((config.cookie_name.clone(), ""))
        .http_only(true)
        .secure(config.cookie_secure)
        .path(config.cookie_path.clone())
        .max_age(time::Duration::ZERO)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_tokens_from_response() {
        let response = serde_json::json!({
            "data": {
                "login": {
                    "accessToken": "secret_access",
                    "refreshToken": "secret_refresh",
                    "expiresIn": 900,
                    "user": {
                        "id": "123",
                        "email": "test@example.com"
                    }
                }
            }
        });

        let stripped = strip_tokens_from_response(response);

        // Tokens should be removed
        assert!(stripped["data"]["login"].get("accessToken").is_none());
        assert!(stripped["data"]["login"].get("refreshToken").is_none());

        // User and expiresIn should remain
        assert!(stripped["data"]["login"].get("user").is_some());
        assert!(stripped["data"]["login"].get("expiresIn").is_some());
    }
}
