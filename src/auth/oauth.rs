//! BFF OAuth Module
//!
//! Implements the IETF-recommended BFF OAuth pattern where the BFF acts as a
//! confidential OAuth client, handling the entire OAuth flow server-side.
//!
//! # BFF OAuth Flow (Full Server-Side)
//! ```text
//! 1. Browser → BFF: GET /api/auth/google (initiate OAuth)
//! 2. BFF → Browser: 302 Redirect to Google OAuth with state cookie
//! 3. Browser → Google: User authenticates
//! 4. Google → Browser: 302 Redirect to BFF callback with code
//! 5. Browser → BFF: GET /api/auth/google/callback?code=...&state=...
//! 6. BFF → Google: POST /token (exchange code for tokens using client_secret)
//! 7. BFF → Google: GET /userinfo (get user profile)
//! 8. BFF → Auth Service: Call loginWithOAuthProvider GraphQL mutation
//! 9. Auth Service → BFF: Return user + session tokens
//! 10. BFF → Redis: Store session (tokens server-side)
//! 11. BFF → Browser: Set session cookie, redirect to frontend
//! ```
//!
//! # Security Benefits
//! - client_secret never leaves BFF (confidential client)
//! - Tokens never reach browser (stored in Redis)
//! - State parameter prevents CSRF attacks
//! - PKCE prevents authorization code interception
//!
//! # Why BFF Handles OAuth (Not Auth Service)
//! - BFF is edge service with external network access
//! - Auth Service is internal-only (no external API calls)
//! - Follows IETF BFF pattern for browser-based apps

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::session::{Session, SessionStore};
use crate::config::BffOAuthConfig;
use crate::state::AppState;

/// OAuth state stored in cookie (for CSRF protection and flow tracking)
#[derive(Debug, Serialize, Deserialize)]
struct OAuthState {
    /// Random nonce for CSRF protection
    nonce: String,
    /// Flow mode: "login", "signup", or "link"
    mode: String,
    /// PKCE code verifier (stored to verify callback)
    code_verifier: String,
    /// Return URL after OAuth completes (for link mode)
    #[serde(default)]
    return_url: Option<String>,
}

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    /// Authorization code from OAuth provider
    code: Option<String>,
    /// State parameter for CSRF protection
    state: Option<String>,
    /// Error code (if OAuth failed)
    error: Option<String>,
    /// Error description
    error_description: Option<String>,
}

/// Query parameters for initiating OAuth
#[derive(Debug, Deserialize)]
pub struct OAuthInitQuery {
    /// Flow mode: "login", "signup", or "link" (default: "login")
    #[serde(default = "default_oauth_mode")]
    mode: String,
    /// Return URL after OAuth completes (for link mode, returns here on success/error)
    #[serde(default)]
    return_url: Option<String>,
}

fn default_oauth_mode() -> String {
    "login".to_string()
}

/// Google token response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    #[allow(dead_code)]
    expires_in: i64,
    #[allow(dead_code)]
    scope: Option<String>,
    id_token: Option<String>,
}

/// Google user info response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    /// Google user ID (sub claim)
    #[serde(alias = "sub")]
    id: String,
    email: String,
    #[serde(default)]
    email_verified: bool,
    name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

/// Auth Service GraphQL response for loginWithOAuthProvider
#[derive(Debug, Deserialize)]
struct AuthServiceLoginResponse {
    data: Option<AuthServiceLoginData>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct AuthServiceLoginData {
    #[serde(rename = "loginWithOauthProvider")]
    login_with_oauth_provider: Option<LoginResult>,
}

#[derive(Debug, Deserialize)]
struct LoginResult {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "refreshToken")]
    refresh_token: String,
    #[serde(rename = "expiresIn")]
    expires_in: i64,
    user: UserInfo,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct UserInfo {
    id: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

/// Result type for auth service login that can indicate linking is required
enum AuthLoginResult {
    /// Login succeeded
    Success(LoginResult),
    /// Account exists but requires linking - contains email and provider
    RequiresLinking { email: String, provider: String },
    /// Account was soft-deleted and can be restored
    CanRestore { email: String, provider: String },
}

/// OAuth info to store in Redis for account linking flow
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingOAuthLink {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: i64,
}

/// OAuth info to store in Redis for account restoration flow
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingOAuthRestore {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: i64,
}

// ============================================================================
// OAuth Handlers
// ============================================================================

/// Initiate Google OAuth flow
///
/// GET /api/auth/google?mode=login|signup
///
/// Redirects the browser to Google's OAuth consent page.
/// Stores CSRF state and PKCE verifier in a secure cookie.
pub async fn google_oauth_init(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<OAuthInitQuery>,
) -> impl IntoResponse {
    let oauth_config = &state.config.bff.oauth;

    // Check if OAuth is enabled and Google is configured
    if !oauth_config.enabled {
        warn!("OAuth not enabled in BFF configuration");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            jar,
            "OAuth is not enabled".to_string(),
        )
            .into_response();
    }

    let google_config = match &oauth_config.google {
        Some(config) => config,
        None => {
            error!("Google OAuth not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                jar,
                "Google OAuth is not configured".to_string(),
            )
                .into_response();
        }
    };

    // Validate and sanitize return_url (only allow relative paths to prevent open redirect)
    let return_url = query.return_url.as_ref().and_then(|url| {
        if url.starts_with('/') && !url.starts_with("//") {
            Some(url.clone())
        } else {
            warn!(
                "Invalid return_url rejected (must be relative path): {}",
                url
            );
            None
        }
    });

    info!(
        "Initiating Google OAuth flow: mode={}, return_url={:?}",
        query.mode, return_url
    );

    // Generate CSRF nonce
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = BASE64.encode(nonce_bytes);

    // Generate PKCE code verifier (RFC 7636)
    let mut verifier_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut verifier_bytes);
    let code_verifier = BASE64
        .encode(verifier_bytes)
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");

    // Calculate PKCE code challenge (S256)
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let code_challenge = BASE64
        .encode(hasher.finalize())
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', "");

    // Create OAuth state with return_url for link mode
    let oauth_state = OAuthState {
        nonce: nonce.clone(),
        mode: query.mode.clone(),
        code_verifier,
        return_url,
    };

    // Serialize and encode state for URL
    let state_json = serde_json::to_string(&oauth_state).unwrap_or_default();
    let state_b64 = BASE64.encode(state_json.as_bytes());

    // Store state in secure cookie
    let state_cookie = Cookie::build((oauth_config.state_cookie_name.clone(), state_b64.clone()))
        .http_only(true)
        .secure(state.config.bff.session.cookie_secure)
        .same_site(SameSite::Lax) // Lax allows redirect from Google
        .path("/")
        .max_age(time::Duration::seconds(
            oauth_config.state_max_age_secs as i64,
        ))
        .build();

    let jar = jar.add(state_cookie);

    // Build Google OAuth URL
    let scopes = google_config.scopes.join(" ");
    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
        client_id={}&\
        redirect_uri={}&\
        response_type=code&\
        scope={}&\
        state={}&\
        code_challenge={}&\
        code_challenge_method=S256&\
        access_type=offline&\
        prompt=consent",
        urlencoding::encode(&google_config.client_id),
        urlencoding::encode(&google_config.redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&state_b64),
        urlencoding::encode(&code_challenge),
    );

    info!(
        "Redirecting to Google OAuth: redirect_uri={}",
        google_config.redirect_uri
    );
    debug!("Google OAuth URL: {}", auth_url);

    (jar, Redirect::temporary(&auth_url)).into_response()
}

/// Handle Google OAuth callback
///
/// GET /api/auth/google/callback?code=...&state=...
///
/// 1. Validates CSRF state from cookie
/// 2. Exchanges code for tokens with Google
/// 3. Gets user info from Google
/// 4. Calls Auth Service to create/login user
/// 5. Creates BFF session in Redis
/// 6. Redirects to frontend with session cookie
pub async fn google_oauth_callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    let oauth_config = &state.config.bff.oauth;

    // Check for OAuth error from provider
    if let Some(error) = &query.error {
        error!(
            "Google OAuth error: {} - {}",
            error,
            query.error_description.as_deref().unwrap_or("")
        );
        let redirect_url = format!(
            "{}{}?error={}&description={}",
            oauth_config.frontend_url,
            oauth_config.error_redirect_path,
            urlencoding::encode(error),
            urlencoding::encode(query.error_description.as_deref().unwrap_or("")),
        );
        return (jar, Redirect::temporary(&redirect_url)).into_response();
    }

    // Validate required parameters
    let code = match &query.code {
        Some(c) => c,
        None => {
            error!("Google OAuth callback missing code");
            return redirect_error(
                oauth_config,
                jar,
                "missing_code",
                "Authorization code not provided",
            );
        }
    };

    let state_param = match &query.state {
        Some(s) => s,
        None => {
            error!("Google OAuth callback missing state");
            return redirect_error(
                oauth_config,
                jar,
                "missing_state",
                "State parameter not provided",
            );
        }
    };

    // Validate state from cookie
    let state_cookie = match jar.get(&oauth_config.state_cookie_name) {
        Some(c) => c.value().to_string(),
        None => {
            error!("Google OAuth callback: state cookie not found");
            return redirect_error(
                oauth_config,
                jar,
                "invalid_state",
                "State cookie not found (CSRF protection)",
            );
        }
    };

    if state_cookie != *state_param {
        error!("Google OAuth callback: state mismatch (CSRF attack?)");
        return redirect_error(
            oauth_config,
            jar,
            "invalid_state",
            "State mismatch (possible CSRF attack)",
        );
    }

    // Decode and parse state
    let oauth_state: OAuthState = match BASE64
        .decode(state_param)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|json| serde_json::from_str(&json).ok())
    {
        Some(s) => s,
        None => {
            error!("Google OAuth callback: failed to decode state");
            return redirect_error(oauth_config, jar, "invalid_state", "Failed to decode state");
        }
    };

    info!("Google OAuth callback: mode={}", oauth_state.mode);

    // Clear state cookie
    let clear_state_cookie = Cookie::build((oauth_config.state_cookie_name.clone(), ""))
        .http_only(true)
        .path("/")
        .max_age(time::Duration::ZERO)
        .build();
    let jar = jar.add(clear_state_cookie);

    // Get Google config
    let google_config = match &oauth_config.google {
        Some(config) => config,
        None => {
            error!("Google OAuth not configured");
            return redirect_error(
                oauth_config,
                jar,
                "config_error",
                "Google OAuth not configured",
            );
        }
    };

    // Exchange code for tokens with Google
    let http_client = match state.http_client() {
        Some(c) => c,
        None => {
            error!("HTTP client not initialized");
            return redirect_error(
                oauth_config,
                jar,
                "internal_error",
                "HTTP client not initialized",
            );
        }
    };

    let token_response = match exchange_google_code(
        http_client,
        &google_config.client_id,
        &google_config.client_secret,
        code,
        &google_config.redirect_uri,
        &oauth_state.code_verifier,
    )
    .await
    {
        Ok(tokens) => tokens,
        Err(e) => {
            error!("Failed to exchange Google code: {}", e);
            return redirect_error(oauth_config, jar, "token_exchange_failed", &e);
        }
    };

    info!("Google token exchange successful");

    // Get user info from Google
    let user_info = match get_google_user_info(http_client, &token_response.access_token).await {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to get Google user info: {}", e);
            return redirect_error(oauth_config, jar, "userinfo_failed", &e);
        }
    };

    info!("Google user info retrieved: email={}", user_info.email);

    // Check for link mode with existing session
    // If user is already authenticated and mode is "link", we should call linkGoogleAccount
    // instead of loginWithOauthProvider
    let session_config = &state.config.bff.session;
    let existing_session = jar
        .get(&session_config.cookie_name)
        .and_then(|cookie| Uuid::parse_str(cookie.value()).ok());

    if let Some(session_id) = existing_session.filter(|_| oauth_state.mode == "link") {
        info!("Link mode with existing session: session_id={}", session_id);

        // Get existing session from Redis to get auth token
        let redis_pool = match state.session_redis() {
            Some(pool) => pool.clone(),
            None => {
                error!("Redis pool not configured");
                return redirect_error_with_return(
                    oauth_config,
                    jar,
                    "internal_error",
                    "Session storage not available",
                    oauth_state.return_url.as_deref(),
                );
            }
        };

        let redis = match redis_pool.get().await {
            Some(conn) => conn,
            None => {
                error!("Failed to get Redis connection");
                return redirect_error_with_return(
                    oauth_config,
                    jar,
                    "internal_error",
                    "Session storage unavailable",
                    oauth_state.return_url.as_deref(),
                );
            }
        };

        let mut store = SessionStore::new(redis.clone(), session_config.clone());
        let session = match store.get(&session_id).await {
            Ok(s) => Some(s),
            Err(e) => {
                warn!(
                    "Session not found or error for link mode: {}, falling back to login flow",
                    e
                );
                // Fall through to normal login flow
                None
            }
        };

        if let Some(session) = session {
            // Call linkGoogleAccount mutation with existing auth token
            match call_link_google_account(
                http_client,
                &state.config.bff.hive_router_url,
                &user_info,
                &session.access_token,
            )
            .await
            {
                Ok(_user) => {
                    info!("Google account linked successfully for user");

                    // Redirect to return_url with success indicator
                    let return_path = oauth_state
                        .return_url
                        .as_deref()
                        .unwrap_or("/conta/contas-vinculadas");
                    let redirect_url = if return_path.contains('?') {
                        format!(
                            "{}{}&link_success=true",
                            oauth_config.frontend_url, return_path
                        )
                    } else {
                        format!(
                            "{}{}?link_success=true",
                            oauth_config.frontend_url, return_path
                        )
                    };

                    info!("Link successful, redirecting to: {}", redirect_url);
                    return (jar, Redirect::temporary(&redirect_url)).into_response();
                }
                Err(e) => {
                    error!("Failed to link Google account: {}", e);
                    return redirect_error_with_return(
                        oauth_config,
                        jar,
                        "link_failed",
                        &e,
                        oauth_state.return_url.as_deref(),
                    );
                }
            }
        }
    }

    // Call Auth Service to create/login user (normal flow)
    let auth_result = match call_auth_service_login(
        http_client,
        &state.config.bff.hive_router_url,
        "google",
        &user_info,
        &oauth_state.mode,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Auth service login failed: {}", e);
            return redirect_error(oauth_config, jar, "auth_failed", &e);
        }
    };

    // Handle account linking or restoration requirement
    let login_result = match auth_result {
        AuthLoginResult::RequiresLinking { email, provider } => {
            info!(
                "Account linking required: email={}, provider={}",
                email, provider
            );

            // Store OAuth info in Redis for later linking
            let pending_link = PendingOAuthLink {
                provider: provider.clone(),
                provider_user_id: user_info.id.clone(),
                email: email.clone(),
                name: user_info.name.clone(),
                avatar_url: user_info.picture.clone(),
                created_at: chrono::Utc::now().timestamp(),
            };

            // Generate a unique link token
            let link_token = Uuid::new_v4().to_string();

            // Get Redis connection
            let redis_pool = match state.session_redis() {
                Some(pool) => pool.clone(),
                None => {
                    error!("Redis pool not configured for pending link storage");
                    return redirect_error(
                        oauth_config,
                        jar,
                        "internal_error",
                        "Link storage not available",
                    );
                }
            };

            let redis = match redis_pool.get().await {
                Some(conn) => conn,
                None => {
                    error!("Failed to get Redis connection for pending link storage");
                    return redirect_error(
                        oauth_config,
                        jar,
                        "internal_error",
                        "Link storage unavailable",
                    );
                }
            };

            // Store pending link with 10 minute TTL
            // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
            let link_key = format!("oauth_link:{}", link_token);
            let link_data = serde_json::to_string(&pending_link).unwrap_or_default();
            let _: Result<(), _> = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                redis::cmd("SET")
                    .arg(&link_key)
                    .arg(&link_data)
                    .arg("EX")
                    .arg(600) // 10 minutes TTL
                    .query_async(&mut redis.clone()),
            )
            .await
            .unwrap_or(Ok(()));

            info!("Stored pending OAuth link: token={}", link_token);

            // Redirect to login page with linking params
            // Note: Use /login directly, NOT error_redirect_path which has ?error=oauth_failed
            // This is not an error - it's a prompt for the user to enter their password
            let mut redirect_url = format!(
                "{}/login?error=account_exists_requires_linking&email={}&provider={}&link_token={}",
                oauth_config.frontend_url,
                urlencoding::encode(&email),
                urlencoding::encode(&provider),
                urlencoding::encode(&link_token),
            );

            // Add return_url to redirect so frontend can redirect back after successful link
            if let Some(ref return_url) = oauth_state.return_url {
                redirect_url.push_str(&format!("&return_url={}", urlencoding::encode(return_url)));
            }

            return (jar, Redirect::temporary(&redirect_url)).into_response();
        }
        AuthLoginResult::CanRestore { email, provider } => {
            info!(
                "Account restoration available: email={}, provider={}",
                email, provider
            );

            // Store OAuth info in Redis for account restoration
            let pending_restore = PendingOAuthRestore {
                provider: provider.clone(),
                provider_user_id: user_info.id.clone(),
                email: email.clone(),
                name: user_info.name.clone(),
                avatar_url: user_info.picture.clone(),
                created_at: chrono::Utc::now().timestamp(),
            };

            // Generate a unique restore token
            let restore_token = Uuid::new_v4().to_string();

            // Get Redis connection
            let redis_pool = match state.session_redis() {
                Some(pool) => pool.clone(),
                None => {
                    error!("Redis pool not configured for pending restore storage");
                    return redirect_error(
                        oauth_config,
                        jar,
                        "internal_error",
                        "Restore storage not available",
                    );
                }
            };

            let redis = match redis_pool.get().await {
                Some(conn) => conn,
                None => {
                    error!("Failed to get Redis connection for pending restore storage");
                    return redirect_error(
                        oauth_config,
                        jar,
                        "internal_error",
                        "Restore storage unavailable",
                    );
                }
            };

            // Store pending restore with 10 minute TTL
            // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
            let restore_key = format!("oauth_restore:{}", restore_token);
            let restore_data = serde_json::to_string(&pending_restore).unwrap_or_default();
            let _: Result<(), _> = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                redis::cmd("SET")
                    .arg(&restore_key)
                    .arg(&restore_data)
                    .arg("EX")
                    .arg(600) // 10 minutes TTL
                    .query_async(&mut redis.clone()),
            )
            .await
            .unwrap_or(Ok(()));

            info!("Stored pending OAuth restore: token={}", restore_token);

            // Redirect to login page with restore params
            // Frontend will show "Welcome back! Restore your account?" modal
            let mut redirect_url = format!(
                "{}/login?action=restore_account&email={}&provider={}&restore_token={}",
                oauth_config.frontend_url,
                urlencoding::encode(&email),
                urlencoding::encode(&provider),
                urlencoding::encode(&restore_token),
            );

            // Add return_url to redirect so frontend can redirect back after successful restore
            if let Some(ref return_url) = oauth_state.return_url {
                redirect_url.push_str(&format!("&return_url={}", urlencoding::encode(return_url)));
            }

            return (jar, Redirect::temporary(&redirect_url)).into_response();
        }
        AuthLoginResult::Success(result) => result,
    };

    info!(
        "Auth service login successful: user_id={}",
        login_result.user.id
    );

    // Create BFF session in Redis
    let user_id = match Uuid::parse_str(&login_result.user.id) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid user ID from auth service: {}", e);
            return redirect_error(oauth_config, jar, "internal_error", "Invalid user ID");
        }
    };

    let session = Session::new(
        user_id,
        login_result.access_token,
        login_result.refresh_token,
        chrono::Utc::now() + chrono::Duration::seconds(login_result.expires_in),
        "0.0.0.0".to_string(), // TODO: Extract from request
        "OAuth".to_string(),
    );

    // Get Redis connection lazily (connects on first use, retries with backoff)
    let redis_pool = match state.session_redis() {
        Some(pool) => pool.clone(),
        None => {
            error!("Redis pool not configured for session storage");
            return redirect_error(
                oauth_config,
                jar,
                "internal_error",
                "Session storage not available",
            );
        }
    };

    let redis = match redis_pool.get().await {
        Some(conn) => conn,
        None => {
            error!("Failed to get Redis connection for session storage (after retries)");
            return redirect_error(
                oauth_config,
                jar,
                "internal_error",
                "Session storage unavailable",
            );
        }
    };

    let mut store = SessionStore::new(redis, state.config.bff.session.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session in Redis: {}", e);
        return redirect_error(
            oauth_config,
            jar,
            "session_error",
            "Failed to create session",
        );
    }

    info!("BFF session created: session_id={}", session.id);

    // Build session cookie
    let session_config = &state.config.bff.session;
    let same_site = match session_config.cookie_same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "lax" => SameSite::Lax,
        "none" => SameSite::None,
        _ => SameSite::Strict,
    };

    let mut session_cookie =
        Cookie::build((session_config.cookie_name.clone(), session.id.to_string()))
            .http_only(true)
            .secure(session_config.cookie_secure)
            .same_site(same_site)
            .path(session_config.cookie_path.clone())
            .max_age(time::Duration::seconds(session_config.ttl_secs as i64))
            .build();

    if !session_config.cookie_domain.is_empty() {
        session_cookie.set_domain(session_config.cookie_domain.clone());
    }

    let jar = jar.add(session_cookie);

    // Redirect to frontend success page
    // Use return_url from state if present (for link mode), otherwise use default success path
    let success_path = oauth_state
        .return_url
        .as_deref()
        .unwrap_or(&oauth_config.success_redirect_path);

    // For link mode, append success indicator to return URL
    let redirect_url = if oauth_state.mode == "link" && oauth_state.return_url.is_some() {
        // Add success query param for link mode so frontend can show success message
        let base_url = format!("{}{}", oauth_config.frontend_url, success_path);
        if base_url.contains('?') {
            format!("{}&link_success=true", base_url)
        } else {
            format!("{}?link_success=true", base_url)
        }
    } else {
        format!("{}{}", oauth_config.frontend_url, success_path)
    };

    info!(
        "OAuth flow complete, mode={}, redirecting to: {}",
        oauth_state.mode, redirect_url
    );

    (jar, Redirect::temporary(&redirect_url)).into_response()
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Exchange authorization code for tokens with Google
async fn exchange_google_code(
    client: &reqwest::Client,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<GoogleTokenResponse, String> {
    let params = [
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", code_verifier),
        ("grant_type", "authorization_code"),
    ];

    debug!("Exchanging Google code for tokens");

    let response = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Token request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!(
            "Google token exchange failed: status={}, body={}",
            status, body
        );
        return Err(format!("Google token exchange failed: {}", status));
    }

    serde_json::from_str(&body).map_err(|e| format!("Failed to parse token response: {}", e))
}

/// Get user info from Google using access token
async fn get_google_user_info(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<GoogleUserInfo, String> {
    debug!("Fetching Google user info");

    let response = client
        .get("https://www.googleapis.com/oauth2/v3/userinfo")
        .bearer_auth(access_token)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("User info request failed: {}", e))?;

    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!("Google user info failed: status={}, body={}", status, body);
        return Err(format!("Google user info failed: {}", status));
    }

    serde_json::from_str(&body).map_err(|e| format!("Failed to parse user info: {}", e))
}

/// Call Auth Service loginWithOAuthProvider mutation via Hive Router
async fn call_auth_service_login(
    client: &reqwest::Client,
    hive_router_url: &str,
    provider: &str,
    user_info: &GoogleUserInfo,
    _mode: &str,
) -> Result<AuthLoginResult, String> {
    debug!(
        "Calling Auth Service loginWithOAuthProvider: provider={}",
        provider
    );

    // GraphQL mutation for OAuth login
    let query = r#"
        mutation LoginWithOauthProvider($input: OauthProviderLoginInput!) {
            loginWithOauthProvider(input: $input) {
                accessToken
                refreshToken
                expiresIn
                user {
                    id
                    email
                }
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "provider": provider.to_uppercase(),
            "providerUserId": user_info.id,
            "email": user_info.email,
            "name": user_info.name,
            "avatarUrl": user_info.picture,
            "firstName": user_info.given_name,
            "lastName": user_info.family_name
        }
    });

    let body = serde_json::json!({
        "query": query,
        "variables": variables,
        "operationName": "LoginWithOauthProvider"
    });

    let response = client
        .post(hive_router_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Auth service request failed: {}", e))?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!(
            "Auth service returned error: status={}, body={}",
            status, response_body
        );
        return Err(format!("Auth service error: {}", status));
    }

    let auth_response: AuthServiceLoginResponse = serde_json::from_str(&response_body)
        .map_err(|e| format!("Failed to parse auth response: {}", e))?;

    // Check for GraphQL errors - detect account linking requirement
    if let Some(errors) = auth_response.errors {
        if !errors.is_empty() {
            let error_msg = errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join(", ");

            // Check for ACCOUNT_EXISTS_REQUIRES_LINKING error pattern
            // Full error format: "OAuth error: {provider} - ACCOUNT_EXISTS_REQUIRES_LINKING:{email}"
            // We need to extract the email after "ACCOUNT_EXISTS_REQUIRES_LINKING:"
            if let Some(linking_error) = errors
                .iter()
                .find(|e| e.message.contains("ACCOUNT_EXISTS_REQUIRES_LINKING:"))
            {
                // Parse the email from the error message
                // Split by "ACCOUNT_EXISTS_REQUIRES_LINKING:" and take the second part (the email)
                if let Some(email) = linking_error
                    .message
                    .split("ACCOUNT_EXISTS_REQUIRES_LINKING:")
                    .nth(1)
                {
                    let email = email.trim();
                    info!("Account linking required for email: {}", email);
                    return Ok(AuthLoginResult::RequiresLinking {
                        email: email.to_string(),
                        provider: provider.to_string(),
                    });
                }
            }

            // Check for ACCOUNT_DELETED_CAN_RESTORE error pattern
            // Full error format: "OAuth error: {provider} - ACCOUNT_DELETED_CAN_RESTORE:{email}"
            if let Some(restore_error) = errors
                .iter()
                .find(|e| e.message.contains("ACCOUNT_DELETED_CAN_RESTORE:"))
            {
                if let Some(email) = restore_error
                    .message
                    .split("ACCOUNT_DELETED_CAN_RESTORE:")
                    .nth(1)
                {
                    let email = email.trim();
                    info!("Account restoration available for email: {}", email);
                    return Ok(AuthLoginResult::CanRestore {
                        email: email.to_string(),
                        provider: provider.to_string(),
                    });
                }
            }

            error!("Auth service GraphQL errors: {}", error_msg);
            return Err(error_msg);
        }
    }

    auth_response
        .data
        .and_then(|d| d.login_with_oauth_provider)
        .map(AuthLoginResult::Success)
        .ok_or_else(|| "No login data in auth service response".to_string())
}

// ============================================================================
// Account Linking Endpoint
// ============================================================================

/// Request body for linking OAuth account with password
#[derive(Debug, Deserialize)]
pub struct LinkOAuthAccountRequest {
    /// The link token from the redirect URL
    pub link_token: String,
    /// User's password for verification
    pub password: String,
}

/// Response for account linking
#[derive(Debug, Serialize)]
pub struct LinkOAuthAccountResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// Link OAuth account to existing user account with password verification
///
/// POST /api/auth/link-oauth-account
///
/// This endpoint is called by the frontend when a user enters their password
/// to link their OAuth provider to their existing account.
pub async fn link_oauth_account(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    axum::Json(request): axum::Json<LinkOAuthAccountRequest>,
) -> impl IntoResponse {
    let _oauth_config = &state.config.bff.oauth;

    info!(
        "Link OAuth account request: link_token={}",
        request.link_token
    );

    // Get Redis connection
    let redis_pool = match state.session_redis() {
        Some(pool) => pool.clone(),
        None => {
            error!("Redis pool not configured");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    let mut redis = match redis_pool.get().await {
        Some(conn) => conn,
        None => {
            error!("Failed to get Redis connection");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Get pending link from Redis
    // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
    let link_key = format!("oauth_link:{}", request.link_token);
    let link_data: Option<String> = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        redis::cmd("GET").arg(&link_key).query_async(&mut redis),
    )
    .await
    .unwrap_or(Ok(None))
    .unwrap_or(None);

    let pending_link: PendingOAuthLink = match link_data {
        Some(data) => match serde_json::from_str(&data) {
            Ok(link) => link,
            Err(e) => {
                error!("Failed to parse pending link data: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    jar,
                    axum::Json(LinkOAuthAccountResponse {
                        success: false,
                        message: Some("Invalid link token".to_string()),
                    }),
                )
                    .into_response();
            }
        },
        None => {
            warn!("Link token not found or expired: {}", request.link_token);
            return (
                StatusCode::BAD_REQUEST,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some("Link token expired or invalid".to_string()),
                }),
            )
                .into_response();
        }
    };

    info!(
        "Found pending link: email={}, provider={}",
        pending_link.email, pending_link.provider
    );

    // NOTE: We delete the token AFTER successful linking (not before)
    // This allows users to retry if they enter the wrong password.
    // Security: Token has 10 min TTL and is single-use after success.

    // Call Auth Service to link the account with password verification
    let http_client = match state.http_client() {
        Some(c) => c,
        None => {
            error!("HTTP client not initialized");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    let login_result = match call_link_oauth_with_password(
        http_client,
        &state.config.bff.hive_router_url,
        &pending_link,
        &request.password,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to link OAuth account: {}", e);
            // Check for invalid password error
            let message = if e.contains("Invalid") || e.contains("credentials") {
                "Invalid password"
            } else {
                "Failed to link account"
            };
            return (
                StatusCode::UNAUTHORIZED,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some(message.to_string()),
                }),
            )
                .into_response();
        }
    };

    info!(
        "OAuth account linked successfully: user_id={}",
        login_result.user.id
    );

    // Delete the link token now that linking succeeded (single-use)
    // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
    let _: Result<(), _> = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        redis::cmd("DEL").arg(&link_key).query_async(&mut redis),
    )
    .await
    .unwrap_or(Ok(()));

    // Create BFF session
    let user_id = match Uuid::parse_str(&login_result.user.id) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid user ID from auth service: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(LinkOAuthAccountResponse {
                    success: false,
                    message: Some("Internal error".to_string()),
                }),
            )
                .into_response();
        }
    };

    let session = Session::new(
        user_id,
        login_result.access_token,
        login_result.refresh_token,
        chrono::Utc::now() + chrono::Duration::seconds(login_result.expires_in),
        "0.0.0.0".to_string(),
        "OAuth-Link".to_string(),
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis.clone(), state.config.bff.session.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            jar,
            axum::Json(LinkOAuthAccountResponse {
                success: false,
                message: Some("Session creation failed".to_string()),
            }),
        )
            .into_response();
    }

    info!(
        "BFF session created for linked account: session_id={}",
        session.id
    );

    // Build session cookie
    let session_config = &state.config.bff.session;
    let same_site = match session_config.cookie_same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "lax" => SameSite::Lax,
        "none" => SameSite::None,
        _ => SameSite::Strict,
    };

    let mut session_cookie =
        Cookie::build((session_config.cookie_name.clone(), session.id.to_string()))
            .http_only(true)
            .secure(session_config.cookie_secure)
            .same_site(same_site)
            .path(session_config.cookie_path.clone())
            .max_age(time::Duration::seconds(session_config.ttl_secs as i64))
            .build();

    if !session_config.cookie_domain.is_empty() {
        session_cookie.set_domain(session_config.cookie_domain.clone());
    }

    let jar = jar.add(session_cookie);

    (
        StatusCode::OK,
        jar,
        axum::Json(LinkOAuthAccountResponse {
            success: true,
            message: None,
        }),
    )
        .into_response()
}

// ============================================================================
// Account Restoration Endpoint
// ============================================================================

/// Request body for restoring a soft-deleted account via OAuth
#[derive(Debug, Deserialize)]
pub struct RestoreOAuthAccountRequest {
    /// The restore token from the redirect URL
    pub restore_token: String,
}

/// Response for account restoration
#[derive(Debug, Serialize)]
pub struct RestoreOAuthAccountResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// Restore a soft-deleted account via OAuth
///
/// POST /api/auth/restore-oauth-account
///
/// This endpoint is called by the frontend when a user confirms they want to
/// restore their previously deleted account via OAuth.
pub async fn restore_oauth_account(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    axum::Json(request): axum::Json<RestoreOAuthAccountRequest>,
) -> impl IntoResponse {
    info!(
        "Restore OAuth account request: restore_token={}",
        request.restore_token
    );

    // Get Redis connection
    let redis_pool = match state.session_redis() {
        Some(pool) => pool.clone(),
        None => {
            error!("Redis pool not configured");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    let mut redis = match redis_pool.get().await {
        Some(conn) => conn,
        None => {
            error!("Failed to get Redis connection");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    // Get pending restore from Redis
    // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
    let restore_key = format!("oauth_restore:{}", request.restore_token);
    let restore_data: Option<String> = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        redis::cmd("GET").arg(&restore_key).query_async(&mut redis),
    )
    .await
    .unwrap_or(Ok(None))
    .unwrap_or(None);

    let pending_restore: PendingOAuthRestore = match restore_data {
        Some(data) => match serde_json::from_str(&data) {
            Ok(restore) => restore,
            Err(e) => {
                error!("Failed to parse pending restore data: {}", e);
                return (
                    StatusCode::BAD_REQUEST,
                    jar,
                    axum::Json(RestoreOAuthAccountResponse {
                        success: false,
                        message: Some("Invalid restore token".to_string()),
                    }),
                )
                    .into_response();
            }
        },
        None => {
            warn!(
                "Restore token not found or expired: {}",
                request.restore_token
            );
            return (
                StatusCode::BAD_REQUEST,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Restore token expired or invalid".to_string()),
                }),
            )
                .into_response();
        }
    };

    info!(
        "Found pending restore: email={}, provider={}",
        pending_restore.email, pending_restore.provider
    );

    // Call Auth Service to restore the account
    let http_client = match state.http_client() {
        Some(c) => c,
        None => {
            error!("HTTP client not initialized");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Service unavailable".to_string()),
                }),
            )
                .into_response();
        }
    };

    let login_result = match call_restore_account_with_oauth(
        http_client,
        &state.config.bff.hive_router_url,
        &pending_restore,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            error!("Failed to restore account: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Failed to restore account".to_string()),
                }),
            )
                .into_response();
        }
    };

    info!(
        "Account restored successfully: user_id={}",
        login_result.user.id
    );

    // Delete the restore token now that restoration succeeded (single-use)
    // CRITICAL: Use timeout to prevent blocking on slow Redis (non-blocking-architecture)
    let _: Result<(), _> = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        redis::cmd("DEL").arg(&restore_key).query_async(&mut redis),
    )
    .await
    .unwrap_or(Ok(()));

    // Create BFF session
    let user_id = match Uuid::parse_str(&login_result.user.id) {
        Ok(id) => id,
        Err(e) => {
            error!("Invalid user ID from auth service: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                jar,
                axum::Json(RestoreOAuthAccountResponse {
                    success: false,
                    message: Some("Internal error".to_string()),
                }),
            )
                .into_response();
        }
    };

    let session = Session::new(
        user_id,
        login_result.access_token,
        login_result.refresh_token,
        chrono::Utc::now() + chrono::Duration::seconds(login_result.expires_in),
        "0.0.0.0".to_string(),
        "OAuth-Restore".to_string(),
    );

    // Store session in Redis
    let mut store = SessionStore::new(redis.clone(), state.config.bff.session.clone());
    if let Err(e) = store.create(&session).await {
        error!("Failed to create session in Redis: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            jar,
            axum::Json(RestoreOAuthAccountResponse {
                success: false,
                message: Some("Session creation failed".to_string()),
            }),
        )
            .into_response();
    }

    info!(
        "BFF session created for restored account: session_id={}",
        session.id
    );

    // Build session cookie
    let session_config = &state.config.bff.session;
    let same_site = match session_config.cookie_same_site.to_lowercase().as_str() {
        "strict" => SameSite::Strict,
        "lax" => SameSite::Lax,
        "none" => SameSite::None,
        _ => SameSite::Strict,
    };

    let mut session_cookie =
        Cookie::build((session_config.cookie_name.clone(), session.id.to_string()))
            .http_only(true)
            .secure(session_config.cookie_secure)
            .same_site(same_site)
            .path(session_config.cookie_path.clone())
            .max_age(time::Duration::seconds(session_config.ttl_secs as i64))
            .build();

    if !session_config.cookie_domain.is_empty() {
        session_cookie.set_domain(session_config.cookie_domain.clone());
    }

    let jar = jar.add(session_cookie);

    (
        StatusCode::OK,
        jar,
        axum::Json(RestoreOAuthAccountResponse {
            success: true,
            message: Some("Account restored successfully".to_string()),
        }),
    )
        .into_response()
}

/// Call Auth Service restoreAccountWithOAuth mutation
async fn call_restore_account_with_oauth(
    client: &reqwest::Client,
    hive_router_url: &str,
    pending_restore: &PendingOAuthRestore,
) -> Result<LoginResult, String> {
    debug!(
        "Calling Auth Service restoreAccountWithOAuth: email={}",
        pending_restore.email
    );

    let query = r#"
        mutation RestoreAccountWithOAuth($input: RestoreAccountWithOAuthInput!) {
            restoreAccountWithOauth(input: $input) {
                accessToken
                refreshToken
                expiresIn
                user {
                    id
                    email
                }
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "email": pending_restore.email,
            "provider": pending_restore.provider.to_uppercase(),
            "providerUserId": pending_restore.provider_user_id,
            "name": pending_restore.name,
            "avatarUrl": pending_restore.avatar_url
        }
    });

    let body = serde_json::json!({
        "query": query,
        "variables": variables,
        "operationName": "RestoreAccountWithOAuth"
    });

    let response = client
        .post(hive_router_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Auth service request failed: {}", e))?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!(
            "Auth service returned error: status={}, body={}",
            status, response_body
        );
        return Err(format!("Auth service error: {}", status));
    }

    // Parse response
    #[derive(Debug, Deserialize)]
    struct RestoreResponse {
        data: Option<RestoreData>,
        errors: Option<Vec<GraphQLError>>,
    }

    #[derive(Debug, Deserialize)]
    struct RestoreData {
        #[serde(rename = "restoreAccountWithOauth")]
        restore_account_with_oauth: Option<LoginResult>,
    }

    let restore_response: RestoreResponse = serde_json::from_str(&response_body)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(errors) = restore_response.errors {
        if !errors.is_empty() {
            let error_msg = errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            error!("Auth service GraphQL errors: {}", error_msg);
            return Err(error_msg);
        }
    }

    restore_response
        .data
        .and_then(|d| d.restore_account_with_oauth)
        .ok_or_else(|| "No restore data in auth service response".to_string())
}

/// Call Auth Service linkOauthProviderWithPassword mutation
async fn call_link_oauth_with_password(
    client: &reqwest::Client,
    hive_router_url: &str,
    pending_link: &PendingOAuthLink,
    password: &str,
) -> Result<LoginResult, String> {
    debug!(
        "Calling Auth Service linkOauthProviderWithPassword: email={}",
        pending_link.email
    );

    let query = r#"
        mutation LinkOauthProviderWithPassword($input: LinkOauthProviderWithPasswordInput!) {
            linkOauthProviderWithPassword(input: $input) {
                accessToken
                refreshToken
                expiresIn
                user {
                    id
                    email
                }
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "email": pending_link.email,
            "password": password,
            "provider": pending_link.provider.to_uppercase(),
            "providerUserId": pending_link.provider_user_id,
            "name": pending_link.name,
            "avatarUrl": pending_link.avatar_url
        }
    });

    let body = serde_json::json!({
        "query": query,
        "variables": variables,
        "operationName": "LinkOauthProviderWithPassword"
    });

    let response = client
        .post(hive_router_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Auth service request failed: {}", e))?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!(
            "Auth service returned error: status={}, body={}",
            status, response_body
        );
        return Err(format!("Auth service error: {}", status));
    }

    // Parse response - reuse the same response types
    #[derive(Debug, Deserialize)]
    struct LinkResponse {
        data: Option<LinkData>,
        errors: Option<Vec<GraphQLError>>,
    }

    #[derive(Debug, Deserialize)]
    struct LinkData {
        #[serde(rename = "linkOauthProviderWithPassword")]
        link_oauth_provider_with_password: Option<LoginResult>,
    }

    let link_response: LinkResponse = serde_json::from_str(&response_body)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(errors) = link_response.errors {
        if !errors.is_empty() {
            let error_msg = errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            error!("Auth service GraphQL errors: {}", error_msg);
            return Err(error_msg);
        }
    }

    link_response
        .data
        .and_then(|d| d.link_oauth_provider_with_password)
        .ok_or_else(|| "No link data in auth service response".to_string())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to redirect to error page
fn redirect_error(
    oauth_config: &BffOAuthConfig,
    jar: CookieJar,
    error_code: &str,
    description: &str,
) -> axum::response::Response {
    let redirect_url = format!(
        "{}{}?error={}&description={}",
        oauth_config.frontend_url,
        oauth_config.error_redirect_path,
        urlencoding::encode(error_code),
        urlencoding::encode(description),
    );
    (jar, Redirect::temporary(&redirect_url)).into_response()
}

/// Helper to redirect to error page with optional return_url
fn redirect_error_with_return(
    oauth_config: &BffOAuthConfig,
    jar: CookieJar,
    error_code: &str,
    description: &str,
    return_url: Option<&str>,
) -> axum::response::Response {
    // Use return_url if present, otherwise use default error path
    let error_path = return_url.unwrap_or(&oauth_config.error_redirect_path);
    let separator = if error_path.contains('?') { "&" } else { "?" };

    let redirect_url = format!(
        "{}{}{}error={}&description={}",
        oauth_config.frontend_url,
        error_path,
        separator,
        urlencoding::encode(error_code),
        urlencoding::encode(description),
    );
    (jar, Redirect::temporary(&redirect_url)).into_response()
}

/// Call Auth Service linkOauthProvider mutation for authenticated users
/// This is used when user is already logged in and wants to link their Google account
async fn call_link_google_account(
    client: &reqwest::Client,
    hive_router_url: &str,
    user_info: &GoogleUserInfo,
    access_token: &str,
) -> Result<UserInfo, String> {
    debug!("Calling Auth Service linkOauthProvider for authenticated user");

    // GraphQL mutation to link OAuth provider to existing authenticated user
    // Uses linkOauthProvider which accepts pre-validated OAuth info from BFF
    let query = r#"
        mutation LinkOauthProvider($input: OauthProviderLoginInput!) {
            linkOauthProvider(input: $input) {
                id
                email
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "provider": "GOOGLE",
            "providerUserId": user_info.id,
            "email": user_info.email,
            "name": user_info.name,
            "avatarUrl": user_info.picture,
            "firstName": user_info.given_name,
            "lastName": user_info.family_name
        }
    });

    let body = serde_json::json!({
        "query": query,
        "variables": variables,
        "operationName": "LinkOauthProvider"
    });

    let response = client
        .post(hive_router_url)
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Auth service request failed: {}", e))?;

    let status = response.status();
    let response_body = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;

    if !status.is_success() {
        error!(
            "Auth service returned error: status={}, body={}",
            status, response_body
        );
        return Err(format!("Auth service error: {}", status));
    }

    // Parse response
    #[derive(Debug, Deserialize)]
    struct LinkOauthResponse {
        data: Option<LinkOauthData>,
        errors: Option<Vec<GraphQLError>>,
    }

    #[derive(Debug, Deserialize)]
    struct LinkOauthData {
        #[serde(rename = "linkOauthProvider")]
        link_oauth_provider: Option<UserInfo>,
    }

    let link_response: LinkOauthResponse = serde_json::from_str(&response_body)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(errors) = link_response.errors {
        if !errors.is_empty() {
            let error_msg = errors
                .iter()
                .map(|e| e.message.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            error!("Auth service GraphQL errors: {}", error_msg);
            return Err(error_msg);
        }
    }

    link_response
        .data
        .and_then(|d| d.link_oauth_provider)
        .ok_or_else(|| "No user data in auth service response".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oauth_state_serialization() {
        let state = OAuthState {
            nonce: "test_nonce".to_string(),
            mode: "login".to_string(),
            code_verifier: "test_verifier".to_string(),
            return_url: None,
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: OAuthState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.nonce, state.nonce);
        assert_eq!(parsed.mode, state.mode);
        assert_eq!(parsed.code_verifier, state.code_verifier);
        assert_eq!(parsed.return_url, state.return_url);
    }

    #[test]
    fn test_oauth_state_with_return_url() {
        let state = OAuthState {
            nonce: "test_nonce".to_string(),
            mode: "link".to_string(),
            code_verifier: "test_verifier".to_string(),
            return_url: Some("/conta/contas-vinculadas".to_string()),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: OAuthState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.mode, "link");
        assert_eq!(
            parsed.return_url,
            Some("/conta/contas-vinculadas".to_string())
        );
    }
}
