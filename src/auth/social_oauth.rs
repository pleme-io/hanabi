//! Social Integration OAuth Module
//!
//! Implements OAuth flows for social platform integrations (Instagram, TikTok, etc.)
//! This is DIFFERENT from login OAuth - it's for linking social accounts to provider profiles.
//!
//! # Key Differences from Login OAuth
//! - Requires authenticated session (user must be logged in)
//! - Stores tokens in social_integrations table (not user sessions)
//! - Redirects to marketing settings page (not home page)
//! - Multiple accounts can be linked per user
//! - Fetches business accounts (Instagram Business/Creator via Facebook Pages)
//!
//! # Instagram/Meta Business Suite Flow
//! ```text
//! 1. Provider clicks "Link Instagram" on marketing settings
//! 2. BFF validates session (must be authenticated)
//! 3. BFF redirects to Facebook OAuth (Meta owns Instagram API)
//! 4. User grants permissions for Instagram Business Account
//! 5. Facebook redirects to BFF callback
//! 6. BFF exchanges code for long-lived token (~60 days)
//! 7. BFF fetches Facebook Pages with Instagram Business Accounts
//! 8. BFF encrypts tokens and stores via GraphQL mutation to Auth Service
//! 9. BFF redirects to frontend with success indicator
//! ```
//!
//! # Performance Optimizations
//! - Reusable AES cipher (initialized once per token encryption)
//! - Minimal string allocations in hot paths
//! - Efficient base64 encoding

use std::sync::Arc;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::session::{SessionError, SessionStore};
use crate::config::MetaSocialOAuthConfig;
use crate::state::AppState;

// ============================================================================
// Types
// ============================================================================

/// OAuth state stored in cookie for social integration flow
#[derive(Debug, Serialize, Deserialize)]
struct SocialOAuthState {
    /// Random nonce for CSRF protection
    nonce: String,
    /// User ID from session (must be authenticated)
    user_id: String,
    /// Platform being linked
    platform: String,
}

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct SocialOAuthCallbackQuery {
    /// Authorization code from OAuth provider
    code: Option<String>,
    /// State parameter for CSRF protection
    state: Option<String>,
    /// Error code (if OAuth failed)
    error: Option<String>,
    /// Error description
    error_description: Option<String>,
}

/// Meta/Facebook token response
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct MetaTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Facebook Pages response
#[derive(Debug, Deserialize)]
struct FacebookPagesResponse {
    data: Vec<FacebookPage>,
}

/// Facebook Page with optional Instagram Business Account
#[derive(Debug, Deserialize)]
struct FacebookPage {
    id: String,
    name: String,
    #[serde(default)]
    instagram_business_account: Option<InstagramBusinessAccountRef>,
    #[serde(default)]
    access_token: Option<String>,
}

/// Reference to Instagram Business Account (ID only)
#[derive(Debug, Deserialize)]
struct InstagramBusinessAccountRef {
    id: String,
}

/// Instagram Business Account details
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct InstagramAccountDetails {
    id: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    profile_picture_url: Option<String>,
    #[serde(default)]
    followers_count: Option<i32>,
    #[serde(default)]
    media_count: Option<i32>,
}

/// Account info to store for an integration
#[derive(Debug, Serialize)]
struct SocialAccountInfo {
    platform_account_id: String,
    account_type: String,
    username: Option<String>,
    display_name: Option<String>,
    profile_picture_url: Option<String>,
    facebook_page_id: Option<String>,
    facebook_page_name: Option<String>,
    page_access_token_encrypted: Option<String>,
    followers_count: Option<i32>,
    is_primary: bool,
}

/// GraphQL mutation input for creating social integration
#[derive(Debug, Serialize)]
struct CreateSocialIntegrationInput {
    platform: String,
    access_token_encrypted: String,
    refresh_token_encrypted: Option<String>,
    token_expires_at: Option<String>,
    platform_user_id: Option<String>,
    platform_user_name: Option<String>,
    scopes: Vec<String>,
    accounts: Vec<CreateSocialAccountInput>,
}

#[derive(Debug, Serialize)]
struct CreateSocialAccountInput {
    platform_account_id: String,
    account_type: String,
    username: Option<String>,
    display_name: Option<String>,
    profile_picture_url: Option<String>,
    facebook_page_id: Option<String>,
    facebook_page_name: Option<String>,
    page_access_token_encrypted: Option<String>,
    followers_count: Option<i32>,
    is_primary: bool,
}

/// GraphQL response for createSocialIntegration
#[derive(Debug, Deserialize)]
struct CreateIntegrationResponse {
    data: Option<CreateIntegrationData>,
    errors: Option<Vec<GraphQLError>>,
}

#[derive(Debug, Deserialize)]
struct CreateIntegrationData {
    #[serde(rename = "createSocialIntegration")]
    create_social_integration: Option<SocialIntegrationResult>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SocialIntegrationResult {
    id: String,
    platform: String,
    status: String,
}

#[derive(Debug, Deserialize)]
struct GraphQLError {
    message: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Initiate Instagram OAuth flow for social integration
///
/// GET /api/social/instagram
///
/// Requires authenticated session. Redirects to Facebook OAuth (Meta owns Instagram API).
pub async fn instagram_oauth_init(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> impl IntoResponse {
    let oauth_config = &state.config.bff.oauth;

    // Check if OAuth is enabled and Instagram is configured
    if !oauth_config.enabled {
        warn!("OAuth not enabled in BFF configuration");
        return redirect_with_error(&state.config.bff.oauth.frontend_url, "OAuth is not enabled");
    }

    let instagram_config = match &oauth_config.instagram {
        Some(config) => config,
        None => {
            error!("Instagram OAuth not configured");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Instagram OAuth is not configured",
            );
        }
    };

    // Extract session from cookie to get user_id
    let session_cookie = jar.get(&state.config.bff.session.cookie_name);
    let session_id = match session_cookie {
        Some(cookie) => cookie.value().to_string(),
        None => {
            warn!("No session cookie for Instagram OAuth - user must be logged in");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "You must be logged in to link Instagram",
            );
        }
    };

    // Get Redis pool for session storage
    let redis_pool = match state.session_redis() {
        Some(pool) => pool.clone(),
        None => {
            error!("Redis session pool not configured");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Session storage not configured",
            );
        }
    };

    // Get connection from pool
    let redis = match redis_pool.get().await {
        Some(conn) => conn,
        None => {
            error!("Failed to get Redis connection");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Session storage unavailable",
            );
        }
    };

    // Parse session_id as UUID
    let session_uuid = match Uuid::parse_str(&session_id) {
        Ok(uuid) => uuid,
        Err(_) => {
            warn!("Invalid session ID format for Instagram OAuth");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Invalid session - please log in again",
            );
        }
    };

    // Validate session exists in Redis
    let mut session_store = SessionStore::new(redis, state.config.bff.session.clone());
    let session = match session_store.get(&session_uuid).await {
        Ok(session) => session,
        Err(SessionError::NotFound) => {
            warn!("Session not found in Redis for Instagram OAuth");
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Session expired - please log in again",
            );
        }
        Err(e) => {
            error!("Redis error checking session: {:?}", e);
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Internal error - please try again",
            );
        }
    };

    let user_id = session.user_id.to_string();
    info!(user_id = %user_id, "Initiating Instagram OAuth flow for social integration");

    // Generate CSRF nonce
    let mut nonce_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = BASE64.encode(nonce_bytes);

    // Create state object
    let oauth_state = SocialOAuthState {
        nonce: nonce.clone(),
        user_id,
        platform: "instagram".to_string(),
    };

    // Serialize state and encode
    let state_json = match serde_json::to_string(&oauth_state) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to serialize OAuth state: {:?}", e);
            return redirect_with_error(
                &state.config.bff.oauth.frontend_url,
                "Internal error - please try again",
            );
        }
    };
    let state_encoded = BASE64.encode(state_json.as_bytes());

    // Build Facebook OAuth URL (Meta owns Instagram API)
    let scopes = instagram_config.scopes.join(",");
    let auth_url = format!(
        "https://www.facebook.com/{}/dialog/oauth?client_id={}&redirect_uri={}&scope={}&response_type=code&state={}",
        instagram_config.api_version,
        urlencoding::encode(&instagram_config.app_id),
        urlencoding::encode(&instagram_config.redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&state_encoded),
    );

    debug!("Redirecting to Facebook OAuth: {}", auth_url);

    // Set state cookie for CSRF protection
    let state_cookie = Cookie::build((
        format!("{}_instagram", oauth_config.state_cookie_name),
        state_encoded,
    ))
    .path("/")
    .http_only(true)
    .secure(state.config.bff.session.cookie_secure)
    .same_site(SameSite::Lax) // Lax allows OAuth redirects
    .max_age(time::Duration::seconds(
        oauth_config.state_max_age_secs as i64,
    ))
    .build();

    let jar = jar.add(state_cookie);

    (jar, Redirect::to(&auth_url)).into_response()
}

/// Handle Instagram OAuth callback
///
/// GET /api/social/instagram/callback?code=...&state=...
///
/// Exchanges code for tokens, fetches Instagram Business Accounts,
/// stores encrypted tokens in Auth Service via GraphQL mutation.
pub async fn instagram_oauth_callback(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Query(query): Query<SocialOAuthCallbackQuery>,
) -> impl IntoResponse {
    let oauth_config = &state.config.bff.oauth;
    let frontend_url = &oauth_config.frontend_url;

    // Get Instagram config
    let instagram_config = match &oauth_config.instagram {
        Some(config) => config,
        None => {
            return redirect_with_error(frontend_url, "Instagram OAuth not configured");
        }
    };

    // Check for OAuth errors from provider
    if let Some(error) = &query.error {
        warn!(
            "Instagram OAuth error: {} - {:?}",
            error, query.error_description
        );
        return redirect_to_marketing_page(frontend_url, instagram_config, false, Some(error));
    }

    // Validate code and state are present
    let code = match &query.code {
        Some(c) => c,
        None => {
            return redirect_with_error(frontend_url, "Missing authorization code");
        }
    };

    let state_param = match &query.state {
        Some(s) => s,
        None => {
            return redirect_with_error(frontend_url, "Missing state parameter");
        }
    };

    // Validate state cookie (CSRF protection)
    let state_cookie_name = format!("{}_instagram", oauth_config.state_cookie_name);
    let state_cookie = jar.get(&state_cookie_name);
    let stored_state = match state_cookie {
        Some(cookie) => cookie.value().to_string(),
        None => {
            warn!("Missing state cookie for Instagram OAuth callback");
            return redirect_with_error(frontend_url, "Invalid OAuth state - please try again");
        }
    };

    // Verify state matches
    if state_param != &stored_state {
        warn!("State mismatch in Instagram OAuth callback");
        return redirect_with_error(frontend_url, "Invalid OAuth state - CSRF detected");
    }

    // Decode and parse state
    let oauth_state: SocialOAuthState = match BASE64.decode(state_param) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(state) => state,
            Err(e) => {
                error!("Failed to parse OAuth state: {:?}", e);
                return redirect_with_error(frontend_url, "Invalid OAuth state");
            }
        },
        Err(e) => {
            error!("Failed to decode OAuth state: {:?}", e);
            return redirect_with_error(frontend_url, "Invalid OAuth state");
        }
    };

    let user_id = &oauth_state.user_id;
    info!(user_id = %user_id, "Processing Instagram OAuth callback");

    // Get shared HTTP client for connection pooling
    // See `.claude/skills/connection-pooling-architecture` for patterns
    let http_client = match state.http_client() {
        Some(client) => client.as_ref(),
        None => {
            error!("HTTP client not configured for social OAuth");
            return redirect_with_error(frontend_url, "Internal configuration error");
        }
    };

    // Clear state cookie
    let jar = jar.remove(Cookie::from(state_cookie_name));

    // Exchange code for access token
    let token_response = match exchange_meta_code(http_client, instagram_config, code).await {
        Ok(response) => response,
        Err(e) => {
            error!("Failed to exchange Instagram OAuth code: {:?}", e);
            return (
                jar,
                redirect_to_marketing_page(
                    frontend_url,
                    instagram_config,
                    false,
                    Some("token_exchange_failed"),
                ),
            )
                .into_response();
        }
    };

    // Exchange short-lived token for long-lived token (~60 days)
    let long_lived_token = match exchange_for_long_lived_token(
        http_client,
        instagram_config,
        &token_response.access_token,
    )
    .await
    {
        Ok(response) => response,
        Err(e) => {
            warn!("Failed to get long-lived token, using short-lived: {:?}", e);
            token_response // Fall back to short-lived token
        }
    };

    let access_token = &long_lived_token.access_token;
    let token_expires_at = long_lived_token
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    // Fetch Facebook Pages with Instagram Business Accounts
    let (accounts, platform_user_id) =
        match fetch_instagram_accounts(http_client, instagram_config, access_token).await {
            Ok(accounts) => accounts,
            Err(e) => {
                error!("Failed to fetch Instagram accounts: {:?}", e);
                return (
                    jar,
                    redirect_to_marketing_page(
                        frontend_url,
                        instagram_config,
                        false,
                        Some("no_instagram_accounts"),
                    ),
                )
                    .into_response();
            }
        };

    if accounts.is_empty() {
        warn!(user_id = %user_id, "No Instagram Business Accounts found");
        return (
            jar,
            redirect_to_marketing_page(
                frontend_url,
                instagram_config,
                false,
                Some("no_business_accounts"),
            ),
        )
            .into_response();
    }

    info!(
        user_id = %user_id,
        account_count = accounts.len(),
        "Found Instagram Business Accounts"
    );

    // Encrypt access token before storing
    let access_token_encrypted =
        match encrypt_token(&instagram_config.token_encryption_key, access_token) {
            Ok(encrypted) => encrypted,
            Err(e) => {
                error!("Failed to encrypt access token: {:?}", e);
                return (
                    jar,
                    redirect_to_marketing_page(
                        frontend_url,
                        instagram_config,
                        false,
                        Some("encryption_failed"),
                    ),
                )
                    .into_response();
            }
        };

    // Prepare account inputs with encrypted page tokens
    let account_inputs: Vec<CreateSocialAccountInput> = accounts
        .into_iter()
        .enumerate()
        .map(|(idx, account)| {
            let page_token_encrypted =
                account
                    .page_access_token_encrypted
                    .as_ref()
                    .and_then(|token| {
                        encrypt_token(&instagram_config.token_encryption_key, token).ok()
                    });

            CreateSocialAccountInput {
                platform_account_id: account.platform_account_id,
                account_type: account.account_type,
                username: account.username,
                display_name: account.display_name,
                profile_picture_url: account.profile_picture_url,
                facebook_page_id: account.facebook_page_id,
                facebook_page_name: account.facebook_page_name,
                page_access_token_encrypted: page_token_encrypted,
                followers_count: account.followers_count,
                is_primary: idx == 0, // First account is primary
            }
        })
        .collect();

    // Create integration input
    let integration_input = CreateSocialIntegrationInput {
        platform: "Instagram".to_string(), // Must match SocialPlatform enum
        access_token_encrypted,
        refresh_token_encrypted: None, // Meta doesn't use refresh tokens
        token_expires_at: token_expires_at.map(|dt| dt.to_rfc3339()),
        platform_user_id,
        platform_user_name: None,
        scopes: instagram_config.scopes.clone(),
        accounts: account_inputs,
    };

    // Call Auth Service to create integration
    match create_social_integration(&state, user_id, integration_input).await {
        Ok(result) => {
            info!(
                user_id = %user_id,
                integration_id = %result.id,
                "Instagram integration created successfully"
            );
            (
                jar,
                redirect_to_marketing_page(frontend_url, instagram_config, true, None),
            )
                .into_response()
        }
        Err(e) => {
            error!(user_id = %user_id, error = %e, "Failed to create Instagram integration");
            (
                jar,
                redirect_to_marketing_page(
                    frontend_url,
                    instagram_config,
                    false,
                    Some("save_failed"),
                ),
            )
                .into_response()
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Exchange authorization code for access token
///
/// # Timeout Handling
///
/// The reqwest::Client is configured with timeouts at construction time in state.rs:
///   - `timeout`: Overall request timeout (bff.http.timeout_secs)
///   - `connect_timeout`: 5 seconds for TCP connection
///
/// This makes per-call timeout wrappers unnecessary - the client handles it.
async fn exchange_meta_code(
    client: &reqwest::Client,
    config: &MetaSocialOAuthConfig,
    code: &str,
) -> Result<MetaTokenResponse, String> {
    let token_url = format!(
        "https://graph.facebook.com/{}/oauth/access_token",
        config.api_version
    );

    let response = client
        .get(&token_url)
        .query(&[
            ("client_id", config.app_id.as_str()),
            ("client_secret", config.app_secret.as_str()),
            ("redirect_uri", config.redirect_uri.as_str()),
            ("code", code),
        ])
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Token exchange failed: {} - {}", status, body));
    }

    response
        .json::<MetaTokenResponse>()
        .await
        .map_err(|e| format!("Failed to parse token response: {:?}", e))
}

/// Exchange short-lived token for long-lived token (~60 days)
async fn exchange_for_long_lived_token(
    client: &reqwest::Client,
    config: &MetaSocialOAuthConfig,
    short_lived_token: &str,
) -> Result<MetaTokenResponse, String> {
    let token_url = format!(
        "https://graph.facebook.com/{}/oauth/access_token",
        config.api_version
    );

    let response = client
        .get(&token_url)
        .query(&[
            ("grant_type", "fb_exchange_token"),
            ("client_id", config.app_id.as_str()),
            ("client_secret", config.app_secret.as_str()),
            ("fb_exchange_token", short_lived_token),
        ])
        .send()
        .await
        .map_err(|e| format!("HTTP request failed: {:?}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!(
            "Long-lived token exchange failed: {} - {}",
            status, body
        ));
    }

    response
        .json::<MetaTokenResponse>()
        .await
        .map_err(|e| format!("Failed to parse token response: {:?}", e))
}

/// Fetch Instagram Business Accounts via Facebook Pages
async fn fetch_instagram_accounts(
    client: &reqwest::Client,
    config: &MetaSocialOAuthConfig,
    access_token: &str,
) -> Result<(Vec<SocialAccountInfo>, Option<String>), String> {
    // First, get Facebook Pages with Instagram Business Accounts
    let pages_url = format!(
        "https://graph.facebook.com/{}/me/accounts",
        config.api_version
    );

    let pages_response = client
        .get(&pages_url)
        .query(&[
            ("access_token", access_token),
            ("fields", "id,name,instagram_business_account,access_token"),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to fetch Facebook pages: {:?}", e))?;

    if !pages_response.status().is_success() {
        let status = pages_response.status();
        let body = pages_response.text().await.unwrap_or_default();
        return Err(format!(
            "Facebook pages request failed: {} - {}",
            status, body
        ));
    }

    let pages: FacebookPagesResponse = pages_response
        .json()
        .await
        .map_err(|e| format!("Failed to parse pages response: {:?}", e))?;

    let mut accounts = Vec::new();
    let mut platform_user_id = None;

    // For each page with an Instagram Business Account, fetch details
    for page in pages.data {
        if let Some(ig_ref) = page.instagram_business_account {
            // Fetch Instagram account details
            let ig_url = format!(
                "https://graph.facebook.com/{}/{}",
                config.api_version, ig_ref.id
            );

            let ig_response = client
                .get(&ig_url)
                .query(&[
                    ("access_token", access_token),
                    (
                        "fields",
                        "id,username,name,profile_picture_url,followers_count,media_count",
                    ),
                ])
                .send()
                .await;

            match ig_response {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(ig_details) = resp.json::<InstagramAccountDetails>().await {
                        // Set platform_user_id from first account
                        if platform_user_id.is_none() {
                            platform_user_id = Some(ig_details.id.clone());
                        }

                        accounts.push(SocialAccountInfo {
                            platform_account_id: ig_details.id,
                            account_type: "business".to_string(),
                            username: ig_details.username,
                            display_name: ig_details.name,
                            profile_picture_url: ig_details.profile_picture_url,
                            facebook_page_id: Some(page.id.clone()),
                            facebook_page_name: Some(page.name.clone()),
                            page_access_token_encrypted: page.access_token.clone(), // Will be encrypted later
                            followers_count: ig_details.followers_count,
                            is_primary: false, // Set later
                        });
                    }
                }
                Ok(resp) => {
                    let body = resp.text().await.unwrap_or_default();
                    warn!("Failed to fetch Instagram account {}: {}", ig_ref.id, body);
                }
                Err(e) => {
                    warn!(
                        "Request failed for Instagram account {}: {:?}",
                        ig_ref.id, e
                    );
                }
            }
        }
    }

    Ok((accounts, platform_user_id))
}

/// Encrypt a token using AES-256-GCM
///
/// # Performance
/// Creates cipher on each call (negligible cost for rare OAuth flows).
/// For high-frequency encryption, consider caching the cipher in AppState.
#[inline]
fn encrypt_token(encryption_key_b64: &str, token: &str) -> Result<String, String> {
    // Decode the base64 encryption key
    let key_bytes = BASE64
        .decode(encryption_key_b64)
        .map_err(|e| format!("Invalid encryption key: {:?}", e))?;

    if key_bytes.len() != 32 {
        return Err(format!(
            "Encryption key must be 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    // Create cipher - for OAuth flows this is acceptable overhead
    // For high-frequency use, could cache in AppState with once_cell
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| format!("Failed to create cipher: {:?}", e))?;

    // Generate random nonce (12 bytes for GCM)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, token.as_bytes())
        .map_err(|e| format!("Encryption failed: {:?}", e))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);

    Ok(BASE64.encode(&combined))
}

/// Create social integration via GraphQL mutation to Auth Service
///
/// # Timeout Handling
/// The reqwest::Client is configured with timeouts at construction time in state.rs.
/// This makes per-call timeout wrappers unnecessary.
async fn create_social_integration(
    state: &AppState,
    user_id: &str,
    input: CreateSocialIntegrationInput,
) -> Result<SocialIntegrationResult, String> {
    // Use shared HTTP client for connection pooling
    // Falls back to default client if http_client not configured
    let client = state
        .http_client()
        .ok_or_else(|| "HTTP client not configured".to_string())?;

    // Build GraphQL mutation
    let mutation = r#"
        mutation CreateSocialIntegration($input: CreateSocialIntegrationGQLInput!) {
            createSocialIntegration(input: $input) {
                id
                platform
                status
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": input
    });

    let body = serde_json::json!({
        "query": mutation,
        "variables": variables
    });

    // Call Hive Router (which routes to Auth Service)
    // Include user_id header for authentication
    let response = client
        .post(&state.config.bff.hive_router_url)
        .header("Content-Type", "application/json")
        .header("x-user-id", user_id)
        .header("x-product", &state.config.bff.product)
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("GraphQL request failed: {:?}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("GraphQL request failed: {} - {}", status, body));
    }

    let gql_response: CreateIntegrationResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse GraphQL response: {:?}", e))?;

    if let Some(errors) = gql_response.errors {
        let error_msg = errors
            .iter()
            .map(|e| e.message.clone())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(error_msg);
    }

    gql_response
        .data
        .and_then(|d| d.create_social_integration)
        .ok_or_else(|| "No data returned from createSocialIntegration".to_string())
}

/// Redirect with error to frontend
fn redirect_with_error(frontend_url: &str, error: &str) -> axum::response::Response {
    let error_encoded = urlencoding::encode(error);
    let redirect_url = format!(
        "{}/services/provider/health/marketing?tab=instagram&error={}",
        frontend_url, error_encoded
    );
    Redirect::to(&redirect_url).into_response()
}

/// Redirect to marketing page with success or error
fn redirect_to_marketing_page(
    frontend_url: &str,
    config: &MetaSocialOAuthConfig,
    success: bool,
    error: Option<&str>,
) -> axum::response::Response {
    let redirect_path = if success {
        &config.success_redirect_path
    } else {
        match error {
            Some(e) => {
                let error_encoded = urlencoding::encode(e);
                return Redirect::to(&format!(
                    "{}/services/provider/health/marketing?tab=instagram&error={}",
                    frontend_url, error_encoded
                ))
                .into_response();
            }
            None => &config.error_redirect_path,
        }
    };

    Redirect::to(&format!("{}{}", frontend_url, redirect_path)).into_response()
}
