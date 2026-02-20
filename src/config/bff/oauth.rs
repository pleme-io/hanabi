use serde::{Deserialize, Serialize};

/// OAuth configuration for BFF-handled external authentication
///
/// # BFF OAuth Flow (IETF Recommended Pattern)
/// The BFF acts as a confidential OAuth client, handling the entire OAuth flow:
/// 1. Browser → BFF: Redirect to `/api/auth/google`
/// 2. BFF → Google: Redirect with client_id, state, PKCE
/// 3. Google → BFF: Redirect to `/api/auth/google/callback` with code
/// 4. BFF → Google: Exchange code for tokens (using client_secret)
/// 5. BFF → Auth Service: Call loginWithOAuthProvider with validated user info
/// 6. BFF → Browser: Set session cookie, redirect to frontend
///
/// This keeps client_secret and external API calls in BFF (edge service),
/// while Auth Service stays internal-only (validates OAuth info, creates sessions).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffOAuthConfig {
    /// Enable OAuth handling in BFF
    #[serde(default)]
    pub enabled: bool,

    /// Google OAuth configuration
    #[serde(default)]
    pub google: Option<BffOAuthProviderConfig>,

    /// Facebook OAuth configuration
    #[serde(default)]
    pub facebook: Option<BffOAuthProviderConfig>,

    /// Instagram/Meta Business Suite OAuth configuration
    /// Used for social integration (NOT login) - providers link their Instagram Business accounts
    #[serde(default)]
    pub instagram: Option<MetaSocialOAuthConfig>,

    /// Frontend URL to redirect to after OAuth completion
    /// e.g., "https://staging.example.com" or "http://localhost:5173"
    pub frontend_url: String,

    /// Frontend path to redirect to after successful OAuth
    pub success_redirect_path: String,

    /// Frontend path to redirect to after OAuth error
    pub error_redirect_path: String,

    /// State cookie name (for CSRF protection)
    pub state_cookie_name: String,

    /// State cookie max age in seconds
    pub state_max_age_secs: u64,
}

impl Default for BffOAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            google: None,
            facebook: None,
            instagram: None,
            frontend_url: "http://localhost:5173".to_string(),
            success_redirect_path: "/".to_string(),
            error_redirect_path: "/login?error=oauth_failed".to_string(),
            state_cookie_name: "oauth_state".to_string(),
            state_max_age_secs: 600,
        }
    }
}

/// OAuth provider configuration (Google, Facebook, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffOAuthProviderConfig {
    /// OAuth client ID (public)
    pub client_id: String,

    /// OAuth client secret (confidential - BFF only)
    pub client_secret: String,

    /// OAuth redirect URI (must match Google Console config)
    /// e.g., "https://staging.example.com/api/auth/google/callback"
    pub redirect_uri: String,

    /// OAuth scopes to request
    pub scopes: Vec<String>,
}

impl Default for BffOAuthProviderConfig {
    fn default() -> Self {
        Self {
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
        }
    }
}

/// Meta Social OAuth configuration for Instagram Business Account linking
///
/// # Social Integration OAuth (NOT Login OAuth)
/// This is for linking Instagram Business/Creator accounts to Hanabi provider profiles.
/// Different from login OAuth because:
/// - Requires different scopes (instagram_basic, pages_show_list, etc.)
/// - Stores integration data in social_integrations table (not user sessions)
/// - Redirects to marketing settings page (not home page)
/// - Multiple accounts can be linked per user
///
/// # Meta Business Suite Flow
/// 1. User clicks "Link Instagram" on marketing settings
/// 2. BFF redirects to Facebook OAuth (Meta owns Instagram API)
/// 3. User grants permissions for their Instagram Business Account
/// 4. BFF exchanges code for long-lived token
/// 5. BFF fetches Facebook Pages with Instagram Business Accounts
/// 6. BFF stores encrypted tokens in auth service via GraphQL mutation
/// 7. Frontend shows linked accounts
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct MetaSocialOAuthConfig {
    /// Meta App ID (same as Facebook App ID)
    pub app_id: String,

    /// Meta App Secret (confidential - BFF only)
    pub app_secret: String,

    /// OAuth redirect URI for Instagram linking
    /// e.g., "https://staging.example.com/api/social/instagram/callback"
    pub redirect_uri: String,

    /// OAuth scopes for Instagram Business Account access
    /// Different from login scopes - needs instagram_basic, pages_show_list, etc.
    pub scopes: Vec<String>,

    /// Facebook Graph API version
    pub api_version: String,

    /// Encryption key for storing tokens at rest (32 bytes, base64 encoded)
    /// Used to encrypt access_token before storing in database
    pub token_encryption_key: String,

    /// Frontend path to redirect after successful Instagram linking
    pub success_redirect_path: String,

    /// Frontend path to redirect after Instagram linking error
    pub error_redirect_path: String,
}

impl Default for MetaSocialOAuthConfig {
    fn default() -> Self {
        Self {
            app_id: String::new(),
            app_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec![
                "instagram_basic".to_string(),
                "instagram_content_publish".to_string(),
                "instagram_manage_comments".to_string(),
                "instagram_manage_insights".to_string(),
                "pages_show_list".to_string(),
                "pages_read_engagement".to_string(),
                "business_management".to_string(),
            ],
            api_version: "v18.0".to_string(),
            token_encryption_key: String::new(),
            success_redirect_path: "/?social=instagram&linked=true".to_string(),
            error_redirect_path: "/error?source=instagram&error=oauth_failed".to_string(),
        }
    }
}
