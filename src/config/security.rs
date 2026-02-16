//! Security configuration (CSP, CORS, HSTS, headers)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Content Security Policy domains
    pub csp: CspConfig,

    /// CORS configuration
    pub cors: CorsConfig,

    /// HSTS (HTTP Strict Transport Security) settings
    pub hsts: HstsConfig,

    /// Additional security headers
    pub headers: SecurityHeaders,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CspConfig {
    /// API domains for connect-src directive
    pub api_domains: Vec<String>,

    /// WebSocket domains for connect-src directive
    pub ws_domains: Vec<String>,

    /// Additional connect-src domains (e.g., external APIs)
    pub additional_connect_src: Vec<String>,

    /// Script sources (e.g., Stripe.js, Cloudflare Insights)
    pub script_sources: Vec<String>,

    /// Font sources (e.g., Google Fonts)
    pub font_sources: Vec<String>,

    /// Style sources (e.g., Google Fonts stylesheets)
    pub style_sources: Vec<String>,

    /// Image sources (defaults: 'self' data: https: blob:)
    /// Override to restrict image sources for enhanced security
    pub img_sources: Vec<String>,

    /// Frame sources for iframe embedding (e.g., Stripe payment forms)
    pub frame_sources: Vec<String>,
}

impl Default for CspConfig {
    fn default() -> Self {
        Self {
            api_domains: Vec::new(),
            ws_domains: Vec::new(),
            additional_connect_src: Vec::new(),
            script_sources: Vec::new(),
            font_sources: Vec::new(),
            style_sources: Vec::new(),
            img_sources: vec![
                "'self'".to_string(),
                "data:".to_string(),
                "https:".to_string(),
                "blob:".to_string(),
            ],
            frame_sources: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,

    /// Whether to allow credentials
    pub allow_credentials: bool,

    /// Preflight cache max-age in seconds (default: 3600 = 1 hour)
    pub max_age_secs: u64,

    /// Additional allowed request headers (beyond defaults)
    pub additional_allowed_headers: Vec<String>,

    /// Additional exposed response headers (beyond defaults)
    pub additional_exposed_headers: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allow_credentials: false,
            max_age_secs: 3600,
            additional_allowed_headers: Vec::new(),
            additional_exposed_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HstsConfig {
    /// Max age in seconds (default: 31536000 = 1 year)
    pub max_age: u64,

    /// Include subdomains
    pub include_subdomains: bool,

    /// Enable preload
    pub preload: bool,
}

impl Default for HstsConfig {
    fn default() -> Self {
        Self {
            max_age: 31536000,
            include_subdomains: true,
            preload: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct SecurityHeaders {
    /// X-Frame-Options value
    pub x_frame_options: String,

    /// Referrer-Policy value
    pub referrer_policy: String,

    /// Permissions-Policy directives
    pub permissions_policy: String,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            x_frame_options: "DENY".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=()".to_string(),
        }
    }
}
