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

/// Cross-Origin-Opener-Policy.
///
/// A closed set from the HTML spec, so it is an enum rather than a String: the
/// difference between `same-origin` and `same-origin-allow-popups` decides
/// whether a popup-based OAuth/PKCE flow can talk to its opener, and a typo in
/// a String field would ship a broken login instead of failing to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginOpenerPolicy {
    /// No isolation. The opener relationship is fully preserved.
    UnsafeNone,
    /// Isolates cross-origin documents but KEEPS the opener link for popups
    /// this document itself opened. Required by popup-based PKCE flows.
    SameOriginAllowPopups,
    /// Full isolation. Severs `window.opener`, which breaks popup auth.
    SameOrigin,
}

/// Cross-Origin-Embedder-Policy. Closed set, same reasoning as COOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginEmbedderPolicy {
    UnsafeNone,
    Credentialless,
    RequireCorp,
}

/// Cross-Origin-Resource-Policy. Closed set, same reasoning as COOP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CrossOriginResourcePolicy {
    SameSite,
    SameOrigin,
    CrossOrigin,
}

impl CrossOriginOpenerPolicy {
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::UnsafeNone => "unsafe-none",
            Self::SameOriginAllowPopups => "same-origin-allow-popups",
            Self::SameOrigin => "same-origin",
        }
    }

    /// True when this policy severs `window.opener`, so a popup-based auth
    /// flow cannot complete under it.
    pub fn breaks_popup_auth(self) -> bool {
        matches!(self, Self::SameOrigin)
    }
}

impl CrossOriginEmbedderPolicy {
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::UnsafeNone => "unsafe-none",
            Self::Credentialless => "credentialless",
            Self::RequireCorp => "require-corp",
        }
    }
}

impl CrossOriginResourcePolicy {
    pub fn as_header_value(self) -> &'static str {
        match self {
            Self::SameSite => "same-site",
            Self::SameOrigin => "same-origin",
            Self::CrossOrigin => "cross-origin",
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

    /// Cross-Origin-Opener-Policy. Was hardcoded to `same-origin` in
    /// middleware; a deployment whose login is a popup needs
    /// `same-origin-allow-popups` and had no way to say so.
    pub cross_origin_opener_policy: CrossOriginOpenerPolicy,

    /// Cross-Origin-Embedder-Policy. Was hardcoded to `credentialless`.
    pub cross_origin_embedder_policy: CrossOriginEmbedderPolicy,

    /// Cross-Origin-Resource-Policy. Was hardcoded to `cross-origin`, which is
    /// the most permissive of the three; a same-origin-only deployment could
    /// not tighten it.
    pub cross_origin_resource_policy: CrossOriginResourcePolicy,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self {
            x_frame_options: "DENY".to_string(),
            referrer_policy: "strict-origin-when-cross-origin".to_string(),
            permissions_policy: "camera=(), microphone=(), geolocation=()".to_string(),
            // Defaults preserve the previously hardcoded values exactly, so
            // adding these knobs changes no existing deployment's headers.
            cross_origin_opener_policy: CrossOriginOpenerPolicy::SameOrigin,
            cross_origin_embedder_policy: CrossOriginEmbedderPolicy::Credentialless,
            cross_origin_resource_policy: CrossOriginResourcePolicy::CrossOrigin,
        }
    }
}

#[cfg(test)]
mod cross_origin_tests {
    use super::*;

    #[test]
    fn defaults_preserve_the_previously_hardcoded_values() {
        let h = SecurityHeaders::default();
        assert_eq!(
            h.cross_origin_opener_policy.as_header_value(),
            "same-origin"
        );
        assert_eq!(
            h.cross_origin_embedder_policy.as_header_value(),
            "credentialless"
        );
        assert_eq!(
            h.cross_origin_resource_policy.as_header_value(),
            "cross-origin"
        );
    }

    #[test]
    fn popup_auth_policy_round_trips_from_yaml() {
        let yaml = "cross_origin_opener_policy: same-origin-allow-popups\n";
        let h: SecurityHeaders = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(
            h.cross_origin_opener_policy,
            CrossOriginOpenerPolicy::SameOriginAllowPopups
        );
        assert_eq!(
            h.cross_origin_opener_policy.as_header_value(),
            "same-origin-allow-popups"
        );
    }

    #[test]
    fn a_typo_is_a_parse_error_not_a_silent_wrong_header() {
        // This is the whole point of the enum. As a String field this typo
        // would have started fine and broken popup login in the browser.
        let yaml = "cross_origin_opener_policy: same-origin-allow-popup\n";
        let parsed: Result<SecurityHeaders, _> = serde_yaml::from_str(yaml);
        assert!(parsed.is_err(), "a misspelled policy must not parse");
    }

    #[test]
    fn every_variant_maps_to_its_spec_token() {
        for (p, want) in [
            (CrossOriginOpenerPolicy::UnsafeNone, "unsafe-none"),
            (
                CrossOriginOpenerPolicy::SameOriginAllowPopups,
                "same-origin-allow-popups",
            ),
            (CrossOriginOpenerPolicy::SameOrigin, "same-origin"),
        ] {
            assert_eq!(p.as_header_value(), want);
        }
        for (p, want) in [
            (CrossOriginResourcePolicy::SameSite, "same-site"),
            (CrossOriginResourcePolicy::SameOrigin, "same-origin"),
            (CrossOriginResourcePolicy::CrossOrigin, "cross-origin"),
        ] {
            assert_eq!(p.as_header_value(), want);
        }
    }

    #[test]
    fn only_full_isolation_breaks_popup_auth() {
        assert!(CrossOriginOpenerPolicy::SameOrigin.breaks_popup_auth());
        assert!(!CrossOriginOpenerPolicy::SameOriginAllowPopups.breaks_popup_auth());
        assert!(!CrossOriginOpenerPolicy::UnsafeNone.breaks_popup_auth());
    }

    #[test]
    fn header_values_are_all_valid_header_values() {
        // as_header_value feeds HeaderValue::from_static, which panics on an
        // invalid value. Prove every variant is safe there.
        for v in [
            CrossOriginOpenerPolicy::UnsafeNone.as_header_value(),
            CrossOriginOpenerPolicy::SameOriginAllowPopups.as_header_value(),
            CrossOriginOpenerPolicy::SameOrigin.as_header_value(),
            CrossOriginEmbedderPolicy::UnsafeNone.as_header_value(),
            CrossOriginEmbedderPolicy::Credentialless.as_header_value(),
            CrossOriginEmbedderPolicy::RequireCorp.as_header_value(),
            CrossOriginResourcePolicy::SameSite.as_header_value(),
            CrossOriginResourcePolicy::SameOrigin.as_header_value(),
            CrossOriginResourcePolicy::CrossOrigin.as_header_value(),
        ] {
            let _ = http::HeaderValue::from_static(v);
        }
    }
}
