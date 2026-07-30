//! JWT decode + role/API-key exemption checks
//!
//! Single source of truth for rate limit exemption logic.
//! Both the BFF tower middleware and federation executor import from here.

use jsonwebtoken::dangerous::insecure_decode;
use serde::{Deserialize, Serialize};

/// JWT claims structure (minimal, for role extraction in rate limiting)
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    /// User roles (includes "superadmin" for exempt users)
    #[serde(default)]
    pub roles: Vec<String>,
    /// Subject (user ID) - for logging
    #[serde(default)]
    pub sub: String,
}

/// Full JWT claims for user context extraction.
/// Used by federation layer to forward user info to subgraphs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserClaims {
    /// Subject (user ID)
    #[serde(default)]
    pub sub: String,

    /// User email
    #[serde(default)]
    pub email: Option<String>,

    /// User roles
    #[serde(default)]
    pub roles: Vec<String>,

    /// User permissions (resource:action format)
    #[serde(default)]
    pub permissions: Vec<String>,

    /// User relationships (for client-provider linking)
    #[serde(default)]
    pub relationships: Vec<String>,

    /// Product scope
    #[serde(default)]
    pub product: Option<String>,
}

/// Decode minimal JWT claims (roles + sub) without signature verification.
/// Verification happens in the auth service — we trust the session's token.
///
/// Uses `jsonwebtoken::dangerous::insecure_decode`, which is the crate's
/// supported way to read claims without verifying. The previous shape --
/// `Validation::insecure_disable_signature_validation` plus a throwaway
/// `DecodingKey::from_secret(&[])` -- is deprecated as of 10.1.0 and no longer
/// works: 10.x builds the verifier eagerly, so an HMAC-shaped key under an
/// RS256 validation returns `InvalidKeyFormat` for every token. `insecure_decode`
/// takes no key at all, which is a truer statement of what this does.
///
/// PERFORMANCE: Inlined for hot path optimization (called on every request with JWT).
#[inline]
pub fn decode_jwt_claims(token: &str) -> Result<JwtClaims, jsonwebtoken::errors::Error> {
    Ok(insecure_decode::<JwtClaims>(token)?.claims)
}

/// Decode full user claims from JWT without verification.
/// (Verification happens in auth service — we trust the session's token.)
///
/// See `decode_jwt_claims` above for why this is `insecure_decode` and not a
/// `Validation` with signature checking switched off.
///
/// PERFORMANCE: Inlined for hot path optimization (called on every authenticated request).
#[inline]
pub fn decode_user_claims(token: &str) -> Result<UserClaims, jsonwebtoken::errors::Error> {
    Ok(insecure_decode::<UserClaims>(token)?.claims)
}

/// Check if request is exempt from rate limiting via API key header.
///
/// Returns `Some(unique_key)` if exempt, `None` otherwise.
/// Each request gets a unique key so they're never rate-limited together.
#[inline]
pub fn check_api_key_exemption(headers: &axum::http::HeaderMap) -> Option<String> {
    let api_key = headers.get("x-api-key")?;
    let key_str = api_key.to_str().ok()?;
    if key_str.is_empty() {
        return None;
    }
    Some(format!(
        "__API_KEY_EXEMPT__:{}:{}",
        key_str,
        uuid::Uuid::new_v4()
    ))
}

/// Check if request is exempt from rate limiting via superadmin JWT role.
///
/// Returns `true` if the Authorization header contains a JWT with a "superadmin" role.
#[inline]
pub fn check_superadmin_exemption(headers: &axum::http::HeaderMap) -> bool {
    let auth_header = match headers.get("authorization") {
        Some(h) => h,
        None => return false,
    };
    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let token = match auth_str.strip_prefix("Bearer ") {
        Some(t) => t,
        None => return false,
    };
    match decode_jwt_claims(token) {
        Ok(claims) => claims.roles.iter().any(|r| r == "superadmin"),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_claims_decoding_invalid() {
        assert!(decode_jwt_claims("not.a.valid.token").is_err());
        assert!(decode_jwt_claims("").is_err());
    }

    /// Build a structurally-valid RS256 JWT with a junk signature.
    ///
    /// Both decoders here call `insecure_disable_signature_validation`, so the
    /// signature bytes are never checked — what matters is that the three-part
    /// structure parses and the payload deserializes.
    fn unsigned_rs256_token(payload_json: &str) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
        let header = B64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = B64.encode(payload_json.as_bytes());
        let signature = B64.encode(b"not-a-real-signature");
        [header, payload, signature].join(".")
    }

    /// The POSITIVE path, asserted separately from the reject path above.
    ///
    /// `test_jwt_claims_decoding_invalid` only proves garbage is refused, and
    /// `test_jwt_claims_structure` only exercises serde on a claims literal —
    /// neither one ever calls `decode_jwt_claims` on a token it should ACCEPT.
    /// Without this, a `jsonwebtoken` upgrade that broke decoding outright
    /// would leave every test in this module green.
    #[test]
    fn test_jwt_claims_decoding_valid() {
        let token = unsigned_rs256_token(r#"{"sub":"user-123","roles":["superadmin"]}"#);
        let claims = decode_jwt_claims(&token).expect("a well-formed JWT must decode");
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.roles, vec!["superadmin".to_string()]);
    }

    #[test]
    fn test_user_claims_decoding_valid() {
        let token = unsigned_rs256_token(
            r#"{"sub":"user-9","email":"a@b.c","roles":["user"],
                "permissions":["post:read"],"relationships":[],"product":"lilitu"}"#,
        );
        let claims = decode_user_claims(&token).expect("a well-formed JWT must decode");
        assert_eq!(claims.sub, "user-9");
        assert_eq!(claims.email.as_deref(), Some("a@b.c"));
        assert_eq!(claims.permissions, vec!["post:read".to_string()]);
        assert_eq!(claims.product.as_deref(), Some("lilitu"));
    }

    #[test]
    fn test_jwt_claims_structure() {
        let claims_json = r#"{"sub": "user-123"}"#;
        let claims: JwtClaims = serde_json::from_str(claims_json).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert!(claims.roles.is_empty());

        let claims_with_roles = r#"{"sub": "admin-user", "roles": ["superadmin", "user"]}"#;
        let claims: JwtClaims = serde_json::from_str(claims_with_roles).unwrap();
        assert_eq!(claims.sub, "admin-user");
        assert!(claims.roles.contains(&"superadmin".to_string()));
    }

    #[test]
    fn test_superadmin_check() {
        let claims = JwtClaims {
            sub: "user-123".to_string(),
            roles: vec!["user".to_string(), "superadmin".to_string()],
        };
        assert!(claims.roles.iter().any(|r| r == "superadmin"));

        let regular_claims = JwtClaims {
            sub: "user-456".to_string(),
            roles: vec!["user".to_string()],
        };
        assert!(!regular_claims.roles.iter().any(|r| r == "superadmin"));
    }
}
