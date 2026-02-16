//! JWT decode + role/API-key exemption checks
//!
//! Single source of truth for rate limit exemption logic.
//! Both the BFF tower middleware and federation executor import from here.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
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
/// PERFORMANCE: Inlined for hot path optimization (called on every request with JWT).
#[inline]
pub fn decode_jwt_claims(token: &str) -> Result<JwtClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let key = DecodingKey::from_secret(&[]);
    let token_data = decode::<JwtClaims>(token, &key, &validation)?;
    Ok(token_data.claims)
}

/// Decode full user claims from JWT without verification.
/// (Verification happens in auth service — we trust the session's token.)
///
/// PERFORMANCE: Inlined for hot path optimization (called on every authenticated request).
#[inline]
pub fn decode_user_claims(token: &str) -> Result<UserClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let key = DecodingKey::from_secret(&[]);
    let token_data = decode::<UserClaims>(token, &key, &validation)?;
    Ok(token_data.claims)
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
