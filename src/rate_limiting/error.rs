//! Unified 429 response in GraphQL errors format
//!
//! All rate limiters (BFF, federation, geo) use this module to produce
//! consistent error responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Build a 429 rate limit HTTP response in GraphQL errors format.
///
/// Used by the BFF tower middleware when `tower_governor` rejects a request,
/// and by the geo rate limiter in handlers.rs.
pub fn rate_limit_response(retry_after_ms: u64, limiter: &str) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(to_graphql_json(retry_after_ms, limiter)),
    )
        .into_response()
}

/// Create the GraphQL-format JSON body for a rate limit error.
///
/// Shared between the HTTP response helper and the federation layer which
/// builds its own `FederationResponse`.
pub fn to_graphql_json(retry_after_ms: u64, limiter: &str) -> serde_json::Value {
    json!({
        "errors": [{
            "message": "Rate limit exceeded",
            "extensions": {
                "code": "RATE_LIMITED",
                "retryAfterMs": retry_after_ms,
                "limiter": limiter
            }
        }]
    })
}

/// Create HTTP headers for rate limit responses.
pub fn rate_limit_headers(retry_after_ms: u64) -> Vec<(String, String)> {
    vec![
        (
            "Retry-After".to_string(),
            (retry_after_ms / 1000).max(1).to_string(),
        ),
        ("X-RateLimit-Reset".to_string(), retry_after_ms.to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graphql_json_format() {
        let json = to_graphql_json(5000, "user");
        assert_eq!(
            json["errors"][0]["extensions"]["code"].as_str().unwrap(),
            "RATE_LIMITED"
        );
        assert_eq!(
            json["errors"][0]["extensions"]["retryAfterMs"].as_u64(),
            Some(5000)
        );
        assert_eq!(
            json["errors"][0]["extensions"]["limiter"].as_str().unwrap(),
            "user"
        );
    }

    #[test]
    fn test_rate_limit_headers() {
        let headers = rate_limit_headers(5000);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Retry-After");
        assert_eq!(headers[0].1, "5");
    }
}
