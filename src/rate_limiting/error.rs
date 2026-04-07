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
    fn test_graphql_json_message() {
        let json = to_graphql_json(1000, "ip");
        assert_eq!(
            json["errors"][0]["message"].as_str().unwrap(),
            "Rate limit exceeded"
        );
    }

    #[test]
    fn test_graphql_json_errors_is_array() {
        let json = to_graphql_json(1000, "global");
        assert!(json["errors"].is_array());
        assert_eq!(json["errors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_rate_limit_headers() {
        let headers = rate_limit_headers(5000);
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Retry-After");
        assert_eq!(headers[0].1, "5");
    }

    #[test]
    fn test_rate_limit_headers_x_ratelimit_reset() {
        let headers = rate_limit_headers(5000);
        assert_eq!(headers[1].0, "X-RateLimit-Reset");
        assert_eq!(headers[1].1, "5000");
    }

    #[test]
    fn test_rate_limit_headers_zero_ms_uses_min_one() {
        let headers = rate_limit_headers(0);
        assert_eq!(headers[0].1, "1");
        assert_eq!(headers[1].1, "0");
    }

    #[test]
    fn test_rate_limit_headers_small_ms_uses_min_one() {
        let headers = rate_limit_headers(500);
        // 500 / 1000 = 0, but .max(1) = 1
        assert_eq!(headers[0].1, "1");
    }

    #[test]
    fn test_rate_limit_headers_exact_second() {
        let headers = rate_limit_headers(1000);
        assert_eq!(headers[0].1, "1");
    }

    #[test]
    fn test_rate_limit_response_status() {
        let response = rate_limit_response(2000, "federation");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_rate_limit_response_body() {
        let response = rate_limit_response(3000, "bff");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX);
        let body = tokio_test::block_on(body).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["errors"][0]["extensions"]["code"], "RATE_LIMITED");
        assert_eq!(json["errors"][0]["extensions"]["limiter"], "bff");
        assert_eq!(json["errors"][0]["extensions"]["retryAfterMs"], 3000);
    }
}
