//! Unified IP extraction from proxy headers
//!
//! Single source of truth for extracting client IP addresses from HTTP requests.
//! Used by both the BFF tower middleware and the geolocation handler.
//!
//! # Priority chain
//!
//! 1. `CF-Connecting-IP` — Cloudflare's authoritative header (most trusted)
//! 2. `X-Real-IP` — Common reverse proxy header (single IP)
//! 3. `X-Forwarded-For` — Proxy chain (first IP is original client)
//! 4. Socket address — Direct connection fallback

use axum::extract::ConnectInfo;
use axum::http::Request;
use std::net::{IpAddr, SocketAddr};

/// Extract client IP from request headers using the unified priority chain.
///
/// Returns `(ip_string, source_header)` for logging/diagnostics.
///
/// PERFORMANCE: Inlined for hot path optimization (called on every request).
#[inline]
pub fn extract_client_ip<T>(req: &Request<T>) -> (String, &'static str) {
    let headers = req.headers();

    // 1. CF-Connecting-IP (Cloudflare)
    if let Some(cf_ip) = headers.get("cf-connecting-ip") {
        if let Ok(s) = cf_ip.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return (trimmed.to_string(), "cf-connecting-ip");
            }
        }
    }

    // 2. X-Real-IP
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(s) = real_ip.to_str() {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return (trimmed.to_string(), "x-real-ip");
            }
        }
    }

    // 3. X-Forwarded-For (first IP in chain)
    if let Some(forwarded) = headers.get("x-forwarded-for") {
        if let Ok(s) = forwarded.to_str() {
            if let Some(first_ip) = s.split(',').next() {
                let trimmed = first_ip.trim();
                if !trimmed.is_empty() {
                    return (trimmed.to_string(), "x-forwarded-for");
                }
            }
        }
    }

    // 4. Socket address (direct connection)
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return (addr.ip().to_string(), "socket");
    }

    ("unknown".to_string(), "none")
}

/// Extract client IP as a parsed `IpAddr`, returning `None` if unparseable.
///
/// PERFORMANCE: Inlined for hot path optimization.
#[inline]
pub fn extract_client_ip_addr<T>(req: &Request<T>) -> Option<IpAddr> {
    let (ip_str, _) = extract_client_ip(req);
    ip_str.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[test]
    fn test_cf_connecting_ip_takes_priority() {
        let req = Request::builder()
            .header("cf-connecting-ip", "1.2.3.4")
            .header("x-real-ip", "5.6.7.8")
            .header("x-forwarded-for", "9.10.11.12")
            .body(())
            .unwrap();

        let (ip, source) = extract_client_ip(&req);
        assert_eq!(ip, "1.2.3.4");
        assert_eq!(source, "cf-connecting-ip");
    }

    #[test]
    fn test_x_real_ip_fallback() {
        let req = Request::builder()
            .header("x-real-ip", "5.6.7.8")
            .header("x-forwarded-for", "9.10.11.12")
            .body(())
            .unwrap();

        let (ip, source) = extract_client_ip(&req);
        assert_eq!(ip, "5.6.7.8");
        assert_eq!(source, "x-real-ip");
    }

    #[test]
    fn test_x_forwarded_for_first_ip() {
        let req = Request::builder()
            .header("x-forwarded-for", "9.10.11.12, 13.14.15.16")
            .body(())
            .unwrap();

        let (ip, source) = extract_client_ip(&req);
        assert_eq!(ip, "9.10.11.12");
        assert_eq!(source, "x-forwarded-for");
    }

    #[test]
    fn test_no_headers_returns_unknown() {
        let req = Request::builder().body(()).unwrap();

        let (ip, source) = extract_client_ip(&req);
        assert_eq!(ip, "unknown");
        assert_eq!(source, "none");
    }
}
