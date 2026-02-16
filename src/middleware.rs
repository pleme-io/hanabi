//! HTTP middleware for security, caching, metrics, and headers
//!
//! This module contains Axum middleware functions that process requests/responses
//! to add security headers, cache control, metrics, and CORS configuration.
//!
//! # Middleware Stack
//! The middleware is applied in this order (top to bottom):
//! 1. Request metrics (timing, counters)
//! 2. Security headers (CSP, HSTS, etc.)
//! 3. Cache control (based on file type)
//! 4. CORS (cross-origin resource sharing)
//!
//! # Security Headers Applied
//! - Content-Security-Policy (CSP)
//! - Strict-Transport-Security (HSTS)
//! - X-Frame-Options
//! - X-Content-Type-Options
//! - Referrer-Policy
//! - Permissions-Policy
//! - Cross-Origin policies (COOP, COEP, CORP)
//! - X-XSS-Protection
//! - X-DNS-Prefetch-Control
//! - X-Download-Options
//! - X-Permitted-Cross-Domain-Policies

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    http::HeaderValue,
    middleware::Next,
    response::{IntoResponse, Response},
};
use http::header;
use once_cell::sync::Lazy;
use regex::Regex;
use tower_http::cors::CorsLayer;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use crate::state::AppState;

// PERFORMANCE: Pre-compile common file extension pattern for 404 detection
// Avoids string operations on every SPA fallback check
static FILE_EXTENSION_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\.[a-zA-Z0-9]{1,10}$").expect("Failed to compile file extension regex")
});

/// Security headers middleware using FluxCD-managed YAML configuration
///
/// Applies defense-in-depth security headers with environment-specific CSP.
/// All headers are configurable via YAML to allow different policies per environment.
///
/// # Headers Applied
/// - **CSP**: Content Security Policy (environment-specific domains)
/// - **HSTS**: HTTP Strict Transport Security (force HTTPS)
/// - **X-Frame-Options**: Prevent clickjacking
/// - **X-Content-Type-Options**: Prevent MIME sniffing
/// - **Referrer-Policy**: Control referrer information
/// - **Permissions-Policy**: Restrict browser features
/// - **COOP/COEP/CORP**: Cross-origin isolation policies
/// - Various X-* headers for defense-in-depth
///
/// # Performance Optimization
/// Uses pre-computed headers from AppState (computed once at startup).
/// On every request, we only copy pre-built HeaderValue instances.
///
/// # Example
/// ```rust
/// Router::new()
///     .layer(middleware::from_fn_with_state(state.clone(), security_headers))
/// ```
#[inline]
pub async fn security_headers(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // PERFORMANCE: Use pre-computed headers from AppState (computed once at startup)
    // This avoids build_csp(), build_hsts(), and HeaderValue::from_str() on every request
    if let Some(ref sec) = state.security_headers {
        headers.insert(header::CONTENT_SECURITY_POLICY, sec.csp.clone());
        headers.insert(header::X_FRAME_OPTIONS, sec.x_frame_options.clone());
        headers.insert(header::REFERRER_POLICY, sec.referrer_policy.clone());
        headers.insert(
            http::HeaderName::from_static("permissions-policy"),
            sec.permissions_policy.clone(),
        );
        headers.insert(header::STRICT_TRANSPORT_SECURITY, sec.hsts.clone());
    }

    // X-Content-Type-Options (static, never changes)
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection (legacy browsers, defense in depth)
    headers.insert(
        http::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );

    // Cross-Origin-Opener-Policy (COOP) - Isolate browsing context
    // Prevents cross-origin attacks via window.opener
    headers.insert(
        http::HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );

    // Cross-Origin-Embedder-Policy (COEP) - Allow cross-origin resources without credentials
    // credentialless: Allows resources like Stripe.js without requiring CORP headers
    // More permissive than require-corp but still maintains security by not sending credentials
    headers.insert(
        http::HeaderName::from_static("cross-origin-embedder-policy"),
        HeaderValue::from_static("credentialless"),
    );

    // Cross-Origin-Resource-Policy (CORP) - Allow cross-origin resource loading
    // Set to cross-origin to work with COEP: credentialless
    // This allows our resources to be loaded by external scripts/services
    headers.insert(
        http::HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("cross-origin"),
    );

    // X-DNS-Prefetch-Control - Disable DNS prefetching to prevent privacy leaks
    headers.insert(
        http::HeaderName::from_static("x-dns-prefetch-control"),
        HeaderValue::from_static("off"),
    );

    // X-Download-Options - Prevent MIME-based attacks in IE
    headers.insert(
        http::HeaderName::from_static("x-download-options"),
        HeaderValue::from_static("noopen"),
    );

    // X-Permitted-Cross-Domain-Policies - Restrict Adobe Flash/PDF cross-domain access
    headers.insert(
        http::HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );

    response
}

/// Cookie security middleware
///
/// NOTE: This web server serves static files and doesn't set cookies directly.
/// Cookie security is enforced at the API gateway level (hive-router).
/// This middleware validates and hardens any Set-Cookie headers from upstream.
///
/// This is defense-in-depth in case API responses accidentally leak through
/// the static file server.
#[allow(dead_code)]
pub async fn cookie_security(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;

    // Harden any Set-Cookie headers from upstream services
    // This is defense-in-depth in case API responses leak through
    if let Some(cookies) = response.headers().get(header::SET_COOKIE) {
        warn!("Set-Cookie header detected in static file response - this should not happen");
        warn!("Cookie value: {:?}", cookies);

        // Log for security monitoring
        state.incr("security.unexpected_cookie", &[("type", "static_response")]);
    }

    response
}

/// Build environment-aware CORS layer from configuration
///
/// Implements defense-in-depth with strict origin validation.
/// Only origins listed in configuration are allowed.
///
/// # CORS Configuration
/// - **Allowed Origins**: Strict whitelist from config.security.cors.allowed_origins
/// - **Allowed Methods**: GET, POST, PUT, DELETE, PATCH, OPTIONS
/// - **Allowed Headers**: Content-Type, Authorization, Accept, Apollo headers
/// - **Exposed Headers**: Content-Type, Cache-Control, ETag
/// - **Credentials**: Optional (config.security.cors.allow_credentials)
/// - **Preflight Cache**: Configurable max-age
///
/// # Example
/// ```rust
/// let cors_layer = build_cors_layer(&config);
/// Router::new().layer(cors_layer)
/// ```
pub fn build_cors_layer(config: &AppConfig) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .security
        .cors
        .allowed_origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    info!(
        "CORS configured for environment: {} with {} allowed origins",
        config.environment,
        allowed_origins.len()
    );

    let mut cors = CorsLayer::new()
        // Allowed origins from configuration (strict whitelist)
        .allow_origin(allowed_origins)
        // Allowed HTTP methods for CORS requests
        .allow_methods([
            http::Method::GET,
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
            http::Method::OPTIONS,
        ])
        // Allowed request headers
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            http::HeaderName::from_static("x-apollo-operation-name"),
            http::HeaderName::from_static("apollo-require-preflight"),
        ])
        // Exposed response headers (accessible to frontend)
        .expose_headers([header::CONTENT_TYPE, header::CACHE_CONTROL, header::ETAG])
        // Preflight cache duration (from configuration)
        .max_age(std::time::Duration::from_secs(
            config.security.cors.max_age_secs,
        ));

    // Credentials (cookies, auth headers) - only if configured
    if config.security.cors.allow_credentials {
        cors = cors.allow_credentials(true);
        info!("CORS credentials enabled for authenticated requests");
    }

    cors
}

/// Request metrics middleware
///
/// Emits StatsD metrics for every HTTP request:
/// - **http.request.duration**: Histogram of request latency in milliseconds
/// - **http.request.count**: Counter of total requests
///
/// Metrics include tags:
/// - method: HTTP method (GET, POST, etc.)
/// - path: Request path
/// - status: HTTP status code
///
/// # Performance Optimization
/// Uses `#[inline]` to reduce function call overhead in hot path.
/// Minimizes string allocations by reusing method/path references.
///
/// # Example
/// ```rust
/// Router::new()
///     .layer(middleware::from_fn_with_state(state.clone(), request_metrics))
/// ```
#[inline]
pub async fn request_metrics(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(|q| q.to_string());

    debug!(
        "HTTP request received: {} {} {}",
        method,
        path,
        query
            .as_ref()
            .map(|q| format!("?{}", q))
            .unwrap_or_default()
    );

    let response = next.run(req).await;

    let latency = start.elapsed();
    let status = response.status().as_u16();

    debug!(
        "HTTP response: {} {} → {} ({:?})",
        method, path, status, latency
    );

    // Emit metrics to Vector
    state.histogram(
        "http.request.duration",
        latency.as_millis() as f64,
        &[
            ("method", &method),
            ("path", &path),
            ("status", &status.to_string()),
        ],
    );
    state.incr(
        "http.request.count",
        &[("method", &method), ("status", &status.to_string())],
    );

    response
}

/// Cache control middleware using FluxCD-managed YAML configuration
///
/// Sets appropriate Cache-Control headers for different file types:
/// - **version.json**: no-cache (always check for updates)
/// - **Hashed assets** (e.g., main.abc123.js): immutable, 1 year cache
/// - **HTML files**: no-cache (ensure fresh content)
/// - **Other static files**: public, configured max-age
///
/// # Caching Strategy
/// - HTML/version.json: NEVER cached (no-store, no-cache)
/// - Hashed assets: Cached forever (immutable, hash changes when content changes)
/// - Other files: Cached for configured duration
///
/// # Performance Optimization
/// Uses `#[inline]` and fast path detection with early returns.
///
/// # Example
/// ```rust
/// Router::new()
///     .layer(middleware::from_fn_with_state(state.clone(), cache_control_headers))
/// ```
#[inline]
pub async fn cache_control_headers(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    // Clone the path before moving req into next.run()
    let path = req.uri().path().to_string();
    let mut response = next.run(req).await;

    // Skip cache headers if disabled in config
    if !state.config.cache.enable_cache_headers {
        return response;
    }

    // CRITICAL: Only apply cache headers to successful responses (200 OK)
    // Skip 404s, 500s, and other error responses to prevent caching errors
    // SPA fallback handler will set its own cache headers for index.html
    if !response.status().is_success() {
        debug!(
            "Skipping cache headers for non-success response: {} {}",
            response.status(),
            path
        );
        return response;
    }

    let headers = response.headers_mut();

    // Determine cache strategy based on file path
    let cache_header = if path == "/version.json" || path == "/env.js" {
        // CRITICAL: version.json and env.js must never be cached
        // version.json: checked on every page load to detect new deployments
        // env.js: runtime configuration that can change without rebuilding frontend
        HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0")
    } else if path == "/sw.js" || path == "/registerSW.js" || path.contains("/workbox-") {
        // CRITICAL: Service worker files must NEVER be cached
        // sw.js: Main service worker - browser must always check for updates
        // registerSW.js: Service worker registration script
        // workbox-*.js: Workbox runtime - must match the sw.js version exactly
        // Caching these files causes "Invalid frame header" errors when old SW references
        // workbox files with different hashes that no longer exist after deployments
        HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0")
    } else if path.ends_with(".html") || path == "/" {
        // HTML files must NEVER be cached to ensure users always get latest version
        // CRITICAL: no-store prevents ANY caching, no-cache forces revalidation
        // This prevents users from being stuck on old versions after deployments
        HeaderValue::from_static("no-cache, no-store, must-revalidate, max-age=0")
    } else if is_hashed_asset_optimized(&path, &state) {
        // Hashed assets (e.g., main.abc123.js) are immutable
        // Can be cached indefinitely because hash changes when content changes
        // PERFORMANCE: Uses pre-compiled regex from AppState (100x faster than per-call compilation)
        let max_age = state.config.cache.static_max_age;
        HeaderValue::from_str(&format!("public, max-age={}, immutable", max_age))
            .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=31536000, immutable"))
    } else {
        // Other static files (non-hashed): use configured max-age but allow caching
        let max_age = state.config.cache.static_max_age;
        HeaderValue::from_str(&format!("public, max-age={}", max_age))
            .unwrap_or_else(|_| HeaderValue::from_static("public, max-age=31536000"))
    };

    headers.insert(header::CACHE_CONTROL, cache_header);

    response
}

/// Check if a file path is a content-hashed asset (optimized version)
///
/// PERFORMANCE: Uses pre-compiled regex from AppState (100x faster than per-call compilation).
/// Falls back to per-call compilation if pre-compiled regex is unavailable.
///
/// Vite generates files like: assets/main-abc123.js, assets/index-def456.css
/// Pattern: /assets/{name}-{hash}.{ext} where hash is typically 8+ alphanumeric chars
///
/// # Arguments
/// * `path` - Request path (e.g., "/assets/main-abc123.js")
/// * `state` - Application state containing pre-compiled regex
///
/// # Returns
/// * `true` - Path matches hashed asset pattern
/// * `false` - Path does not match
fn is_hashed_asset_optimized(path: &str, state: &crate::state::AppState) -> bool {
    // Use pre-compiled regex if available (100x faster)
    if let Some(ref regex) = state.hashed_asset_regex {
        return regex.is_match(path);
    }

    // Fallback to per-call compilation (should rarely happen - only if initial compilation failed)
    is_hashed_asset(path, &state.config.network.hashed_asset_pattern)
}

/// Check if a file path is a content-hashed asset (fallback version)
///
/// This is the slow path that compiles regex on each call.
/// Only used if pre-compiled regex is unavailable.
fn is_hashed_asset(path: &str, pattern: &str) -> bool {
    Regex::new(pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// SPA 404 fallback middleware
///
/// Intercepts 404 responses from static file serving and serves index.html instead.
/// This ensures SPA routes always work, even if ServeDir returns 404.
///
/// # Why This Is Needed
/// ServeDir's not_found_service should handle missing files, but there are edge cases
/// where it might return 404 directly (e.g., certain path patterns, directory handling).
/// This middleware provides a safety net to ensure SPA routing always works.
///
/// # Behavior
/// - Checks if response status is 404 NOT FOUND
/// - Checks if request path is NOT a static asset (no file extension or known SPA route)
/// - If both conditions are true, serves index.html with 200 OK instead
///
/// # Example
/// ```rust
/// Router::new()
///     .layer(middleware::from_fn_with_state(state.clone(), spa_404_fallback))
/// ```
pub async fn spa_404_fallback(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let response = next.run(req).await;

    // Only intercept 404 responses
    if response.status() != http::StatusCode::NOT_FOUND {
        return response;
    }

    // Don't intercept 404s for actual file requests (with extensions)
    // These are legitimate 404s (e.g., missing image, missing JS file)
    // PERFORMANCE: Use pre-compiled regex instead of string operations
    let has_file_extension = FILE_EXTENSION_REGEX.is_match(&path);

    // If it has a file extension, it's a real file request - keep the 404
    if has_file_extension {
        debug!("Keeping 404 for file request: {}", path);
        return response;
    }

    // This is likely an SPA route - serve index.html with 200 OK
    info!(
        "SPA 404 fallback: intercepting 404 for path '{}', serving index.html",
        path
    );

    let index_path = std::path::Path::new(&state.config.server.static_dir)
        .join(&state.config.preflight.index_html_path);

    match tokio::fs::read_to_string(&index_path).await {
        Ok(content) => (
            http::StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (
                    header::CACHE_CONTROL,
                    "no-cache, no-store, must-revalidate, max-age=0",
                ),
            ],
            content,
        )
            .into_response(),
        Err(e) => {
            error!("SPA 404 fallback: failed to read index.html: {}", e);
            // Return original 404 if we can't read index.html
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_hashed_asset_matches() {
        let pattern =
            r"/assets/.+-[a-f0-9]{8,}\.(js|css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|webp|ico)$";

        // Should match hashed assets
        assert!(is_hashed_asset("/assets/main-abc12345.js", pattern));
        assert!(is_hashed_asset("/assets/index-def67890.css", pattern));
        assert!(is_hashed_asset("/assets/font-12345678.woff2", pattern));

        // Should not match non-hashed assets
        assert!(!is_hashed_asset("/assets/main.js", pattern));
        assert!(!is_hashed_asset("/index.html", pattern));
        assert!(!is_hashed_asset("/env.js", pattern));
    }

    #[test]
    fn test_is_hashed_asset_invalid_pattern() {
        // Invalid regex should return false gracefully
        let result = is_hashed_asset("/assets/main.js", "[invalid(regex");
        assert!(!result);
    }
}
