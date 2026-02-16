//! Unified Rate Limiting for Hanabi BFF
//!
//! Consolidates all rate limiting into a single module with shared IP extraction,
//! exemption logic, error formatting, and configuration helpers.
//!
//! # Sub-modules
//!
//! - [`ip`] — Unified IP extraction from proxy headers
//! - [`exemption`] — JWT decode + role/API-key exemption checks
//! - [`error`] — Unified 429 response in GraphQL errors format
//! - [`config`] — QuotaParams helper with correct `governor::Quota::per_second()` usage
//! - [`dynamic`] — DynamicRateLimiter with hot-reload capability
//! - [`sync`] — NATS config subscriber for runtime rate limit updates
//! - [`bff`] — BFF HTTP rate limiter (tower middleware)
//! - [`federation`] — Federation 3-level rate limiter

#[allow(dead_code)]
pub mod bff;
#[allow(dead_code)]
pub mod config;
pub mod dynamic;
#[allow(dead_code)]
pub mod error;
#[allow(dead_code)]
pub mod exemption;
#[allow(dead_code)]
pub mod federation;
#[allow(dead_code)]
pub mod ip;
pub mod sync;

// Re-exports for convenient access
#[allow(unused_imports)]
pub use bff::build_rate_limit_layer;
pub use dynamic::{DynamicRateLimitConfig, DynamicRateLimiter};
#[allow(unused_imports)]
pub use exemption::{decode_user_claims, UserClaims};
#[allow(unused_imports)]
pub use federation::{
    FederationRateLimiter, OperationType, RateLimitConfig, RateLimitContext, RateLimitResult,
    RateLimitErrorResponse,
};
pub use sync::spawn_rate_limit_config_subscriber;
