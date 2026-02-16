//! Federation Rate Limiting
//!
//! Provides rate limiting for GraphQL federation operations with support for:
//! - Per-user limits (based on user ID or IP)
//! - Per-operation limits (different limits for mutations vs queries)
//! - Per-subgraph limits (prevent overloading specific services)
//! - Role-based exemptions (admins can bypass limits)
//!
//! # Architecture
//!
//! ```text
//! Request → [User Limiter] → [Operation Limiter] → [Subgraph Limiter] → Execute
//!               │                    │                    │
//!               ▼                    ▼                    ▼
//!           Per-user            Per-operation        Per-subgraph
//!           bucket              bucket               bucket
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};
use governor::RateLimiter;
use tracing::{debug, info};

use super::config::QuotaParams;
use super::error;
use crate::metrics::{MetricsClient, MetricsExt};

/// Configuration for federation rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Default requests per second for all operations
    pub default_rps: u32,

    /// Burst size (token bucket capacity)
    pub burst_size: u32,

    /// Roles exempt from rate limiting
    pub exempt_roles: Vec<String>,

    /// Per-operation rate limits
    pub operation_limits: Vec<OperationRateLimit>,

    /// Per-subgraph rate limits
    pub subgraph_limits: Vec<SubgraphRateLimit>,

    /// Use IP address as fallback when user ID not available
    pub use_ip_fallback: bool,

    /// Maximum number of tracked keys (LRU eviction)
    pub max_keys: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_rps: 1000,
            burst_size: 2000,
            exempt_roles: vec!["admin".to_string(), "service".to_string()],
            operation_limits: vec![],
            subgraph_limits: vec![],
            use_ip_fallback: true,
            max_keys: 100_000,
        }
    }
}

/// Rate limit for specific operations
#[derive(Debug, Clone)]
pub struct OperationRateLimit {
    /// Operation name pattern (e.g., "mutation*", "createOrder")
    pub pattern: String,

    /// Requests per second for this pattern
    pub requests_per_second: u32,

    /// Optional burst size override
    pub burst_size: Option<u32>,
}

/// Rate limit for specific subgraphs
#[derive(Debug, Clone)]
pub struct SubgraphRateLimit {
    /// Subgraph name
    pub subgraph: String,

    /// Requests per second for this subgraph
    pub requests_per_second: u32,

    /// Optional burst size override
    pub burst_size: Option<u32>,
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    /// Request allowed
    Allowed,
    /// Request rate limited
    Limited {
        /// When the next request will be allowed (milliseconds)
        retry_after_ms: u64,
        /// Which limiter triggered (user, operation, subgraph)
        limiter: String,
    },
    /// User exempt from rate limiting
    Exempt {
        /// Reason for exemption
        reason: String,
    },
}

/// Rate limit context from request
#[derive(Debug, Clone)]
pub struct RateLimitContext {
    /// User ID (if authenticated)
    pub user_id: Option<String>,

    /// User roles (for exemption checking)
    pub user_roles: Vec<String>,

    /// Client IP address
    pub client_ip: Option<IpAddr>,

    /// Operation name
    pub operation_name: Option<String>,

    /// Operation type (query, mutation, subscription)
    pub operation_type: OperationType,

    /// Target subgraph (if known)
    pub subgraph: Option<String>,

    /// Product scope
    pub product: String,
}

/// GraphQL operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    Query,
    Mutation,
    Subscription,
}

impl OperationType {
    /// Parse operation type from query string
    pub fn from_query(query: &str) -> Self {
        let query_lower = query.trim().to_lowercase();
        if query_lower.starts_with("mutation") {
            OperationType::Mutation
        } else if query_lower.starts_with("subscription") {
            OperationType::Subscription
        } else {
            OperationType::Query
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            OperationType::Query => "query",
            OperationType::Mutation => "mutation",
            OperationType::Subscription => "subscription",
        }
    }
}

/// Type alias for the rate limiter
type KeyedLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Federation rate limiter
pub struct FederationRateLimiter {
    /// Configuration
    config: RateLimitConfig,

    /// Per-user rate limiters
    user_limiters: DashMap<String, Arc<KeyedLimiter>>,

    /// Per-operation rate limiters (keyed by pattern)
    operation_limiters: HashMap<String, Arc<KeyedLimiter>>,

    /// Per-subgraph rate limiters
    subgraph_limiters: HashMap<String, Arc<KeyedLimiter>>,

    /// Default rate limiter quota
    default_limiter_quota: governor::Quota,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl FederationRateLimiter {
    /// Create a new federation rate limiter
    pub fn new(config: RateLimitConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        // Create operation limiters using shared QuotaParams
        let mut operation_limiters = HashMap::with_capacity(config.operation_limits.len());
        for limit in &config.operation_limits {
            let burst = limit.burst_size.unwrap_or(config.burst_size);
            let params = QuotaParams {
                requests_per_second: limit.requests_per_second,
                burst_size: burst,
            };
            operation_limiters
                .insert(limit.pattern.clone(), Arc::new(RateLimiter::direct(params.to_quota())));
        }

        // Create subgraph limiters using shared QuotaParams
        let mut subgraph_limiters = HashMap::with_capacity(config.subgraph_limits.len());
        for limit in &config.subgraph_limits {
            let burst = limit.burst_size.unwrap_or(config.burst_size);
            let params = QuotaParams {
                requests_per_second: limit.requests_per_second,
                burst_size: burst,
            };
            subgraph_limiters
                .insert(limit.subgraph.clone(), Arc::new(RateLimiter::direct(params.to_quota())));
        }

        // Default quota using shared QuotaParams
        let default_params = QuotaParams {
            requests_per_second: config.default_rps,
            burst_size: config.burst_size,
        };
        let default_limiter_quota = default_params.to_quota();

        info!(
            default_rps = config.default_rps,
            burst_size = config.burst_size,
            operation_limits = operation_limiters.len(),
            subgraph_limits = subgraph_limiters.len(),
            exempt_roles = ?config.exempt_roles,
            "Federation rate limiter initialized"
        );

        Self {
            config,
            user_limiters: DashMap::new(),
            operation_limiters,
            subgraph_limiters,
            default_limiter_quota,
            metrics,
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check rate limit for a request
    pub fn check(&self, ctx: &RateLimitContext) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        // Check exemptions
        if let Some(exemption) = self.check_exemption(ctx) {
            return exemption;
        }

        // Get the rate limit key
        let key = self.get_key(ctx);

        // Check user/IP rate limit
        if let Some(result) = self.check_user_limit(&key) {
            self.metrics
                .incr("bff.federation.rate_limit.user_limited", &[]);
            return result;
        }

        // Check operation-specific rate limit
        if let Some(result) = self.check_operation_limit(ctx) {
            self.metrics
                .incr("bff.federation.rate_limit.operation_limited", &[]);
            return result;
        }

        // Check subgraph-specific rate limit
        if let Some(result) = self.check_subgraph_limit(ctx) {
            self.metrics
                .incr("bff.federation.rate_limit.subgraph_limited", &[]);
            return result;
        }

        // All checks passed
        self.metrics
            .incr("bff.federation.rate_limit.allowed", &[]);

        RateLimitResult::Allowed
    }

    /// Check if user is exempt from rate limiting
    fn check_exemption(&self, ctx: &RateLimitContext) -> Option<RateLimitResult> {
        for role in &ctx.user_roles {
            if self.config.exempt_roles.contains(role) {
                self.metrics.incr(
                    "bff.federation.rate_limit.exempt",
                    &[("role", role.as_str())],
                );
                return Some(RateLimitResult::Exempt {
                    reason: format!("role:{}", role),
                });
            }
        }
        None
    }

    /// Get the rate limit key for a request
    #[inline]
    fn get_key(&self, ctx: &RateLimitContext) -> String {
        if let Some(ref user_id) = ctx.user_id {
            format!("user:{}", user_id)
        } else if self.config.use_ip_fallback {
            if let Some(ip) = ctx.client_ip {
                format!("ip:{}", ip)
            } else {
                "anonymous".to_string()
            }
        } else {
            "anonymous".to_string()
        }
    }

    /// Check user/IP rate limit
    fn check_user_limit(&self, key: &str) -> Option<RateLimitResult> {
        let limiter = self
            .user_limiters
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(RateLimiter::direct(self.default_limiter_quota)));

        match limiter.check() {
            Ok(()) => None,
            Err(_not_until) => Some(RateLimitResult::Limited {
                retry_after_ms: 1000,
                limiter: "user".to_string(),
            }),
        }
    }

    /// Check operation-specific rate limit
    fn check_operation_limit(&self, ctx: &RateLimitContext) -> Option<RateLimitResult> {
        let op_name = ctx.operation_name.as_deref().unwrap_or("anonymous");
        let op_type = ctx.operation_type.as_str();

        for (pattern, limiter) in &self.operation_limiters {
            if Self::matches_pattern(pattern, op_name) || Self::matches_pattern(pattern, op_type) {
                let limiter: &KeyedLimiter = limiter.as_ref();
                match limiter.check() {
                    Ok(()) => return None,
                    Err(_not_until) => {
                        return Some(RateLimitResult::Limited {
                            retry_after_ms: 1000,
                            limiter: format!("operation:{}", pattern),
                        });
                    }
                }
            }
        }

        None
    }

    /// Check subgraph-specific rate limit
    fn check_subgraph_limit(&self, ctx: &RateLimitContext) -> Option<RateLimitResult> {
        let subgraph = ctx.subgraph.as_ref()?;

        if let Some(limiter) = self.subgraph_limiters.get(subgraph) {
            let limiter: &KeyedLimiter = limiter.as_ref();
            match limiter.check() {
                Ok(()) => None,
                Err(_not_until) => Some(RateLimitResult::Limited {
                    retry_after_ms: 1000,
                    limiter: format!("subgraph:{}", subgraph),
                }),
            }
        } else {
            None
        }
    }

    /// Check if a value matches a pattern (supports * wildcard)
    #[inline]
    fn matches_pattern(pattern: &str, value: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            value.starts_with(prefix)
        } else {
            pattern == value
        }
    }

    /// Clean up old limiters to prevent memory growth
    pub fn cleanup(&self) {
        if self.user_limiters.len() > self.config.max_keys {
            let to_remove = self.user_limiters.len() - self.config.max_keys;
            let mut removed = 0;

            self.user_limiters.retain(|_, _| {
                if removed < to_remove {
                    removed += 1;
                    false
                } else {
                    true
                }
            });

            self.metrics
                .count("bff.federation.rate_limit.cleanup", removed as i64, &[]);

            debug!(removed = removed, "Rate limiter cleanup completed");
        }
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            tracked_keys: self.user_limiters.len(),
            operation_limiters: self.operation_limiters.len(),
            subgraph_limiters: self.subgraph_limiters.len(),
        }
    }
}

/// Rate limiter statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    /// Number of tracked user/IP keys
    pub tracked_keys: usize,

    /// Number of operation-specific limiters
    pub operation_limiters: usize,

    /// Number of subgraph-specific limiters
    pub subgraph_limiters: usize,
}

/// Helper to build rate limit error response
pub struct RateLimitErrorResponse;

impl RateLimitErrorResponse {
    /// Create a GraphQL rate limit error response
    pub fn to_graphql(retry_after_ms: u64, limiter: &str) -> serde_json::Value {
        error::to_graphql_json(retry_after_ms, limiter)
    }

    /// Create HTTP headers for rate limit response
    pub fn headers(retry_after_ms: u64) -> Vec<(String, String)> {
        error::rate_limit_headers(retry_after_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_type_parsing() {
        assert_eq!(
            OperationType::from_query("query { users { id } }"),
            OperationType::Query
        );
        assert_eq!(
            OperationType::from_query("mutation { createUser { id } }"),
            OperationType::Mutation
        );
        assert_eq!(
            OperationType::from_query("subscription { onUserCreated { id } }"),
            OperationType::Subscription
        );
        assert_eq!(
            OperationType::from_query("{ users { id } }"),
            OperationType::Query
        );
    }

    #[test]
    fn test_pattern_matching() {
        assert!(FederationRateLimiter::matches_pattern(
            "mutation*",
            "mutation"
        ));
        assert!(FederationRateLimiter::matches_pattern(
            "mutation*",
            "mutationCreateUser"
        ));
        assert!(!FederationRateLimiter::matches_pattern(
            "mutation*",
            "query"
        ));
        assert!(FederationRateLimiter::matches_pattern(
            "createUser",
            "createUser"
        ));
        assert!(!FederationRateLimiter::matches_pattern(
            "createUser",
            "updateUser"
        ));
    }

    #[test]
    fn test_rate_limiter_creation() {
        let config = RateLimitConfig {
            operation_limits: vec![OperationRateLimit {
                pattern: "mutation*".to_string(),
                requests_per_second: 10,
                burst_size: Some(20),
            }],
            subgraph_limits: vec![SubgraphRateLimit {
                subgraph: "auth".to_string(),
                requests_per_second: 50,
                burst_size: None,
            }],
            ..Default::default()
        };

        let limiter = FederationRateLimiter::new(config, None);
        assert!(limiter.is_enabled());

        let stats = limiter.stats();
        assert_eq!(stats.operation_limiters, 1);
        assert_eq!(stats.subgraph_limiters, 1);
    }

    #[test]
    fn test_exemption() {
        let config = RateLimitConfig {
            exempt_roles: vec!["admin".to_string()],
            ..Default::default()
        };

        let limiter = FederationRateLimiter::new(config, None);

        let ctx = RateLimitContext {
            user_id: Some("user-1".to_string()),
            user_roles: vec!["admin".to_string()],
            client_ip: None,
            operation_name: None,
            operation_type: OperationType::Query,
            subgraph: None,
            product: "novaskyn".to_string(),
        };

        let result = limiter.check(&ctx);
        assert!(matches!(result, RateLimitResult::Exempt { .. }));
    }

    #[test]
    fn test_rate_limiting_flow() {
        let config = RateLimitConfig {
            default_rps: 1,
            burst_size: 1,
            ..Default::default()
        };

        let limiter = FederationRateLimiter::new(config, None);

        let ctx = RateLimitContext {
            user_id: Some("user-1".to_string()),
            user_roles: vec![],
            client_ip: None,
            operation_name: Some("getUsers".to_string()),
            operation_type: OperationType::Query,
            subgraph: None,
            product: "novaskyn".to_string(),
        };

        // First request should be allowed
        let result = limiter.check(&ctx);
        assert!(matches!(result, RateLimitResult::Allowed));

        // Second request should be rate limited (only 1 request allowed)
        let result = limiter.check(&ctx);
        assert!(matches!(result, RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_disabled_rate_limiting() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };

        let limiter = FederationRateLimiter::new(config, None);

        let ctx = RateLimitContext {
            user_id: None,
            user_roles: vec![],
            client_ip: None,
            operation_name: None,
            operation_type: OperationType::Query,
            subgraph: None,
            product: "novaskyn".to_string(),
        };

        for _ in 0..100 {
            let result = limiter.check(&ctx);
            assert!(matches!(result, RateLimitResult::Allowed));
        }
    }

    #[test]
    fn test_key_generation() {
        let config = RateLimitConfig::default();
        let limiter = FederationRateLimiter::new(config, None);

        let ctx = RateLimitContext {
            user_id: Some("user-123".to_string()),
            user_roles: vec![],
            client_ip: Some("192.168.1.1".parse().unwrap()),
            operation_name: None,
            operation_type: OperationType::Query,
            subgraph: None,
            product: "novaskyn".to_string(),
        };
        assert_eq!(limiter.get_key(&ctx), "user:user-123");

        let ctx = RateLimitContext {
            user_id: None,
            user_roles: vec![],
            client_ip: Some("192.168.1.1".parse().unwrap()),
            operation_name: None,
            operation_type: OperationType::Query,
            subgraph: None,
            product: "novaskyn".to_string(),
        };
        assert_eq!(limiter.get_key(&ctx), "ip:192.168.1.1");
    }

    #[test]
    fn test_rate_limit_error_response() {
        let response = RateLimitErrorResponse::to_graphql(5000, "user");
        assert_eq!(
            response["errors"][0]["extensions"]["code"]
                .as_str()
                .unwrap(),
            "RATE_LIMITED"
        );
        assert_eq!(
            response["errors"][0]["extensions"]["retryAfterMs"].as_u64(),
            Some(5000)
        );

        let headers = RateLimitErrorResponse::headers(5000);
        assert_eq!(headers.len(), 2);
    }
}
