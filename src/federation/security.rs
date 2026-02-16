#![allow(dead_code)]
//! GraphQL Security Module
//!
//! Implements security features to protect against malicious queries:
//! - Query depth limiting (DoS protection)
//! - Query complexity analysis (cost-based rejection)
//! - Introspection control (disable in production)
//!
//! # Why These Matter
//!
//! According to security research, 80% of GraphQL APIs are vulnerable to DoS attacks
//! via deeply nested or expensive queries. These protections mitigate:
//! - Resource exhaustion from deeply nested queries
//! - CPU/memory spikes from complex field resolution
//! - Information disclosure via introspection in production
//!
//! # References
//! - [GraphQL Security Best Practices](https://graphql.org/learn/security/)
//! - [Apollo GraphQL Security Checklist](https://www.apollographql.com/blog/9-ways-to-secure-your-graphql-api-security-checklist)

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::metrics::{MetricsClient, MetricsExt};

/// Security-related errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Query depth {depth} exceeds maximum allowed depth of {max_depth}")]
    DepthLimitExceeded { depth: usize, max_depth: usize },

    #[error(
        "Query complexity {complexity} exceeds maximum allowed complexity of {max_complexity}"
    )]
    ComplexityLimitExceeded {
        complexity: u32,
        max_complexity: u32,
    },

    #[error("Introspection queries are disabled in this environment")]
    IntrospectionDisabled,

    #[error("Query parsing error: {0}")]
    ParseError(String),
}

/// Query depth limiter configuration
#[derive(Debug, Clone)]
pub struct DepthLimitConfig {
    /// Maximum allowed query depth
    pub max_depth: usize,

    /// Allow introspection queries to exceed depth limit
    /// (Introspection queries have depth ~13, common limit is 5-10)
    pub allow_introspection_depth_override: bool,

    /// Custom depth limits per operation name
    pub operation_limits: HashMap<String, usize>,
}

impl Default for DepthLimitConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            allow_introspection_depth_override: true,
            operation_limits: HashMap::new(),
        }
    }
}

/// Query depth analyzer
///
/// Calculates the nesting depth of a GraphQL query and enforces limits.
///
/// # Example
/// ```text
/// query {                    # depth 0
///   user {                   # depth 1
///     posts {                # depth 2
///       comments {           # depth 3
///         author {           # depth 4
///           name             # depth 5
///         }
///       }
///     }
///   }
/// }
/// ```
pub struct DepthLimiter {
    config: DepthLimitConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl DepthLimiter {
    /// Create a new depth limiter
    pub fn new(config: DepthLimitConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    /// Validate query depth
    ///
    /// Returns Ok(depth) if within limits, Err if exceeded
    pub fn validate(
        &self,
        query: &str,
        operation_name: Option<&str>,
    ) -> Result<usize, SecurityError> {
        // Quick check for introspection
        let is_introspection = Self::is_introspection_query(query);

        // Calculate depth
        let depth = self.calculate_depth(query)?;

        // Determine applicable limit
        let max_depth = if let Some(op_name) = operation_name {
            self.config
                .operation_limits
                .get(op_name)
                .copied()
                .unwrap_or(self.config.max_depth)
        } else {
            self.config.max_depth
        };

        // Check if introspection can override
        let effective_limit = if is_introspection && self.config.allow_introspection_depth_override
        {
            usize::MAX // No limit for introspection
        } else {
            max_depth
        };

        if depth > effective_limit {
            self.metrics.incr("bff.federation.security.depth_exceeded", &[]);
            warn!(
                depth = depth,
                max_depth = max_depth,
                operation = operation_name.unwrap_or("anonymous"),
                "Query depth limit exceeded"
            );
            return Err(SecurityError::DepthLimitExceeded {
                depth,
                max_depth: effective_limit,
            });
        }

        self.metrics.histogram("bff.federation.security.query_depth", depth as f64, &[]);

        debug!(
            depth = depth,
            max_depth = max_depth,
            "Query depth within limits"
        );
        Ok(depth)
    }

    /// Calculate query depth by parsing the structure
    fn calculate_depth(&self, query: &str) -> Result<usize, SecurityError> {
        // Simple bracket-counting depth calculator
        // For production, could use graphql-parser crate for accurate AST analysis
        let mut max_depth: usize = 0;
        let mut current_depth: usize = 0;
        let mut in_string = false;
        let mut prev_char = ' ';

        for ch in query.chars() {
            // Handle string escaping
            if ch == '"' && prev_char != '\\' {
                in_string = !in_string;
            }

            if !in_string {
                match ch {
                    '{' => {
                        current_depth += 1;
                        max_depth = max_depth.max(current_depth);
                    }
                    '}' => {
                        current_depth = current_depth.saturating_sub(1);
                    }
                    _ => {}
                }
            }

            prev_char = ch;
        }

        Ok(max_depth)
    }

    /// Check if query is an introspection query
    fn is_introspection_query(query: &str) -> bool {
        query.contains("__schema") || query.contains("__type")
    }
}

/// Query complexity configuration
#[derive(Debug, Clone)]
pub struct ComplexityConfig {
    /// Maximum allowed complexity score
    pub max_complexity: u32,

    /// Default cost per field
    pub default_field_cost: u32,

    /// Cost multiplier for list fields (applied to depth)
    pub list_multiplier: u32,

    /// Custom costs per field (type.field → cost)
    pub field_costs: HashMap<String, u32>,

    /// Fields that are "free" (cost 0)
    pub free_fields: HashSet<String>,
}

impl Default for ComplexityConfig {
    fn default() -> Self {
        let mut free_fields = HashSet::new();
        // Scalar fields are typically free
        free_fields.insert("id".to_string());
        free_fields.insert("__typename".to_string());

        Self {
            max_complexity: 1000,
            default_field_cost: 1,
            list_multiplier: 10,
            field_costs: HashMap::new(),
            free_fields,
        }
    }
}

/// Query complexity analyzer
///
/// Estimates query cost before execution to prevent expensive queries.
///
/// # Algorithm
/// Each field gets a base cost (default: 1).
/// List fields multiply cost by list_multiplier.
/// Custom costs can be assigned per field.
///
/// # Example
/// ```text
/// query {
///   products(first: 100) {    # cost: 1 (query) + 100 * (
///     name                     #   1 +
///     reviews {                #   10 * (
///       text                   #     1 +
///       author {               #     1 * (
///         name                 #       1
///       }                      #     ) = 2
///     }                        #   ) = 30
///   }                          # ) = 3100
/// }
/// ```
pub struct ComplexityAnalyzer {
    config: ComplexityConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl ComplexityAnalyzer {
    /// Create a new complexity analyzer
    pub fn new(config: ComplexityConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    /// Validate query complexity
    ///
    /// Returns Ok(complexity) if within limits, Err if exceeded
    pub fn validate(
        &self,
        query: &str,
        operation_name: Option<&str>,
    ) -> Result<u32, SecurityError> {
        let complexity = self.calculate_complexity(query)?;

        if complexity > self.config.max_complexity {
            self.metrics.incr("bff.federation.security.complexity_exceeded", &[]);
            warn!(
                complexity = complexity,
                max_complexity = self.config.max_complexity,
                operation = operation_name.unwrap_or("anonymous"),
                "Query complexity limit exceeded"
            );
            return Err(SecurityError::ComplexityLimitExceeded {
                complexity,
                max_complexity: self.config.max_complexity,
            });
        }

        self.metrics.histogram(
            "bff.federation.security.query_complexity",
            complexity as f64,
            &[],
        );

        debug!(
            complexity = complexity,
            max_complexity = self.config.max_complexity,
            "Query complexity within limits"
        );
        Ok(complexity)
    }

    /// Calculate complexity score
    fn calculate_complexity(&self, query: &str) -> Result<u32, SecurityError> {
        // Simplified complexity calculation
        // For production, use graphql-parser for accurate AST analysis

        let mut complexity: u32 = 0;
        let mut depth_multiplier: u32 = 1;
        let mut in_string = false;
        let mut prev_char = ' ';
        let mut current_field = String::new();
        let mut in_field_name = false;

        for ch in query.chars() {
            // Handle string escaping
            if ch == '"' && prev_char != '\\' {
                in_string = !in_string;
            }

            if !in_string {
                match ch {
                    '{' => {
                        // Check if preceding field is a list (has arguments like first:, limit:)
                        let has_list_arg = current_field.contains("first")
                            || current_field.contains("limit")
                            || current_field.contains("last");

                        if has_list_arg {
                            depth_multiplier =
                                depth_multiplier.saturating_mul(self.config.list_multiplier);
                        }

                        current_field.clear();
                        in_field_name = false;
                    }
                    '}' => {
                        // Pop list multiplier
                        if depth_multiplier > 1 {
                            depth_multiplier /= self.config.list_multiplier.max(1);
                            depth_multiplier = depth_multiplier.max(1);
                        }
                    }
                    '(' => {
                        in_field_name = false;
                    }
                    ')' => {
                        in_field_name = true;
                    }
                    _ if ch.is_alphanumeric() || ch == '_' => {
                        if in_field_name || (!current_field.is_empty() && prev_char.is_whitespace())
                        {
                            // Starting a new field name
                            if !current_field.is_empty() && !current_field.contains('(') {
                                // Add cost for the previous field
                                let field_cost = self.get_field_cost(&current_field);
                                complexity = complexity
                                    .saturating_add(field_cost.saturating_mul(depth_multiplier));
                            }
                            current_field.clear();
                            in_field_name = true;
                        }
                        if in_field_name {
                            current_field.push(ch);
                        }
                    }
                    _ if ch.is_whitespace() => {
                        // End of current token
                    }
                    _ => {}
                }
            }

            prev_char = ch;
        }

        // Don't count below the default field cost
        Ok(complexity.max(self.config.default_field_cost))
    }

    /// Get cost for a specific field
    fn get_field_cost(&self, field_name: &str) -> u32 {
        // Check free fields
        if self.config.free_fields.contains(field_name) {
            return 0;
        }

        // Check custom costs
        if let Some(cost) = self.config.field_costs.get(field_name) {
            return *cost;
        }

        self.config.default_field_cost
    }
}

/// Introspection control configuration
#[derive(Debug, Clone)]
pub struct IntrospectionConfig {
    /// Allow introspection queries
    pub enabled: bool,

    /// Allow introspection for specific IP addresses (e.g., localhost)
    pub allowed_ips: Vec<String>,

    /// Allow introspection for requests with specific headers
    pub allowed_headers: Vec<(String, String)>,
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: true, // Enabled by default for development
            allowed_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
            allowed_headers: vec![],
        }
    }
}

/// Introspection controller
///
/// Controls access to introspection queries based on environment and context.
pub struct IntrospectionController {
    config: IntrospectionConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl IntrospectionController {
    /// Create a new introspection controller
    pub fn new(config: IntrospectionConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    /// Check if introspection is allowed for this request
    ///
    /// # Arguments
    /// * `query` - The GraphQL query string
    /// * `client_ip` - The client's IP address
    /// * `headers` - Request headers as key-value pairs
    pub fn validate(
        &self,
        query: &str,
        client_ip: Option<&str>,
        headers: &[(String, String)],
    ) -> Result<(), SecurityError> {
        // Quick check if query contains introspection
        if !Self::is_introspection_query(query) {
            return Ok(());
        }

        // If introspection is globally enabled, allow
        if self.config.enabled {
            return Ok(());
        }

        // Check allowed IPs
        if let Some(ip) = client_ip {
            if self.config.allowed_ips.iter().any(|allowed| allowed == ip) {
                debug!(ip = ip, "Introspection allowed for IP");
                return Ok(());
            }
        }

        // Check allowed headers
        for (required_key, required_value) in &self.config.allowed_headers {
            for (key, value) in headers {
                if key.eq_ignore_ascii_case(required_key) && value == required_value {
                    debug!(header = required_key, "Introspection allowed for header");
                    return Ok(());
                }
            }
        }

        // Introspection blocked
        self.metrics.incr("bff.federation.security.introspection_blocked", &[]);
        info!(
            client_ip = client_ip.unwrap_or("unknown"),
            "Introspection query blocked"
        );
        Err(SecurityError::IntrospectionDisabled)
    }

    /// Check if query is an introspection query
    fn is_introspection_query(query: &str) -> bool {
        query.contains("__schema") || query.contains("__type")
    }
}

/// Combined security validator
///
/// Aggregates all security checks into a single validation call.
pub struct SecurityValidator {
    depth_limiter: Option<DepthLimiter>,
    complexity_analyzer: Option<ComplexityAnalyzer>,
    introspection_controller: Option<IntrospectionController>,
    metrics: Option<Arc<MetricsClient>>,
}

/// Security validation result
#[derive(Debug)]
pub struct SecurityValidationResult {
    /// Query depth (if calculated)
    pub depth: Option<usize>,

    /// Query complexity (if calculated)
    pub complexity: Option<u32>,

    /// Whether introspection was detected
    pub is_introspection: bool,
}

impl SecurityValidator {
    /// Create a new security validator
    pub fn new(
        depth_config: Option<DepthLimitConfig>,
        complexity_config: Option<ComplexityConfig>,
        introspection_config: Option<IntrospectionConfig>,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        let depth_limiter = depth_config.map(|c| DepthLimiter::new(c, metrics.clone()));
        let complexity_analyzer =
            complexity_config.map(|c| ComplexityAnalyzer::new(c, metrics.clone()));
        let introspection_controller =
            introspection_config.map(|c| IntrospectionController::new(c, metrics.clone()));

        Self {
            depth_limiter,
            complexity_analyzer,
            introspection_controller,
            metrics,
        }
    }

    /// Validate a query against all enabled security rules
    ///
    /// # Arguments
    /// * `query` - The GraphQL query string
    /// * `operation_name` - Optional operation name
    /// * `client_ip` - Optional client IP address
    /// * `headers` - Request headers as key-value pairs
    pub fn validate(
        &self,
        query: &str,
        operation_name: Option<&str>,
        client_ip: Option<&str>,
        headers: &[(String, String)],
    ) -> Result<SecurityValidationResult, SecurityError> {
        let is_introspection = query.contains("__schema") || query.contains("__type");

        // Check introspection first (fastest check)
        if let Some(ref controller) = self.introspection_controller {
            controller.validate(query, client_ip, headers)?;
        }

        // Check depth
        let depth = if let Some(ref limiter) = self.depth_limiter {
            Some(limiter.validate(query, operation_name)?)
        } else {
            None
        };

        // Check complexity
        let complexity = if let Some(ref analyzer) = self.complexity_analyzer {
            Some(analyzer.validate(query, operation_name)?)
        } else {
            None
        };

        self.metrics.incr("bff.federation.security.validation_passed", &[]);

        Ok(SecurityValidationResult {
            depth,
            complexity,
            is_introspection,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_depth_calculation() {
        let limiter = DepthLimiter::new(DepthLimitConfig::default(), None);

        // Simple query
        let query = r#"query { user { name } }"#;
        assert_eq!(limiter.calculate_depth(query).unwrap(), 2);

        // Nested query
        let query = r#"query { user { posts { comments { author { name } } } } }"#;
        assert_eq!(limiter.calculate_depth(query).unwrap(), 5);

        // Flat query
        let query = r#"query { user }"#;
        assert_eq!(limiter.calculate_depth(query).unwrap(), 1);
    }

    #[test]
    fn test_depth_limit_exceeded() {
        let config = DepthLimitConfig {
            max_depth: 3,
            allow_introspection_depth_override: false,
            ..Default::default()
        };
        let limiter = DepthLimiter::new(config, None);

        let query = r#"query { user { posts { comments { author { name } } } } }"#;
        let result = limiter.validate(query, None);

        assert!(matches!(
            result,
            Err(SecurityError::DepthLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_introspection_detection() {
        assert!(DepthLimiter::is_introspection_query(
            "query { __schema { types { name } } }"
        ));
        assert!(DepthLimiter::is_introspection_query(
            "query { __type(name: \"User\") { name } }"
        ));
        assert!(!DepthLimiter::is_introspection_query(
            "query { user { name } }"
        ));
    }

    #[test]
    fn test_complexity_calculation() {
        let analyzer = ComplexityAnalyzer::new(ComplexityConfig::default(), None);

        let query = r#"query { user { name email } }"#;
        let complexity = analyzer.calculate_complexity(query).unwrap();
        assert!(complexity >= 1);
    }

    #[test]
    fn test_introspection_blocked() {
        let config = IntrospectionConfig {
            enabled: false,
            allowed_ips: vec![],
            allowed_headers: vec![],
        };
        let controller = IntrospectionController::new(config, None);

        let query = "query { __schema { types { name } } }";
        let result = controller.validate(query, Some("10.0.0.1"), &[]);

        assert!(matches!(result, Err(SecurityError::IntrospectionDisabled)));
    }

    #[test]
    fn test_introspection_allowed_for_ip() {
        let config = IntrospectionConfig {
            enabled: false,
            allowed_ips: vec!["127.0.0.1".to_string()],
            allowed_headers: vec![],
        };
        let controller = IntrospectionController::new(config, None);

        let query = "query { __schema { types { name } } }";
        let result = controller.validate(query, Some("127.0.0.1"), &[]);

        assert!(result.is_ok());
    }
}
