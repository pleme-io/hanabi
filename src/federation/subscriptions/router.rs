//! Subscription routing - determines which subgraph handles each subscription
//!
//! Parses the subscription query to extract the field name, then looks up
//! which subgraph owns that subscription field using the supergraph schema.

use once_cell::sync::Lazy;
use regex::Regex;
use thiserror::Error;
use tracing::{debug, warn};

use crate::federation::supergraph::Supergraph;

/// PERFORMANCE: Pre-compiled regex for subscription field extraction.
/// Compiled once at first use, reused for all subsequent calls.
/// Pattern: subscription [OperationName] { fieldName...
static SUBSCRIPTION_FIELD_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"subscription\s*(?:\w+)?\s*(?:\([^)]*\))?\s*\{\s*(\w+)")
        .expect("Invalid subscription field regex pattern")
});

/// Routes subscription requests to the appropriate subgraph
pub struct SubscriptionRouter {
    /// Map of subscription field name → subgraph name
    routes: std::collections::HashMap<String, String>,
}

impl SubscriptionRouter {
    /// Create a new router from a parsed supergraph
    pub fn new(supergraph: &Supergraph) -> Self {
        Self {
            routes: supergraph.subscription_routes.clone(),
        }
    }

    /// Determine which subgraph should handle a subscription query
    ///
    /// # Arguments
    /// * `query` - The GraphQL subscription query
    ///
    /// # Returns
    /// The subgraph name (e.g., "job-scheduler") if found
    pub fn route(&self, query: &str) -> Result<String, SubscriptionRouterError> {
        // Extract the subscription field name from the query
        // Examples:
        //   "subscription { jobsUpdated { id name } }" → "jobsUpdated"
        //   "subscription JobsWatch { jobsUpdated(statuses: [RUNNING]) { id } }" → "jobsUpdated"
        //   "subscription { onNewMessage(conversationId: \"...\") { content } }" → "onNewMessage"

        let field_name = Self::extract_subscription_field(query)?;

        debug!("Extracted subscription field: {}", field_name);

        // Look up the subgraph for this field
        self.routes.get(&field_name).cloned().ok_or_else(|| {
            warn!("No route found for subscription field: {}", field_name);
            SubscriptionRouterError::UnknownField(field_name)
        })
    }

    /// Extract the first field name from a subscription query
    fn extract_subscription_field(query: &str) -> Result<String, SubscriptionRouterError> {
        // Remove comments and normalize whitespace
        let query = query.trim();

        // PERFORMANCE: Uses pre-compiled lazy regex (100x faster than per-call compilation)
        // Pattern: subscription [OperationName] { fieldName...
        SUBSCRIPTION_FIELD_REGEX
            .captures(query)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .ok_or_else(|| {
                SubscriptionRouterError::ParseError(
                    "Could not extract subscription field from query".to_string(),
                )
            })
    }

    /// Check if a query is a subscription operation
    pub fn is_subscription(query: &str) -> bool {
        let query = query.trim().to_lowercase();

        // Check for subscription keyword at the start
        query.starts_with("subscription") ||
        // Or after a comment block
        query.lines()
            .find(|line| !line.trim().starts_with('#'))
            .map(|first_line| first_line.trim().to_lowercase().starts_with("subscription"))
            .unwrap_or(false)
    }

    /// Get all known subscription fields
    pub fn known_fields(&self) -> Vec<&str> {
        self.routes.keys().map(|s| s.as_str()).collect()
    }
}

#[derive(Debug, Error)]
pub enum SubscriptionRouterError {
    #[error("Failed to parse subscription query: {0}")]
    ParseError(String),

    #[error("Unknown subscription field: {0}")]
    UnknownField(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_router() -> SubscriptionRouter {
        let mut routes = HashMap::new();
        routes.insert("jobsUpdated".to_string(), "job-scheduler".to_string());
        routes.insert("jobUpdated".to_string(), "job-scheduler".to_string());
        routes.insert("onNewMessage".to_string(), "chat".to_string());
        routes.insert("onTypingStatusChanged".to_string(), "chat".to_string());

        SubscriptionRouter { routes }
    }

    #[test]
    fn test_extract_simple_subscription() {
        let query = "subscription { jobsUpdated { id name } }";
        let field = SubscriptionRouter::extract_subscription_field(query).unwrap();
        assert_eq!(field, "jobsUpdated");
    }

    #[test]
    fn test_extract_named_subscription() {
        let query = "subscription JobsWatch { jobsUpdated { id name } }";
        let field = SubscriptionRouter::extract_subscription_field(query).unwrap();
        assert_eq!(field, "jobsUpdated");
    }

    #[test]
    fn test_extract_subscription_with_args() {
        let query = r#"subscription { onNewMessage(conversationId: "abc-123") { content } }"#;
        let field = SubscriptionRouter::extract_subscription_field(query).unwrap();
        assert_eq!(field, "onNewMessage");
    }

    #[test]
    fn test_extract_subscription_with_variables() {
        let query = "subscription JobsWatch($statuses: [JobStatus!]) { jobsUpdated(statuses: $statuses) { id } }";
        let field = SubscriptionRouter::extract_subscription_field(query).unwrap();
        assert_eq!(field, "jobsUpdated");
    }

    #[test]
    fn test_route_to_job_scheduler() {
        let router = test_router();
        let query = "subscription { jobsUpdated { id } }";
        let subgraph = router.route(query).unwrap();
        assert_eq!(subgraph, "job-scheduler");
    }

    #[test]
    fn test_route_to_chat() {
        let router = test_router();
        let query = "subscription { onNewMessage(conversationId: \"123\") { content } }";
        let subgraph = router.route(query).unwrap();
        assert_eq!(subgraph, "chat");
    }

    #[test]
    fn test_route_unknown_field() {
        let router = test_router();
        let query = "subscription { unknownField { id } }";
        let result = router.route(query);
        assert!(matches!(
            result,
            Err(SubscriptionRouterError::UnknownField(_))
        ));
    }

    #[test]
    fn test_is_subscription() {
        assert!(SubscriptionRouter::is_subscription(
            "subscription { jobsUpdated { id } }"
        ));
        assert!(SubscriptionRouter::is_subscription(
            "subscription JobsWatch { jobsUpdated { id } }"
        ));
        assert!(SubscriptionRouter::is_subscription(
            "  subscription { foo }"
        ));
        assert!(!SubscriptionRouter::is_subscription(
            "query { users { id } }"
        ));
        assert!(!SubscriptionRouter::is_subscription(
            "mutation { createUser { id } }"
        ));
    }
}
