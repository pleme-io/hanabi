#![allow(dead_code)]
//! Entity-Level Cache Control
//!
//! Parses @cacheControl directives from GraphQL schema to configure
//! per-entity and per-field cache TTLs.
//!
//! # Schema Directive Format
//!
//! The @cacheControl directive (Apollo Federation standard) can be applied to:
//! - Object types (applies to all queries returning this type)
//! - Fields (applies to specific field queries)
//!
//! ```graphql
//! directive @cacheControl(
//!   maxAge: Int
//!   scope: CacheControlScope
//!   inheritMaxAge: Boolean
//! ) on FIELD_DEFINITION | OBJECT | INTERFACE | UNION
//!
//! enum CacheControlScope {
//!   PUBLIC
//!   PRIVATE
//! }
//!
//! type Product @cacheControl(maxAge: 300) {
//!   id: ID!
//!   name: String!
//!   price: Float! @cacheControl(maxAge: 60)  # More volatile
//!   reviews: [Review!]! @cacheControl(maxAge: 30)
//! }
//!
//! type User @cacheControl(maxAge: 0, scope: PRIVATE) {
//!   id: ID!
//!   email: String!
//! }
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! let schema_sdl = fs::read_to_string("supergraph.graphql")?;
//! let cache_hints = EntityCacheHints::from_schema(&schema_sdl)?;
//!
//! // Get TTL for a specific type
//! let product_ttl = cache_hints.get_type_ttl("Product"); // Some(300)
//! let user_ttl = cache_hints.get_type_ttl("User"); // Some(0) = no cache
//!
//! // Get TTL for a specific field
//! let price_ttl = cache_hints.get_field_ttl("Product", "price"); // Some(60)
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use std::sync::LazyLock;
use thiserror::Error;
use tracing::{debug, info};

use crate::metrics::MetricsClient;

/// Regex to match @cacheControl directive on type definitions
/// Captures: 1=type name, 2=full directive args
static TYPE_CACHE_CONTROL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"type\s+(\w+)[^{]*@cacheControl\s*\(([^)]+)\)"#)
        .expect("Valid regex for type @cacheControl")
});

/// Regex to match @cacheControl directive on field definitions
static FIELD_CACHE_CONTROL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(\w+)\s*(?:\([^)]*\))?\s*:\s*[^@\n]+@cacheControl\s*\(\s*maxAge:\s*(\d+)"#)
        .expect("Valid regex for field @cacheControl")
});

/// Regex to match scope in @cacheControl
static SCOPE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"scope:\s*(PUBLIC|PRIVATE)"#).expect("Valid regex for scope"));

/// Regex to match maxAge in directive args
static MAX_AGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"maxAge:\s*(\d+)"#).expect("Valid regex for maxAge"));

/// Errors that can occur during cache hint parsing
#[derive(Debug, Error)]
pub enum EntityCacheError {
    #[error("Failed to parse schema: {0}")]
    ParseError(String),

    #[error("Invalid maxAge value: {0}")]
    InvalidMaxAge(String),
}

/// Cache control scope
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheScope {
    /// Cacheable by any cache (CDN, browser, BFF)
    #[default]
    Public,
    /// Only cacheable per-user (requires user context in cache key)
    Private,
}

/// Cache hint for a single type or field
#[derive(Debug, Clone)]
pub struct CacheHint {
    /// Maximum age in seconds (0 = no cache)
    pub max_age: u64,
    /// Cache scope
    pub scope: CacheScope,
    /// Whether to inherit maxAge from parent type
    pub inherit_max_age: bool,
}

impl Default for CacheHint {
    fn default() -> Self {
        Self {
            max_age: 60, // Default 60 second TTL
            scope: CacheScope::Public,
            inherit_max_age: false,
        }
    }
}

impl CacheHint {
    /// Create a cache hint from parsed values
    pub fn new(max_age: u64, scope: CacheScope) -> Self {
        Self {
            max_age,
            scope,
            inherit_max_age: false,
        }
    }

    /// Convert to Duration
    pub fn as_duration(&self) -> Duration {
        Duration::from_secs(self.max_age)
    }

    /// Check if this hint indicates no caching
    pub fn is_no_cache(&self) -> bool {
        self.max_age == 0
    }

    /// Check if this is private (user-scoped)
    pub fn is_private(&self) -> bool {
        self.scope == CacheScope::Private
    }
}

/// Entity cache hints parsed from schema
#[derive(Clone)]
pub struct EntityCacheHints {
    /// Type-level cache hints (TypeName → CacheHint)
    type_hints: HashMap<String, CacheHint>,

    /// Field-level cache hints (TypeName.fieldName → CacheHint)
    field_hints: HashMap<String, CacheHint>,

    /// Default hint for types without explicit directive
    default_hint: CacheHint,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl EntityCacheHints {
    /// Create empty cache hints with default configuration
    pub fn new(metrics: Option<Arc<MetricsClient>>) -> Self {
        Self {
            type_hints: HashMap::new(),
            field_hints: HashMap::new(),
            default_hint: CacheHint::default(),
            metrics,
        }
    }

    /// Parse cache hints from schema SDL
    pub fn from_schema(
        schema_sdl: &str,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Result<Self, EntityCacheError> {
        let mut hints = Self::new(metrics);

        // Parse type-level @cacheControl directives
        for cap in TYPE_CACHE_CONTROL_RE.captures_iter(schema_sdl) {
            let type_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let directive_args = cap.get(2).map(|m| m.as_str()).unwrap_or("");

            // Extract maxAge from directive args
            let max_age = MAX_AGE_RE
                .captures(directive_args)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<u64>().ok())
                .unwrap_or(60);

            // Check for scope in directive args
            let scope = if let Some(scope_cap) = SCOPE_RE.captures(directive_args) {
                if scope_cap.get(1).map(|m| m.as_str()) == Some("PRIVATE") {
                    CacheScope::Private
                } else {
                    CacheScope::Public
                }
            } else {
                CacheScope::Public
            };

            debug!(
                type_name = type_name,
                max_age = max_age,
                scope = ?scope,
                "Parsed type cache hint"
            );

            hints
                .type_hints
                .insert(type_name.to_string(), CacheHint::new(max_age, scope));
        }

        // Parse field-level @cacheControl directives
        // This is more complex as we need context (which type the field belongs to)
        hints.parse_field_hints(schema_sdl)?;

        info!(
            type_hints = hints.type_hints.len(),
            field_hints = hints.field_hints.len(),
            "Entity cache hints parsed from schema"
        );

        Ok(hints)
    }

    /// Parse field-level cache control hints
    fn parse_field_hints(&mut self, schema_sdl: &str) -> Result<(), EntityCacheError> {
        // Find all type definitions with their content
        let type_re = Regex::new(r#"type\s+(\w+)[^{]*\{([^}]+)\}"#)
            .map_err(|e| EntityCacheError::ParseError(e.to_string()))?;

        for cap in type_re.captures_iter(schema_sdl) {
            let type_name = cap.get(1).map(|m| m.as_str()).unwrap_or("");
            let type_body = cap.get(2).map(|m| m.as_str()).unwrap_or("");

            // Find fields with @cacheControl in this type
            for field_cap in FIELD_CACHE_CONTROL_RE.captures_iter(type_body) {
                let field_name = field_cap.get(1).map(|m| m.as_str()).unwrap_or("");
                let max_age_str = field_cap.get(2).map(|m| m.as_str()).unwrap_or("60");

                let max_age = max_age_str
                    .parse::<u64>()
                    .map_err(|_| EntityCacheError::InvalidMaxAge(max_age_str.to_string()))?;

                let key = format!("{}.{}", type_name, field_name);
                debug!(field = key, max_age = max_age, "Parsed field cache hint");

                self.field_hints
                    .insert(key, CacheHint::new(max_age, CacheScope::Public));
            }
        }

        Ok(())
    }

    /// Get cache hint for a type
    pub fn get_type_hint(&self, type_name: &str) -> Option<&CacheHint> {
        self.type_hints.get(type_name)
    }

    /// Get TTL for a type (None if no explicit directive)
    pub fn get_type_ttl(&self, type_name: &str) -> Option<u64> {
        self.type_hints.get(type_name).map(|h| h.max_age)
    }

    /// Get cache hint for a field
    pub fn get_field_hint(&self, type_name: &str, field_name: &str) -> Option<&CacheHint> {
        let key = format!("{}.{}", type_name, field_name);
        self.field_hints.get(&key)
    }

    /// Get TTL for a field (None if no explicit directive)
    pub fn get_field_ttl(&self, type_name: &str, field_name: &str) -> Option<u64> {
        let key = format!("{}.{}", type_name, field_name);
        self.field_hints.get(&key).map(|h| h.max_age)
    }

    /// Get effective TTL for a field (field hint > type hint > default)
    pub fn effective_ttl(&self, type_name: &str, field_name: &str) -> u64 {
        // Field-level hint takes precedence
        if let Some(field_hint) = self.get_field_hint(type_name, field_name) {
            return field_hint.max_age;
        }

        // Fall back to type-level hint
        if let Some(type_hint) = self.get_type_hint(type_name) {
            return type_hint.max_age;
        }

        // Fall back to default
        self.default_hint.max_age
    }

    /// Check if a type should be cached (maxAge > 0)
    pub fn is_cacheable(&self, type_name: &str) -> bool {
        self.get_type_hint(type_name)
            .map(|h| !h.is_no_cache())
            .unwrap_or(true) // Default is cacheable
    }

    /// Check if a type requires private caching
    pub fn is_private(&self, type_name: &str) -> bool {
        self.get_type_hint(type_name)
            .map(|h| h.is_private())
            .unwrap_or(false)
    }

    /// Set default cache hint
    pub fn with_default(mut self, hint: CacheHint) -> Self {
        self.default_hint = hint;
        self
    }

    /// Add a type hint programmatically
    pub fn add_type_hint(&mut self, type_name: &str, hint: CacheHint) {
        self.type_hints.insert(type_name.to_string(), hint);
    }

    /// Add a field hint programmatically
    pub fn add_field_hint(&mut self, type_name: &str, field_name: &str, hint: CacheHint) {
        let key = format!("{}.{}", type_name, field_name);
        self.field_hints.insert(key, hint);
    }

    /// Get minimum TTL across all types in a query result
    ///
    /// This is useful for determining cache TTL when a response contains
    /// multiple entity types - use the minimum to avoid stale data.
    pub fn min_ttl_for_types(&self, type_names: &[&str]) -> u64 {
        type_names
            .iter()
            .filter_map(|t| self.get_type_ttl(t))
            .min()
            .unwrap_or(self.default_hint.max_age)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SCHEMA: &str = r#"
        directive @cacheControl(maxAge: Int, scope: CacheControlScope) on FIELD_DEFINITION | OBJECT

        enum CacheControlScope {
            PUBLIC
            PRIVATE
        }

        type Product @cacheControl(maxAge: 300) {
            id: ID!
            name: String!
            price: Float! @cacheControl(maxAge: 60)
            reviews: [Review!]! @cacheControl(maxAge: 30)
        }

        type Category @cacheControl(maxAge: 3600) {
            id: ID!
            name: String!
            products: [Product!]!
        }

        type User @cacheControl(maxAge: 0) {
            id: ID!
            email: String!
            orders: [Order!]!
        }

        type Order {
            id: ID!
            total: Float!
        }
    "#;

    #[test]
    fn test_parse_type_hints() {
        let hints = EntityCacheHints::from_schema(TEST_SCHEMA, None).expect("should parse");

        assert_eq!(hints.get_type_ttl("Product"), Some(300));
        assert_eq!(hints.get_type_ttl("Category"), Some(3600));
        assert_eq!(hints.get_type_ttl("User"), Some(0));
        assert_eq!(hints.get_type_ttl("Order"), None); // No directive
    }

    #[test]
    fn test_parse_field_hints() {
        let hints = EntityCacheHints::from_schema(TEST_SCHEMA, None).expect("should parse");

        assert_eq!(hints.get_field_ttl("Product", "price"), Some(60));
        assert_eq!(hints.get_field_ttl("Product", "reviews"), Some(30));
        assert_eq!(hints.get_field_ttl("Product", "name"), None); // No field directive
    }

    #[test]
    fn test_effective_ttl() {
        let hints = EntityCacheHints::from_schema(TEST_SCHEMA, None).expect("should parse");

        // Field with explicit hint
        assert_eq!(hints.effective_ttl("Product", "price"), 60);

        // Field without hint, type with hint
        assert_eq!(hints.effective_ttl("Product", "name"), 300);

        // Type without hint, use default
        assert_eq!(hints.effective_ttl("Order", "id"), 60); // default
    }

    #[test]
    fn test_is_cacheable() {
        let hints = EntityCacheHints::from_schema(TEST_SCHEMA, None).expect("should parse");

        assert!(hints.is_cacheable("Product"));
        assert!(hints.is_cacheable("Category"));
        assert!(!hints.is_cacheable("User")); // maxAge: 0
        assert!(hints.is_cacheable("Order")); // No directive = cacheable
    }

    #[test]
    fn test_min_ttl_for_types() {
        let hints = EntityCacheHints::from_schema(TEST_SCHEMA, None).expect("should parse");

        // Product (300) and Category (3600) → min 300
        assert_eq!(hints.min_ttl_for_types(&["Product", "Category"]), 300);

        // Including User (0) → min 0
        assert_eq!(hints.min_ttl_for_types(&["Product", "User"]), 0);
    }

    #[test]
    fn test_programmatic_hints() {
        let mut hints = EntityCacheHints::new(None);

        hints.add_type_hint("Custom", CacheHint::new(120, CacheScope::Public));
        hints.add_field_hint(
            "Custom",
            "expensiveField",
            CacheHint::new(600, CacheScope::Public),
        );

        assert_eq!(hints.get_type_ttl("Custom"), Some(120));
        assert_eq!(hints.get_field_ttl("Custom", "expensiveField"), Some(600));
    }

    #[test]
    fn test_private_scope() {
        let schema = r#"
            type User @cacheControl(maxAge: 60, scope: PRIVATE) {
                id: ID!
            }
        "#;

        let hints = EntityCacheHints::from_schema(schema, None).expect("should parse");
        assert!(hints.is_private("User"));
    }
}
