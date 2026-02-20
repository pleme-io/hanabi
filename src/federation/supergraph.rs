//! Supergraph loading and parsing
//!
//! This module handles loading the Apollo Federation supergraph schema
//! and extracting subgraph information for direct routing.
//!
//! # Supergraph Structure
//! The supergraph schema contains `@join__graph` directives that define
//! each subgraph's name and URL. Example:
//! ```graphql
//! enum join__Graph {
//!   JOB_SCHEDULER @join__graph(name: "job-scheduler", url: "http://job-scheduler:8080/graphql")
//!   CHAT @join__graph(name: "chat", url: "http://chat:8080/graphql")
//! }
//! ```
//!
//! # Subscription Routing
//! Subscription fields have `@join__field(graph: GRAPH_NAME)` directives
//! that indicate which subgraph owns the subscription. Example:
//! ```graphql
//! type Subscription {
//!   jobsUpdated: [Job!]! @join__field(graph: JOB_SCHEDULER)
//!   onNewMessage: Message! @join__field(graph: CHAT)
//! }
//! ```

#![allow(dead_code)]

use apollo_parser::cst::{self, CstNode};
use apollo_parser::Parser;
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Represents a subgraph in the federation
#[derive(Debug, Clone)]
pub struct Subgraph {
    /// Subgraph name (kebab-case, e.g., "job-scheduler")
    pub name: String,

    /// HTTP URL for queries/mutations
    pub url: String,

    /// WebSocket URL for subscriptions (derived from HTTP URL)
    pub ws_url: String,
}

impl Subgraph {
    /// Create a new subgraph with derived WebSocket URL
    ///
    /// WebSocket URL is derived from HTTP URL by:
    /// 1. Replacing http:// with ws:// (or https:// with wss://)
    /// 2. Keeping the same path (industry standard: unified /graphql for HTTP and WebSocket)
    ///
    /// Example: http://job-scheduler:8080/graphql -> ws://job-scheduler:8080/graphql
    pub fn new(name: String, url: String) -> Self {
        // Derive WebSocket URL from HTTP URL
        // Replace protocol (http→ws, https→wss) but keep same path
        // Industry standard: unified /graphql endpoint for both HTTP and WebSocket
        let ws_url = if url.starts_with("https://") {
            url.replacen("https://", "wss://", 1)
        } else if url.starts_with("http://") {
            url.replacen("http://", "ws://", 1)
        } else {
            format!("ws://{}", url)
        };

        Self { name, url, ws_url }
    }

    /// Check if this subgraph provides a field on a type
    ///
    /// # WARNING
    ///
    /// This method is DEPRECATED and always returns true!
    /// Use `Supergraph::provides_field(type_name, field_name, subgraph_name)` instead,
    /// which correctly checks the field_ownership map.
    ///
    /// This stub caused a critical routing bug where all queries were sent to the
    /// first subgraph in HashMap iteration order.
    #[deprecated(
        since = "0.1.0",
        note = "Use Supergraph::provides_field(type_name, field_name, subgraph_name) instead"
    )]
    pub fn provides_field(&self, _type_name: &str, _field_name: &str) -> bool {
        // BUG: This always returns true! Do not use this method.
        // The actual ownership is tracked in Supergraph::field_ownership
        true
    }
}

/// Parsed supergraph with subgraph information
#[derive(Debug, Clone)]
pub struct Supergraph {
    /// Raw supergraph SDL
    pub schema: String,

    /// Map of subgraph name (lowercase) → Subgraph
    subgraphs_map: HashMap<String, Subgraph>,

    /// Map of subscription field name → subgraph name
    pub subscription_routes: HashMap<String, String>,

    /// Map of (type_name, field_name) → subgraph name
    /// Used for query planning to determine field ownership
    field_ownership: HashMap<(String, String), String>,
}

impl Supergraph {
    /// Create an empty supergraph (for testing)
    pub fn empty() -> Self {
        Self {
            schema: String::new(),
            subgraphs_map: HashMap::new(),
            subscription_routes: HashMap::new(),
            field_ownership: HashMap::new(),
        }
    }

    /// Builder method for testing: add a subgraph
    #[cfg(test)]
    pub fn with_subgraph(mut self, name: &str, url: &str) -> Self {
        let subgraph = Subgraph::new(name.to_string(), url.to_string());
        self.subgraphs_map.insert(name.to_lowercase(), subgraph);
        self
    }

    /// Builder method for testing: register field ownership
    #[cfg(test)]
    pub fn with_field_owner(mut self, type_name: &str, field_name: &str, subgraph: &str) -> Self {
        self.field_ownership.insert(
            (type_name.to_string(), field_name.to_string()),
            subgraph.to_lowercase(),
        );
        self
    }

    /// Check if a subgraph provides a field (for query planning)
    pub fn provides_field(&self, type_name: &str, field_name: &str, subgraph_name: &str) -> bool {
        self.field_ownership
            .get(&(type_name.to_string(), field_name.to_string()))
            .map(|owner| owner == &subgraph_name.to_lowercase())
            .unwrap_or(false)
    }

    /// Load supergraph from URL (file:// or http://)
    pub async fn load(url: &str) -> Result<Self, SupergraphError> {
        let schema = if url.starts_with("file://") {
            let path = url
                .strip_prefix("file://")
                .ok_or_else(|| SupergraphError::IoError(format!("Invalid file URL: {}", url)))?;
            tokio::fs::read_to_string(path)
                .await
                .map_err(|e| SupergraphError::IoError(e.to_string()))?
        } else {
            reqwest::get(url)
                .await
                .map_err(|e| SupergraphError::FetchError(e.to_string()))?
                .text()
                .await
                .map_err(|e| SupergraphError::FetchError(e.to_string()))?
        };

        Self::parse(&schema)
    }

    /// Parse supergraph SDL to extract subgraphs and subscription routes
    pub fn parse(schema: &str) -> Result<Self, SupergraphError> {
        let subgraphs = Self::parse_subgraphs(schema)?;
        let subscription_routes = Self::parse_subscription_routes(schema, &subgraphs);
        let field_ownership = Self::parse_field_ownership(schema, &subgraphs);

        info!(
            "Loaded supergraph: {} subgraphs, {} subscription routes, {} field mappings",
            subgraphs.len(),
            subscription_routes.len(),
            field_ownership.len()
        );

        for (name, subgraph) in &subgraphs {
            debug!(
                "  Subgraph {}: {} (ws: {})",
                name, subgraph.url, subgraph.ws_url
            );
        }

        for (field, subgraph) in &subscription_routes {
            debug!("  Subscription {} → {}", field, subgraph);
        }

        Ok(Self {
            schema: schema.to_string(),
            subgraphs_map: subgraphs,
            subscription_routes,
            field_ownership,
        })
    }

    /// Get all subgraphs
    pub fn subgraphs(&self) -> &HashMap<String, Subgraph> {
        &self.subgraphs_map
    }

    /// Get subgraph by name (case-insensitive)
    pub fn subgraph(&self, name: &str) -> Option<&Subgraph> {
        self.subgraphs_map.get(&name.to_lowercase())
    }

    /// Parse @join__graph directives to extract subgraph URLs using apollo-parser
    ///
    /// Uses apollo-parser for spec-compliant GraphQL parsing that correctly handles
    /// all valid Federation v2 constructs including:
    /// - Reversed argument order (url before name)
    /// - Extra whitespace and newlines
    /// - Complex URLs with query parameters
    /// - Comments between arguments
    ///
    /// Refactored to use helper functions for reduced nesting (Gate 21 compliance).
    fn parse_subgraphs(schema: &str) -> Result<HashMap<String, Subgraph>, SupergraphError> {
        let mut subgraphs = HashMap::new();

        // Parse the supergraph schema with apollo-parser (error-resilient)
        let parser = Parser::new(schema);
        let tree = parser.parse();

        // Log any parse errors (apollo-parser is error-resilient)
        let errors: Vec<_> = tree.errors().collect();
        if !errors.is_empty() {
            warn!(
                "Supergraph schema has {} parse errors during subgraph extraction",
                errors.len()
            );
            for err in errors.iter().take(3) {
                debug!("Parse error: {}", err.message());
            }
        }

        let document = tree.document();

        // Find the join__Graph enum definition
        for definition in document.definitions() {
            // Use helper to extract enum values (reduces nesting)
            let Some(values) = Self::extract_join_graph_enum(&definition) else {
                continue;
            };

            // Parse each enum value with @join__graph directive
            for value in values.enum_value_definitions() {
                let Some(enum_value) = value.enum_value().map(|v| v.text().to_string()) else {
                    continue;
                };

                // Use helper to extract name/url from @join__graph (reduces nesting)
                if let Some((name, url)) = Self::extract_join_graph_directive(&value) {
                    let subgraph = Subgraph::new(name.clone(), url);

                    trace!(
                        "Found subgraph: {} ({}) -> {}",
                        enum_value,
                        name,
                        subgraph.url
                    );

                    // Store by lowercase name for case-insensitive lookup
                    subgraphs.insert(name.to_lowercase(), subgraph.clone());

                    // Also store by enum value (UPPER_SNAKE_CASE) for subscription routing
                    subgraphs.insert(enum_value.to_lowercase(), subgraph);
                }
            }
        }

        if subgraphs.is_empty() {
            return Err(SupergraphError::NoSubgraphsFound);
        }

        Ok(subgraphs)
    }

    /// Extract the join__Graph enum values definition from a definition node
    /// Helper to reduce nesting in parse_subgraphs (Gate 21 compliance)
    fn extract_join_graph_enum(definition: &cst::Definition) -> Option<cst::EnumValuesDefinition> {
        let enum_def = match definition {
            cst::Definition::EnumTypeDefinition(enum_def) => enum_def,
            _ => return None,
        };

        let enum_name = enum_def.name()?.text().to_string();
        if enum_name != "join__Graph" {
            return None;
        }

        enum_def.enum_values_definition()
    }

    /// Extract name and url from @join__graph directive on an enum value
    /// Helper to reduce nesting in parse_subgraphs (Gate 21 compliance)
    fn extract_join_graph_directive(
        enum_value: &cst::EnumValueDefinition,
    ) -> Option<(String, String)> {
        let directives = enum_value.directives()?;

        for directive in directives.directives() {
            let directive_name = directive.name()?.text().to_string();
            if directive_name != "join__graph" {
                continue;
            }

            let mut name_arg: Option<String> = None;
            let mut url_arg: Option<String> = None;

            let arguments = directive.arguments()?;
            for argument in arguments.arguments() {
                let arg_name = argument.name()?.text().to_string();
                let value = argument.value()?;
                let value_text = Self::extract_string_value(&value);

                match arg_name.as_str() {
                    "name" => name_arg = Some(value_text),
                    "url" => url_arg = Some(value_text),
                    _ => {}
                }
            }

            // Return if we have both name and url
            if let (Some(name), Some(url)) = (name_arg, url_arg) {
                return Some((name, url));
            }
        }

        None
    }

    /// Extract string value from a GraphQL value node (removes quotes)
    fn extract_string_value(value: &cst::Value) -> String {
        let text = value.syntax().text().to_string();
        // Remove surrounding quotes if present
        if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
            text[1..text.len() - 1].to_string()
        } else {
            text
        }
    }

    /// Parse Subscription type to extract field → subgraph mapping using apollo-parser
    ///
    /// Uses apollo-parser for spec-compliant GraphQL parsing that correctly handles
    /// large Subscription types spanning thousands of lines. The previous regex-based
    /// approach failed because `[^}]+` stopped at the first closing brace.
    ///
    /// Refactored to use helper functions for reduced nesting (Gate 21 compliance).
    fn parse_subscription_routes(
        schema: &str,
        subgraphs: &HashMap<String, Subgraph>,
    ) -> HashMap<String, String> {
        let mut routes = HashMap::new();

        // Parse the supergraph schema with apollo-parser (error-resilient)
        let parser = Parser::new(schema);
        let tree = parser.parse();
        let document = tree.document();

        // Walk the CST to find the Subscription type definition
        for definition in document.definitions() {
            // Use helper to extract type info (reduces nesting)
            let Some((type_name, fields_def)) = Self::extract_type_fields(&definition) else {
                continue;
            };

            // Only process the Subscription type
            if type_name != "Subscription" {
                continue;
            }

            // Parse fields in the Subscription type
            let Some(fields_def) = fields_def else {
                continue;
            };

            for field in fields_def.field_definitions() {
                let Some(field_name) = field.name().map(|n| n.text().to_string()) else {
                    continue;
                };

                // Use helper to extract @join__field graph (reduces nesting)
                if let Some(subgraph_name) = Self::extract_join_field_graph(&field, subgraphs) {
                    trace!("Subscription route: {} -> {}", field_name, subgraph_name);
                    routes.insert(field_name, subgraph_name);
                }
            }
        }

        routes
    }

    /// Get subgraph by name (case-insensitive) - alias for subgraph()
    pub fn get_subgraph(&self, name: &str) -> Option<&Subgraph> {
        self.subgraphs_map.get(&name.to_lowercase())
    }

    /// Get subgraph for a subscription field
    pub fn get_subscription_subgraph(&self, field_name: &str) -> Option<&Subgraph> {
        let subgraph_name = self.subscription_routes.get(field_name)?;
        self.get_subgraph(subgraph_name)
    }

    /// List all subscription-capable subgraphs
    pub fn subscription_subgraphs(&self) -> Vec<&Subgraph> {
        self.subscription_routes
            .values()
            .filter_map(|name| self.get_subgraph(name))
            .collect()
    }

    /// Parse field ownership from @join__field directives using apollo-parser
    ///
    /// This function uses apollo-parser for spec-compliant GraphQL parsing that
    /// correctly handles nested braces, complex argument syntax, and large schemas.
    ///
    /// Refactored to use helper functions for reduced nesting (Gate 21 compliance).
    fn parse_field_ownership(
        schema: &str,
        subgraphs: &HashMap<String, Subgraph>,
    ) -> HashMap<(String, String), String> {
        let mut ownership = HashMap::new();

        // Parse the supergraph schema with apollo-parser (error-resilient)
        let parser = Parser::new(schema);
        let tree = parser.parse();

        // Log any parse errors (apollo-parser is error-resilient)
        let errors: Vec<_> = tree.errors().collect();
        if !errors.is_empty() {
            warn!(
                "Supergraph schema has {} parse errors (continuing with partial results)",
                errors.len()
            );
            for err in errors.iter().take(5) {
                debug!("Parse error: {}", err.message());
            }
        }

        let document = tree.document();

        // Walk the CST to find type definitions
        for definition in document.definitions() {
            // Use helper to extract type info (reduces nesting by 2 levels)
            let Some((type_name, fields_def)) = Self::extract_type_fields(&definition) else {
                continue;
            };

            // Parse fields in this type
            let Some(fields_def) = fields_def else {
                continue;
            };

            for field in fields_def.field_definitions() {
                let Some(field_name) = field.name().map(|n| n.text().to_string()) else {
                    continue;
                };

                // Use helper to extract @join__field graph (reduces nesting by 6 levels)
                if let Some(subgraph_name) = Self::extract_join_field_graph(&field, subgraphs) {
                    trace!(
                        "Field ownership: {}.{} -> {}",
                        type_name,
                        field_name,
                        subgraph_name
                    );
                    ownership.insert((type_name.clone(), field_name), subgraph_name);
                }
            }
        }

        ownership
    }

    /// Extract text from a GraphQL value node
    fn extract_value_text(value: &cst::Value) -> String {
        // For enum values like AUTH, BOOKING, etc.
        // The value is an enum value, not a string
        value.syntax().text().to_string()
    }

    /// Extract the 'graph' argument from a @join__field directive on a field
    /// Returns the resolved subgraph name if found
    /// Helper to reduce nesting in parsing functions (Gate 21 compliance)
    fn extract_join_field_graph(
        field: &cst::FieldDefinition,
        subgraphs: &HashMap<String, Subgraph>,
    ) -> Option<String> {
        let directives = field.directives()?;

        for directive in directives.directives() {
            let directive_name = directive.name()?.text().to_string();
            if directive_name != "join__field" {
                continue;
            }

            let arguments = directive.arguments()?;
            for argument in arguments.arguments() {
                let arg_name = argument.name()?.text().to_string();
                if arg_name != "graph" {
                    continue;
                }

                let value = argument.value()?;
                let graph_name = Self::extract_value_text(&value);
                if graph_name.is_empty() {
                    continue;
                }

                return Self::resolve_subgraph_name(&graph_name, subgraphs);
            }
        }

        None
    }

    /// Extract type name and fields definition from a definition node
    /// Helper to reduce nesting in parsing functions (Gate 21 compliance)
    fn extract_type_fields(
        definition: &cst::Definition,
    ) -> Option<(String, Option<cst::FieldsDefinition>)> {
        match definition {
            cst::Definition::ObjectTypeDefinition(type_def) => {
                let name = type_def.name()?.text().to_string();
                if name.starts_with("__") {
                    return None; // Skip built-in types
                }
                Some((name, type_def.fields_definition()))
            }
            cst::Definition::ObjectTypeExtension(type_ext) => {
                let name = type_ext.name()?.text().to_string();
                Some((name, type_ext.fields_definition()))
            }
            _ => None,
        }
    }

    /// Resolve a graph name (e.g., "AUTH", "PRODUCT_CATALOG") to a subgraph name
    fn resolve_subgraph_name(
        graph_name: &str,
        subgraphs: &HashMap<String, Subgraph>,
    ) -> Option<String> {
        // Try direct lowercase lookup
        let lowercase = graph_name.to_lowercase();
        if let Some(subgraph) = subgraphs.get(&lowercase) {
            return Some(subgraph.name.clone());
        }

        // Try converting UPPER_SNAKE_CASE to kebab-case
        let kebab_name = lowercase.replace('_', "-");
        if subgraphs.values().any(|s| s.name == kebab_name) {
            return Some(kebab_name);
        }

        // Log warning for unresolved graph names
        debug!(
            "Could not resolve graph name '{}' to subgraph (tried: {}, {})",
            graph_name, lowercase, kebab_name
        );
        None
    }

    /// Check if a subgraph provides a specific field on a type
    pub fn subgraph_provides_field(
        &self,
        subgraph_name: &str,
        type_name: &str,
        field_name: &str,
    ) -> bool {
        self.field_ownership
            .get(&(type_name.to_string(), field_name.to_string()))
            .map(|s| s == subgraph_name)
            .unwrap_or(false)
    }

    /// Get the subgraph that owns a specific field
    pub fn get_field_owner(&self, type_name: &str, field_name: &str) -> Option<&String> {
        self.field_ownership
            .get(&(type_name.to_string(), field_name.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum SupergraphError {
    #[error("Failed to read supergraph: {0}")]
    IoError(String),

    #[error("Failed to fetch supergraph: {0}")]
    FetchError(String),

    #[error("Failed to parse supergraph: {0}")]
    ParseError(String),

    #[error("No subgraphs found in supergraph schema")]
    NoSubgraphsFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SUPERGRAPH: &str = r#"
schema
  @link(url: "https://specs.apollo.dev/link/v1.0")
  @link(url: "https://specs.apollo.dev/join/v0.4", for: EXECUTION)
{
  query: Query
  mutation: Mutation
  subscription: Subscription
}

enum join__Graph {
  CHAT @join__graph(name: "chat", url: "http://chat.myapp-staging:8080/graphql")
  JOB_SCHEDULER @join__graph(name: "job-scheduler", url: "http://job-scheduler.myapp-staging:8080/graphql")
  AUTH @join__graph(name: "auth", url: "http://auth.myapp-staging:8080/graphql")
}

type Subscription {
  jobsUpdated(statuses: [JobStatus!]): [Job!]! @join__field(graph: JOB_SCHEDULER)
  jobUpdated(id: UUID!): Job @join__field(graph: JOB_SCHEDULER)
  onNewMessage(conversationId: UUID!): Message! @join__field(graph: CHAT)
  onTypingStatusChanged(conversationId: UUID!): TypingStatus! @join__field(graph: CHAT)
}
"#;

    #[test]
    fn test_parse_subgraphs() {
        let supergraph = Supergraph::parse(TEST_SUPERGRAPH).unwrap();

        assert!(supergraph.subgraphs().len() >= 3);

        let chat = supergraph.get_subgraph("chat").unwrap();
        assert_eq!(chat.name, "chat");
        assert_eq!(chat.url, "http://chat.myapp-staging:8080/graphql");
        assert_eq!(chat.ws_url, "ws://chat.myapp-staging:8080/graphql");

        let job_scheduler = supergraph.get_subgraph("job-scheduler").unwrap();
        assert_eq!(job_scheduler.name, "job-scheduler");
    }

    #[test]
    fn test_parse_subscription_routes() {
        let supergraph = Supergraph::parse(TEST_SUPERGRAPH).unwrap();

        assert_eq!(supergraph.subscription_routes.len(), 4);
        assert_eq!(
            supergraph.subscription_routes.get("jobsUpdated"),
            Some(&"job-scheduler".to_string())
        );
        assert_eq!(
            supergraph.subscription_routes.get("onNewMessage"),
            Some(&"chat".to_string())
        );
    }

    #[test]
    fn test_get_subscription_subgraph() {
        let supergraph = Supergraph::parse(TEST_SUPERGRAPH).unwrap();

        let subgraph = supergraph.get_subscription_subgraph("jobsUpdated").unwrap();
        assert_eq!(subgraph.name, "job-scheduler");

        let subgraph = supergraph
            .get_subscription_subgraph("onNewMessage")
            .unwrap();
        assert_eq!(subgraph.name, "chat");

        assert!(supergraph
            .get_subscription_subgraph("unknownField")
            .is_none());
    }

    #[test]
    fn test_parse_field_ownership_with_production_supergraph() {
        // This test uses the production supergraph to verify that apollo-parser
        // correctly handles large types like Query that have many fields.
        // The previous regex-based approach failed because [^}]+ stopped at
        // the first closing brace within nested structures.
        let supergraph_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../infrastructure/hive-router/supergraph.graphql"
        );

        let schema = match std::fs::read_to_string(supergraph_path) {
            Ok(s) => s,
            Err(_) => {
                eprintln!(
                    "Skipping test: production supergraph not found at {}",
                    supergraph_path
                );
                return;
            }
        };

        let supergraph = Supergraph::parse(&schema).expect("Failed to parse production supergraph");

        // Verify critical Query fields that were failing with regex approach
        // These are in the Query type which spans many lines with nested structures

        // Payment service fields
        assert!(
            supergraph.subgraph_provides_field("payment", "Query", "myPaymentMethods"),
            "payment subgraph should provide Query.myPaymentMethods"
        );

        // Booking service fields
        assert!(
            supergraph.subgraph_provides_field("booking", "Query", "serviceCategories"),
            "booking subgraph should provide Query.serviceCategories"
        );
        assert!(
            supergraph.subgraph_provides_field("booking", "Query", "myBookings"),
            "booking subgraph should provide Query.myBookings"
        );

        // Auth service fields
        assert!(
            supergraph.subgraph_provides_field("auth", "Query", "me"),
            "auth subgraph should provide Query.me"
        );

        // Feature-flags service fields
        assert!(
            supergraph.subgraph_provides_field("feature-flags", "Query", "isFeatureEnabled"),
            "feature-flags subgraph should provide Query.isFeatureEnabled"
        );

        // Product-catalog service fields
        assert!(
            supergraph.subgraph_provides_field("product-catalog", "Query", "products"),
            "product-catalog subgraph should provide Query.products"
        );

        // Also verify get_field_owner returns correct values
        assert_eq!(
            supergraph.get_field_owner("Query", "myPaymentMethods"),
            Some(&"payment".to_string()),
            "Query.myPaymentMethods should be owned by payment"
        );
        assert_eq!(
            supergraph.get_field_owner("Query", "serviceCategories"),
            Some(&"booking".to_string()),
            "Query.serviceCategories should be owned by booking"
        );

        // Log some stats for debugging
        let total_fields = supergraph.field_ownership.len();
        println!(
            "Parsed {} field ownership entries from production supergraph",
            total_fields
        );
        assert!(
            total_fields > 100,
            "Expected at least 100 field ownership entries, got {}",
            total_fields
        );
    }
}
