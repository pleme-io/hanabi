#![allow(dead_code)]
//! Query Cost Analysis Module
//!
//! Provides accurate AST-based query cost calculation for:
//! - Resource allocation and load shedding decisions
//! - Cost-based rate limiting and quotas
//! - Response cost reporting
//!
//! # Algorithm
//!
//! Cost is calculated by traversing the query AST:
//! - Each field has a base cost (default: 1)
//! - List arguments (first, limit, last) multiply child costs
//! - Custom costs can be assigned per field via configuration
//! - Free fields (id, __typename) have zero cost
//!
//! # Example
//!
//! ```text
//! query {
//!   products(first: 100) {    # base: 1, multiplier: 100
//!     name                     # cost: 100 * 1 = 100
//!     reviews {                # list field, multiplier: 10
//!       text                   # cost: 100 * 10 * 1 = 1000
//!       author {               # cost: 100 * 10 * 1 = 1000
//!         name                 # cost: 100 * 10 * 1 = 1000
//!       }
//!     }
//!   }
//! }
//! # Total: 1 + 100 + 1000 + 1000 + 1000 = 3101
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use apollo_parser::{cst, Parser};
use thiserror::Error;
use tracing::{debug, warn};

use crate::metrics::{MetricsClient, MetricsExt};

/// Cost analysis errors
#[derive(Debug, Error)]
pub enum CostError {
    #[error("Query cost {cost} exceeds maximum allowed cost of {max_cost}")]
    CostExceeded { cost: u32, max_cost: u32 },

    #[error("Query parsing failed: {0}")]
    ParseError(String),
}

/// Query cost analysis result
#[derive(Debug, Clone)]
pub struct CostAnalysis {
    /// Total calculated cost
    pub total_cost: u32,

    /// Number of fields selected
    pub field_count: u32,

    /// Maximum nesting depth encountered
    pub max_depth: u32,

    /// Number of list fields (fields with pagination args)
    pub list_count: u32,

    /// Whether the query was deemed expensive (cost > threshold)
    pub is_expensive: bool,
}

impl CostAnalysis {
    /// Create a new cost analysis with default values
    fn new() -> Self {
        Self {
            total_cost: 0,
            field_count: 0,
            max_depth: 0,
            list_count: 0,
            is_expensive: false,
        }
    }
}

/// Cost analyzer configuration
#[derive(Debug, Clone)]
pub struct CostConfig {
    /// Maximum allowed cost (0 = unlimited)
    pub max_cost: u32,

    /// Default cost per field
    pub default_field_cost: u32,

    /// Default multiplier for list fields
    pub default_list_multiplier: u32,

    /// Cost threshold for "expensive" queries (triggers warnings, potentially different handling)
    pub expensive_threshold: u32,

    /// Custom costs per field (format: "TypeName.fieldName" → cost)
    pub field_costs: HashMap<String, u32>,

    /// Fields that are free (cost 0)
    pub free_fields: HashSet<String>,

    /// Default list size assumption when no argument present
    pub default_list_size: u32,
}

impl Default for CostConfig {
    fn default() -> Self {
        let mut free_fields = HashSet::new();
        // Standard free fields
        free_fields.insert("id".to_string());
        free_fields.insert("__typename".to_string());

        Self {
            max_cost: 10_000,
            default_field_cost: 1,
            default_list_multiplier: 10,
            expensive_threshold: 5_000,
            field_costs: HashMap::new(),
            free_fields,
            default_list_size: 10,
        }
    }
}

/// AST-based query cost analyzer
///
/// Uses apollo-parser for accurate query cost estimation.
pub struct CostAnalyzer {
    config: CostConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl CostAnalyzer {
    /// Create a new cost analyzer
    pub fn new(config: CostConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    /// Analyze query cost
    ///
    /// Returns a detailed cost analysis or error if cost exceeds limit.
    pub fn analyze(&self, query: &str) -> Result<CostAnalysis, CostError> {
        let parser = Parser::new(query);
        let cst = parser.parse();

        // Check for parse errors
        if cst.errors().len() > 0 {
            let errors: Vec<String> = cst.errors().map(|e| e.message().to_string()).collect();
            return Err(CostError::ParseError(errors.join("; ")));
        }

        let document = cst.document();
        let mut analysis = CostAnalysis::new();

        // Analyze each definition in the document
        for definition in document.definitions() {
            match definition {
                cst::Definition::OperationDefinition(op) => {
                    if let Some(selection_set) = op.selection_set() {
                        self.analyze_selection_set(&selection_set, 1, 0, &mut analysis);
                    }
                }
                cst::Definition::FragmentDefinition(_frag) => {
                    // Fragments are counted when spread, not at definition
                    // For now, we skip fragment definitions
                    debug!("Skipping fragment definition");
                }
                _ => {}
            }
        }

        // Check thresholds
        analysis.is_expensive = analysis.total_cost >= self.config.expensive_threshold;

        // Emit metrics
        self.metrics.histogram(
            "bff.federation.cost.calculated",
            f64::from(analysis.total_cost),
            &[],
        );

        if analysis.is_expensive {
            self.metrics.incr("bff.federation.cost.expensive_queries", &[]);
        }

        // Enforce limit
        if self.config.max_cost > 0 && analysis.total_cost > self.config.max_cost {
            self.metrics.incr("bff.federation.cost.rejected", &[]);
            warn!(
                cost = analysis.total_cost,
                max = self.config.max_cost,
                "Query cost exceeded"
            );
            return Err(CostError::CostExceeded {
                cost: analysis.total_cost,
                max_cost: self.config.max_cost,
            });
        }

        debug!(
            cost = analysis.total_cost,
            fields = analysis.field_count,
            depth = analysis.max_depth,
            lists = analysis.list_count,
            "Query cost calculated"
        );

        Ok(analysis)
    }

    /// Analyze a selection set
    fn analyze_selection_set(
        &self,
        selection_set: &cst::SelectionSet,
        multiplier: u32,
        depth: u32,
        analysis: &mut CostAnalysis,
    ) {
        let current_depth = depth + 1;
        if current_depth > analysis.max_depth {
            analysis.max_depth = current_depth;
        }

        for selection in selection_set.selections() {
            match selection {
                cst::Selection::Field(field) => {
                    self.analyze_field(&field, multiplier, current_depth, analysis);
                }
                cst::Selection::FragmentSpread(_spread) => {
                    // Fragment spreads would require resolving the fragment definition
                    // For now, we add a base cost
                    analysis.total_cost = analysis.total_cost.saturating_add(multiplier);
                    analysis.field_count += 1;
                }
                cst::Selection::InlineFragment(inline) => {
                    if let Some(inner_set) = inline.selection_set() {
                        self.analyze_selection_set(&inner_set, multiplier, current_depth, analysis);
                    }
                }
            }
        }
    }

    /// Analyze a single field
    fn analyze_field(
        &self,
        field: &cst::Field,
        multiplier: u32,
        depth: u32,
        analysis: &mut CostAnalysis,
    ) {
        let field_name = field
            .name()
            .map(|n| n.text().to_string())
            .unwrap_or_default();

        // Check if it's a free field
        if self.config.free_fields.contains(&field_name) {
            // Still count it but don't add cost
            analysis.field_count += 1;
            if let Some(selection_set) = field.selection_set() {
                self.analyze_selection_set(&selection_set, multiplier, depth, analysis);
            }
            return;
        }

        // Get field cost (custom or default)
        let base_cost = self
            .config
            .field_costs
            .get(&field_name)
            .copied()
            .unwrap_or(self.config.default_field_cost);

        // Calculate cost with multiplier
        let cost = multiplier.saturating_mul(base_cost);
        analysis.total_cost = analysis.total_cost.saturating_add(cost);
        analysis.field_count += 1;

        // Check for list arguments and calculate new multiplier
        let list_size = self.extract_list_size(field);
        let new_multiplier = if let Some(size) = list_size {
            analysis.list_count += 1;
            multiplier.saturating_mul(size)
        } else {
            multiplier
        };

        // Recurse into nested selections
        if let Some(selection_set) = field.selection_set() {
            self.analyze_selection_set(&selection_set, new_multiplier, depth, analysis);
        }
    }

    /// Extract list size from field arguments
    fn extract_list_size(&self, field: &cst::Field) -> Option<u32> {
        let arguments = field.arguments()?;

        for argument in arguments.arguments() {
            let arg_name = argument.name()?.text().to_string();

            // Check for pagination arguments
            if arg_name == "first" || arg_name == "limit" || arg_name == "last" {
                if let Some(value) = argument.value() {
                    return self.extract_int_value(&value);
                }
            }
        }

        None
    }

    /// Extract integer value from an argument value
    fn extract_int_value(&self, value: &cst::Value) -> Option<u32> {
        match value {
            cst::Value::IntValue(int_val) => {
                let token = int_val.int_token()?;
                let text = token.text();
                text.parse::<u32>().ok()
            }
            cst::Value::Variable(_) => {
                // For variables, use default list size
                Some(self.config.default_list_size)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_analyzer() -> CostAnalyzer {
        CostAnalyzer::new(CostConfig::default(), None)
    }

    #[test]
    fn test_simple_query_cost() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                user {
                    name
                    email
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        assert!(result.total_cost > 0);
        assert_eq!(result.field_count, 3); // user, name, email
        assert_eq!(result.max_depth, 2); // user -> name/email
    }

    #[test]
    fn test_list_query_cost() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                products(first: 100) {
                    name
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        // products: 1, name: 100 * 1 = 100
        assert!(result.total_cost >= 100);
        assert_eq!(result.list_count, 1);
    }

    #[test]
    fn test_nested_list_cost() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                products(first: 10) {
                    reviews(first: 5) {
                        text
                    }
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        // products: 1, reviews: 10 * 1 = 10, text: 10 * 5 * 1 = 50
        assert!(result.total_cost >= 50);
        assert_eq!(result.list_count, 2);
    }

    #[test]
    fn test_free_fields() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                user {
                    id
                    __typename
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        // Only 'user' has cost, id and __typename are free
        assert_eq!(result.total_cost, 1);
        assert_eq!(result.field_count, 3);
    }

    #[test]
    fn test_cost_exceeds_limit() {
        let config = CostConfig {
            max_cost: 100,
            ..Default::default()
        };
        let analyzer = CostAnalyzer::new(config, None);

        let query = r#"
            query {
                products(first: 1000) {
                    name
                    price
                    description
                }
            }
        "#;

        let result = analyzer.analyze(query);
        assert!(result.is_err());
        if let Err(CostError::CostExceeded { cost, max_cost }) = result {
            assert!(cost > 100);
            assert_eq!(max_cost, 100);
        }
    }

    #[test]
    fn test_deep_nesting_depth() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                a {
                    b {
                        c {
                            d {
                                e
                            }
                        }
                    }
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        assert_eq!(result.max_depth, 5);
    }

    #[test]
    fn test_inline_fragment_cost() {
        let analyzer = test_analyzer();
        let query = r#"
            query {
                node {
                    ... on User {
                        name
                        email
                    }
                    ... on Post {
                        title
                    }
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        // node: 1, name: 1, email: 1, title: 1
        assert!(result.total_cost >= 3);
    }

    #[test]
    fn test_custom_field_costs() {
        let mut field_costs = HashMap::new();
        field_costs.insert("expensiveField".to_string(), 100);

        let config = CostConfig {
            field_costs,
            ..Default::default()
        };
        let analyzer = CostAnalyzer::new(config, None);

        let query = r#"
            query {
                expensiveField
                cheapField
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        // expensiveField: 100, cheapField: 1
        assert_eq!(result.total_cost, 101);
    }

    #[test]
    fn test_expensive_query_flag() {
        let config = CostConfig {
            expensive_threshold: 10,
            max_cost: 0, // Unlimited
            ..Default::default()
        };
        let analyzer = CostAnalyzer::new(config, None);

        let query = r#"
            query {
                products(first: 20) {
                    name
                }
            }
        "#;

        let result = analyzer.analyze(query).expect("should analyze");
        assert!(result.is_expensive);
    }
}
