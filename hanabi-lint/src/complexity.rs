//! Complexity metrics analyzer using syn AST
//!
//! Computes cyclomatic complexity, cognitive complexity, and other metrics
//! based on AST analysis of Rust source files.

use crate::error::{LintError, Result};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{
    Arm, BinOp, ExprBinary, ExprIf, ExprLoop, ExprMatch, ExprWhile, File, ImplItemFn,
    ItemFn,
};

/// Complexity metrics for a single function
#[derive(Debug, Clone, serde::Serialize)]
pub struct FunctionMetrics {
    pub name: String,
    pub path: PathBuf,
    pub line: usize,
    pub cyclomatic_complexity: usize,
    pub cognitive_complexity: usize,
    pub lines_of_code: usize,
    pub nesting_depth: usize,
}

impl FunctionMetrics {
    /// Check if this function exceeds complexity thresholds
    pub fn exceeds_thresholds(&self, cc_max: usize, cognitive_max: usize) -> bool {
        self.cyclomatic_complexity > cc_max || self.cognitive_complexity > cognitive_max
    }
}

/// Overall complexity summary for a codebase
#[derive(Debug, Default, serde::Serialize)]
pub struct ComplexitySummary {
    pub total_functions: usize,
    pub avg_cyclomatic: f64,
    pub max_cyclomatic: usize,
    pub avg_cognitive: f64,
    pub max_cognitive: usize,
    pub functions_exceeding_cc: usize,
    pub functions_exceeding_cognitive: usize,
    pub high_complexity_functions: Vec<FunctionMetrics>,
}

impl ComplexitySummary {
    pub fn from_metrics(metrics: &[FunctionMetrics], cc_threshold: usize, cog_threshold: usize) -> Self {
        if metrics.is_empty() {
            return Self::default();
        }

        let total = metrics.len();
        let sum_cc: usize = metrics.iter().map(|m| m.cyclomatic_complexity).sum();
        let sum_cog: usize = metrics.iter().map(|m| m.cognitive_complexity).sum();
        let max_cc = metrics.iter().map(|m| m.cyclomatic_complexity).max().unwrap_or(0);
        let max_cog = metrics.iter().map(|m| m.cognitive_complexity).max().unwrap_or(0);

        let exceeding_cc = metrics.iter().filter(|m| m.cyclomatic_complexity > cc_threshold).count();
        let exceeding_cog = metrics.iter().filter(|m| m.cognitive_complexity > cog_threshold).count();

        let high_complexity: Vec<_> = metrics
            .iter()
            .filter(|m| m.exceeds_thresholds(cc_threshold, cog_threshold))
            .cloned()
            .collect();

        Self {
            total_functions: total,
            avg_cyclomatic: sum_cc as f64 / total as f64,
            max_cyclomatic: max_cc,
            avg_cognitive: sum_cog as f64 / total as f64,
            max_cognitive: max_cog,
            functions_exceeding_cc: exceeding_cc,
            functions_exceeding_cognitive: exceeding_cog,
            high_complexity_functions: high_complexity,
        }
    }

    pub fn passes_thresholds(&self, avg_cc: f64, avg_cog: f64) -> bool {
        self.avg_cyclomatic <= avg_cc && self.avg_cognitive <= avg_cog
    }
}

/// AST visitor for computing complexity metrics
struct ComplexityVisitor<'a> {
    file_path: &'a Path,
    #[allow(dead_code)]
    source: &'a str, // Reserved for future LOC calculation
    metrics: Vec<FunctionMetrics>,

    // Current function tracking
    current_function: Option<String>,
    current_line: usize,
    cyclomatic: usize,
    cognitive: usize,
    max_nesting: usize,
    current_nesting: usize,
}

impl<'a> ComplexityVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
            metrics: Vec::new(),
            current_function: None,
            current_line: 0,
            cyclomatic: 1, // Base complexity
            cognitive: 0,
            max_nesting: 0,
            current_nesting: 0,
        }
    }

    fn start_function(&mut self, name: &str, line: usize) {
        self.current_function = Some(name.to_string());
        self.current_line = line;
        self.cyclomatic = 1; // Base complexity
        self.cognitive = 0;
        self.max_nesting = 0;
        self.current_nesting = 0;
    }

    fn end_function(&mut self) {
        if let Some(name) = self.current_function.take() {
            let loc = self.estimate_loc();
            self.metrics.push(FunctionMetrics {
                name,
                path: self.file_path.to_path_buf(),
                line: self.current_line,
                cyclomatic_complexity: self.cyclomatic,
                cognitive_complexity: self.cognitive,
                lines_of_code: loc,
                nesting_depth: self.max_nesting,
            });
        }
    }

    fn estimate_loc(&self) -> usize {
        // Simple estimate - could be improved with span analysis
        10 // Placeholder
    }

    fn increment_cyclomatic(&mut self) {
        self.cyclomatic += 1;
    }

    fn increment_cognitive(&mut self, amount: usize) {
        self.cognitive += amount;
    }

    fn enter_nesting(&mut self) {
        self.current_nesting += 1;
        if self.current_nesting > self.max_nesting {
            self.max_nesting = self.current_nesting;
        }
    }

    fn exit_nesting(&mut self) {
        self.current_nesting = self.current_nesting.saturating_sub(1);
    }

    fn get_line(&self, span: proc_macro2::Span) -> usize {
        span.start().line
    }
}

impl<'ast, 'a> Visit<'ast> for ComplexityVisitor<'a> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let name = node.sig.ident.to_string();
        let line = self.get_line(node.sig.ident.span());

        self.start_function(&name, line);
        syn::visit::visit_item_fn(self, node);
        self.end_function();
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let name = node.sig.ident.to_string();
        let line = self.get_line(node.sig.ident.span());

        self.start_function(&name, line);
        syn::visit::visit_impl_item_fn(self, node);
        self.end_function();
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        // Cyclomatic: +1 for each if
        self.increment_cyclomatic();

        // Cognitive: +1, plus nesting penalty
        self.increment_cognitive(1 + self.current_nesting);

        self.enter_nesting();
        syn::visit::visit_expr_if(self, node);
        self.exit_nesting();
    }

    fn visit_expr_match(&mut self, node: &'ast ExprMatch) {
        // Cyclomatic: +1 for each arm (minus 1 for the match itself)
        let arm_count = node.arms.len();
        if arm_count > 0 {
            self.cyclomatic += arm_count - 1;
        }

        // Cognitive: +1 for match, plus nesting
        self.increment_cognitive(1 + self.current_nesting);

        self.enter_nesting();
        syn::visit::visit_expr_match(self, node);
        self.exit_nesting();
    }

    fn visit_expr_loop(&mut self, node: &'ast ExprLoop) {
        self.increment_cyclomatic();
        self.increment_cognitive(1 + self.current_nesting);

        self.enter_nesting();
        syn::visit::visit_expr_loop(self, node);
        self.exit_nesting();
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        self.increment_cyclomatic();
        self.increment_cognitive(1 + self.current_nesting);

        self.enter_nesting();
        syn::visit::visit_expr_while(self, node);
        self.exit_nesting();
    }

    fn visit_expr_binary(&mut self, node: &'ast ExprBinary) {
        // Cyclomatic: +1 for && and ||
        match node.op {
            BinOp::And(_) | BinOp::Or(_) => {
                self.increment_cyclomatic();
                self.increment_cognitive(1);
            }
            _ => {}
        }

        syn::visit::visit_expr_binary(self, node);
    }

    fn visit_arm(&mut self, node: &'ast Arm) {
        // Match arms with guards add complexity
        if node.guard.is_some() {
            self.increment_cyclomatic();
            self.increment_cognitive(1);
        }

        syn::visit::visit_arm(self, node);
    }
}

/// Analyze a single file for complexity metrics
pub fn analyze_file(path: &Path) -> Result<Vec<FunctionMetrics>> {
    let source = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let syntax_tree: File = syn::parse_file(&source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = ComplexityVisitor::new(path, &source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.metrics)
}

/// Analyze all Rust files in a directory
pub fn analyze_directory(dir: &Path) -> Result<Vec<FunctionMetrics>> {
    let mut all_metrics = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
    {
        match analyze_file(entry.path()) {
            Ok(metrics) => all_metrics.extend(metrics),
            Err(LintError::ParseError { path, message }) => {
                eprintln!("Warning: Could not parse {}: {}", path.display(), message);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(all_metrics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn analyze_code(code: &str) -> Vec<FunctionMetrics> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path()).unwrap()
    }

    #[test]
    fn test_simple_function_complexity() {
        let metrics = analyze_code(
            r#"
            fn simple() {
                let x = 1;
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic_complexity, 1); // Base complexity
    }

    #[test]
    fn test_if_increases_complexity() {
        let metrics = analyze_code(
            r#"
            fn with_if(x: bool) {
                if x {
                    println!("yes");
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic_complexity, 2); // 1 + 1 for if
    }

    #[test]
    fn test_match_complexity() {
        let metrics = analyze_code(
            r#"
            fn with_match(x: Option<i32>) {
                match x {
                    Some(v) => println!("{}", v),
                    None => println!("none"),
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic_complexity, 2); // 1 + (2 arms - 1)
    }

    #[test]
    fn test_nested_complexity() {
        let metrics = analyze_code(
            r#"
            fn nested(x: bool, y: bool) {
                if x {
                    if y {
                        println!("both");
                    }
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert!(metrics[0].cognitive_complexity > 2); // Nested penalty
        assert_eq!(metrics[0].nesting_depth, 2);
    }

    #[test]
    fn test_loop_increases_complexity() {
        let metrics = analyze_code(
            r#"
            fn with_loop() {
                loop {
                    break;
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic_complexity, 2); // 1 base + 1 loop
    }

    #[test]
    fn test_while_increases_complexity() {
        let metrics = analyze_code(
            r#"
            fn with_while(mut x: i32) {
                while x > 0 {
                    x -= 1;
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].cyclomatic_complexity, 2);
    }

    #[test]
    fn test_logical_operators_increase_complexity() {
        let metrics = analyze_code(
            r#"
            fn with_logic(a: bool, b: bool, c: bool) {
                if a && b || c {
                    println!("complex");
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        // 1 base + 1 if + 1 && + 1 || = 4
        assert_eq!(metrics[0].cyclomatic_complexity, 4);
    }

    #[test]
    fn test_match_with_guard() {
        let metrics = analyze_code(
            r#"
            fn with_guard(x: Option<i32>) {
                match x {
                    Some(v) if v > 0 => println!("positive"),
                    Some(_) => println!("non-positive"),
                    None => println!("none"),
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        // 1 base + 2 arms (3-1) + 1 guard = 4
        assert_eq!(metrics[0].cyclomatic_complexity, 4);
    }

    #[test]
    fn test_impl_method_tracked() {
        let metrics = analyze_code(
            r#"
            struct Foo;
            impl Foo {
                fn bar(&self, x: bool) {
                    if x { println!("yes"); }
                }
            }
        "#,
        );

        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0].name, "bar");
        assert_eq!(metrics[0].cyclomatic_complexity, 2);
    }

    #[test]
    fn test_multiple_functions_tracked() {
        let metrics = analyze_code(
            r#"
            fn first() { }
            fn second(x: bool) {
                if x { println!("y"); }
            }
        "#,
        );

        assert_eq!(metrics.len(), 2);
        assert_eq!(metrics[0].name, "first");
        assert_eq!(metrics[0].cyclomatic_complexity, 1);
        assert_eq!(metrics[1].name, "second");
        assert_eq!(metrics[1].cyclomatic_complexity, 2);
    }

    #[test]
    fn test_loc_placeholder_returns_10() {
        let metrics = analyze_code("fn x() { let a = 1; }");
        assert_eq!(metrics[0].lines_of_code, 10);
    }

    #[test]
    fn test_exceeds_thresholds() {
        let m = FunctionMetrics {
            name: "complex".to_string(),
            path: PathBuf::from("test.rs"),
            line: 1,
            cyclomatic_complexity: 15,
            cognitive_complexity: 5,
            lines_of_code: 10,
            nesting_depth: 2,
        };
        assert!(m.exceeds_thresholds(10, 20));
        assert!(m.exceeds_thresholds(20, 4));
        assert!(!m.exceeds_thresholds(20, 20));
    }

    #[test]
    fn test_complexity_summary_from_empty() {
        let summary = ComplexitySummary::from_metrics(&[], 10, 10);
        assert_eq!(summary.total_functions, 0);
        assert_eq!(summary.avg_cyclomatic, 0.0);
        assert_eq!(summary.max_cyclomatic, 0);
    }

    #[test]
    fn test_complexity_summary_from_metrics() {
        let metrics = vec![
            FunctionMetrics {
                name: "a".to_string(),
                path: PathBuf::from("t.rs"),
                line: 1,
                cyclomatic_complexity: 2,
                cognitive_complexity: 3,
                lines_of_code: 10,
                nesting_depth: 1,
            },
            FunctionMetrics {
                name: "b".to_string(),
                path: PathBuf::from("t.rs"),
                line: 10,
                cyclomatic_complexity: 8,
                cognitive_complexity: 12,
                lines_of_code: 10,
                nesting_depth: 3,
            },
        ];

        let summary = ComplexitySummary::from_metrics(&metrics, 5, 10);
        assert_eq!(summary.total_functions, 2);
        assert_eq!(summary.avg_cyclomatic, 5.0); // (2+8)/2
        assert_eq!(summary.max_cyclomatic, 8);
        assert_eq!(summary.avg_cognitive, 7.5); // (3+12)/2
        assert_eq!(summary.max_cognitive, 12);
        assert_eq!(summary.functions_exceeding_cc, 1); // b > 5
        assert_eq!(summary.functions_exceeding_cognitive, 1); // b > 10
        assert_eq!(summary.high_complexity_functions.len(), 1);
        assert_eq!(summary.high_complexity_functions[0].name, "b");
    }

    #[test]
    fn test_passes_thresholds() {
        let summary = ComplexitySummary {
            avg_cyclomatic: 5.0,
            avg_cognitive: 8.0,
            ..Default::default()
        };
        assert!(summary.passes_thresholds(5.0, 8.0));
        assert!(summary.passes_thresholds(10.0, 10.0));
        assert!(!summary.passes_thresholds(4.9, 8.0));
        assert!(!summary.passes_thresholds(5.0, 7.9));
    }

    #[test]
    fn test_deeply_nested_nesting_depth() {
        let metrics = analyze_code(
            r#"
            fn deep(a: bool, b: bool, c: bool) {
                if a {
                    if b {
                        if c {
                            println!("deep");
                        }
                    }
                }
            }
        "#,
        );

        assert_eq!(metrics[0].nesting_depth, 3);
    }
}
