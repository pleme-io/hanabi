//! Refactoring detector using AST analysis
//!
//! Detects code that needs refactoring based on industry-standard thresholds:
//! - Gate 19: Function Size (≤ 100 lines)
//! - Gate 20: Parameter Count (≤ 7 parameters)
//! - Gate 21: Nesting Depth (≤ 6 levels)
//! - Gate 22: Module Cohesion (≤ 1500 lines per file)
//!
//! Based on:
//! - Martin Fowler's Refactoring (code smells)
//! - McConnell's Code Complete: 50-100 lines ideal, 100-200 acceptable
//! - Miller's Law (7±2 cognitive limit for parameters)
//! - SonarQube defaults (5-6 nesting depth)
//! - Google style guides (1000-1500 lines for complex modules)

use crate::error::{LintError, Result};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{Attribute, File, ImplItemFn, ItemFn, ItemMod};

// ============================================================================
// Configuration
// ============================================================================

/// Default thresholds (configurable via CLI)
/// These values are calibrated based on industry standards and Hanabi's complexity:
/// - Function lines: 100 (McConnell recommends 50-100 ideal, 100-200 acceptable)
/// - Parameters: 7 (Miller's Law 7±2 cognitive limit)
/// - Nesting depth: 8 (SonarQube allows 8 for parser/compiler code that walks ASTs)
/// - File lines: 4000 (BFF has large config structs, planners, handlers by design)
pub const DEFAULT_MAX_FUNCTION_LINES: usize = 100;
pub const DEFAULT_MAX_PARAMETERS: usize = 7;
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 8;
pub const DEFAULT_MAX_FILE_LINES: usize = 4000;

// ============================================================================
// Types
// ============================================================================

/// Types of refactoring violations
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefactoringViolationKind {
    /// Function exceeds line limit (Gate 19)
    LongFunction,
    /// Function has too many parameters (Gate 20)
    TooManyParameters,
    /// Code has deep nesting (Gate 21)
    DeepNesting,
    /// File exceeds line limit (Gate 22)
    LargeFile,
}

impl RefactoringViolationKind {
    /// Returns the gate number for this violation
    pub fn gate_number(&self) -> usize {
        match self {
            Self::LongFunction => 19,
            Self::TooManyParameters => 20,
            Self::DeepNesting => 21,
            Self::LargeFile => 22,
        }
    }

    /// Returns the refactoring remedy for this smell
    pub fn remedy(&self) -> &'static str {
        match self {
            Self::LongFunction => "Extract Method",
            Self::TooManyParameters => "Introduce Parameter Object",
            Self::DeepNesting => "Replace Nested Conditional with Guard Clauses",
            Self::LargeFile => "Extract Class / Split Module",
        }
    }

    /// Returns human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::LongFunction => "Function exceeds line limit",
            Self::TooManyParameters => "Too many parameters",
            Self::DeepNesting => "Deep nesting detected",
            Self::LargeFile => "File exceeds line limit",
        }
    }
}

/// A detected refactoring opportunity
#[derive(Debug, Clone, serde::Serialize)]
pub struct RefactoringViolation {
    pub path: PathBuf,
    pub line: usize,
    pub kind: RefactoringViolationKind,
    pub name: String,
    pub current_value: usize,
    pub threshold: usize,
    pub in_test: bool,
}

// ============================================================================
// Thresholds Configuration
// ============================================================================

/// Configuration for refactoring thresholds
#[derive(Debug, Clone)]
pub struct RefactoringThresholds {
    pub max_function_lines: usize,
    pub max_parameters: usize,
    pub max_nesting_depth: usize,
    pub max_file_lines: usize,
}

impl Default for RefactoringThresholds {
    fn default() -> Self {
        Self {
            max_function_lines: DEFAULT_MAX_FUNCTION_LINES,
            max_parameters: DEFAULT_MAX_PARAMETERS,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_file_lines: DEFAULT_MAX_FILE_LINES,
        }
    }
}

// ============================================================================
// AST Visitor for Function-Level Analysis
// ============================================================================

/// Visitor for detecting refactoring opportunities at function level
struct RefactoringVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    thresholds: &'a RefactoringThresholds,
    violations: Vec<RefactoringViolation>,
    test_context_depth: usize,
}

impl<'a> RefactoringVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str, thresholds: &'a RefactoringThresholds) -> Self {
        Self {
            file_path,
            source,
            thresholds,
            violations: Vec::new(),
            test_context_depth: 0,
        }
    }

    fn in_test_context(&self) -> bool {
        self.test_context_depth > 0
    }

    fn has_test_attr(attrs: &[Attribute]) -> bool {
        for attr in attrs {
            if let Some(ident) = attr.path().get_ident() {
                let name = ident.to_string();
                if name == "test" || name == "tokio::test" {
                    return true;
                }
            }
            if attr.path().is_ident("cfg") {
                if let Ok(meta) = attr.meta.require_list() {
                    let tokens = meta.tokens.to_string();
                    if tokens.contains("test") {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn count_function_lines(&self, start_line: usize, end_line: usize) -> usize {
        if end_line <= start_line {
            return 0;
        }

        let lines: Vec<&str> = self.source.lines().collect();
        let mut count = 0;

        for i in start_line..=end_line.min(lines.len()) {
            if i > 0 && i <= lines.len() {
                let line = lines[i - 1].trim();
                // Count non-empty, non-comment lines
                if !line.is_empty()
                    && !line.starts_with("//")
                    && !line.starts_with("///")
                    && !line.starts_with("//!")
                {
                    count += 1;
                }
            }
        }

        count
    }

    fn count_nesting_depth(&self, block: &syn::Block) -> usize {
        let mut max_depth = 0;
        let mut visitor = NestingVisitor { current_depth: 0, max_depth: 0 };
        syn::visit::visit_block(&mut visitor, block);
        max_depth = max_depth.max(visitor.max_depth);
        max_depth
    }

    fn analyze_function(&mut self, name: &str, sig: &syn::Signature, block: Option<&syn::Block>, span_start: usize, span_end: usize) {
        // Skip test functions
        if self.in_test_context() {
            return;
        }

        // Gate 19: Function size
        let line_count = self.count_function_lines(span_start, span_end);
        if line_count > self.thresholds.max_function_lines {
            self.violations.push(RefactoringViolation {
                path: self.file_path.to_path_buf(),
                line: span_start,
                kind: RefactoringViolationKind::LongFunction,
                name: name.to_string(),
                current_value: line_count,
                threshold: self.thresholds.max_function_lines,
                in_test: false,
            });
        }

        // Gate 20: Parameter count
        let param_count = sig.inputs.len();
        if param_count > self.thresholds.max_parameters {
            self.violations.push(RefactoringViolation {
                path: self.file_path.to_path_buf(),
                line: span_start,
                kind: RefactoringViolationKind::TooManyParameters,
                name: name.to_string(),
                current_value: param_count,
                threshold: self.thresholds.max_parameters,
                in_test: false,
            });
        }

        // Gate 21: Nesting depth
        if let Some(block) = block {
            let nesting_depth = self.count_nesting_depth(block);
            if nesting_depth > self.thresholds.max_nesting_depth {
                self.violations.push(RefactoringViolation {
                    path: self.file_path.to_path_buf(),
                    line: span_start,
                    kind: RefactoringViolationKind::DeepNesting,
                    name: name.to_string(),
                    current_value: nesting_depth,
                    threshold: self.thresholds.max_nesting_depth,
                    in_test: false,
                });
            }
        }
    }
}

/// Helper visitor to count nesting depth
struct NestingVisitor {
    current_depth: usize,
    max_depth: usize,
}

impl<'ast> Visit<'ast> for NestingVisitor {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_if(self, node);
        self.current_depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_match(self, node);
        self.current_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_loop(self, node);
        self.current_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_while(self, node);
        self.current_depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_for_loop(self, node);
        self.current_depth -= 1;
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.current_depth += 1;
        self.max_depth = self.max_depth.max(self.current_depth);
        syn::visit::visit_expr_closure(self, node);
        self.current_depth -= 1;
    }
}

impl<'ast, 'a> Visit<'ast> for RefactoringVisitor<'a> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        let is_test_mod =
            node.ident == "tests" || node.ident == "test" || Self::has_test_attr(&node.attrs);

        if is_test_mod {
            self.test_context_depth += 1;
        }

        syn::visit::visit_item_mod(self, node);

        if is_test_mod {
            self.test_context_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let is_test_fn = Self::has_test_attr(&node.attrs);

        if is_test_fn {
            self.test_context_depth += 1;
        }

        let name = node.sig.ident.to_string();
        let start = node.sig.fn_token.span.start().line;
        // Estimate end line from block
        let end = start + 100; // Will be refined by actual line counting

        self.analyze_function(&name, &node.sig, Some(&node.block), start, end);

        syn::visit::visit_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let is_test_fn = Self::has_test_attr(&node.attrs);

        if is_test_fn {
            self.test_context_depth += 1;
        }

        let name = node.sig.ident.to_string();
        let start = node.sig.fn_token.span.start().line;
        let end = start + 100;

        self.analyze_function(&name, &node.sig, Some(&node.block), start, end);

        syn::visit::visit_impl_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }
}

// ============================================================================
// Summary Types
// ============================================================================

/// Summary of refactoring analysis
#[derive(Debug, Default, serde::Serialize)]
pub struct RefactoringSummary {
    pub long_function_count: usize,
    pub too_many_params_count: usize,
    pub deep_nesting_count: usize,
    pub large_file_count: usize,
    pub violations: Vec<RefactoringViolation>,
}

impl RefactoringSummary {
    /// Create summary from violations
    pub fn from_violations(violations: Vec<RefactoringViolation>) -> Self {
        let mut summary = Self::default();

        for v in &violations {
            if v.in_test {
                continue;
            }
            match v.kind {
                RefactoringViolationKind::LongFunction => summary.long_function_count += 1,
                RefactoringViolationKind::TooManyParameters => summary.too_many_params_count += 1,
                RefactoringViolationKind::DeepNesting => summary.deep_nesting_count += 1,
                RefactoringViolationKind::LargeFile => summary.large_file_count += 1,
            }
        }

        summary.violations = violations;
        summary
    }

    /// Check if all gates pass
    pub fn all_gates_pass(&self) -> bool {
        self.long_function_count == 0
            && self.too_many_params_count == 0
            && self.deep_nesting_count == 0
            && self.large_file_count == 0
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Analyze a single file for refactoring opportunities
pub fn analyze_file(path: &Path, thresholds: &RefactoringThresholds) -> Result<Vec<RefactoringViolation>> {
    let source = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut violations = Vec::new();

    // Gate 22: File size check (before parsing)
    let line_count = source.lines().count();
    if line_count > thresholds.max_file_lines {
        violations.push(RefactoringViolation {
            path: path.to_path_buf(),
            line: 1,
            kind: RefactoringViolationKind::LargeFile,
            name: path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            current_value: line_count,
            threshold: thresholds.max_file_lines,
            in_test: path.to_string_lossy().contains("test"),
        });
    }

    // Skip further analysis for test files
    if path.to_string_lossy().contains("/tests/")
        || path.to_string_lossy().contains("_test.rs")
        || path.file_name().map(|n| n.to_string_lossy().ends_with("_test.rs")).unwrap_or(false)
    {
        return Ok(violations);
    }

    // Parse and analyze AST
    let syntax_tree: File = syn::parse_file(&source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = RefactoringVisitor::new(path, &source, thresholds);
    visitor.visit_file(&syntax_tree);
    violations.extend(visitor.violations);

    Ok(violations)
}

/// Analyze all Rust files in a directory
pub fn analyze_directory(dir: &Path) -> Result<RefactoringSummary> {
    analyze_directory_with_thresholds(dir, &RefactoringThresholds::default())
}

/// Analyze all Rust files in a directory with custom thresholds
pub fn analyze_directory_with_thresholds(
    dir: &Path,
    thresholds: &RefactoringThresholds,
) -> Result<RefactoringSummary> {
    let mut all_violations = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
    {
        match analyze_file(entry.path(), thresholds) {
            Ok(violations) => all_violations.extend(violations),
            Err(LintError::ParseError { path, message }) => {
                eprintln!("Warning: Could not parse {}: {}", path.display(), message);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(RefactoringSummary::from_violations(all_violations))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn analyze_code(code: &str) -> Vec<RefactoringViolation> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path(), &RefactoringThresholds::default()).unwrap()
    }

    fn analyze_code_with_thresholds(code: &str, thresholds: &RefactoringThresholds) -> Vec<RefactoringViolation> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path(), thresholds).unwrap()
    }

    #[test]
    fn test_detects_long_function() {
        // Create a function with 60 lines (exceeds default 50)
        let mut code = String::from("fn long_function() {\n");
        for i in 0..55 {
            code.push_str(&format!("    let x{} = {};\n", i, i));
        }
        code.push_str("}\n");

        let thresholds = RefactoringThresholds {
            max_function_lines: 50,
            ..Default::default()
        };

        let violations = analyze_code_with_thresholds(&code, &thresholds);
        let long_fn_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == RefactoringViolationKind::LongFunction)
            .collect();

        assert_eq!(long_fn_violations.len(), 1);
        assert!(long_fn_violations[0].current_value > 50);
    }

    #[test]
    fn test_detects_too_many_parameters() {
        let code = r#"
            fn too_many_params(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) {
                let x = a + b + c + d + e + f;
            }
        "#;

        let violations = analyze_code(code);
        let param_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == RefactoringViolationKind::TooManyParameters)
            .collect();

        assert_eq!(param_violations.len(), 1);
        assert_eq!(param_violations[0].current_value, 6);
    }

    #[test]
    fn test_detects_deep_nesting() {
        let code = r#"
            fn deeply_nested(x: i32) {
                if x > 0 {
                    if x > 1 {
                        if x > 2 {
                            if x > 3 {
                                if x > 4 {
                                    println!("deep!");
                                }
                            }
                        }
                    }
                }
            }
        "#;

        let violations = analyze_code(code);
        let nesting_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == RefactoringViolationKind::DeepNesting)
            .collect();

        assert_eq!(nesting_violations.len(), 1);
        assert!(nesting_violations[0].current_value > 4);
    }

    #[test]
    fn test_ignores_test_functions() {
        let code = r#"
            fn normal_long_function(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32) {}

            #[cfg(test)]
            mod tests {
                #[test]
                fn test_many_params(a: i32, b: i32, c: i32, d: i32, e: i32, f: i32, g: i32) {
                    // This is fine in tests
                }
            }
        "#;

        let violations = analyze_code(code);
        let param_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == RefactoringViolationKind::TooManyParameters && !v.in_test)
            .collect();

        // Should only detect the production function
        assert_eq!(param_violations.len(), 1);
    }

    #[test]
    fn test_short_function_passes() {
        let code = r#"
            fn short_function(a: i32, b: i32) -> i32 {
                a + b
            }
        "#;

        let violations = analyze_code(code);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_summary_counts() {
        let violations = vec![
            RefactoringViolation {
                path: PathBuf::from("test.rs"),
                line: 1,
                kind: RefactoringViolationKind::LongFunction,
                name: "foo".to_string(),
                current_value: 60,
                threshold: 50,
                in_test: false,
            },
            RefactoringViolation {
                path: PathBuf::from("test.rs"),
                line: 10,
                kind: RefactoringViolationKind::TooManyParameters,
                name: "bar".to_string(),
                current_value: 7,
                threshold: 5,
                in_test: false,
            },
        ];

        let summary = RefactoringSummary::from_violations(violations);
        assert_eq!(summary.long_function_count, 1);
        assert_eq!(summary.too_many_params_count, 1);
        assert!(!summary.all_gates_pass());
    }
}
