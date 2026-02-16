//! Production hygiene detector using AST and regex
//!
//! Detects code quality issues in production code:
//! - Hardcoded secrets (API keys, passwords, tokens)
//! - Blocking calls in async contexts
//! - Debug code (dbg!, println!, eprintln!)
//! - Missing timeouts on HTTP clients
//! - Missing doc comments on public functions

use crate::error::{LintError, Result};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use syn::visit::Visit;
use syn::{Attribute, Expr, ExprCall, ExprMethodCall, File, ItemFn, ItemMod, Macro};

// ============================================================================
// Types and Constants
// ============================================================================

/// Pattern matches for secret detection
static SECRET_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // API keys and tokens
        Regex::new(r#"(?i)["']?[a-z_]*api[_\-]?key["']?\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']"#)
            .expect("valid regex"),
        Regex::new(r#"(?i)["']?[a-z_]*secret["']?\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']"#)
            .expect("valid regex"),
        Regex::new(r#"(?i)["']?[a-z_]*token["']?\s*[:=]\s*["'][a-zA-Z0-9]{16,}["']"#)
            .expect("valid regex"),
        Regex::new(r#"(?i)["']?password["']?\s*[:=]\s*["'][^"']{8,}["']"#).expect("valid regex"),
        // AWS patterns
        Regex::new(r#"AKIA[0-9A-Z]{16}"#).expect("valid regex"),
        // Private keys
        Regex::new(r#"-----BEGIN (RSA |EC )?PRIVATE KEY-----"#).expect("valid regex"),
        // JWT tokens (but not the parsing code)
        Regex::new(r#"ey[A-Za-z0-9_-]{20,}\.ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"#)
            .expect("valid regex"),
    ]
});

/// Blocking operations that should not be used in async contexts
static BLOCKING_FUNCTIONS: LazyLock<Vec<(&'static str, &'static str)>> = LazyLock::new(|| {
    vec![
        ("std::fs", "read"),
        ("std::fs", "write"),
        ("std::fs", "read_to_string"),
        ("std::fs", "write"),
        ("std::fs", "create_dir"),
        ("std::fs", "create_dir_all"),
        ("std::fs", "remove_file"),
        ("std::fs", "remove_dir"),
        ("std::fs", "remove_dir_all"),
        ("std::fs", "rename"),
        ("std::fs", "copy"),
        ("std::fs", "metadata"),
        ("std::fs", "symlink_metadata"),
        ("std::fs", "read_dir"),
        ("std::fs", "read_link"),
        ("std::thread", "sleep"),
    ]
});

/// Debug macros that should not be in production
static DEBUG_MACROS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| vec!["dbg", "println", "eprintln"]);

/// Types of hygiene violations
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneViolationKind {
    HardcodedSecret,
    BlockingInAsync,
    DebugCode,
    MissingTimeout,
    MissingDocComment,
}

impl HygieneViolationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HardcodedSecret => "hardcoded_secret",
            Self::BlockingInAsync => "blocking_in_async",
            Self::DebugCode => "debug_code",
            Self::MissingTimeout => "missing_timeout",
            Self::MissingDocComment => "missing_doc_comment",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::HardcodedSecret => "Hardcoded secret detected",
            Self::BlockingInAsync => "Blocking call in async context",
            Self::DebugCode => "Debug code in production",
            Self::MissingTimeout => "HTTP client without timeout",
            Self::MissingDocComment => "Public function without doc comment",
        }
    }
}

/// A detected hygiene violation
#[derive(Debug, Clone, serde::Serialize)]
pub struct HygieneViolation {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub kind: HygieneViolationKind,
    pub context: String,
    pub in_test: bool,
}

// ============================================================================
// Secret Detection (Gate 14)
// ============================================================================

/// Check source code for hardcoded secrets
pub fn detect_secrets(path: &Path, source: &str) -> Vec<HygieneViolation> {
    let mut violations = Vec::new();

    // Skip test files entirely
    if path.to_string_lossy().contains("test") {
        return violations;
    }

    // Find test module start (line number)
    let test_module_start = find_test_module_start(source);

    for (line_num, line) in source.lines().enumerate() {
        // Skip comments
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }

        // Skip lines within test module
        if let Some(test_start) = test_module_start {
            if line_num >= test_start {
                continue;
            }
        }

        for pattern in SECRET_PATTERNS.iter() {
            if pattern.is_match(line) {
                // Additional check: ignore if it's clearly a variable/config reference
                if line.contains("env::var")
                    || line.contains("config.")
                    || line.contains("std::env")
                {
                    continue;
                }

                violations.push(HygieneViolation {
                    path: path.to_path_buf(),
                    line: line_num + 1,
                    column: 1,
                    kind: HygieneViolationKind::HardcodedSecret,
                    context: truncate_line(line, 80),
                    in_test: false,
                });
            }
        }
    }

    violations
}

/// Find the line number where the test module starts
fn find_test_module_start(source: &str) -> Option<usize> {
    for (line_num, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        // Check for #[cfg(test)] or mod tests
        if trimmed == "#[cfg(test)]" || trimmed.starts_with("mod tests") {
            return Some(line_num);
        }
    }
    None
}

// ============================================================================
// Async Safety Detection (Gate 15)
// ============================================================================

/// AST visitor for detecting blocking calls in async functions
struct AsyncSafetyVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    violations: Vec<HygieneViolation>,
    async_context_depth: usize,
    test_context_depth: usize,
}

impl<'a> AsyncSafetyVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
            violations: Vec::new(),
            async_context_depth: 0,
            test_context_depth: 0,
        }
    }

    fn in_async_context(&self) -> bool {
        self.async_context_depth > 0
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

    fn get_line_col(&self, span: proc_macro2::Span) -> (usize, usize) {
        let start = span.start();
        (start.line, start.column + 1)
    }

    fn get_context(&self, line: usize) -> String {
        self.source
            .lines()
            .nth(line.saturating_sub(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }

    fn is_blocking_call(&self, path: &syn::Path) -> bool {
        let path_str = path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");

        // Tokio's async functions are safe, exclude them
        if path_str.contains("tokio") {
            return false;
        }

        // Check for known blocking operations
        for (module, func) in BLOCKING_FUNCTIONS.iter() {
            // Must be std::* not tokio::* (already checked above)
            if path_str.contains(module) && path_str.contains(func) {
                return true;
            }
        }

        // Check for std::thread::sleep specifically
        if (path_str == "sleep" || path_str.ends_with("::sleep"))
            && (path_str.contains("std") || path_str.contains("thread"))
        {
            return true;
        }

        false
    }

    fn add_violation(&mut self, span: proc_macro2::Span, kind: HygieneViolationKind) {
        let (line, column) = self.get_line_col(span);
        let context = self.get_context(line);

        self.violations.push(HygieneViolation {
            path: self.file_path.to_path_buf(),
            line,
            column,
            kind,
            context,
            in_test: self.in_test_context(),
        });
    }
}

impl<'ast, 'a> Visit<'ast> for AsyncSafetyVisitor<'a> {
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
        let is_async = node.sig.asyncness.is_some();

        if is_test_fn {
            self.test_context_depth += 1;
        }
        if is_async {
            self.async_context_depth += 1;
        }

        syn::visit::visit_item_fn(self, node);

        if is_async {
            self.async_context_depth -= 1;
        }
        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.in_async_context() && !self.in_test_context() {
            if let Expr::Path(path_expr) = &*node.func {
                if self.is_blocking_call(&path_expr.path) {
                    self.add_violation(
                        path_expr.path.segments.first().map_or_else(
                            proc_macro2::Span::call_site,
                            |s| s.ident.span(),
                        ),
                        HygieneViolationKind::BlockingInAsync,
                    );
                }
            }
        }

        syn::visit::visit_expr_call(self, node);
    }
}

/// Detect blocking calls in async functions
pub fn detect_async_safety(path: &Path, source: &str) -> Result<Vec<HygieneViolation>> {
    let syntax_tree: File = syn::parse_file(source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = AsyncSafetyVisitor::new(path, source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.violations)
}

// ============================================================================
// Debug Code Detection (Gate 16)
// ============================================================================

/// AST visitor for detecting debug macros
struct DebugCodeVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    violations: Vec<HygieneViolation>,
    test_context_depth: usize,
}

impl<'a> DebugCodeVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
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

    fn get_line_col(&self, span: proc_macro2::Span) -> (usize, usize) {
        let start = span.start();
        (start.line, start.column + 1)
    }

    fn get_context(&self, line: usize) -> String {
        self.source
            .lines()
            .nth(line.saturating_sub(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}

impl<'ast, 'a> Visit<'ast> for DebugCodeVisitor<'a> {
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

        syn::visit::visit_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(ident) = node.path.get_ident() {
            let macro_name = ident.to_string();

            if DEBUG_MACROS.contains(&macro_name.as_str()) && !self.in_test_context() {
                let (line, column) = self.get_line_col(ident.span());
                let context = self.get_context(line);

                self.violations.push(HygieneViolation {
                    path: self.file_path.to_path_buf(),
                    line,
                    column,
                    kind: HygieneViolationKind::DebugCode,
                    context,
                    in_test: false,
                });
            }
        }

        syn::visit::visit_macro(self, node);
    }
}

/// Detect debug macros in production code
pub fn detect_debug_code(path: &Path, source: &str) -> Result<Vec<HygieneViolation>> {
    let syntax_tree: File = syn::parse_file(source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = DebugCodeVisitor::new(path, source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.violations)
}

// ============================================================================
// Timeout Check (Gate 17)
// ============================================================================

/// AST visitor for detecting reqwest clients without timeout
struct TimeoutVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    violations: Vec<HygieneViolation>,
    /// Track method chains on reqwest::Client::builder()
    in_client_builder: bool,
    has_timeout: bool,
    builder_span: Option<proc_macro2::Span>,
    test_context_depth: usize,
}

impl<'a> TimeoutVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
            violations: Vec::new(),
            in_client_builder: false,
            has_timeout: false,
            builder_span: None,
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

    fn get_line_col(&self, span: proc_macro2::Span) -> (usize, usize) {
        let start = span.start();
        (start.line, start.column + 1)
    }

    fn get_context(&self, line: usize) -> String {
        self.source
            .lines()
            .nth(line.saturating_sub(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}

impl<'ast, 'a> Visit<'ast> for TimeoutVisitor<'a> {
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

        syn::visit::visit_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();

        // Detect Client::builder() or new() patterns
        if method_name == "builder" || method_name == "new" {
            // Check if receiver looks like Client
            if let Expr::Path(path) = &*node.receiver {
                let path_str = path
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::");

                if path_str.contains("Client") || path_str == "reqwest" {
                    self.in_client_builder = true;
                    self.has_timeout = false;
                    self.builder_span = Some(node.method.span());
                }
            }
        }

        // Detect .timeout() call
        if method_name == "timeout" || method_name == "connect_timeout" {
            self.has_timeout = true;
        }

        // Detect .build() call - end of builder chain
        if method_name == "build" && self.in_client_builder && !self.in_test_context() {
            if !self.has_timeout {
                if let Some(span) = self.builder_span {
                    let (line, column) = self.get_line_col(span);
                    let context = self.get_context(line);

                    self.violations.push(HygieneViolation {
                        path: self.file_path.to_path_buf(),
                        line,
                        column,
                        kind: HygieneViolationKind::MissingTimeout,
                        context,
                        in_test: false,
                    });
                }
            }

            self.in_client_builder = false;
            self.has_timeout = false;
            self.builder_span = None;
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Detect HTTP clients without configured timeouts
pub fn detect_missing_timeouts(path: &Path, source: &str) -> Result<Vec<HygieneViolation>> {
    let syntax_tree: File = syn::parse_file(source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = TimeoutVisitor::new(path, source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.violations)
}

// ============================================================================
// Doc Coverage (Gate 18)
// ============================================================================

/// AST visitor for detecting public functions without doc comments
struct DocCoverageVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    violations: Vec<HygieneViolation>,
    test_context_depth: usize,
}

impl<'a> DocCoverageVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
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

    fn has_doc_comment(attrs: &[Attribute]) -> bool {
        for attr in attrs {
            // Check for #[doc = "..."] (which is what /// becomes)
            if attr.path().is_ident("doc") {
                return true;
            }
        }
        false
    }

    fn get_line_col(&self, span: proc_macro2::Span) -> (usize, usize) {
        let start = span.start();
        (start.line, start.column + 1)
    }

    fn get_context(&self, line: usize) -> String {
        self.source
            .lines()
            .nth(line.saturating_sub(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}

impl<'ast, 'a> Visit<'ast> for DocCoverageVisitor<'a> {
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
        // Check if this is a public function
        if matches!(node.vis, syn::Visibility::Public(_)) && !self.in_test_context() {
            // Check for doc comments
            if !Self::has_doc_comment(&node.attrs) {
                let (line, column) = self.get_line_col(node.sig.fn_token.span);
                let context = self.get_context(line);

                self.violations.push(HygieneViolation {
                    path: self.file_path.to_path_buf(),
                    line,
                    column,
                    kind: HygieneViolationKind::MissingDocComment,
                    context,
                    in_test: false,
                });
            }
        }

        // Check test attrs before visiting
        let is_test_fn = Self::has_test_attr(&node.attrs);
        if is_test_fn {
            self.test_context_depth += 1;
        }

        syn::visit::visit_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }
}

/// Detect public functions without doc comments
pub fn detect_missing_docs(path: &Path, source: &str) -> Result<Vec<HygieneViolation>> {
    let syntax_tree: File = syn::parse_file(source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = DocCoverageVisitor::new(path, source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.violations)
}

// ============================================================================
// Public API
// ============================================================================

/// Summary of all hygiene violations
#[derive(Debug, Default, serde::Serialize)]
pub struct HygieneSummary {
    pub secrets_count: usize,
    pub async_safety_count: usize,
    pub debug_code_count: usize,
    pub missing_timeout_count: usize,
    pub missing_docs_count: usize,
    pub violations: Vec<HygieneViolation>,
}

impl HygieneSummary {
    pub fn from_violations(violations: Vec<HygieneViolation>) -> Self {
        let mut summary = Self::default();

        for v in &violations {
            if v.in_test {
                continue; // Only count production violations
            }
            match v.kind {
                HygieneViolationKind::HardcodedSecret => summary.secrets_count += 1,
                HygieneViolationKind::BlockingInAsync => summary.async_safety_count += 1,
                HygieneViolationKind::DebugCode => summary.debug_code_count += 1,
                HygieneViolationKind::MissingTimeout => summary.missing_timeout_count += 1,
                HygieneViolationKind::MissingDocComment => summary.missing_docs_count += 1,
            }
        }

        summary.violations = violations;
        summary
    }
}

/// Analyze a single file for all hygiene issues
pub fn analyze_file(path: &Path) -> Result<Vec<HygieneViolation>> {
    let source = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut violations = Vec::new();

    // Secret detection (regex-based, no parsing)
    violations.extend(detect_secrets(path, &source));

    // AST-based detections (may fail on invalid syntax)
    if let Ok(async_violations) = detect_async_safety(path, &source) {
        violations.extend(async_violations);
    }

    if let Ok(debug_violations) = detect_debug_code(path, &source) {
        violations.extend(debug_violations);
    }

    if let Ok(timeout_violations) = detect_missing_timeouts(path, &source) {
        violations.extend(timeout_violations);
    }

    if let Ok(doc_violations) = detect_missing_docs(path, &source) {
        violations.extend(doc_violations);
    }

    Ok(violations)
}

/// Analyze all Rust files in a directory
pub fn analyze_directory(dir: &Path) -> Result<HygieneSummary> {
    let mut all_violations = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
    {
        match analyze_file(entry.path()) {
            Ok(violations) => all_violations.extend(violations),
            Err(LintError::ParseError { path, message }) => {
                eprintln!("Warning: Could not parse {}: {}", path.display(), message);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(HygieneSummary::from_violations(all_violations))
}

// ============================================================================
// Helpers
// ============================================================================

fn truncate_line(line: &str, max_len: usize) -> String {
    let trimmed = line.trim();
    if trimmed.len() > max_len {
        format!("{}...", &trimmed[..max_len - 3])
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn analyze_code(code: &str) -> Vec<HygieneViolation> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path()).unwrap()
    }

    #[test]
    fn test_detects_debug_macro() {
        let violations = analyze_code(
            r#"
            fn main() {
                dbg!(x);
            }
        "#,
        );

        let debug_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == HygieneViolationKind::DebugCode)
            .collect();

        assert_eq!(debug_violations.len(), 1);
    }

    #[test]
    fn test_detects_println() {
        let violations = analyze_code(
            r#"
            fn main() {
                println!("hello");
            }
        "#,
        );

        let debug_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == HygieneViolationKind::DebugCode)
            .collect();

        assert_eq!(debug_violations.len(), 1);
    }

    #[test]
    fn test_ignores_debug_in_tests() {
        let violations = analyze_code(
            r#"
            fn production() {
                println!("this is bad");
            }

            #[cfg(test)]
            mod tests {
                #[test]
                fn test_something() {
                    dbg!(x);
                    println!("this is fine in tests");
                }
            }
        "#,
        );

        let production_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == HygieneViolationKind::DebugCode && !v.in_test)
            .collect();

        assert_eq!(production_violations.len(), 1);
    }

    #[test]
    fn test_detects_missing_doc_comment() {
        let violations = analyze_code(
            r#"
            pub fn public_without_docs() {}

            /// Has docs
            pub fn public_with_docs() {}

            fn private_no_docs() {}
        "#,
        );

        let doc_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == HygieneViolationKind::MissingDocComment)
            .collect();

        assert_eq!(doc_violations.len(), 1);
    }
}
