//! Configuration anti-pattern detection for Hanabi
//!
//! Detects violations of configuration management best practices:
//! - Runtime env::var() calls outside config/
//! - Magic numbers in business logic
//! - Mutable configuration wrappers

use crate::error::{LintError, Result};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{Expr, ExprCall, ExprMethodCall, ExprPath, File, ItemStatic, Type};

/// A configuration anti-pattern violation
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigViolation {
    /// Path to the file containing the violation
    pub path: PathBuf,
    /// Line number where the violation occurs
    pub line: usize,
    /// Type of violation
    pub kind: ConfigViolationKind,
    /// Context or additional details
    pub context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigViolationKind {
    /// env::var() call outside config module
    RuntimeEnvVar,
    /// Magic number literal in business logic
    MagicNumber,
    /// Mutable config wrapper (RwLock<Config>, Mutex<Config>)
    MutableConfig,
}

impl ConfigViolationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeEnvVar => "runtime_env_var",
            Self::MagicNumber => "magic_number",
            Self::MutableConfig => "mutable_config",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::RuntimeEnvVar => "env::var() call outside config module",
            Self::MagicNumber => "Magic number in business logic",
            Self::MutableConfig => "Mutable configuration wrapper",
        }
    }
}

/// Summary of configuration violations
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ConfigSummary {
    /// Total number of violations
    pub total_violations: usize,
    /// Number of runtime env::var violations
    pub env_var_violations: usize,
    /// Number of magic number violations
    pub magic_number_violations: usize,
    /// Number of mutable config violations
    pub mutable_config_violations: usize,
    /// Whether configuration check passed
    pub passed: bool,
    /// Detailed violations (limited to first 20)
    pub violations: Vec<ConfigViolation>,
}

impl ConfigSummary {
    pub fn from_violations(violations: Vec<ConfigViolation>) -> Self {
        let env_var_violations = violations
            .iter()
            .filter(|v| v.kind == ConfigViolationKind::RuntimeEnvVar)
            .count();
        let magic_number_violations = violations
            .iter()
            .filter(|v| v.kind == ConfigViolationKind::MagicNumber)
            .count();
        let mutable_config_violations = violations
            .iter()
            .filter(|v| v.kind == ConfigViolationKind::MutableConfig)
            .count();

        let total = violations.len();
        // Only env_var and mutable_config are hard failures
        // Magic numbers are warnings for now (too noisy to be a gate initially)
        let passed = env_var_violations == 0 && mutable_config_violations == 0;

        Self {
            total_violations: total,
            env_var_violations,
            magic_number_violations,
            mutable_config_violations,
            passed,
            violations: violations.into_iter().take(20).collect(),
        }
    }
}

/// Visitor to detect configuration anti-patterns
struct ConfigVisitor<'a> {
    violations: Vec<ConfigViolation>,
    file_path: &'a Path,
    in_test: bool,
    in_const: bool,
    in_config_module: bool,
}

impl<'a> ConfigVisitor<'a> {
    fn new(file_path: &'a Path) -> Self {
        // Check if we're in the config module
        let path_str = file_path.to_string_lossy();
        let in_config_module = path_str.contains("/config/") || path_str.ends_with("/config.rs");

        Self {
            violations: Vec::new(),
            file_path,
            in_test: false,
            in_const: false,
            in_config_module,
        }
    }

    fn add_violation(&mut self, kind: ConfigViolationKind, line: usize, context: String) {
        self.violations.push(ConfigViolation {
            path: self.file_path.to_path_buf(),
            line,
            kind,
            context,
        });
    }

    /// Check if an expression is an env::var call
    fn is_env_var_call(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Call(ExprCall { func, .. }) => {
                if let Expr::Path(ExprPath { path, .. }) = func.as_ref() {
                    let path_str = path_to_string(path);
                    path_str.contains("env::var")
                        || path_str.contains("std::env::var")
                        || path_str == "var"
                } else {
                    false
                }
            }
            Expr::MethodCall(ExprMethodCall { method, .. }) => {
                // env::var is a function, not a method, but check anyway
                method == "var"
            }
            _ => false,
        }
    }

    /// Check if a type is a mutable config wrapper
    fn is_mutable_config_type(&self, ty: &Type) -> Option<String> {
        // Convert type to string representation
        let type_str = type_to_string(ty);
        let type_str_lower = type_str.to_lowercase();

        // Check for patterns like RwLock<...Config...>, Mutex<...Config...>
        if (type_str.contains("RwLock") || type_str.contains("Mutex") || type_str.contains("RefCell"))
            && type_str_lower.contains("config")
        {
            Some(type_str.replace(' ', ""))
        } else {
            None
        }
    }
}

/// Convert a syn::Type to a string representation
fn type_to_string(ty: &Type) -> String {
    match ty {
        Type::Path(type_path) => {
            type_path
                .path
                .segments
                .iter()
                .map(|seg| {
                    let ident = seg.ident.to_string();
                    match &seg.arguments {
                        syn::PathArguments::None => ident,
                        syn::PathArguments::AngleBracketed(args) => {
                            let inner: Vec<String> = args
                                .args
                                .iter()
                                .filter_map(|arg| {
                                    if let syn::GenericArgument::Type(inner_ty) = arg {
                                        Some(type_to_string(inner_ty))
                                    } else {
                                        None
                                    }
                                })
                                .collect();
                            format!("{}<{}>", ident, inner.join(", "))
                        }
                        syn::PathArguments::Parenthesized(_) => ident,
                    }
                })
                .collect::<Vec<_>>()
                .join("::")
        }
        _ => "unknown".to_string(),
    }
}

impl<'ast, 'a> Visit<'ast> for ConfigVisitor<'a> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        // Check if this is a test module
        let was_in_test = self.in_test;
        if node.ident == "tests" || node.ident == "test" {
            self.in_test = true;
        }

        syn::visit::visit_item_mod(self, node);
        self.in_test = was_in_test;
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        // Constants are allowed to have literals
        let was_in_const = self.in_const;
        self.in_const = true;
        syn::visit::visit_item_const(self, node);
        self.in_const = was_in_const;
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        // Check for mutable config wrappers in static declarations
        if let Some(type_str) = self.is_mutable_config_type(&node.ty) {
            let line = node.ident.span().start().line;
            self.add_violation(
                ConfigViolationKind::MutableConfig,
                line,
                format!("static {}: {}", node.ident, type_str),
            );
        }

        // Static initializers are like constants
        let was_in_const = self.in_const;
        self.in_const = true;
        syn::visit::visit_item_static(self, node);
        self.in_const = was_in_const;
    }

    fn visit_item_struct(&mut self, node: &'ast syn::ItemStruct) {
        // Check struct fields for mutable config wrappers
        for field in &node.fields {
            if let Some(type_str) = self.is_mutable_config_type(&field.ty) {
                let line = field
                    .ident
                    .as_ref()
                    .map(|i| i.span().start().line)
                    .unwrap_or(1);
                let field_name = field
                    .ident
                    .as_ref()
                    .map(|i| i.to_string())
                    .unwrap_or_else(|| "unnamed".to_string());
                self.add_violation(
                    ConfigViolationKind::MutableConfig,
                    line,
                    format!("{}.{}: {}", node.ident, field_name, type_str),
                );
            }
        }

        syn::visit::visit_item_struct(self, node);
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        // Skip test code
        if self.in_test {
            syn::visit::visit_expr(self, expr);
            return;
        }

        // Check for env::var calls outside config module
        if !self.in_config_module && self.is_env_var_call(expr) {
            let line = get_expr_line(expr);
            self.add_violation(
                ConfigViolationKind::RuntimeEnvVar,
                line,
                "env::var() call outside config module".to_string(),
            );
        }

        // Check for magic numbers (only outside const/static context)
        // This is intentionally conservative - only flag obvious cases
        if !self.in_const && !self.in_config_module {
            if let Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(lit_int),
                ..
            }) = expr
            {
                // Parse the integer value
                if let Ok(value) = lit_int.base10_parse::<i64>() {
                    // Skip common acceptable values: -1, 0, 1, 2
                    // and values that look like array indices or common constants
                    if !(-1..=2).contains(&value)
                        && value != 10
                        && value != 100
                        && value != 1000
                        && value % 1024 != 0
                    {
                        // Only flag suspicious numbers that are likely config values
                        // Timeouts (> 10), limits (> 100), ports, buffer sizes
                        let suspicious = value > 10
                            || value < -1
                            || (value >= 1024 && value <= 65535); // Port range

                        if suspicious {
                            let line = lit_int.span().start().line;
                            self.add_violation(
                                ConfigViolationKind::MagicNumber,
                                line,
                                format!("literal value: {}", value),
                            );
                        }
                    }
                }
            }
        }

        syn::visit::visit_expr(self, expr);
    }
}

/// Convert a syn::Path to a string
fn path_to_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Get the line number of an expression
fn get_expr_line(expr: &Expr) -> usize {
    match expr {
        Expr::Call(e) => e.paren_token.span.open().start().line,
        Expr::MethodCall(e) => e.method.span().start().line,
        _ => 1,
    }
}

/// Analyze a single Rust file for configuration violations
pub fn analyze_file(path: &Path) -> Result<Vec<ConfigViolation>> {
    let content = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let file: File = syn::parse_file(&content).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = ConfigVisitor::new(path);
    visitor.visit_file(&file);

    Ok(visitor.violations)
}

/// Analyze a directory for configuration violations
pub fn analyze_directory(dir: &Path) -> Result<ConfigSummary> {
    let mut all_violations = Vec::new();

    fn visit_dir(dir: &Path, violations: &mut Vec<ConfigViolation>) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Skip target and hidden directories
                let name = path
                    .file_name()
                    .and_then(|n: &std::ffi::OsStr| n.to_str())
                    .unwrap_or("");
                if name != "target" && !name.starts_with('.') {
                    visit_dir(&path, violations)?;
                }
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                match analyze_file(&path) {
                    Ok(file_violations) => violations.extend(file_violations),
                    Err(LintError::ParseError { .. }) => {
                        // Skip files that don't parse (might be generated code)
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(())
    }

    visit_dir(dir, &mut all_violations)?;

    Ok(ConfigSummary::from_violations(all_violations))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn analyze_code(code: &str) -> Vec<ConfigViolation> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path()).unwrap()
    }

    #[test]
    fn test_detects_env_var_call() {
        let code = r#"
            fn get_timeout() -> u64 {
                std::env::var("TIMEOUT").unwrap().parse().unwrap()
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .any(|v| v.kind == ConfigViolationKind::RuntimeEnvVar));
    }

    #[test]
    fn test_ignores_env_var_in_test() {
        let code = r#"
            #[cfg(test)]
            mod tests {
                fn test_something() {
                    std::env::var("TEST_VAR").ok();
                }
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .all(|v| v.kind != ConfigViolationKind::RuntimeEnvVar));
    }

    #[test]
    fn test_detects_mutable_config_rwlock() {
        let code = r#"
            use std::sync::RwLock;

            pub struct AppState {
                pub config: RwLock<AppConfig>,
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .any(|v| v.kind == ConfigViolationKind::MutableConfig));
    }

    #[test]
    fn test_detects_mutable_config_mutex() {
        let code = r#"
            use std::sync::Mutex;

            static CONFIG: Mutex<ServerConfig> = Mutex::new(ServerConfig::default());
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .any(|v| v.kind == ConfigViolationKind::MutableConfig));
    }

    #[test]
    fn test_allows_arc_config() {
        let code = r#"
            use std::sync::Arc;

            pub struct AppState {
                pub config: Arc<AppConfig>,
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .all(|v| v.kind != ConfigViolationKind::MutableConfig));
    }

    #[test]
    fn test_detects_magic_number() {
        let code = r#"
            fn check_timeout(elapsed: u64) -> bool {
                elapsed > 5000
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .any(|v| v.kind == ConfigViolationKind::MagicNumber));
    }

    #[test]
    fn test_allows_small_numbers() {
        let code = r#"
            fn increment(x: i32) -> i32 {
                x + 1
            }
        "#;
        let violations = analyze_code(code);
        assert!(violations
            .iter()
            .all(|v| v.kind != ConfigViolationKind::MagicNumber));
    }

    #[test]
    fn test_allows_const_numbers() {
        let code = r#"
            const MAX_CONNECTIONS: usize = 10000;

            fn check(n: usize) -> bool {
                n < MAX_CONNECTIONS
            }
        "#;
        let violations = analyze_code(code);
        // The literal 10000 is in a const, so should not be flagged
        let magic_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == ConfigViolationKind::MagicNumber)
            .collect();
        assert!(magic_violations.is_empty());
    }

    #[test]
    fn test_config_summary_passed() {
        let violations = vec![];
        let summary = ConfigSummary::from_violations(violations);
        assert!(summary.passed);
    }

    #[test]
    fn test_config_summary_failed_env_var() {
        let violations = vec![ConfigViolation {
            path: PathBuf::from("test.rs"),
            line: 1,
            kind: ConfigViolationKind::RuntimeEnvVar,
            context: "test".to_string(),
        }];
        let summary = ConfigSummary::from_violations(violations);
        assert!(!summary.passed);
    }

    #[test]
    fn test_config_summary_magic_numbers_dont_fail() {
        // Magic numbers are warnings, not failures
        let violations = vec![ConfigViolation {
            path: PathBuf::from("test.rs"),
            line: 1,
            kind: ConfigViolationKind::MagicNumber,
            context: "test".to_string(),
        }];
        let summary = ConfigSummary::from_violations(violations);
        assert!(summary.passed); // Magic numbers alone don't fail
        assert_eq!(summary.magic_number_violations, 1);
    }
}
