//! AST-based unwrap and panic detector using syn
//!
//! This module accurately detects production unwraps by parsing Rust AST,
//! properly distinguishing test code from production code at the structural level.

use crate::error::{LintError, Result};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{Attribute, ExprMethodCall, File, ItemFn, ItemMod, ItemStatic, Macro};

/// A detected violation in the source code
#[derive(Debug, Clone, serde::Serialize)]
pub struct Violation {
    pub path: PathBuf,
    pub line: usize,
    pub column: usize,
    pub kind: ViolationKind,
    pub context: String,
    pub in_test: bool,
}

/// Types of violations we detect
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind {
    Unwrap,
    Expect,
    Panic,
    Unreachable,
    Todo,
    Unimplemented,
}

impl ViolationKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unwrap => "unwrap()",
            Self::Expect => "expect()",
            Self::Panic => "panic!()",
            Self::Unreachable => "unreachable!()",
            Self::Todo => "todo!()",
            Self::Unimplemented => "unimplemented!()",
        }
    }

    pub fn severity(&self) -> &'static str {
        match self {
            Self::Unwrap | Self::Expect => "error",
            Self::Panic | Self::Unreachable | Self::Todo | Self::Unimplemented => "error",
        }
    }
}

/// AST visitor that detects unwraps and panics
struct UnwrapVisitor<'a> {
    file_path: &'a Path,
    source: &'a str,
    violations: Vec<Violation>,
    test_context_depth: usize,
    /// Track when we're inside a static item (LazyLock/Lazy initialization)
    /// expect() is acceptable in statics because they fail-fast at startup
    static_context_depth: usize,
}

impl<'a> UnwrapVisitor<'a> {
    fn new(file_path: &'a Path, source: &'a str) -> Self {
        Self {
            file_path,
            source,
            violations: Vec::new(),
            test_context_depth: 0,
            static_context_depth: 0,
        }
    }

    fn in_test_context(&self) -> bool {
        self.test_context_depth > 0
    }

    /// Check if we're inside a static item (LazyLock, Lazy, etc.)
    /// expect() is acceptable in statics because they fail-fast at startup
    fn in_static_context(&self) -> bool {
        self.static_context_depth > 0
    }

    /// Check if attributes include #[cfg(test)] or #[test]
    fn has_test_attr(attrs: &[Attribute]) -> bool {
        for attr in attrs {
            if let Some(ident) = attr.path().get_ident() {
                let name = ident.to_string();
                if name == "test" || name == "tokio::test" {
                    return true;
                }
            }
            // Check for #[cfg(test)]
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

    fn add_violation(&mut self, span: proc_macro2::Span, kind: ViolationKind) {
        let (line, column) = self.get_line_col(span);
        let context = self.get_context(line);

        self.violations.push(Violation {
            path: self.file_path.to_path_buf(),
            line,
            column,
            kind,
            context,
            in_test: self.in_test_context(),
        });
    }
}

impl<'ast, 'a> Visit<'ast> for UnwrapVisitor<'a> {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        // Check if this module is a test module
        let is_test_mod =
            node.ident == "tests" || node.ident == "test" || Self::has_test_attr(&node.attrs);

        if is_test_mod {
            self.test_context_depth += 1;
        }

        // Visit the module contents
        syn::visit::visit_item_mod(self, node);

        if is_test_mod {
            self.test_context_depth -= 1;
        }
    }

    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        // Check if this function has #[test] attribute
        let is_test_fn = Self::has_test_attr(&node.attrs);

        if is_test_fn {
            self.test_context_depth += 1;
        }

        syn::visit::visit_item_fn(self, node);

        if is_test_fn {
            self.test_context_depth -= 1;
        }
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        // Static items (LazyLock, Lazy, etc.) are initialized at startup
        // expect() is acceptable here because it fails fast at startup
        self.static_context_depth += 1;
        syn::visit::visit_item_static(self, node);
        self.static_context_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method_name = node.method.to_string();

        match method_name.as_str() {
            "unwrap" => {
                // unwrap is never acceptable in production code
                self.add_violation(node.method.span(), ViolationKind::Unwrap);
            }
            "expect" => {
                // expect() is acceptable in static contexts (LazyLock, Lazy)
                // because they fail-fast at startup, not during request handling
                if !self.in_static_context() {
                    self.add_violation(node.method.span(), ViolationKind::Expect);
                }
            }
            _ => {}
        }

        // Continue visiting nested expressions
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        if let Some(ident) = node.path.get_ident() {
            let macro_name = ident.to_string();
            let kind = match macro_name.as_str() {
                "panic" => Some(ViolationKind::Panic),
                "unreachable" => Some(ViolationKind::Unreachable),
                "todo" => Some(ViolationKind::Todo),
                "unimplemented" => Some(ViolationKind::Unimplemented),
                _ => None,
            };

            if let Some(kind) = kind {
                self.add_violation(ident.span(), kind);
            }
        }

        syn::visit::visit_macro(self, node);
    }
}

/// Analyze a single Rust file for violations
pub fn analyze_file(path: &Path) -> Result<Vec<Violation>> {
    let source = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let syntax_tree: File = syn::parse_file(&source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = UnwrapVisitor::new(path, &source);
    visitor.visit_file(&syntax_tree);

    Ok(visitor.violations)
}

/// Analyze all Rust files in a directory
pub fn analyze_directory(dir: &Path) -> Result<Vec<Violation>> {
    let mut all_violations = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
    {
        match analyze_file(entry.path()) {
            Ok(violations) => all_violations.extend(violations),
            Err(LintError::ParseError { path, message }) => {
                // Log parse errors but continue
                eprintln!("Warning: Could not parse {}: {}", path.display(), message);
            }
            Err(e) => return Err(e),
        }
    }

    Ok(all_violations)
}

/// Summary of violations by type
#[derive(Debug, Default, serde::Serialize)]
pub struct ViolationSummary {
    pub total: usize,
    pub production: usize,
    pub test: usize,
    pub by_kind: std::collections::HashMap<String, usize>,
}

impl ViolationSummary {
    pub fn from_violations(violations: &[Violation]) -> Self {
        let mut summary = Self::default();
        summary.total = violations.len();

        for v in violations {
            if v.in_test {
                summary.test += 1;
            } else {
                summary.production += 1;
            }

            *summary
                .by_kind
                .entry(v.kind.as_str().to_string())
                .or_default() += 1;
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn analyze_code(code: &str) -> Vec<Violation> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(code.as_bytes()).unwrap();
        analyze_file(file.path()).unwrap()
    }

    #[test]
    fn test_detects_unwrap() {
        let violations = analyze_code(
            r#"
            fn main() {
                let x: Option<i32> = Some(1);
                let y = x.unwrap();
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Unwrap);
        assert!(!violations[0].in_test);
    }

    #[test]
    fn test_detects_expect() {
        let violations = analyze_code(
            r#"
            fn main() {
                let x: Option<i32> = Some(1);
                let y = x.expect("should exist");
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Expect);
    }

    #[test]
    fn test_ignores_test_modules() {
        let violations = analyze_code(
            r#"
            fn production_code() {
                let x = Some(1).unwrap(); // This should be detected
            }

            #[cfg(test)]
            mod tests {
                fn test_code() {
                    let x = Some(1).unwrap(); // This is in test
                }
            }
        "#,
        );

        let production: Vec<_> = violations.iter().filter(|v| !v.in_test).collect();
        let test: Vec<_> = violations.iter().filter(|v| v.in_test).collect();

        assert_eq!(production.len(), 1);
        assert_eq!(test.len(), 1);
    }

    #[test]
    fn test_detects_panic_macro() {
        let violations = analyze_code(
            r#"
            fn main() {
                panic!("oops");
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Panic);
    }

    #[test]
    fn test_detects_todo_macro() {
        let violations = analyze_code(
            r#"
            fn main() {
                todo!("implement this");
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Todo);
    }

    #[test]
    fn test_detects_unreachable_macro() {
        let violations = analyze_code(
            r#"
            fn main() {
                unreachable!("should not happen");
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Unreachable);
    }

    #[test]
    fn test_detects_unimplemented_macro() {
        let violations = analyze_code(
            r#"
            fn main() {
                unimplemented!();
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Unimplemented);
    }

    #[test]
    fn test_expect_allowed_in_static() {
        let violations = analyze_code(
            r#"
            static RE: i32 = {
                let x: Option<i32> = Some(1);
                x.expect("static init")
            };
        "#,
        );

        let production: Vec<_> = violations.iter().filter(|v| !v.in_test).collect();
        // expect in static should NOT produce a violation
        assert!(
            production.iter().all(|v| v.kind != ViolationKind::Expect),
            "expect in static should be allowed"
        );
    }

    #[test]
    fn test_unwrap_still_detected_in_static() {
        let violations = analyze_code(
            r#"
            static VAL: i32 = {
                let x: Option<i32> = Some(1);
                x.unwrap()
            };
        "#,
        );

        let unwraps: Vec<_> = violations
            .iter()
            .filter(|v| v.kind == ViolationKind::Unwrap)
            .collect();
        assert_eq!(unwraps.len(), 1);
    }

    #[test]
    fn test_test_fn_attribute() {
        let violations = analyze_code(
            r#"
            fn prod() {
                let _ = Some(1).unwrap();
            }

            #[test]
            fn test_something() {
                let _ = Some(1).unwrap();
            }
        "#,
        );

        let production: Vec<_> = violations.iter().filter(|v| !v.in_test).collect();
        let test: Vec<_> = violations.iter().filter(|v| v.in_test).collect();
        assert_eq!(production.len(), 1);
        assert_eq!(test.len(), 1);
    }

    #[test]
    fn test_mod_named_tests_is_test_context() {
        let violations = analyze_code(
            r#"
            mod tests {
                fn helper() {
                    let _ = Some(1).unwrap();
                }
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert!(violations[0].in_test);
    }

    #[test]
    fn test_mod_named_test_is_test_context() {
        let violations = analyze_code(
            r#"
            mod test {
                fn helper() {
                    let _ = Some(1).unwrap();
                }
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert!(violations[0].in_test);
    }

    #[test]
    fn test_multiple_violations_in_same_fn() {
        let violations = analyze_code(
            r#"
            fn multi() {
                let a = Some(1).unwrap();
                let b = Some(2).expect("b");
                panic!("oh no");
            }
        "#,
        );

        assert_eq!(violations.len(), 3);
        assert_eq!(violations[0].kind, ViolationKind::Unwrap);
        assert_eq!(violations[1].kind, ViolationKind::Expect);
        assert_eq!(violations[2].kind, ViolationKind::Panic);
    }

    #[test]
    fn test_violation_kind_as_str() {
        assert_eq!(ViolationKind::Unwrap.as_str(), "unwrap()");
        assert_eq!(ViolationKind::Expect.as_str(), "expect()");
        assert_eq!(ViolationKind::Panic.as_str(), "panic!()");
        assert_eq!(ViolationKind::Unreachable.as_str(), "unreachable!()");
        assert_eq!(ViolationKind::Todo.as_str(), "todo!()");
        assert_eq!(ViolationKind::Unimplemented.as_str(), "unimplemented!()");
    }

    #[test]
    fn test_violation_kind_severity_all_error() {
        assert_eq!(ViolationKind::Unwrap.severity(), "error");
        assert_eq!(ViolationKind::Expect.severity(), "error");
        assert_eq!(ViolationKind::Panic.severity(), "error");
        assert_eq!(ViolationKind::Unreachable.severity(), "error");
        assert_eq!(ViolationKind::Todo.severity(), "error");
        assert_eq!(ViolationKind::Unimplemented.severity(), "error");
    }

    #[test]
    fn test_violation_summary_from_violations() {
        let violations = vec![
            Violation {
                path: PathBuf::from("a.rs"),
                line: 1,
                column: 1,
                kind: ViolationKind::Unwrap,
                context: String::new(),
                in_test: false,
            },
            Violation {
                path: PathBuf::from("a.rs"),
                line: 2,
                column: 1,
                kind: ViolationKind::Unwrap,
                context: String::new(),
                in_test: true,
            },
            Violation {
                path: PathBuf::from("b.rs"),
                line: 1,
                column: 1,
                kind: ViolationKind::Panic,
                context: String::new(),
                in_test: false,
            },
        ];

        let summary = ViolationSummary::from_violations(&violations);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.production, 2);
        assert_eq!(summary.test, 1);
        assert_eq!(summary.by_kind.get("unwrap()"), Some(&2));
        assert_eq!(summary.by_kind.get("panic!()"), Some(&1));
    }

    #[test]
    fn test_violation_summary_empty() {
        let summary = ViolationSummary::from_violations(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.production, 0);
        assert_eq!(summary.test, 0);
        assert!(summary.by_kind.is_empty());
    }

    #[test]
    fn test_violation_kind_serde() {
        let json = serde_json::to_string(&ViolationKind::Unwrap).unwrap();
        assert_eq!(json, "\"unwrap\"");
        let json = serde_json::to_string(&ViolationKind::Unreachable).unwrap();
        assert_eq!(json, "\"unreachable\"");
    }

    #[test]
    fn test_violation_has_line_and_column() {
        let violations = analyze_code(
            r#"fn main() {
    let x = Some(1).unwrap();
}"#,
        );

        assert_eq!(violations.len(), 1);
        assert!(violations[0].line > 0);
        assert!(violations[0].column > 0);
    }

    #[test]
    fn test_violation_context_contains_code() {
        let violations = analyze_code(
            r#"
            fn main() {
                let val = Some(42).unwrap();
            }
        "#,
        );

        assert_eq!(violations.len(), 1);
        assert!(violations[0].context.contains("unwrap"));
    }
}
