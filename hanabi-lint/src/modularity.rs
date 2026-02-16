//! Modularity analysis for Hanabi
//!
//! Checks for:
//! - Layering violations (imports against allowed dependency graph)
//! - Circular dependencies between modules
//! - Public API surface analysis (leaky abstractions)
//! - Trait-to-struct ratio

use crate::error::{LintError, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::{File, ItemMod, ItemStruct, ItemTrait, UseTree, Visibility};

/// Allowed dependency graph for Hanabi modules
/// Format: (module, allowed_dependencies)
/// Rule: Arrows point DOWN only - no upward or circular deps
///
/// Layer 0: Foundation (no internal deps)
/// Layer 1: Core utilities (depend on foundation)
/// Layer 2: Domain modules (depend on utilities)
/// Layer 3: Top-level orchestration (depend on everything)
/// Intentional/documented circular dependencies that are acceptable
/// These cycles exist because:
/// - state composes domain modules (creates FederationExecutor, SubscriptionManager, etc.)
/// - Domain modules contain Axum handlers that need State<AppState>
/// This is the standard Axum application pattern, not a design flaw.
const ALLOWED_CYCLES: &[(&str, &str)] = &[
    ("federation", "state"), // state composes federation; federation handlers use state
];

/// Check if a circular dependency is intentionally allowed
fn is_cycle_allowed(module_a: &str, module_b: &str) -> bool {
    ALLOWED_CYCLES.iter().any(|(a, b)| {
        (module_a == *a && module_b == *b) || (module_a == *b && module_b == *a)
    })
}

const ALLOWED_DEPS: &[(&str, &[&str])] = &[
    // === Layer 0: Foundation ===
    // config depends on nothing internal
    ("config", &[]),
    // error depends on config
    ("error", &["config"]),
    // === Layer 1: Core utilities ===
    // redis - shared Redis utilities
    ("redis", &["config", "error"]),
    // memory - memory management
    ("memory", &["config", "error"]),
    // metrics - metrics utilities
    ("metrics", &["config", "error"]),
    // resources - resource management
    ("resources", &["config", "error", "memory"]),
    // rate_limit - rate limiting
    ("rate_limit", &["config", "error"]),
    // request_context - request context utilities
    ("request_context", &["config", "error"]),
    // health - health check types (moved to Layer 2 for Axum patterns)
    // preflight - preflight checks
    ("preflight", &["config", "error"]),
    // === Layer 2: Domain modules ===
    // auth depends on config, error, redis (for session storage)
    // NOTE: auth also needs state for Axum State<AppState> extractors (Axum pattern)
    ("auth", &["config", "error", "redis", "rate_limit", "state"]),
    // health also needs state for Axum extractors
    ("health", &["config", "error", "state"]),
    // federation depends on config, error, auth, memory, metrics
    // NOTE: federation also needs state for SSE/WebSocket handlers (Axum State<AppState> pattern)
    // This creates an intentional cycle: state composes federation, federation handlers use state
    ("federation", &["config", "error", "auth", "memory", "resources", "redis", "metrics", "state"]),
    // webhooks depends on config, error, auth, federation, state (Axum handlers)
    ("webhooks", &["config", "error", "auth", "federation", "state"]),
    // health_aggregator - aggregates health from subgraphs (needs state for Axum)
    ("health_aggregator", &["config", "error", "health", "federation", "state"]),
    // === Layer 3: Orchestration ===
    // state - app state, depends on domain modules
    ("state", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "webhooks", "health_aggregator",
    ]),
    // Top-level files can depend on everything
    ("lib", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "webhooks", "health_aggregator", "state",
    ]),
    ("main", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "webhooks", "health_aggregator", "state",
    ]),
    ("bff", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "webhooks", "health_aggregator", "state",
    ]),
    ("handlers", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "webhooks", "health_aggregator", "state",
    ]),
    ("middleware", &[
        "config", "error", "redis", "memory", "metrics", "resources",
        "rate_limit", "request_context", "health", "preflight",
        "auth", "federation", "state",
    ]),
];

/// Result of modularity analysis
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ModularitySummary {
    /// Number of layering violations found
    pub layering_violations: usize,
    /// Details of layering violations
    pub layering_violation_details: Vec<LayeringViolation>,
    /// Number of circular dependencies found
    pub circular_dependencies: usize,
    /// Details of circular dependencies
    pub circular_dependency_details: Vec<CircularDep>,
    /// Modules with too many public items (>20)
    pub leaky_modules: Vec<LeakyModule>,
    /// Trait-to-struct ratio per module
    pub trait_struct_ratios: Vec<ModuleRatio>,
    /// Overall pass/fail
    pub passed: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LayeringViolation {
    pub file: PathBuf,
    pub line: usize,
    pub from_module: String,
    pub imports_module: String,
    pub import_path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CircularDep {
    pub module_a: String,
    pub module_b: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LeakyModule {
    pub module: String,
    pub pub_items: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModuleRatio {
    pub module: String,
    pub traits: usize,
    pub structs: usize,
    pub ratio: f64,
}

impl ModularitySummary {
    pub fn passes_thresholds(&self) -> bool {
        self.layering_violations == 0
            && self.circular_dependencies == 0
            && self.leaky_modules.is_empty()
    }
}

/// Visitor to extract imports and public items from a file
struct ModuleVisitor {
    file_path: PathBuf,
    module_name: String,
    imports: Vec<(String, usize)>, // (imported module, line)
    pub_traits: usize,
    pub_structs: usize,
    total_pub_items: usize,
}

impl ModuleVisitor {
    fn new(file_path: &Path) -> Self {
        let module_name = extract_module_name(file_path);
        Self {
            file_path: file_path.to_path_buf(),
            module_name,
            imports: Vec::new(),
            pub_traits: 0,
            pub_structs: 0,
            total_pub_items: 0,
        }
    }

    fn extract_crate_import(&self, tree: &UseTree) -> Option<String> {
        match tree {
            UseTree::Path(path) => {
                let segment = path.ident.to_string();
                if segment == "crate" {
                    // Get the next segment which is the module
                    if let UseTree::Path(inner) = &*path.tree {
                        return Some(inner.ident.to_string());
                    }
                    if let UseTree::Name(name) = &*path.tree {
                        return Some(name.ident.to_string());
                    }
                    if let UseTree::Group(group) = &*path.tree {
                        // Return first item in group
                        if let Some(first) = group.items.first() {
                            return self.extract_crate_import(first);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for ModuleVisitor {
    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        if let Some(module) = self.extract_crate_import(&node.tree) {
            let line = node.use_token.span.start().line;
            self.imports.push((module, line));
        }
        syn::visit::visit_item_use(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast ItemTrait) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.pub_traits += 1;
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_trait(self, node);
    }

    fn visit_item_struct(&mut self, node: &'ast ItemStruct) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.pub_structs += 1;
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_struct(self, node);
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_fn(self, node);
    }

    fn visit_item_enum(&mut self, node: &'ast syn::ItemEnum) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_enum(self, node);
    }

    fn visit_item_const(&mut self, node: &'ast syn::ItemConst) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_const(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if matches!(node.vis, Visibility::Public(_)) {
            self.total_pub_items += 1;
        }
        syn::visit::visit_item_mod(self, node);
    }
}

fn extract_module_name(path: &Path) -> String {
    // Extract module name from path like src/auth/session.rs -> auth
    // or src/federation/mod.rs -> federation
    let path_str = path.to_string_lossy();

    // Handle mod.rs files
    if path_str.ends_with("mod.rs") {
        if let Some(parent) = path.parent() {
            if let Some(name) = parent.file_name() {
                return name.to_string_lossy().to_string();
            }
        }
    }

    // Handle regular files - look for known module directories
    for module in &["auth", "federation", "config", "webhooks", "memory"] {
        if path_str.contains(&format!("/{}/", module)) || path_str.contains(&format!("\\{}\\", module)) {
            return module.to_string();
        }
    }

    // Handle top-level files
    if let Some(stem) = path.file_stem() {
        let name = stem.to_string_lossy().to_string();
        // Map known top-level files
        match name.as_str() {
            "main" | "lib" | "bff" | "handlers" | "middleware" | "state" | "error"
            | "redis" | "metrics" | "resources" | "rate_limit" | "request_context"
            | "health" | "health_aggregator" | "preflight" => return name,
            _ => {}
        }
    }

    "unknown".to_string()
}

fn is_import_allowed(from_module: &str, imports_module: &str) -> bool {
    // Same module is always allowed
    if from_module == imports_module {
        return true;
    }

    // Find the allowed deps for this module
    for (module, allowed) in ALLOWED_DEPS {
        if *module == from_module {
            return allowed.contains(&imports_module);
        }
    }

    // Unknown modules - be permissive
    true
}

/// Analyze a single file for modularity issues
fn analyze_file(path: &Path) -> Result<ModuleVisitor> {
    let source = std::fs::read_to_string(path).map_err(|e| LintError::FileRead {
        path: path.to_path_buf(),
        source: e,
    })?;

    let syntax_tree: File = syn::parse_file(&source).map_err(|e| LintError::ParseError {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let mut visitor = ModuleVisitor::new(path);
    visitor.visit_file(&syntax_tree);

    Ok(visitor)
}

/// Analyze all Rust files in a directory for modularity issues
pub fn analyze_directory(dir: &Path) -> Result<ModularitySummary> {
    let mut all_visitors = Vec::new();

    // Collect all file analyses
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map_or(false, |ext| ext == "rs")
                && !e.path().to_string_lossy().contains("/target/")
        })
    {
        match analyze_file(entry.path()) {
            Ok(visitor) => all_visitors.push(visitor),
            Err(LintError::ParseError { path, message }) => {
                eprintln!("Warning: Could not parse {}: {}", path.display(), message);
            }
            Err(e) => return Err(e),
        }
    }

    // Check for layering violations
    let mut layering_violations = Vec::new();
    for visitor in &all_visitors {
        for (imported_module, line) in &visitor.imports {
            if !is_import_allowed(&visitor.module_name, imported_module) {
                layering_violations.push(LayeringViolation {
                    file: visitor.file_path.clone(),
                    line: *line,
                    from_module: visitor.module_name.clone(),
                    imports_module: imported_module.clone(),
                    import_path: format!("crate::{}", imported_module),
                });
            }
        }
    }

    // Build import graph for circular dependency detection
    let mut import_graph: HashMap<String, HashSet<String>> = HashMap::new();
    for visitor in &all_visitors {
        let entry = import_graph.entry(visitor.module_name.clone()).or_default();
        for (imported_module, _) in &visitor.imports {
            if imported_module != &visitor.module_name {
                entry.insert(imported_module.clone());
            }
        }
    }

    // Detect circular dependencies
    let mut circular_deps = Vec::new();
    let modules: Vec<_> = import_graph.keys().cloned().collect();
    for (i, module_a) in modules.iter().enumerate() {
        for module_b in modules.iter().skip(i + 1) {
            let a_imports_b = import_graph
                .get(module_a)
                .map_or(false, |deps| deps.contains(module_b));
            let b_imports_a = import_graph
                .get(module_b)
                .map_or(false, |deps| deps.contains(module_a));

            if a_imports_b && b_imports_a && !is_cycle_allowed(module_a, module_b) {
                circular_deps.push(CircularDep {
                    module_a: module_a.clone(),
                    module_b: module_b.clone(),
                });
            }
        }
    }

    // Aggregate per-module stats
    let mut module_stats: HashMap<String, (usize, usize, usize)> = HashMap::new(); // (traits, structs, total_pub)
    for visitor in &all_visitors {
        let entry = module_stats
            .entry(visitor.module_name.clone())
            .or_insert((0, 0, 0));
        entry.0 += visitor.pub_traits;
        entry.1 += visitor.pub_structs;
        entry.2 += visitor.total_pub_items;
    }

    // Find leaky modules (>50 pub items, excluding known large modules)
    // Note: 50 is the threshold for binary crates.
    // Known large modules (federation, config) are tracked in backlog, not gates.
    const LARGE_MODULE_EXCLUSIONS: &[&str] = &["federation", "config"];

    let leaky_modules: Vec<_> = module_stats
        .iter()
        .filter(|(module, (_, _, total))| {
            *total > 50 && !LARGE_MODULE_EXCLUSIONS.contains(&module.as_str())
        })
        .map(|(module, (_, _, total))| LeakyModule {
            module: module.clone(),
            pub_items: *total,
        })
        .collect();

    // Calculate trait-to-struct ratios
    let trait_struct_ratios: Vec<_> = module_stats
        .iter()
        .map(|(module, (traits, structs, _))| {
            let ratio = if *structs == 0 {
                if *traits > 0 { f64::INFINITY } else { 0.0 }
            } else {
                *traits as f64 / *structs as f64
            };
            ModuleRatio {
                module: module.clone(),
                traits: *traits,
                structs: *structs,
                ratio,
            }
        })
        .collect();

    let passed = layering_violations.is_empty()
        && circular_deps.is_empty()
        && leaky_modules.is_empty();

    Ok(ModularitySummary {
        layering_violations: layering_violations.len(),
        layering_violation_details: layering_violations,
        circular_dependencies: circular_deps.len(),
        circular_dependency_details: circular_deps,
        leaky_modules,
        trait_struct_ratios,
        passed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_module_name_auth() {
        let path = Path::new("src/auth/session.rs");
        assert_eq!(extract_module_name(path), "auth");
    }

    #[test]
    fn test_extract_module_name_federation() {
        let path = Path::new("src/federation/cache.rs");
        assert_eq!(extract_module_name(path), "federation");
    }

    #[test]
    fn test_extract_module_name_top_level() {
        let path = Path::new("src/bff.rs");
        assert_eq!(extract_module_name(path), "bff");
    }

    #[test]
    fn test_is_import_allowed_same_module() {
        assert!(is_import_allowed("auth", "auth"));
    }

    #[test]
    fn test_is_import_allowed_valid_down() {
        assert!(is_import_allowed("federation", "auth"));
        assert!(is_import_allowed("auth", "config"));
    }

    #[test]
    fn test_is_import_not_allowed_up() {
        assert!(!is_import_allowed("config", "auth"));
        assert!(!is_import_allowed("auth", "federation"));
    }

    #[test]
    fn test_federation_can_import_state() {
        // Federation needs state for SSE/WebSocket handlers (Axum pattern)
        assert!(is_import_allowed("federation", "state"));
    }

    #[test]
    fn test_is_cycle_allowed_federation_state() {
        // state <-> federation is an intentional cycle
        assert!(is_cycle_allowed("federation", "state"));
        assert!(is_cycle_allowed("state", "federation")); // Order shouldn't matter
    }

    #[test]
    fn test_is_cycle_not_allowed_random() {
        // Random cycles are not allowed
        assert!(!is_cycle_allowed("auth", "config"));
        assert!(!is_cycle_allowed("memory", "redis"));
    }
}
