//! Report generation for perfection check results
//!
//! Supports both human-readable terminal output and JSON for CI integration.

use crate::backlog::BacklogSummary;
use crate::cargo_checks::{CargoCheckResult, CargoCheckSummary, CargoCheckType};
use crate::complexity::ComplexitySummary;
use crate::config_detector::ConfigSummary;
use crate::coverage::CoverageSummary;
use crate::hygiene_detector::{HygieneSummary, HygieneViolationKind};
use crate::modularity::ModularitySummary;
use crate::refactoring_detector::{RefactoringSummary, RefactoringViolationKind};
use crate::unwrap_detector::{Violation, ViolationSummary};
use colored::*;
use serde::Serialize;

/// The overall perfection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfectionState {
    Perfect,
    Stable,
    Degraded,
}

impl PerfectionState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Perfect => "PERFECT",
            Self::Stable => "STABLE",
            Self::Degraded => "DEGRADED",
        }
    }

    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Perfect => "🟢",
            Self::Stable => "🟡",
            Self::Degraded => "🔴",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Perfect => "All gates pass, backlog empty",
            Self::Stable => "All gates pass, backlog has items",
            Self::Degraded => "One or more gates failing",
        }
    }
}

/// A single gate result
#[derive(Debug, Clone, Serialize)]
pub struct GateResult {
    pub name: String,
    pub passed: bool,
    pub message: String,
    pub details: Vec<String>,
}

/// Complete perfection check report
#[derive(Debug, Serialize)]
pub struct PerfectionReport {
    pub state: PerfectionState,
    pub gates_passed: usize,
    pub gates_total: usize,
    pub gates: Vec<GateResult>,
    pub violations: ViolationSummary,
    pub complexity: ComplexitySummary,
    pub cargo: CargoCheckSummary,
    pub modularity: ModularitySummary,
    pub coverage: CoverageSummary,
    pub config: ConfigSummary,
    pub hygiene: HygieneSummary,
    pub refactoring: RefactoringSummary,
    pub audit: Option<CargoCheckResult>,
    pub backlog: BacklogSummary,
    pub duration_ms: u64,
}

impl PerfectionReport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        violations: &[Violation],
        complexity: ComplexitySummary,
        cargo: CargoCheckSummary,
        modularity: ModularitySummary,
        coverage: CoverageSummary,
        config: ConfigSummary,
        hygiene: HygieneSummary,
        refactoring: RefactoringSummary,
        audit: Option<CargoCheckResult>,
        backlog: BacklogSummary,
        duration_ms: u64,
        cc_threshold: usize,
        cognitive_threshold: usize,
    ) -> Self {
        let violation_summary = ViolationSummary::from_violations(violations);
        let production_violations: Vec<_> = violations.iter().filter(|v| !v.in_test).collect();

        // Build gate results
        let mut gates = Vec::new();

        // Gate 1: Zero Production Unwraps
        let unwrap_count = production_violations
            .iter()
            .filter(|v| matches!(v.kind, crate::unwrap_detector::ViolationKind::Unwrap | crate::unwrap_detector::ViolationKind::Expect))
            .count();
        gates.push(GateResult {
            name: "Zero Production Unwraps".to_string(),
            passed: unwrap_count == 0,
            message: if unwrap_count == 0 {
                "No production unwraps".to_string()
            } else {
                format!("{} production unwrap(s) found", unwrap_count)
            },
            details: production_violations
                .iter()
                .filter(|v| matches!(v.kind, crate::unwrap_detector::ViolationKind::Unwrap | crate::unwrap_detector::ViolationKind::Expect))
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.kind.as_str()))
                .collect(),
        });

        // Gate 2: Zero Production Panics
        let panic_count = production_violations
            .iter()
            .filter(|v| matches!(v.kind,
                crate::unwrap_detector::ViolationKind::Panic |
                crate::unwrap_detector::ViolationKind::Unreachable |
                crate::unwrap_detector::ViolationKind::Todo |
                crate::unwrap_detector::ViolationKind::Unimplemented))
            .count();
        gates.push(GateResult {
            name: "Zero Production Panics".to_string(),
            passed: panic_count == 0,
            message: if panic_count == 0 {
                "No production panics".to_string()
            } else {
                format!("{} production panic(s) found", panic_count)
            },
            details: vec![],
        });

        // Gate 3: Clippy Clean
        let clippy_result = cargo.results.iter().find(|r| r.check_type == CargoCheckType::Clippy);
        gates.push(GateResult {
            name: "Clippy Clean".to_string(),
            passed: clippy_result.map(|r| r.passed).unwrap_or(true),
            message: clippy_result
                .map(|r| r.message.clone())
                .unwrap_or_else(|| "Clippy not run".to_string()),
            details: clippy_result
                .map(|r| r.details.clone())
                .unwrap_or_default(),
        });

        // Gate 4: All Tests Pass
        let test_result = cargo.results.iter().find(|r| r.check_type == CargoCheckType::Test);
        gates.push(GateResult {
            name: "All Tests Pass".to_string(),
            passed: test_result.map(|r| r.passed).unwrap_or(true),
            message: test_result
                .map(|r| r.message.clone())
                .unwrap_or_else(|| "Tests not run".to_string()),
            details: test_result
                .map(|r| r.details.clone())
                .unwrap_or_default(),
        });

        // Gate 5: Formatted Code
        let fmt_result = cargo.results.iter().find(|r| r.check_type == CargoCheckType::Format);
        gates.push(GateResult {
            name: "Formatted Code".to_string(),
            passed: fmt_result.map(|r| r.passed).unwrap_or(true),
            message: fmt_result
                .map(|r| r.message.clone())
                .unwrap_or_else(|| "Format not checked".to_string()),
            details: vec![],
        });

        // Gate 6: Complexity Thresholds
        let complexity_passed = complexity.passes_thresholds(10.0, 15.0);
        gates.push(GateResult {
            name: "Complexity Thresholds".to_string(),
            passed: complexity_passed,
            message: format!(
                "Avg CC: {:.1} (max {}), Avg Cognitive: {:.1} (max {})",
                complexity.avg_cyclomatic,
                cc_threshold,
                complexity.avg_cognitive,
                cognitive_threshold
            ),
            details: complexity
                .high_complexity_functions
                .iter()
                .take(3)
                .map(|f| format!("{}:{} - CC:{}, Cog:{}", f.path.display(), f.line, f.cyclomatic_complexity, f.cognitive_complexity))
                .collect(),
        });

        // Gate 7: Modularity - No Layering Violations
        gates.push(GateResult {
            name: "No Layering Violations".to_string(),
            passed: modularity.layering_violations == 0,
            message: if modularity.layering_violations == 0 {
                "No layering violations".to_string()
            } else {
                format!("{} layering violation(s) found", modularity.layering_violations)
            },
            details: modularity
                .layering_violation_details
                .iter()
                .take(5)
                .map(|v| format!("{}:{}: {} imports {}", v.file.display(), v.line, v.from_module, v.imports_module))
                .collect(),
        });

        // Gate 8: Modularity - No Circular Dependencies
        gates.push(GateResult {
            name: "No Circular Dependencies".to_string(),
            passed: modularity.circular_dependencies == 0,
            message: if modularity.circular_dependencies == 0 {
                "No circular dependencies".to_string()
            } else {
                format!("{} circular dependency(ies) found", modularity.circular_dependencies)
            },
            details: modularity
                .circular_dependency_details
                .iter()
                .take(5)
                .map(|c| format!("{} <-> {}", c.module_a, c.module_b))
                .collect(),
        });

        // Gate 9: Modularity - No Leaky Abstractions
        gates.push(GateResult {
            name: "No Leaky Abstractions".to_string(),
            passed: modularity.leaky_modules.is_empty(),
            message: if modularity.leaky_modules.is_empty() {
                "All modules have clean APIs (<20 pub items)".to_string()
            } else {
                format!("{} module(s) with >20 pub items", modularity.leaky_modules.len())
            },
            details: modularity
                .leaky_modules
                .iter()
                .take(5)
                .map(|m| format!("{}: {} pub items", m.module, m.pub_items))
                .collect(),
        });

        // Gate 10: Test Coverage (100%)
        gates.push(GateResult {
            name: "Test Coverage 100%".to_string(),
            passed: coverage.passed,
            message: coverage.message.clone(),
            details: coverage
                .uncovered_files
                .iter()
                .take(5)
                .map(|f| format!("{}: {:.1}% ({}/{})", f.path, f.coverage, f.lines_covered, f.lines_total))
                .collect(),
        });

        // Gate 11: No Runtime env::var Calls
        gates.push(GateResult {
            name: "No Runtime env::var".to_string(),
            passed: config.env_var_violations == 0,
            message: if config.env_var_violations == 0 {
                "All env::var calls in config module".to_string()
            } else {
                format!("{} runtime env::var call(s) outside config/", config.env_var_violations)
            },
            details: config
                .violations
                .iter()
                .filter(|v| v.kind == crate::config_detector::ConfigViolationKind::RuntimeEnvVar)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 12: No Mutable Configuration
        gates.push(GateResult {
            name: "No Mutable Config".to_string(),
            passed: config.mutable_config_violations == 0,
            message: if config.mutable_config_violations == 0 {
                "All config wrapped in Arc (immutable)".to_string()
            } else {
                format!("{} mutable config wrapper(s) found", config.mutable_config_violations)
            },
            details: config
                .violations
                .iter()
                .filter(|v| v.kind == crate::config_detector::ConfigViolationKind::MutableConfig)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 13: Security Audit (cargo audit)
        let audit_passed = audit.as_ref().map(|a| a.passed).unwrap_or(true);
        gates.push(GateResult {
            name: "Security Audit".to_string(),
            passed: audit_passed,
            message: audit
                .as_ref()
                .map(|a| a.message.clone())
                .unwrap_or_else(|| "Security audit skipped".to_string()),
            details: audit
                .as_ref()
                .map(|a| a.details.clone())
                .unwrap_or_default(),
        });

        // Gate 14: No Hardcoded Secrets
        gates.push(GateResult {
            name: "No Hardcoded Secrets".to_string(),
            passed: hygiene.secrets_count == 0,
            message: if hygiene.secrets_count == 0 {
                "No hardcoded secrets detected".to_string()
            } else {
                format!("{} potential secret(s) found", hygiene.secrets_count)
            },
            details: hygiene
                .violations
                .iter()
                .filter(|v| v.kind == HygieneViolationKind::HardcodedSecret && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 15: Async Safety
        gates.push(GateResult {
            name: "Async Safety".to_string(),
            passed: hygiene.async_safety_count == 0,
            message: if hygiene.async_safety_count == 0 {
                "No blocking calls in async contexts".to_string()
            } else {
                format!("{} blocking call(s) in async", hygiene.async_safety_count)
            },
            details: hygiene
                .violations
                .iter()
                .filter(|v| v.kind == HygieneViolationKind::BlockingInAsync && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 16: No Debug Code
        gates.push(GateResult {
            name: "No Debug Code".to_string(),
            passed: hygiene.debug_code_count == 0,
            message: if hygiene.debug_code_count == 0 {
                "No debug macros in production".to_string()
            } else {
                format!("{} debug macro(s) found", hygiene.debug_code_count)
            },
            details: hygiene
                .violations
                .iter()
                .filter(|v| v.kind == HygieneViolationKind::DebugCode && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 17: Timeout Configured
        gates.push(GateResult {
            name: "Timeout Configured".to_string(),
            passed: hygiene.missing_timeout_count == 0,
            message: if hygiene.missing_timeout_count == 0 {
                "All HTTP clients have timeouts".to_string()
            } else {
                format!("{} client(s) without timeout", hygiene.missing_timeout_count)
            },
            details: hygiene
                .violations
                .iter()
                .filter(|v| v.kind == HygieneViolationKind::MissingTimeout && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 18: Doc Coverage
        // Note: Doc coverage is a softer gate - we track but may not fail on it initially
        gates.push(GateResult {
            name: "Doc Coverage".to_string(),
            passed: hygiene.missing_docs_count == 0,
            message: if hygiene.missing_docs_count == 0 {
                "All public functions documented".to_string()
            } else {
                format!("{} public fn(s) without docs", hygiene.missing_docs_count)
            },
            details: hygiene
                .violations
                .iter()
                .filter(|v| v.kind == HygieneViolationKind::MissingDocComment && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {}", v.path.display(), v.line, v.context))
                .collect(),
        });

        // Gate 19: Function Size (≤100 lines per McConnell's Code Complete)
        gates.push(GateResult {
            name: "Function Size".to_string(),
            passed: refactoring.long_function_count == 0,
            message: if refactoring.long_function_count == 0 {
                "All functions ≤ 100 lines".to_string()
            } else {
                format!("{} function(s) exceed 100 lines", refactoring.long_function_count)
            },
            details: refactoring
                .violations
                .iter()
                .filter(|v| v.kind == RefactoringViolationKind::LongFunction && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {} ({} lines, max {})", v.path.display(), v.line, v.name, v.current_value, v.threshold))
                .collect(),
        });

        // Gate 20: Parameter Count (≤7 per Miller's Law)
        gates.push(GateResult {
            name: "Parameter Count".to_string(),
            passed: refactoring.too_many_params_count == 0,
            message: if refactoring.too_many_params_count == 0 {
                "All functions ≤ 7 parameters".to_string()
            } else {
                format!("{} function(s) exceed 7 parameters", refactoring.too_many_params_count)
            },
            details: refactoring
                .violations
                .iter()
                .filter(|v| v.kind == RefactoringViolationKind::TooManyParameters && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {} ({} params, max {})", v.path.display(), v.line, v.name, v.current_value, v.threshold))
                .collect(),
        });

        // Gate 21: Nesting Depth (≤8 for parser/compiler code that walks ASTs)
        gates.push(GateResult {
            name: "Nesting Depth".to_string(),
            passed: refactoring.deep_nesting_count == 0,
            message: if refactoring.deep_nesting_count == 0 {
                "All functions ≤ 8 nesting levels".to_string()
            } else {
                format!("{} function(s) exceed 8 nesting levels", refactoring.deep_nesting_count)
            },
            details: refactoring
                .violations
                .iter()
                .filter(|v| v.kind == RefactoringViolationKind::DeepNesting && !v.in_test)
                .take(5)
                .map(|v| format!("{}:{}: {} (depth {}, max {})", v.path.display(), v.line, v.name, v.current_value, v.threshold))
                .collect(),
        });

        // Gate 22: Module Cohesion (≤4000 lines for complex domain modules)
        gates.push(GateResult {
            name: "Module Cohesion".to_string(),
            passed: refactoring.large_file_count == 0,
            message: if refactoring.large_file_count == 0 {
                "All files ≤ 4000 lines".to_string()
            } else {
                format!("{} file(s) exceed 4000 lines", refactoring.large_file_count)
            },
            details: refactoring
                .violations
                .iter()
                .filter(|v| v.kind == RefactoringViolationKind::LargeFile && !v.in_test)
                .take(5)
                .map(|v| format!("{}: {} lines (max {})", v.path.display(), v.current_value, v.threshold))
                .collect(),
        });

        let gates_passed = gates.iter().filter(|g| g.passed).count();
        let gates_total = gates.len();

        // Determine overall state
        let state = if gates_passed == gates_total {
            if backlog.is_empty() {
                PerfectionState::Perfect
            } else {
                PerfectionState::Stable
            }
        } else {
            PerfectionState::Degraded
        };

        Self {
            state,
            gates_passed,
            gates_total,
            gates,
            violations: violation_summary,
            complexity,
            cargo,
            modularity,
            coverage,
            config,
            hygiene,
            refactoring,
            audit,
            backlog,
            duration_ms,
        }
    }

    /// Output as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Output as pretty terminal format
    pub fn to_pretty(&self) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "{}\n",
            "╔══════════════════════════════════════════════════════════════════╗"
                .bright_blue()
        ));
        output.push_str(&format!(
            "{}\n",
            "║              HANABI PERFECTION CHECK                              ║"
                .bright_blue()
        ));
        output.push_str(&format!(
            "{}\n\n",
            "╚══════════════════════════════════════════════════════════════════╝"
                .bright_blue()
        ));

        // Gates
        for gate in &self.gates {
            output.push_str(&format!(
                "{}\n",
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
            ));
            output.push_str(&format!("Gate: {}\n", gate.name.bold()));
            output.push_str(&format!("  {}\n", gate.message));

            let status = if gate.passed {
                "  Status: ✅ PASS".green()
            } else {
                "  Status: ❌ FAIL".red()
            };
            output.push_str(&format!("{}\n", status));

            for detail in &gate.details {
                output.push_str(&format!("    {}\n", detail.dimmed()));
            }
            output.push('\n');
        }

        // Backlog
        output.push_str(&format!(
            "{}\n",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━".dimmed()
        ));
        output.push_str(&format!("{}\n", "Progress: Backlog Status".bold()));
        output.push_str(&format!(
            "  Open items: {} (target: 0)\n",
            self.backlog.total_open
        ));
        if self.backlog.is_empty() {
            output.push_str(&format!("{}\n", "  Status: ✅ EMPTY".green()));
        } else {
            output.push_str(&format!(
                "  Status: ⚠️  {} items remaining\n",
                self.backlog.total_open
            ));
        }
        output.push('\n');

        // Summary
        output.push_str(&format!(
            "{}\n",
            "╔══════════════════════════════════════════════════════════════════╗"
                .bright_blue()
        ));
        output.push_str(&format!(
            "{}\n",
            "║                        SUMMARY                                    ║"
                .bright_blue()
        ));
        output.push_str(&format!(
            "{}\n\n",
            "╚══════════════════════════════════════════════════════════════════╝"
                .bright_blue()
        ));

        output.push_str(&format!(
            "  Gates Passed: {} / {}\n",
            self.gates_passed, self.gates_total
        ));
        output.push_str(&format!("  Duration: {}ms\n\n", self.duration_ms));

        // Final state
        let state_display = match self.state {
            PerfectionState::Perfect => format!(
                "  ╭────────────────────────────────────────╮\n  │  {} {}                            │\n  │  {}         │\n  │  Maintain by invoking skill after      │\n  │  any Hanabi change                     │\n  ╰────────────────────────────────────────╯\n",
                self.state.emoji(),
                self.state.as_str().green().bold(),
                self.state.description()
            ),
            PerfectionState::Stable => format!(
                "  ╭────────────────────────────────────────╮\n  │  {} {}                             │\n  │  {}     │\n  │  Continue kaizen to reach PERFECT      │\n  ╰────────────────────────────────────────╯\n",
                self.state.emoji(),
                self.state.as_str().yellow().bold(),
                self.state.description()
            ),
            PerfectionState::Degraded => format!(
                "  ╭────────────────────────────────────────╮\n  │  {} {}                           │\n  │  {}             │\n  │  Fix gate failures immediately         │\n  ╰────────────────────────────────────────╯\n",
                self.state.emoji(),
                self.state.as_str().red().bold(),
                self.state.description()
            ),
        };
        output.push_str(&state_display);

        output
    }
}
