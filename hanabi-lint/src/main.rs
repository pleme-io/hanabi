//! hanabi-lint CLI - Perfection checker for Hanabi BFF server
//!
//! Run this tool after any Hanabi changes to verify the codebase
//! maintains (or restores) its quality state.

use clap::{Parser, ValueEnum};
use hanabi_lint::{
    backlog, cargo_checks, complexity, config_detector, coverage, hygiene_detector, modularity,
    refactoring_detector, unwrap_detector, PerfectionReport, PerfectionState, Result,
};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "hanabi-lint")]
#[command(about = "Perfection checker for Hanabi BFF server")]
#[command(version)]
struct Args {
    /// Output format
    #[arg(short, long, value_enum, default_value = "pretty")]
    format: OutputFormat,

    /// Skip cargo test (faster but less thorough)
    #[arg(long)]
    skip_tests: bool,

    /// Skip clippy check
    #[arg(long)]
    skip_clippy: bool,

    /// Skip complexity analysis
    #[arg(long)]
    skip_complexity: bool,

    /// Skip modularity analysis
    #[arg(long)]
    skip_modularity: bool,

    /// Skip configuration analysis (env::var, magic numbers, mutable config)
    #[arg(long)]
    skip_config: bool,

    /// Skip hygiene analysis (secrets, async safety, debug code, timeouts, docs)
    #[arg(long)]
    skip_hygiene: bool,

    /// Skip refactoring analysis (function size, params, nesting, file size)
    #[arg(long)]
    skip_refactoring: bool,

    /// Skip security audit (cargo audit)
    #[arg(long)]
    skip_audit: bool,

    /// Run full coverage analysis (slow, requires cargo-llvm-cov)
    #[arg(long)]
    coverage: bool,

    /// Cyclomatic complexity threshold (default: 10)
    #[arg(long, default_value = "10")]
    cc_threshold: usize,

    /// Cognitive complexity threshold (default: 15)
    #[arg(long, default_value = "15")]
    cognitive_threshold: usize,

    /// Path to workspace root (auto-detected if not specified)
    #[arg(short, long)]
    workspace: Option<PathBuf>,

    /// Only check for violations, don't run cargo commands
    #[arg(long)]
    violations_only: bool,

    /// Exit with code 0 even if checks fail (for CI that handles exit codes separately)
    #[arg(long)]
    no_fail: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
enum OutputFormat {
    /// Human-readable terminal output with colors
    Pretty,
    /// JSON output for CI/CD integration
    Json,
    /// Minimal output (just the state)
    Minimal,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let start = Instant::now();

    // Discover workspace
    let current_dir = std::env::current_dir()?;
    let start_path = args.workspace.as_ref().unwrap_or(&current_dir);
    let workspace = cargo_checks::CargoWorkspace::discover(start_path)?;

    // Run AST analysis for violations
    let violations = unwrap_detector::analyze_directory(&workspace.hanabi_src)?;

    // Run complexity analysis
    let complexity_summary = if args.skip_complexity {
        complexity::ComplexitySummary::default()
    } else {
        let metrics = complexity::analyze_directory(&workspace.hanabi_src)?;
        complexity::ComplexitySummary::from_metrics(
            &metrics,
            args.cc_threshold,
            args.cognitive_threshold,
        )
    };

    // Run cargo checks
    let cargo_summary = if args.violations_only {
        cargo_checks::CargoCheckSummary::default()
    } else {
        let mut results = Vec::new();

        if !args.skip_clippy {
            results.push(cargo_checks::run_clippy(&workspace.hanabi_manifest)?);
        }

        if !args.skip_tests {
            results.push(cargo_checks::run_tests(&workspace.hanabi_manifest)?);
        }

        results.push(cargo_checks::run_format_check(&workspace.hanabi_manifest)?);

        cargo_checks::CargoCheckSummary::from_results(results)
    };

    // Run modularity analysis
    let modularity_summary = if args.skip_modularity || args.violations_only {
        modularity::ModularitySummary::default()
    } else {
        modularity::analyze_directory(&workspace.hanabi_src)?
    };

    // Run configuration analysis
    let config_summary = if args.skip_config || args.violations_only {
        config_detector::ConfigSummary::default()
    } else {
        config_detector::analyze_directory(&workspace.hanabi_src)?
    };

    // Run hygiene analysis (Gates 14-18)
    let hygiene_summary = if args.skip_hygiene || args.violations_only {
        hygiene_detector::HygieneSummary::default()
    } else {
        hygiene_detector::analyze_directory(&workspace.hanabi_src)?
    };

    // Run refactoring analysis (Gates 19-22)
    let refactoring_summary = if args.skip_refactoring || args.violations_only {
        refactoring_detector::RefactoringSummary::default()
    } else {
        refactoring_detector::analyze_directory(&workspace.hanabi_src)?
    };

    // Run security audit (Gate 13)
    let audit_result = if args.skip_audit || args.violations_only {
        None
    } else {
        Some(cargo_checks::run_audit(&workspace.hanabi_manifest)?)
    };

    // Run coverage analysis
    let coverage_summary = if args.coverage && !args.violations_only {
        coverage::run_coverage_check(&workspace.hanabi_manifest, 100.0)?
    } else if !args.violations_only && !args.skip_tests {
        // Quick check - just verify tests pass
        coverage::run_quick_coverage_check(&workspace.hanabi_manifest)?
    } else {
        coverage::CoverageSummary {
            passed: true,
            message: "Coverage check skipped".to_string(),
            ..Default::default()
        }
    };

    // Parse backlog
    let backlog_summary = if workspace.backlog_path().exists() {
        backlog::parse_backlog(&workspace.backlog_path())?
    } else {
        backlog::BacklogSummary::default()
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    // Generate report
    let report = PerfectionReport::new(
        &violations,
        complexity_summary,
        cargo_summary,
        modularity_summary,
        coverage_summary,
        config_summary,
        hygiene_summary,
        refactoring_summary,
        audit_result,
        backlog_summary,
        duration_ms,
        args.cc_threshold,
        args.cognitive_threshold,
    );

    // Output report
    match args.format {
        OutputFormat::Pretty => {
            println!("{}", report.to_pretty());
        }
        OutputFormat::Json => {
            println!("{}", report.to_json());
        }
        OutputFormat::Minimal => {
            println!(
                "{} {} ({}/{} gates)",
                report.state.emoji(),
                report.state.as_str(),
                report.gates_passed,
                report.gates_total
            );
        }
    }

    // Exit code
    if args.no_fail {
        Ok(())
    } else {
        match report.state {
            PerfectionState::Perfect | PerfectionState::Stable => Ok(()),
            PerfectionState::Degraded => std::process::exit(1),
        }
    }
}
