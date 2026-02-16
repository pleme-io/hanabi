//! Test coverage analysis for Hanabi
//!
//! Checks for 100% unit test coverage using cargo-llvm-cov.

use crate::error::{LintError, Result};
use std::path::Path;
use std::process::Command;

/// Result of coverage analysis
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CoverageSummary {
    /// Whether coverage check passed (both line AND branch if available)
    pub passed: bool,
    /// Line coverage percentage
    pub line_coverage: f64,
    /// Branch coverage percentage (if available)
    pub branch_coverage: Option<f64>,
    /// Number of lines covered
    pub lines_covered: usize,
    /// Total number of lines
    pub lines_total: usize,
    /// Number of branches covered (if available)
    pub branches_covered: Option<usize>,
    /// Total number of branches (if available)
    pub branches_total: Option<usize>,
    /// Whether llvm-cov is installed
    pub tool_available: bool,
    /// Message about the check
    pub message: String,
    /// Files with less than 100% coverage
    pub uncovered_files: Vec<UncoveredFile>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UncoveredFile {
    pub path: String,
    pub coverage: f64,
    pub lines_covered: usize,
    pub lines_total: usize,
    pub branch_coverage: Option<f64>,
}

impl CoverageSummary {
    /// Check if coverage passes the required threshold
    /// Requires BOTH line coverage AND branch coverage (when available) to meet threshold
    pub fn passes_threshold(&self, required: f64) -> bool {
        if !self.tool_available {
            return false;
        }

        let line_ok = self.line_coverage >= required;

        // Branch coverage must also pass if it's available
        let branch_ok = self.branch_coverage.map(|b| b >= required).unwrap_or(true);

        line_ok && branch_ok
    }
}

/// Check if cargo-llvm-cov is installed
fn is_llvm_cov_available() -> bool {
    Command::new("cargo")
        .args(["llvm-cov", "--version"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run coverage check on Hanabi
pub fn run_coverage_check(manifest_path: &Path, threshold: f64) -> Result<CoverageSummary> {
    // Check if llvm-cov is available
    if !is_llvm_cov_available() {
        return Ok(CoverageSummary {
            passed: false,
            tool_available: false,
            message: "cargo-llvm-cov not installed. Install with: cargo install cargo-llvm-cov".to_string(),
            ..Default::default()
        });
    }

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    // Run cargo llvm-cov with JSON output (lib tests only)
    // Integration tests have visibility issues with pub(crate) items
    let output = Command::new("cargo")
        .args([
            "llvm-cov",
            "--manifest-path",
            manifest_path.to_str().unwrap_or_default(),
            "--lib",
            "--json",
            "--output-path",
            "-", // Output to stdout
        ])
        .current_dir(manifest_dir)
        .output()
        .map_err(|e| LintError::CargoError {
            command: "llvm-cov".to_string(),
            message: e.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Check for common issues
        if stderr.contains("could not compile") {
            return Ok(CoverageSummary {
                passed: false,
                tool_available: true,
                message: format!("Compilation failed during coverage check: {}",
                    stderr.lines().take(3).collect::<Vec<_>>().join(" ")),
                ..Default::default()
            });
        }

        return Ok(CoverageSummary {
            passed: false,
            tool_available: true,
            message: format!("Coverage check failed: {}", stderr.lines().next().unwrap_or("unknown error")),
            ..Default::default()
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON output
    parse_coverage_json(&stdout, threshold)
}

fn parse_coverage_json(json_str: &str, threshold: f64) -> Result<CoverageSummary> {
    let json: serde_json::Value = serde_json::from_str(json_str).map_err(|e| LintError::ParseError {
        path: std::path::PathBuf::from("<coverage-output>"),
        message: format!("Failed to parse coverage JSON: {}", e),
    })?;

    // Extract totals from the JSON
    let data = json.get("data").and_then(|d| d.get(0));
    let totals = data.and_then(|d| d.get("totals"));

    let (lines_covered, lines_total, line_coverage) = if let Some(lines) = totals.and_then(|t| t.get("lines")) {
        let covered = lines.get("covered").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let total = lines.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let percent = lines.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
        (covered, total, percent)
    } else {
        (0, 0, 0.0)
    };

    // Extract branch coverage
    let branches = totals.and_then(|t| t.get("branches"));
    let branch_coverage = branches.and_then(|b| b.get("percent")).and_then(|v| v.as_f64());
    let branches_covered = branches
        .and_then(|b| b.get("covered"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);
    let branches_total = branches
        .and_then(|b| b.get("count"))
        .and_then(|v| v.as_u64())
        .map(|v| v as usize);

    // Find files with less than 100% coverage (line OR branch)
    let mut uncovered_files = Vec::new();
    if let Some(files) = data.and_then(|d| d.get("files")).and_then(|f| f.as_array()) {
        for file in files {
            let filename = file.get("filename").and_then(|f| f.as_str()).unwrap_or("");

            // Skip test files and non-hanabi files
            if filename.contains("/tests/") || filename.contains("test.rs") || !filename.contains("hanabi") {
                continue;
            }

            let summary = file.get("summary");

            let (covered, total, percent) = if let Some(lines) = summary.and_then(|s| s.get("lines")) {
                let covered = lines.get("covered").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let total = lines.get("count").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let percent = lines.get("percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
                (covered, total, percent)
            } else {
                continue;
            };

            let file_branch_cov = summary
                .and_then(|s| s.get("branches"))
                .and_then(|b| b.get("percent"))
                .and_then(|v| v.as_f64());

            // File is uncovered if line coverage < 100% OR branch coverage < 100% (when available)
            let line_below_threshold = percent < 100.0 && total > 0;
            let branch_below_threshold = file_branch_cov.map(|b| b < 100.0).unwrap_or(false);

            if line_below_threshold || branch_below_threshold {
                uncovered_files.push(UncoveredFile {
                    path: filename.to_string(),
                    coverage: percent,
                    lines_covered: covered,
                    lines_total: total,
                    branch_coverage: file_branch_cov,
                });
            }
        }
    }

    // Sort by coverage (lowest first)
    uncovered_files.sort_by(|a, b| a.coverage.partial_cmp(&b.coverage).unwrap_or(std::cmp::Ordering::Equal));

    // Check BOTH line AND branch coverage (when available)
    let line_passed = line_coverage >= threshold;
    let branch_passed = branch_coverage.map(|b| b >= threshold).unwrap_or(true);
    let passed = line_passed && branch_passed;

    let message = if passed {
        match branch_coverage {
            Some(branch) => format!(
                "Coverage: Lines {:.1}%, Branches {:.1}% (threshold: {:.0}%)",
                line_coverage, branch, threshold
            ),
            None => format!("Coverage: {:.1}% lines (threshold: {:.0}%)", line_coverage, threshold),
        }
    } else {
        let mut issues = Vec::new();
        if !line_passed {
            issues.push(format!("lines {:.1}%", line_coverage));
        }
        if !branch_passed {
            if let Some(branch) = branch_coverage {
                issues.push(format!("branches {:.1}%", branch));
            }
        }
        format!(
            "Coverage below {:.0}%: {} ({} files need tests)",
            threshold,
            issues.join(", "),
            uncovered_files.len()
        )
    };

    Ok(CoverageSummary {
        passed,
        line_coverage,
        branch_coverage,
        lines_covered,
        lines_total,
        branches_covered,
        branches_total,
        tool_available: true,
        message,
        uncovered_files: uncovered_files.into_iter().take(10).collect(), // Limit to top 10
    })
}

/// Quick coverage check without full analysis (just verify tests pass)
pub fn run_quick_coverage_check(manifest_path: &Path) -> Result<CoverageSummary> {
    // Just run lib tests and report pass/fail
    // Integration tests have visibility issues with pub(crate) items
    let output = Command::new("cargo")
        .args([
            "test",
            "--manifest-path",
            manifest_path.to_str().unwrap_or_default(),
            "--lib",
            "--no-fail-fast",
        ])
        .output()
        .map_err(|e| LintError::CargoError {
            command: "test".to_string(),
            message: e.to_string(),
        })?;

    let passed = output.status.success();

    Ok(CoverageSummary {
        passed,
        tool_available: true,
        message: if passed {
            "Tests pass (full coverage check skipped - use --coverage for detailed analysis)".to_string()
        } else {
            "Tests failed - coverage check skipped".to_string()
        },
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_coverage_json_empty() {
        let json = r#"{"data": [{"totals": {"lines": {"covered": 0, "count": 0, "percent": 0}}}]}"#;
        let result = parse_coverage_json(json, 100.0).unwrap();
        assert!(!result.passed);
        assert_eq!(result.line_coverage, 0.0);
    }

    #[test]
    fn test_parse_coverage_json_full() {
        let json = r#"{"data": [{"totals": {"lines": {"covered": 100, "count": 100, "percent": 100.0}}}]}"#;
        let result = parse_coverage_json(json, 100.0).unwrap();
        assert!(result.passed);
        assert_eq!(result.line_coverage, 100.0);
    }

    #[test]
    fn test_parse_coverage_json_partial() {
        let json = r#"{"data": [{"totals": {"lines": {"covered": 80, "count": 100, "percent": 80.0}}}]}"#;
        let result = parse_coverage_json(json, 100.0).unwrap();
        assert!(!result.passed);
        assert_eq!(result.line_coverage, 80.0);
    }

    #[test]
    fn test_parse_coverage_json_with_branches_full() {
        let json = r#"{"data": [{"totals": {
            "lines": {"covered": 100, "count": 100, "percent": 100.0},
            "branches": {"covered": 50, "count": 50, "percent": 100.0}
        }}]}"#;
        let result = parse_coverage_json(json, 100.0).unwrap();
        assert!(result.passed);
        assert_eq!(result.line_coverage, 100.0);
        assert_eq!(result.branch_coverage, Some(100.0));
        assert_eq!(result.branches_covered, Some(50));
        assert_eq!(result.branches_total, Some(50));
    }

    #[test]
    fn test_parse_coverage_json_with_branches_partial() {
        // Lines at 100%, branches at 80% - should fail
        let json = r#"{"data": [{"totals": {
            "lines": {"covered": 100, "count": 100, "percent": 100.0},
            "branches": {"covered": 40, "count": 50, "percent": 80.0}
        }}]}"#;
        let result = parse_coverage_json(json, 100.0).unwrap();
        assert!(!result.passed);
        assert_eq!(result.line_coverage, 100.0);
        assert_eq!(result.branch_coverage, Some(80.0));
    }

    #[test]
    fn test_passes_threshold_line_only() {
        let summary = CoverageSummary {
            line_coverage: 100.0,
            branch_coverage: None,
            tool_available: true,
            ..Default::default()
        };
        assert!(summary.passes_threshold(100.0));
    }

    #[test]
    fn test_passes_threshold_both_pass() {
        let summary = CoverageSummary {
            line_coverage: 100.0,
            branch_coverage: Some(100.0),
            tool_available: true,
            ..Default::default()
        };
        assert!(summary.passes_threshold(100.0));
    }

    #[test]
    fn test_passes_threshold_line_fails() {
        let summary = CoverageSummary {
            line_coverage: 80.0,
            branch_coverage: Some(100.0),
            tool_available: true,
            ..Default::default()
        };
        assert!(!summary.passes_threshold(100.0));
    }

    #[test]
    fn test_passes_threshold_branch_fails() {
        let summary = CoverageSummary {
            line_coverage: 100.0,
            branch_coverage: Some(80.0),
            tool_available: true,
            ..Default::default()
        };
        assert!(!summary.passes_threshold(100.0));
    }

    #[test]
    fn test_passes_threshold_tool_unavailable() {
        let summary = CoverageSummary {
            line_coverage: 100.0,
            branch_coverage: Some(100.0),
            tool_available: false,
            ..Default::default()
        };
        assert!(!summary.passes_threshold(100.0));
    }
}
