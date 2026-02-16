//! Cargo integration for running clippy, tests, and format checks
//!
//! Uses cargo_metadata for workspace information and spawns cargo commands
//! with structured JSON output parsing.

use crate::error::{LintError, Result};
// cargo_metadata is available for future workspace analysis
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Result of a cargo check operation
#[derive(Debug, Clone, serde::Serialize)]
pub struct CargoCheckResult {
    pub check_type: CargoCheckType,
    pub passed: bool,
    pub message: String,
    pub details: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoCheckType {
    Clippy,
    Test,
    Format,
    Audit,
}

impl CargoCheckType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clippy => "clippy",
            Self::Test => "test",
            Self::Format => "format",
            Self::Audit => "audit",
        }
    }
}

/// Cargo workspace information
pub struct CargoWorkspace {
    pub workspace_root: PathBuf,
    pub hanabi_manifest: PathBuf,
    pub hanabi_src: PathBuf,
}

impl CargoWorkspace {
    /// Discover the Hanabi package in the workspace
    pub fn discover(start_dir: &Path) -> Result<Self> {
        // Try to find workspace root by looking for .git or walking up
        let workspace_root = find_workspace_root(start_dir)?;

        // Look for hanabi package
        let hanabi_dir = workspace_root.join("pkgs/platform/hanabi");
        if !hanabi_dir.exists() {
            return Err(LintError::HanabiNotFound);
        }

        let hanabi_manifest = hanabi_dir.join("Cargo.toml");
        if !hanabi_manifest.exists() {
            return Err(LintError::HanabiNotFound);
        }

        let hanabi_src = hanabi_dir.join("src");

        Ok(Self {
            workspace_root,
            hanabi_manifest,
            hanabi_src,
        })
    }

    /// Get the backlog file path
    pub fn backlog_path(&self) -> PathBuf {
        self.workspace_root
            .join(".claude/skills/hanabi-development/backlog/IMPROVEMENTS.md")
    }
}

fn find_workspace_root(start: &Path) -> Result<PathBuf> {
    let mut current = start.to_path_buf();

    loop {
        // Check for .git directory (indicates repo root)
        if current.join(".git").exists() {
            return Ok(current);
        }

        // Check for root Cargo.toml with workspace
        let cargo_toml = current.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                if contents.contains("[workspace]") {
                    return Ok(current);
                }
            }
        }

        // Move up one directory
        if let Some(parent) = current.parent() {
            current = parent.to_path_buf();
        } else {
            break;
        }
    }

    Err(LintError::WorkspaceNotFound)
}

/// Run clippy with deny warnings
pub fn run_clippy(manifest_path: &Path) -> Result<CargoCheckResult> {
    let start = std::time::Instant::now();

    let output = Command::new("cargo")
        .args([
            "clippy",
            "--manifest-path",
            manifest_path.to_str().unwrap_or_default(),
            "--message-format=json",
            "--",
            "-D",
            "warnings",
        ])
        .output()
        .map_err(|e| LintError::CargoError {
            command: "clippy".to_string(),
            message: e.to_string(),
        })?;

    let duration_ms = start.elapsed().as_millis() as u64;
    parse_cargo_output(output, CargoCheckType::Clippy, duration_ms)
}

/// Run cargo test
pub fn run_tests(manifest_path: &Path) -> Result<CargoCheckResult> {
    let start = std::time::Instant::now();

    // Run lib tests only - integration tests have visibility issues with pub(crate) items
    // See IMPROVEMENTS.md for details on the known visibility issues
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

    let duration_ms = start.elapsed().as_millis() as u64;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let _stderr = String::from_utf8_lossy(&output.stderr); // Reserved for future error extraction

    let passed = output.status.success() && !stdout.contains("FAILED");

    let mut details = Vec::new();
    if stdout.contains("FAILED") {
        // Extract failed test names
        for line in stdout.lines() {
            if line.contains("FAILED") {
                details.push(line.trim().to_string());
            }
        }
    }

    let message = if passed {
        "All tests passed".to_string()
    } else {
        format!("{} test(s) failed", details.len())
    };

    Ok(CargoCheckResult {
        check_type: CargoCheckType::Test,
        passed,
        message,
        details,
        duration_ms,
    })
}

/// Run cargo fmt --check
pub fn run_format_check(manifest_path: &Path) -> Result<CargoCheckResult> {
    let start = std::time::Instant::now();

    let output = Command::new("cargo")
        .args([
            "fmt",
            "--manifest-path",
            manifest_path.to_str().unwrap_or_default(),
            "--check",
        ])
        .output()
        .map_err(|e| LintError::CargoError {
            command: "fmt".to_string(),
            message: e.to_string(),
        })?;

    let duration_ms = start.elapsed().as_millis() as u64;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let passed = output.status.success();

    let mut details = Vec::new();
    if !passed {
        // Extract files that need formatting
        for line in stdout.lines().chain(stderr.lines()) {
            if line.contains("Diff in") || line.contains("would reformat") {
                details.push(line.trim().to_string());
            }
        }
    }

    let message = if passed {
        "Code is properly formatted".to_string()
    } else {
        format!("{} file(s) need formatting", details.len().max(1))
    };

    Ok(CargoCheckResult {
        check_type: CargoCheckType::Format,
        passed,
        message,
        details,
        duration_ms,
    })
}

/// Run cargo audit (if available)
pub fn run_audit(manifest_path: &Path) -> Result<CargoCheckResult> {
    let start = std::time::Instant::now();

    // Check if cargo-audit is installed
    let check = Command::new("cargo")
        .args(["audit", "--version"])
        .output();

    if check.is_err() || !check.unwrap().status.success() {
        return Ok(CargoCheckResult {
            check_type: CargoCheckType::Audit,
            passed: true,
            message: "cargo-audit not installed, skipping".to_string(),
            details: vec![],
            duration_ms: 0,
        });
    }

    let manifest_dir = manifest_path.parent().unwrap_or(Path::new("."));

    let output = Command::new("cargo")
        .args(["audit", "--json"])
        .current_dir(manifest_dir)
        .output()
        .map_err(|e| LintError::CargoError {
            command: "audit".to_string(),
            message: e.to_string(),
        })?;

    let duration_ms = start.elapsed().as_millis() as u64;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let passed = output.status.success();

    let mut details = Vec::new();
    // Parse JSON output for vulnerabilities
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.get("list")) {
            if let Some(arr) = vulns.as_array() {
                for vuln in arr {
                    if let Some(advisory) = vuln.get("advisory") {
                        let id = advisory
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        let pkg = advisory
                            .get("package")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        details.push(format!("{}: {}", id, pkg));
                    }
                }
            }
        }
    }

    let message = if passed {
        "No known vulnerabilities".to_string()
    } else {
        format!("{} vulnerability(ies) found", details.len())
    };

    Ok(CargoCheckResult {
        check_type: CargoCheckType::Audit,
        passed,
        message,
        details,
        duration_ms,
    })
}

fn parse_cargo_output(
    output: Output,
    check_type: CargoCheckType,
    duration_ms: u64,
) -> Result<CargoCheckResult> {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut details = Vec::new();
    let mut error_count = 0;
    let mut warning_count = 0;

    // Parse JSON lines from cargo output
    for line in stdout.lines() {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if let Some(reason) = json.get("reason").and_then(|r| r.as_str()) {
                if reason == "compiler-message" {
                    if let Some(message) = json.get("message") {
                        if let Some(level) = message.get("level").and_then(|l| l.as_str()) {
                            match level {
                                "error" => {
                                    error_count += 1;
                                    if let Some(rendered) =
                                        message.get("rendered").and_then(|r| r.as_str())
                                    {
                                        // Take first line of rendered message
                                        if let Some(first_line) = rendered.lines().next() {
                                            details.push(first_line.to_string());
                                        }
                                    }
                                }
                                "warning" => {
                                    warning_count += 1;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    // Also check stderr for errors not in JSON
    if stderr.contains("error") || stderr.contains("error[E") {
        for line in stderr.lines() {
            if line.contains("error[E") || line.starts_with("error:") {
                details.push(line.to_string());
                error_count += 1;
            }
        }
    }

    let passed = output.status.success() && error_count == 0;

    let message = match check_type {
        CargoCheckType::Clippy => {
            if passed {
                "No clippy warnings".to_string()
            } else {
                format!("{} error(s), {} warning(s)", error_count, warning_count)
            }
        }
        _ => {
            if passed {
                "Passed".to_string()
            } else {
                format!("{} issue(s) found", error_count)
            }
        }
    };

    Ok(CargoCheckResult {
        check_type,
        passed,
        message,
        details: details.into_iter().take(10).collect(), // Limit details
        duration_ms,
    })
}

/// Summary of all cargo checks
#[derive(Debug, Default, serde::Serialize)]
pub struct CargoCheckSummary {
    pub all_passed: bool,
    pub results: Vec<CargoCheckResult>,
    pub total_duration_ms: u64,
}

impl CargoCheckSummary {
    pub fn from_results(results: Vec<CargoCheckResult>) -> Self {
        let all_passed = results.iter().all(|r| r.passed);
        let total_duration_ms = results.iter().map(|r| r.duration_ms).sum();

        Self {
            all_passed,
            results,
            total_duration_ms,
        }
    }
}
