//! Preflight checks - Run before server starts
//!
//! This module performs critical validation checks before the server accepts
//! any traffic. These checks ensure the deployment is valid and the application
//! can function correctly.
//!
//! # Checks Performed
//! 1. **Static Assets**: Verify critical files exist (index.html, env.js)
//! 2. **React Bundle Integrity**: Verify React root element and JavaScript bundles
//!
//! # When to Use
//! - **Preflight checks**: Run once during startup (before binding ports)
//! - **Health checks**: Run continuously during operation (see health.rs)
//!
//! # Failure Behavior
//! If any preflight check fails, the server will:
//! 1. Log detailed error messages
//! 2. Exit with non-zero status code
//! 3. Prevent Kubernetes pod from becoming Ready
//!
//! This fail-fast approach prevents serving broken deployments to users.
//!
//! # Example
//! ```rust
//! PreflightChecks::run_all(&config)?;
//! // Server startup continues only if all checks pass
//! ```

use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;

/// Static regex for extracting script tags from HTML
/// Pre-compiled at first use for performance
static SCRIPT_TAG_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"<script[^>]+src="([^"]+\.js)"#).expect("Static SCRIPT_TAG_REGEX pattern is valid")
});
use std::path::Path;
use tracing::{error, info};

use crate::config::AppConfig;

/// Preflight checks to run before server starts
///
/// This is a unit struct (no fields) that provides static methods for
/// running validation checks during server startup.
pub struct PreflightChecks;

impl PreflightChecks {
    /// Verify critical static assets exist
    ///
    /// Checks that all files listed in config.preflight.critical_files exist
    /// in the static directory. This ensures the deployment includes required
    /// files before the server starts accepting traffic.
    ///
    /// # Arguments
    /// * `config` - Application configuration
    ///
    /// # Returns
    /// * `Ok(())` - All critical files exist
    /// * `Err(String)` - One or more files are missing
    ///
    /// # Default Critical Files
    /// - index.html (React SPA entry point)
    /// - env.js (Runtime environment configuration)
    ///
    /// # Example
    /// ```rust
    /// PreflightChecks::check_static_assets(&config)?;
    /// ```
    pub fn check_static_assets(config: &AppConfig) -> Result<(), String> {
        info!("Checking static assets");

        for file_name in &config.preflight.critical_files {
            let file_path = Path::new(&config.server.static_dir).join(file_name);

            if !file_path.exists() {
                error!("✗ Critical file missing: {}", file_path.display());
                return Err(format!("Missing critical file: {}", file_path.display()));
            }
            info!("✓ Found: {}", file_path.display());
        }

        Ok(())
    }

    /// Verify React/Vite bundle integrity (framework-level verification)
    ///
    /// Performs deep inspection of the React bundle to ensure it's properly built:
    /// 1. Verifies index.html contains React root element (#root or #root)
    /// 2. Extracts JavaScript bundle references from <script> tags
    /// 3. Verifies all referenced JavaScript files exist on disk
    ///
    /// # Arguments
    /// * `config` - Application configuration
    ///
    /// # Returns
    /// * `Ok(())` - React bundle is valid and complete
    /// * `Err(String)` - Missing root element, no bundles, or bundle files missing
    ///
    /// # Why This Check?
    /// Vite builds can silently fail or produce incomplete bundles. This check
    /// catches deployment issues before they cause user-facing errors:
    /// - Incomplete builds (missing JavaScript)
    /// - Misconfigured base paths
    /// - File copy errors during deployment
    ///
    /// # Example
    /// ```rust
    /// PreflightChecks::check_react_bundle_integrity(&config)?;
    /// ```
    pub fn check_react_bundle_integrity(config: &AppConfig) -> Result<(), String> {
        info!("Verifying React bundle integrity");

        let html_path =
            Path::new(&config.server.static_dir).join(&config.preflight.index_html_path);
        let html_content = fs::read_to_string(&html_path)
            .map_err(|e| format!("Failed to read index.html: {}", e))?;

        // Verify index.html contains React app root
        if !html_content.contains("id=\"root\"") && !html_content.contains("id='root'") {
            error!("✗ React root element not found in index.html");
            return Err("React root element (#root) missing from index.html".to_string());
        }
        info!("✓ React root element found");

        // Extract script tags to verify JavaScript bundles (using pre-compiled static regex)
        let mut js_files = Vec::new();
        for cap in SCRIPT_TAG_REGEX.captures_iter(&html_content) {
            if let Some(src) = cap.get(1) {
                js_files.push(src.as_str().to_string());
            }
        }

        if js_files.is_empty() {
            error!("✗ No JavaScript bundles found in index.html");
            return Err("No JavaScript bundles found in index.html".to_string());
        }

        // Verify all referenced JavaScript files exist
        for js_file in &js_files {
            // Skip external URLs (CDN scripts like React from unpkg)
            if js_file.starts_with("http://") || js_file.starts_with("https://") {
                info!("⊘ Skipping external script: {}", js_file);
                continue;
            }

            // Handle both absolute and relative paths
            let js_path = if js_file.starts_with('/') {
                Path::new(&config.server.static_dir).join(js_file.trim_start_matches('/'))
            } else {
                Path::new(&config.server.static_dir).join(js_file)
            };

            if !js_path.exists() {
                error!(
                    "✗ Referenced JavaScript bundle missing: {}",
                    js_path.display()
                );
                return Err(format!("JavaScript bundle not found: {}", js_file));
            }
            info!("✓ Found bundle: {}", js_file);
        }

        info!(
            "✓ React bundle integrity verified ({} bundles)",
            js_files.len()
        );
        Ok(())
    }

    /// Run all preflight checks
    ///
    /// Executes all configured preflight checks in sequence. If any check fails,
    /// returns immediately with an error (fail-fast behavior).
    ///
    /// # Arguments
    /// * `config` - Application configuration
    ///
    /// # Returns
    /// * `Ok(())` - All checks passed
    /// * `Err(String)` - First check that failed
    ///
    /// # Checks Performed
    /// 1. Static assets verification (always)
    /// 2. React bundle integrity (if config.preflight.verify_react_bundle is true)
    ///
    /// # Example
    /// ```rust
    /// // In main function, before starting server:
    /// PreflightChecks::run_all(&config)?;
    /// info!("Preflight checks passed, starting server...");
    /// ```
    pub fn run_all(config: &AppConfig) -> Result<(), String> {
        info!("=== Running Preflight Checks ===");

        Self::check_static_assets(config)?;

        if config.preflight.verify_react_bundle {
            Self::check_react_bundle_integrity(config)?;
        } else {
            info!("⊘ React bundle verification disabled");
        }

        info!("=== All Preflight Checks Passed ===");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preflight_checks_unit_struct() {
        // Verify PreflightChecks is a unit struct
        let _checks = PreflightChecks;
    }

    // Integration tests would require:
    // - Temporary directories with test files
    // - Valid configuration objects
    // - Mock React bundle files
    // These are better suited for integration test suite
}
