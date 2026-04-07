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
    use tempfile::TempDir;

    fn test_config(dir: &TempDir) -> AppConfig {
        let mut config: AppConfig = serde_yaml::from_str("{}").unwrap();
        config.server.static_dir = dir.path().to_string_lossy().to_string();
        config
    }

    #[test]
    fn test_preflight_checks_unit_struct() {
        let _checks = PreflightChecks;
    }

    #[test]
    fn test_check_static_assets_all_present() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        std::fs::write(dir.path().join("env.js"), "window.ENV={}").unwrap();
        let config = test_config(&dir);
        assert!(PreflightChecks::check_static_assets(&config).is_ok());
    }

    #[test]
    fn test_check_static_assets_missing_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        // env.js is missing
        let config = test_config(&dir);
        let err = PreflightChecks::check_static_assets(&config).unwrap_err();
        assert!(err.contains("env.js"));
    }

    #[test]
    fn test_check_static_assets_empty_critical_files() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(&dir);
        config.preflight.critical_files = vec![];
        assert!(PreflightChecks::check_static_assets(&config).is_ok());
    }

    #[test]
    fn test_react_bundle_integrity_valid() {
        let dir = TempDir::new().unwrap();
        let html = r#"<!DOCTYPE html>
<html><head></head><body>
<div id="root"></div>
<script type="module" src="/assets/main.abc123.js"></script>
</body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        std::fs::create_dir_all(dir.path().join("assets")).unwrap();
        std::fs::write(dir.path().join("assets/main.abc123.js"), "//js").unwrap();
        let config = test_config(&dir);
        assert!(PreflightChecks::check_react_bundle_integrity(&config).is_ok());
    }

    #[test]
    fn test_react_bundle_missing_root_element() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id="app"></div>
<script src="/main.js"></script></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        let config = test_config(&dir);
        let err = PreflightChecks::check_react_bundle_integrity(&config).unwrap_err();
        assert!(err.contains("root"));
    }

    #[test]
    fn test_react_bundle_no_js_files() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id="root"></div></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        let config = test_config(&dir);
        let err = PreflightChecks::check_react_bundle_integrity(&config).unwrap_err();
        assert!(err.contains("No JavaScript"));
    }

    #[test]
    fn test_react_bundle_missing_js_file() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id="root"></div>
<script src="/assets/missing.js"></script></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        let config = test_config(&dir);
        let err = PreflightChecks::check_react_bundle_integrity(&config).unwrap_err();
        assert!(err.contains("missing.js"));
    }

    #[test]
    fn test_react_bundle_skips_external_urls() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id="root"></div>
<script src="https://cdn.example.com/react.js"></script>
<script src="/app.js"></script></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        std::fs::write(dir.path().join("app.js"), "//js").unwrap();
        let config = test_config(&dir);
        assert!(PreflightChecks::check_react_bundle_integrity(&config).is_ok());
    }

    #[test]
    fn test_react_bundle_handles_relative_paths() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id="root"></div>
<script src="app.js"></script></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        std::fs::write(dir.path().join("app.js"), "//js").unwrap();
        let config = test_config(&dir);
        assert!(PreflightChecks::check_react_bundle_integrity(&config).is_ok());
    }

    #[test]
    fn test_react_bundle_single_quote_root() {
        let dir = TempDir::new().unwrap();
        let html = r#"<html><body><div id='root'></div>
<script src="/app.js"></script></body></html>"#;
        std::fs::write(dir.path().join("index.html"), html).unwrap();
        std::fs::write(dir.path().join("app.js"), "//js").unwrap();
        let config = test_config(&dir);
        assert!(PreflightChecks::check_react_bundle_integrity(&config).is_ok());
    }

    #[test]
    fn test_react_bundle_missing_index_html() {
        let dir = TempDir::new().unwrap();
        let config = test_config(&dir);
        let err = PreflightChecks::check_react_bundle_integrity(&config).unwrap_err();
        assert!(err.contains("Failed to read"));
    }

    #[test]
    fn test_run_all_skips_react_check_when_disabled() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        std::fs::write(dir.path().join("env.js"), "//").unwrap();
        let mut config = test_config(&dir);
        config.preflight.verify_react_bundle = false;
        assert!(PreflightChecks::run_all(&config).is_ok());
    }

    #[test]
    fn test_run_all_fails_on_static_assets_before_react_check() {
        let dir = TempDir::new().unwrap();
        // No files at all - static assets check should fail first
        let config = test_config(&dir);
        let err = PreflightChecks::run_all(&config).unwrap_err();
        assert!(err.contains("Missing critical file"));
    }
}
