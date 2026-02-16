//! Preflight checks configuration (critical files verification)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct PreflightConfig {
    /// Critical files that must exist for server to start
    pub critical_files: Vec<String>,

    /// Verify React bundle integrity (check for root element, script tags)
    pub verify_react_bundle: bool,

    /// HTML file to check for React root element
    pub index_html_path: String,
}

impl Default for PreflightConfig {
    fn default() -> Self {
        Self {
            critical_files: vec!["index.html".to_string(), "env.js".to_string()],
            verify_react_bundle: true,
            index_html_path: "index.html".to_string(),
        }
    }
}
