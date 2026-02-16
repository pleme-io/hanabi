//! Cache control configuration for static assets and HTML
//!
//! # Cache Strategy (Defense-in-Depth)
//!
//! ## Never Cached (no-store, no-cache, max-age=0)
//! - HTML files (`index.html`, `/`) - Users must always get latest version
//! - `version.json` - Checked on every page load to detect new deployments
//! - `env.js` - Runtime configuration that can change without frontend rebuild
//!
//! ## Short Cache (1 day = 86400 seconds)
//! - Non-hashed static assets (favicons, manifest.json, etc.)
//! - Files that may change but don't have content hashes in filename
//!
//! ## Long Cache (immutable, 1 year = 31536000 seconds)
//! - Content-hashed assets (e.g., `main-abc123.js`, `styles-def456.css`)
//! - Hash changes when content changes, so safe to cache indefinitely
//! - Vite automatically generates these hashed filenames on build
//!
//! ## Rationale
//! - HTML never cached: Ensures users get latest SPA shell immediately
//! - env.js never cached: Runtime config changes don't require rebuilds
//! - version.json never cached: Enables instant new-version detection
//! - Hashed assets cached forever: Content hash guarantees freshness
//! - Non-hashed assets cached 1 day: Balance between performance and freshness

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Enable cache control headers (default: true)
    pub enable_cache_headers: bool,

    /// Cache max-age for non-hashed static assets in seconds
    /// Default: 86400 (1 day) - reasonable balance between performance and freshness
    /// NOTE: Hashed assets (e.g., main-abc123.js) are ALWAYS cached with immutable + 1 year
    pub static_max_age: u32,

    /// Cache max-age for HTML files in seconds (DEPRECATED - HTML is always no-cache)
    /// This field is kept for backwards compatibility but ignored by middleware
    /// HTML files ALWAYS get: no-cache, no-store, must-revalidate, max-age=0
    pub html_max_age: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enable_cache_headers: true,
            static_max_age: 86400, // 1 day (reasonable default)
            html_max_age: 0,       // HTML never cached (enforced in middleware)
        }
    }
}
