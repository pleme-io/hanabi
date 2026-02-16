#![allow(dead_code)]
//! Static file serving paths configuration
//!
//! Single source of truth for all file system paths used by the web server

use std::path::PathBuf;

/// Default static files directory
/// This is where the built React application and runtime config files are served from
pub const DEFAULT_STATIC_DIR: &str = "/app/static";

/// Runtime environment config file name
pub const ENV_CONFIG_FILE: &str = "env.js";

/// Get the static files directory path
pub fn static_dir() -> PathBuf {
    PathBuf::from(DEFAULT_STATIC_DIR)
}

/// Get the full path to the env.js config file
pub fn env_config_path() -> PathBuf {
    static_dir().join(ENV_CONFIG_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_dir() {
        assert_eq!(static_dir(), PathBuf::from("/app/static"));
    }

    #[test]
    fn test_env_config_path() {
        assert_eq!(env_config_path(), PathBuf::from("/app/static/env.js"));
    }
}
