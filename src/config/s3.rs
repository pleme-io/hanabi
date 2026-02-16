//! S3 configuration for image proxy
//!
//! Configures access to S3-compatible storage (RustFS/MinIO) for serving images.

use serde::{Deserialize, Serialize};

/// S3 configuration for image proxy
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct S3Config {
    /// Whether S3 image proxy is enabled
    pub enabled: bool,

    /// S3 endpoint URL (e.g., "http://rustfs-svc.rustfs.svc.cluster.local:9000")
    pub endpoint: String,

    /// S3 bucket name
    pub bucket: String,

    /// S3 region (use "us-east-1" for MinIO/RustFS)
    pub region: String,

    /// S3 access key (loaded from env var S3_ACCESS_KEY if not set)
    #[serde(default)]
    pub access_key: Option<String>,

    /// S3 secret key (loaded from env var S3_SECRET_KEY if not set)
    #[serde(default)]
    pub secret_key: Option<String>,

    /// Use path-style URLs (required for MinIO/RustFS)
    pub path_style: bool,
}

impl Default for S3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: std::env::var("S3_ENDPOINT")
                .unwrap_or_else(|_| "http://minio.storage.svc.cluster.local:9000".to_string()),
            bucket: std::env::var("S3_BUCKET").unwrap_or_else(|_| "uploads".to_string()),
            region: std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
            access_key: std::env::var("S3_ACCESS_KEY").ok(),
            secret_key: std::env::var("S3_SECRET_KEY").ok(),
            path_style: true,
        }
    }
}

impl S3Config {
    /// Get the access key (from config or env var)
    pub fn get_access_key(&self) -> Option<String> {
        self.access_key
            .clone()
            .or_else(|| std::env::var("S3_ACCESS_KEY").ok())
    }

    /// Get the secret key (from config or env var)
    pub fn get_secret_key(&self) -> Option<String> {
        self.secret_key
            .clone()
            .or_else(|| std::env::var("S3_SECRET_KEY").ok())
    }

    /// Check if S3 is properly configured
    pub fn is_configured(&self) -> bool {
        self.enabled && self.get_access_key().is_some() && self.get_secret_key().is_some()
    }
}
