//! Compression configuration (Brotli, Gzip)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CompressionConfig {
    /// Enable Brotli compression (default: true)
    pub enable_brotli: bool,

    /// Enable Gzip compression (default: true)
    pub enable_gzip: bool,

    /// Minimum response size to compress in bytes (default: 1024)
    pub min_compress_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enable_brotli: true,
            enable_gzip: true,
            min_compress_size: 1024,
        }
    }
}
