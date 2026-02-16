//! Server configuration (ports, timeouts, worker threads, TCP settings)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Static files directory
    pub static_dir: String,

    /// HTTP port (default: 80)
    pub http_port: u16,

    /// Health check port (default: 8080)
    pub health_port: u16,

    /// Service name for logging and metrics
    pub service_name: String,

    /// Service version
    pub service_version: String,

    /// Bind address (default: 0.0.0.0)
    pub bind_address: String,

    /// Request timeout in seconds (default: 30)
    pub request_timeout_secs: u64,

    /// Keep-alive timeout in seconds (default: 75)
    pub keepalive_timeout_secs: u64,

    /// Maximum concurrent connections (default: 10000)
    pub max_concurrent_connections: usize,

    /// Tokio worker threads (default: num_cpus, 0 = auto)
    pub worker_threads: usize,

    /// Enable TCP_NODELAY (default: true for low latency)
    pub tcp_nodelay: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            static_dir: String::new(),
            http_port: 0,
            health_port: 0,
            service_name: String::new(),
            service_version: String::new(),
            bind_address: "0.0.0.0".to_string(),
            request_timeout_secs: 30,
            keepalive_timeout_secs: 75,
            max_concurrent_connections: 10000,
            worker_threads: 0,
            tcp_nodelay: true,
        }
    }
}
