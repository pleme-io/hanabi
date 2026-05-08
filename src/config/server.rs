//! Server configuration (ports, timeouts, worker threads, TCP settings)

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Static files directory (primary webapp served at root "/")
    /// Can be pre-populated via volume mount, baked into image, or downloaded from S3
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

    /// Server role. Default `Standalone` (the historical mode — full
    /// edge BFF). Set to `Sidecar` when running as the L7 sub-component
    /// of a pleme-io mesh data plane (Sprint M3 of theory/MESH.md):
    /// hanabi binds loopback only, skips static-file serving, expects
    /// the colocated workload at `upstream_loopback`, and reads its
    /// L7 policy block from `policy_source`.
    #[serde(default)]
    pub role: ServerRole,

    /// In `Sidecar` mode, the loopback URL of the colocated workload
    /// container hanabi forwards plaintext to (e.g.
    /// `http://127.0.0.1:8082`). Ignored in `Standalone` mode.
    #[serde(default)]
    pub upstream_loopback: Option<String>,

    /// In `Sidecar` mode, filesystem path or unix socket where the
    /// renderer drops the typed L7 policy block (CSP per-route,
    /// rate-limit per-edge, etc). Ignored in `Standalone` mode.
    #[serde(default)]
    pub policy_source: Option<String>,

    /// In `Sidecar` mode, suppress all static-file serving paths
    /// (sidecar mode is pure L7 pass-through). Default `false` so
    /// existing standalone callers are untouched.
    #[serde(default)]
    pub no_static: bool,

    /// S3 webapp sources — download webapp archives from S3 at startup
    ///
    /// Each source downloads a tar.gz archive from S3 and extracts it to a target
    /// directory. The primary source (first entry, or a source with `target_dir` matching
    /// `static_dir`) populates the main webapp. Additional sources can provide separate
    /// apps served at different path prefixes.
    ///
    /// Example YAML:
    /// ```yaml
    /// webapp_sources:
    ///   - name: main-app
    ///     endpoint: http://rustfs-svc.rustfs.svc.cluster.local:9000
    ///     bucket: webapps
    ///     key: lilitu/latest.tar.gz
    ///     target_dir: /app/static
    ///   - name: admin-panel
    ///     endpoint: http://rustfs-svc.rustfs.svc.cluster.local:9000
    ///     bucket: webapps
    ///     key: admin/latest.tar.gz
    ///     target_dir: /app/admin
    /// ```
    #[serde(default)]
    pub webapp_sources: Vec<WebappS3Source>,
}

/// S3 source for downloading a webapp archive at startup
///
/// Downloads a tar.gz archive from an S3-compatible endpoint and extracts it
/// to `target_dir`. Supports authentication via access/secret keys (from YAML
/// config or env vars). Multiple sources allow deploying different webapps
/// or webapp versions from different S3 locations.
///
/// The archive should contain the webapp files at the root level
/// (index.html, assets/, etc.)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebappS3Source {
    /// Human-readable name for this source (used in logs)
    #[serde(default)]
    pub name: String,

    /// S3 endpoint URL (e.g., "http://rustfs-svc.rustfs.svc.cluster.local:9000")
    pub endpoint: String,

    /// S3 bucket name containing the webapp archive
    pub bucket: String,

    /// S3 object key for the webapp archive (e.g., "webapp/latest.tar.gz")
    pub key: String,

    /// Local directory to extract the archive into
    /// For the primary webapp, this should match `server.static_dir`
    pub target_dir: String,

    /// S3 region (default: "us-east-1" for MinIO/RustFS)
    #[serde(default = "default_region")]
    pub region: String,

    /// S3 access key (can also use env var referenced by `access_key_env`)
    #[serde(default)]
    pub access_key: Option<String>,

    /// S3 secret key (can also use env var referenced by `secret_key_env`)
    #[serde(default)]
    pub secret_key: Option<String>,

    /// Env var name to read access key from (default: none)
    /// Example: "S3_WEBAPP_ACCESS_KEY" or "ADMIN_S3_ACCESS_KEY"
    #[serde(default)]
    pub access_key_env: Option<String>,

    /// Env var name to read secret key from (default: none)
    /// Example: "S3_WEBAPP_SECRET_KEY" or "ADMIN_S3_SECRET_KEY"
    #[serde(default)]
    pub secret_key_env: Option<String>,

    /// Use path-style URLs (required for MinIO/RustFS, default: true)
    #[serde(default = "default_path_style")]
    pub path_style: bool,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

fn default_path_style() -> bool {
    true
}

impl WebappS3Source {
    /// Get the access key (from config field or referenced env var)
    pub fn get_access_key(&self) -> Option<String> {
        self.access_key.clone().or_else(|| {
            self.access_key_env
                .as_ref()
                .and_then(|env_name| std::env::var(env_name).ok())
        })
    }

    /// Get the secret key (from config field or referenced env var)
    pub fn get_secret_key(&self) -> Option<String> {
        self.secret_key.clone().or_else(|| {
            self.secret_key_env
                .as_ref()
                .and_then(|env_name| std::env::var(env_name).ok())
        })
    }

    /// Display name for logging
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.bucket
        } else {
            &self.name
        }
    }
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
            role: ServerRole::default(),
            upstream_loopback: None,
            policy_source: None,
            no_static: false,
            webapp_sources: Vec::new(),
        }
    }
}

/// Server role — `Standalone` (full edge BFF, the historical
/// behavior) or `Sidecar` (L7 sub-component of a pleme-io mesh data
/// plane; see theory/MESH.md §V).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerRole {
    Standalone,
    Sidecar,
}

impl Default for ServerRole {
    fn default() -> Self {
        Self::Standalone
    }
}

impl ServerConfig {
    /// True when the config requests sidecar (mesh-L7) mode.
    #[must_use]
    pub fn is_sidecar(&self) -> bool {
        self.role == ServerRole::Sidecar
    }

    /// True when static-file paths should be skipped in this mode —
    /// either explicitly via `no_static`, or implicit when running as
    /// a sidecar.
    #[must_use]
    pub fn skip_static(&self) -> bool {
        self.no_static || self.is_sidecar()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_standalone() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.role, ServerRole::Standalone);
        assert!(!cfg.is_sidecar());
        assert!(!cfg.skip_static());
        assert!(cfg.upstream_loopback.is_none());
        assert!(cfg.policy_source.is_none());
        assert!(!cfg.no_static);
    }

    #[test]
    fn sidecar_role_implies_skip_static() {
        let mut cfg = ServerConfig::default();
        cfg.role = ServerRole::Sidecar;
        assert!(cfg.is_sidecar());
        // Sidecar always skips static, even without explicit no_static.
        assert!(cfg.skip_static());
    }

    #[test]
    fn explicit_no_static_in_standalone_skips() {
        let mut cfg = ServerConfig::default();
        cfg.no_static = true;
        assert!(!cfg.is_sidecar());
        assert!(cfg.skip_static());
    }

    #[test]
    fn yaml_round_trip_preserves_role_and_slots() {
        let yaml = r#"
http_port: 0
health_port: 0
static_dir: ""
service_name: "x"
service_version: "1"
bind_address: "127.0.0.1"
request_timeout_secs: 30
keepalive_timeout_secs: 75
max_concurrent_connections: 100
worker_threads: 0
tcp_nodelay: true
role: sidecar
upstream_loopback: "http://127.0.0.1:8082"
policy_source: "/etc/hanabi/policy.yaml"
no_static: true
"#;
        let cfg: ServerConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.is_sidecar());
        assert_eq!(cfg.upstream_loopback.as_deref(), Some("http://127.0.0.1:8082"));
        assert_eq!(cfg.policy_source.as_deref(), Some("/etc/hanabi/policy.yaml"));
        assert!(cfg.no_static);
    }
}
