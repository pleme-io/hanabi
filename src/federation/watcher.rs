#![allow(dead_code)]
//! Supergraph hot reload watcher
//!
//! This module provides automatic supergraph schema reloading when the source
//! file or URL changes. Inspired by Apollo Router's --hot-reload flag.
//!
//! # Supported Sources
//! - `file://path` - Uses file modification time for change detection
//! - `http(s)://url` - Uses ETag/Last-Modified headers, falls back to content hash
//!
//! # Architecture
//! ```
//! SupergraphWatcher
//!   │
//!   ├─► Polling Task (spawned on start)
//!   │     │
//!   │     ├─► Check for changes (file mtime / HTTP headers)
//!   │     │
//!   │     └─► On change: reload → update Arc<RwLock<Supergraph>>
//!   │
//!   └─► shutdown() → Stops polling task
//! ```
//!
//! # Usage
//! ```rust,ignore
//! let watcher = SupergraphWatcher::new(config, supergraph_arc);
//! watcher.start().await; // Spawns background task
//! // ... later ...
//! watcher.shutdown().await; // Graceful shutdown
//! ```

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{watch, RwLock};
use tracing::{debug, error, info, warn};

/// PERFORMANCE: Static RandomState for deterministic hashing within process lifetime.
/// Initialized once, reused for all hash operations. ahash is 2-3x faster than DefaultHasher.
static AHASH_STATE: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);

use super::supergraph::{Supergraph, SupergraphError};
use crate::config::BffFederationConfig;
use crate::metrics::{MetricsClient, MetricsExt};

/// Strip the "file://" prefix from a URL, returning the path
///
/// # Errors
/// Returns `SupergraphError::IoError` if the URL doesn't start with "file://"
#[inline]
fn strip_file_prefix(url: &str) -> Result<&str, SupergraphError> {
    url.strip_prefix("file://").ok_or_else(|| {
        SupergraphError::IoError(format!(
            "Invalid file URL (missing file:// prefix): {}",
            url
        ))
    })
}

/// Result of a supergraph reload operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupergraphReloadResult {
    /// Whether the reload was successful
    pub success: bool,

    /// SHA-256 hash of the new supergraph schema (first 16 chars)
    pub hash: String,

    /// Number of subgraphs in the loaded schema
    pub subgraph_count: usize,

    /// Number of subscription routes
    pub subscription_route_count: usize,

    /// Source URL the supergraph was loaded from
    pub source: String,

    /// Optional error message if reload failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Watches for supergraph schema changes and triggers reload
pub struct SupergraphWatcher {
    /// URL to watch (file:// or http://)
    supergraph_url: String,

    /// Poll interval in seconds
    poll_interval_secs: u64,

    /// Shared supergraph state to update
    supergraph: Arc<RwLock<Option<Supergraph>>>,

    /// Shutdown signal sender
    shutdown_tx: Option<watch::Sender<bool>>,

    /// Metrics client for observability
    metrics: Option<Arc<MetricsClient>>,

    /// HTTP client for fetching supergraph (uses connection pooling)
    http_client: Arc<reqwest::Client>,

    /// Last known file modification time (for file:// URLs)
    last_modified: Arc<RwLock<Option<SystemTime>>>,

    /// Last known content hash (for http:// URLs without ETag)
    last_hash: Arc<RwLock<Option<u64>>>,

    /// Last ETag value (for http:// URLs)
    last_etag: Arc<RwLock<Option<String>>>,
}

/// Context for the watch loop (Parameter Object pattern)
/// Groups related parameters to reduce function parameter count per Gate 20
struct WatchLoopContext {
    /// URL to watch
    url: String,
    /// Poll interval
    interval: Duration,
    /// Shared supergraph state
    supergraph: Arc<RwLock<Option<Supergraph>>>,
    /// Optional metrics client
    metrics: Option<Arc<MetricsClient>>,
    /// HTTP client for fetching
    http_client: Arc<reqwest::Client>,
    /// Shutdown signal receiver
    shutdown_rx: watch::Receiver<bool>,
    /// Last file modification time
    last_modified: Arc<RwLock<Option<SystemTime>>>,
    /// Last content hash
    last_hash: Arc<RwLock<Option<u64>>>,
    /// Last ETag value
    last_etag: Arc<RwLock<Option<String>>>,
}

impl SupergraphWatcher {
    /// Create a new supergraph watcher
    ///
    /// # Arguments
    /// * `config` - Federation configuration
    /// * `supergraph` - Shared supergraph state to update
    /// * `metrics` - Optional metrics client
    /// * `http_client` - Optional HTTP client (if None, creates a new one)
    pub fn new(
        config: &BffFederationConfig,
        supergraph: Arc<RwLock<Option<Supergraph>>>,
        metrics: Option<Arc<MetricsClient>>,
        http_client: Option<Arc<reqwest::Client>>,
    ) -> Self {
        // Use provided client or create a new one with defaults
        let client = http_client.unwrap_or_else(|| {
            Arc::new(
                match reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .pool_idle_timeout(std::time::Duration::from_secs(90))
                    .pool_max_idle_per_host(2) // Small pool for supergraph fetching
                    .build()
                {
                    Ok(client) => client,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create HTTP client for supergraph watcher, using defaults");
                        reqwest::Client::new()
                    }
                },
            )
        });

        Self {
            supergraph_url: config.supergraph_url.clone(),
            poll_interval_secs: config.poll_interval_secs,
            supergraph,
            shutdown_tx: None,
            metrics,
            http_client: client,
            last_modified: Arc::new(RwLock::new(None)),
            last_hash: Arc::new(RwLock::new(None)),
            last_etag: Arc::new(RwLock::new(None)),
        }
    }

    /// Start the watcher background task
    ///
    /// Returns immediately after spawning the task.
    /// Use `shutdown()` to stop the watcher.
    pub fn start(&mut self) {
        if self.poll_interval_secs == 0 {
            info!("Supergraph hot reload disabled (poll_interval_secs = 0)");
            return;
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        self.shutdown_tx = Some(shutdown_tx);

        let url = self.supergraph_url.clone();
        let interval = Duration::from_secs(self.poll_interval_secs);
        let supergraph = self.supergraph.clone();
        let metrics = self.metrics.clone();
        let http_client = self.http_client.clone();
        let last_modified = self.last_modified.clone();
        let last_hash = self.last_hash.clone();
        let last_etag = self.last_etag.clone();

        info!(
            "Starting supergraph hot reload watcher (interval: {}s, source: {})",
            self.poll_interval_secs, self.supergraph_url
        );

        // Use parameter object for watch_loop (Gate 20 compliance)
        let watch_ctx = WatchLoopContext {
            url,
            interval,
            supergraph,
            metrics,
            http_client,
            shutdown_rx,
            last_modified,
            last_hash,
            last_etag,
        };

        tokio::spawn(async move {
            Self::watch_loop(watch_ctx).await;
        });
    }

    /// Stop the watcher background task
    pub async fn shutdown(&self) {
        if let Some(ref tx) = self.shutdown_tx {
            let _ = tx.send(true);
            info!("Supergraph watcher shutdown signal sent");
        }
    }

    /// Main watch loop
    /// Uses WatchLoopContext to bundle parameters (Gate 20 compliance)
    async fn watch_loop(ctx: WatchLoopContext) {
        // Destructure context for local access
        let WatchLoopContext {
            url,
            interval,
            supergraph,
            metrics,
            http_client,
            mut shutdown_rx,
            last_modified,
            last_hash,
            last_etag,
        } = ctx;

        // Initialize last known state from current supergraph
        if url.starts_with("file://") {
            if let Ok(path) = strip_file_prefix(&url) {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    if let Ok(modified) = metadata.modified() {
                        *last_modified.write().await = Some(modified);
                    }
                }
            }
        }

        let mut interval_timer = tokio::time::interval(interval);
        // Skip the first immediate tick
        interval_timer.tick().await;

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    // Check for changes
                    match Self::check_for_changes(
                        &url,
                        &http_client,
                        &last_modified,
                        &last_hash,
                        &last_etag,
                    ).await {
                        Ok(Some(new_schema)) => {
                            info!("Supergraph schema changed, reloading...");

                            metrics.incr("bff.federation.supergraph.reload_started", &[]);

                            // Parse new schema
                            match Supergraph::parse(&new_schema) {
                                Ok(new_supergraph) => {
                                    let subgraph_count = new_supergraph.subgraphs().len() / 2;
                                    let route_count = new_supergraph.subscription_routes.len();

                                    // Update shared state
                                    *supergraph.write().await = Some(new_supergraph);

                                    info!(
                                        "Supergraph reloaded successfully: {} subgraphs, {} subscription routes",
                                        subgraph_count, route_count
                                    );

                                    if let Some(ref m) = metrics {
                                        m.increment("bff.federation.supergraph.reload_success", &[]);
                                        m.gauge("bff.federation.subgraphs", subgraph_count as f64, &[]);
                                        m.gauge("bff.federation.subscription_routes", route_count as f64, &[]);
                                    }
                                }
                                Err(e) => {
                                    error!("Failed to parse new supergraph: {} - keeping old schema", e);

                                    metrics.incr("bff.federation.supergraph.reload_failed", &[("reason", "parse_error")]);
                                }
                            }
                        }
                        Ok(None) => {
                            // No changes
                            debug!("Supergraph unchanged");
                        }
                        Err(e) => {
                            warn!("Error checking supergraph: {} - will retry", e);

                            metrics.incr("bff.federation.supergraph.check_error", &[]);
                        }
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Supergraph watcher shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Check if supergraph has changed
    ///
    /// Returns Ok(Some(new_schema)) if changed, Ok(None) if unchanged
    async fn check_for_changes(
        url: &str,
        http_client: &reqwest::Client,
        last_modified: &RwLock<Option<SystemTime>>,
        last_hash: &RwLock<Option<u64>>,
        last_etag: &RwLock<Option<String>>,
    ) -> Result<Option<String>, SupergraphError> {
        if url.starts_with("file://") {
            Self::check_file_changes(url, last_modified).await
        } else {
            Self::check_http_changes(url, http_client, last_hash, last_etag).await
        }
    }

    /// Check file for changes using modification time
    async fn check_file_changes(
        url: &str,
        last_modified: &RwLock<Option<SystemTime>>,
    ) -> Result<Option<String>, SupergraphError> {
        let path = strip_file_prefix(url)?;

        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|e| SupergraphError::IoError(e.to_string()))?;

        let current_modified = metadata
            .modified()
            .map_err(|e| SupergraphError::IoError(e.to_string()))?;

        let mut last = last_modified.write().await;

        match *last {
            Some(prev) if prev == current_modified => {
                // No change
                Ok(None)
            }
            _ => {
                // Changed or first check
                *last = Some(current_modified);

                let content = tokio::fs::read_to_string(path)
                    .await
                    .map_err(|e| SupergraphError::IoError(e.to_string()))?;

                Ok(Some(content))
            }
        }
    }

    /// Check HTTP URL for changes using ETag or content hash
    async fn check_http_changes(
        url: &str,
        http_client: &reqwest::Client,
        last_hash: &RwLock<Option<u64>>,
        last_etag: &RwLock<Option<String>>,
    ) -> Result<Option<String>, SupergraphError> {
        let prev_etag = last_etag.read().await.clone();

        // Try conditional GET with ETag (uses connection pooling)
        let mut request = http_client.get(url);
        if let Some(ref etag) = prev_etag {
            request = request.header("If-None-Match", etag);
        }

        let response = request
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| SupergraphError::FetchError(e.to_string()))?;

        // Check for 304 Not Modified
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
        }

        // Store new ETag if present
        if let Some(etag) = response.headers().get("etag") {
            if let Ok(etag_str) = etag.to_str() {
                *last_etag.write().await = Some(etag_str.to_string());
            }
        }

        let content = response
            .text()
            .await
            .map_err(|e| SupergraphError::FetchError(e.to_string()))?;

        // If no ETag support, use content hash
        let current_hash = Self::hash_content(&content);
        let mut last = last_hash.write().await;

        match *last {
            Some(prev) if prev == current_hash => {
                // Content unchanged
                Ok(None)
            }
            _ => {
                // Changed or first check
                *last = Some(current_hash);
                Ok(Some(content))
            }
        }
    }

    /// Simple hash function for content comparison
    ///
    /// PERFORMANCE: Uses ahash instead of DefaultHasher for 2-3x faster hashing.
    /// ahash leverages AES-NI instructions on modern CPUs for optimal performance.
    /// Uses static RandomState for deterministic hashing within process lifetime.
    fn hash_content(content: &str) -> u64 {
        AHASH_STATE.hash_one(content)
    }
}

/// Wrapper for supergraph that supports hot reload
///
/// Provides thread-safe read access to the supergraph while allowing
/// background updates from the watcher.
pub struct HotReloadableSupergraph {
    /// Current supergraph state
    supergraph: Arc<RwLock<Option<Supergraph>>>,

    /// Watcher task handle (if hot reload is enabled)
    watcher: Option<SupergraphWatcher>,
}

impl HotReloadableSupergraph {
    /// Create a new hot-reloadable supergraph
    ///
    /// # Arguments
    /// * `config` - Federation configuration
    /// * `metrics` - Optional metrics client
    /// * `http_client` - Optional HTTP client for fetching supergraph (uses connection pooling)
    pub async fn new(
        config: &BffFederationConfig,
        metrics: Option<Arc<MetricsClient>>,
        http_client: Option<Arc<reqwest::Client>>,
    ) -> Result<Self, SupergraphError> {
        // Initial load (uses provided client or one-off for initial fetch)
        let initial = if let Some(ref client) = http_client {
            Self::load_with_client(&config.supergraph_url, client).await?
        } else {
            Supergraph::load(&config.supergraph_url).await?
        };
        let supergraph = Arc::new(RwLock::new(Some(initial)));

        // Create watcher if hot reload is enabled
        let watcher = if config.hot_reload && config.poll_interval_secs > 0 {
            let mut w = SupergraphWatcher::new(config, supergraph.clone(), metrics, http_client);
            w.start();
            Some(w)
        } else {
            None
        };

        Ok(Self {
            supergraph,
            watcher,
        })
    }

    /// Load supergraph using provided HTTP client (for connection reuse)
    async fn load_with_client(
        url: &str,
        client: &reqwest::Client,
    ) -> Result<Supergraph, SupergraphError> {
        let schema = if url.starts_with("file://") {
            let path = strip_file_prefix(url)?;
            tokio::fs::read_to_string(path)
                .await
                .map_err(|e| SupergraphError::IoError(e.to_string()))?
        } else {
            client
                .get(url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| SupergraphError::FetchError(e.to_string()))?
                .text()
                .await
                .map_err(|e| SupergraphError::FetchError(e.to_string()))?
        };

        Supergraph::parse(&schema)
    }

    /// Get read access to the current supergraph
    ///
    /// Returns None if supergraph is not loaded (should not happen in normal operation)
    pub async fn get(&self) -> Option<tokio::sync::RwLockReadGuard<'_, Option<Supergraph>>> {
        let guard = self.supergraph.read().await;
        if guard.is_some() {
            Some(guard)
        } else {
            None
        }
    }

    /// Get the underlying Arc for sharing with handlers
    pub fn shared(&self) -> Arc<RwLock<Option<Supergraph>>> {
        self.supergraph.clone()
    }

    /// Shutdown the watcher (if running)
    pub async fn shutdown(&self) {
        if let Some(ref watcher) = self.watcher {
            watcher.shutdown().await;
        }
    }

    /// Force reload the supergraph from its configured source
    ///
    /// This method is called by the admin API to trigger an immediate reload
    /// without waiting for the polling interval. Useful during deployments
    /// to ensure the new supergraph is picked up immediately.
    ///
    /// # Arguments
    /// * `config` - Federation configuration containing the supergraph URL
    /// * `metrics` - Optional metrics client for observability
    ///
    /// # Returns
    /// * `Ok(SupergraphReloadResult)` - Reload result with hash and stats
    /// * `Err(SupergraphError)` - If loading or parsing fails
    pub async fn force_reload(
        &self,
        config: &BffFederationConfig,
        metrics: Option<&Arc<MetricsClient>>,
    ) -> Result<SupergraphReloadResult, SupergraphError> {
        info!("Force reloading supergraph from: {}", config.supergraph_url);

        if let Some(m) = metrics {
            m.increment("bff.federation.supergraph.force_reload_started", &[]);
        }

        // Load schema from source
        let schema = Self::load_schema_from_source(&config.supergraph_url).await?;

        // Compute hash for verification
        let hash = Self::compute_schema_hash(&schema);

        // Parse the schema
        let new_supergraph = match Supergraph::parse(&schema) {
            Ok(sg) => sg,
            Err(e) => {
                error!("Failed to parse supergraph during force reload: {}", e);

                if let Some(m) = metrics {
                    m.increment(
                        "bff.federation.supergraph.force_reload_failed",
                        &[("reason", "parse_error")],
                    );
                }

                return Ok(SupergraphReloadResult {
                    success: false,
                    hash,
                    subgraph_count: 0,
                    subscription_route_count: 0,
                    source: config.supergraph_url.clone(),
                    error: Some(format!("Parse error: {}", e)),
                });
            }
        };

        let subgraph_count = new_supergraph.subgraphs().len() / 2; // subgraphs() returns name+url pairs
        let subscription_route_count = new_supergraph.subscription_routes.len();

        // Update shared state
        *self.supergraph.write().await = Some(new_supergraph);

        info!(
            "Supergraph force reloaded successfully: hash={}, {} subgraphs, {} subscription routes",
            hash, subgraph_count, subscription_route_count
        );

        if let Some(m) = metrics {
            m.increment("bff.federation.supergraph.force_reload_success", &[]);
            m.gauge("bff.federation.subgraphs", subgraph_count as f64, &[]);
            m.gauge(
                "bff.federation.subscription_routes",
                subscription_route_count as f64,
                &[],
            );
        }

        Ok(SupergraphReloadResult {
            success: true,
            hash,
            subgraph_count,
            subscription_route_count,
            source: config.supergraph_url.clone(),
            error: None,
        })
    }

    /// Load schema content from a file:// or http:// URL
    async fn load_schema_from_source(url: &str) -> Result<String, SupergraphError> {
        if url.starts_with("file://") {
            let path = strip_file_prefix(url)?;
            tokio::fs::read_to_string(path)
                .await
                .map_err(|e| SupergraphError::IoError(format!("Failed to read {}: {}", path, e)))
        } else if url.starts_with("http://") || url.starts_with("https://") {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    SupergraphError::FetchError(format!("Failed to create HTTP client: {}", e))
                })?;

            client
                .get(url)
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .map_err(|e| {
                    SupergraphError::FetchError(format!("Failed to fetch {}: {}", url, e))
                })?
                .text()
                .await
                .map_err(|e| {
                    SupergraphError::FetchError(format!(
                        "Failed to read response from {}: {}",
                        url, e
                    ))
                })
        } else {
            Err(SupergraphError::IoError(format!(
                "Unsupported URL scheme: {}",
                url
            )))
        }
    }

    /// Compute a short hash of the schema content for verification
    fn compute_schema_hash(content: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        let result = hasher.finalize();
        format!("{:x}", result)[..16].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_content() {
        let hash1 = SupergraphWatcher::hash_content("hello world");
        let hash2 = SupergraphWatcher::hash_content("hello world");
        let hash3 = SupergraphWatcher::hash_content("hello world!");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_watcher_creation() {
        let config = BffFederationConfig {
            enabled: true,
            hot_reload: true,
            poll_interval_secs: 30,
            supergraph_url: "file:///nonexistent".to_string(),
            ..Default::default()
        };

        let supergraph = Arc::new(RwLock::new(None));
        let watcher = SupergraphWatcher::new(&config, supergraph, None, None);

        assert_eq!(watcher.poll_interval_secs, 30);
    }
}
