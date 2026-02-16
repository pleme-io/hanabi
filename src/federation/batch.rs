#![allow(dead_code, unused)]
//! Request Batching with DataLoader Pattern
//!
//! Provides automatic batching of subgraph requests to solve the N+1 problem
//! and reduce network overhead in GraphQL federation.
//!
//! # The N+1 Problem
//!
//! ```text
//! Without batching:
//! Query: { posts { author { name } } }
//!
//! Post 1 → fetch author 101 → HTTP call
//! Post 2 → fetch author 102 → HTTP call
//! Post 3 → fetch author 101 → HTTP call (duplicate!)
//! Post 4 → fetch author 103 → HTTP call
//! = 4 HTTP calls (with 1 duplicate)
//!
//! With batching:
//! Post 1 → queue(101)
//! Post 2 → queue(102)
//! Post 3 → queue(101)  → deduplicated
//! Post 4 → queue(103)
//! Batch window closes → fetch [101, 102, 103] → 1 HTTP call
//! = 1 HTTP call
//! ```
//!
//! # Usage
//!
//! ```rust
//! // Create a batcher for user entity fetches
//! let batcher = EntityBatcher::new(BatchConfig::default(), user_loader);
//!
//! // Queue fetches (will be batched automatically)
//! let user1 = batcher.load("user-1").await?;
//! let user2 = batcher.load("user-2").await?;
//!
//! // Or load multiple at once
//! let users = batcher.load_many(&["user-1", "user-2", "user-3"]).await?;
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::one::Ref as DashMapRef;
use dashmap::DashMap;
use futures_util::future::join_all;
use tokio::sync::{oneshot, Mutex};
use tokio::time::{sleep, Instant};
use tracing::{debug, info};

use crate::metrics::{MetricsClient, MetricsExt};

/// Configuration for request batching
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Enable batching
    pub enabled: bool,

    /// Maximum time to wait for more requests (milliseconds)
    pub batch_window_ms: u64,

    /// Maximum batch size before forcing execution
    pub max_batch_size: usize,

    /// Enable request caching (deduplicate within batch window)
    pub enable_cache: bool,

    /// Cache TTL in milliseconds (0 = no expiry within window)
    pub cache_ttl_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_window_ms: 10, // 10ms batch window
            max_batch_size: 100,
            enable_cache: true,
            cache_ttl_ms: 1000, // 1 second cache
        }
    }
}

/// Batch loader function type
///
/// Takes a vector of keys and returns a map of key → value.
/// Keys not found in the result will receive None.
pub type BatchLoaderFn<K, V> = Box<
    dyn Fn(Vec<K>) -> Pin<Box<dyn Future<Output = Result<HashMap<K, V>, BatchError>> + Send>>
        + Send
        + Sync,
>;

/// Error from batch loading
#[derive(Debug, Clone)]
pub struct BatchError {
    /// Error message
    pub message: String,
    /// Which keys failed (if partial failure)
    pub failed_keys: Vec<String>,
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Batch error: {}", self.message)
    }
}

impl std::error::Error for BatchError {}

impl BatchError {
    /// Create a new batch error
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            failed_keys: vec![],
        }
    }

    /// Create a batch error with failed keys
    pub fn with_keys(message: impl Into<String>, keys: Vec<String>) -> Self {
        Self {
            message: message.into(),
            failed_keys: keys,
        }
    }
}

/// Pending request in the batch queue
struct PendingRequest<K, V> {
    /// The key being loaded
    key: K,
    /// Channel to send result
    sender: oneshot::Sender<Result<Option<V>, BatchError>>,
}

/// State for a batch in progress
struct BatchState<K, V> {
    /// Pending requests
    pending: Vec<PendingRequest<K, V>>,
    /// When the batch was started
    started_at: Instant,
    /// Scheduler handle (to cancel if batch executes early)
    scheduler_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Generic entity batcher using DataLoader pattern
///
/// Batches multiple load requests within a time window and executes
/// them as a single batch fetch.
pub struct EntityBatcher<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Configuration
    config: BatchConfig,

    /// The batch loader function
    loader: Arc<BatchLoaderFn<K, V>>,

    /// Current batch state (protected by mutex)
    batch_state: Arc<Mutex<Option<BatchState<K, V>>>>,

    /// Cache of recently loaded values
    cache: Arc<DashMap<K, CacheEntry<V>>>,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

/// Cache entry with expiry
struct CacheEntry<V> {
    value: Option<V>,
    expires_at: Instant,
}

impl<K, V> EntityBatcher<K, V>
where
    K: Clone + Eq + Hash + Send + Sync + std::fmt::Debug + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Create a new entity batcher
    pub fn new(
        config: BatchConfig,
        loader: impl Fn(Vec<K>) -> Pin<Box<dyn Future<Output = Result<HashMap<K, V>, BatchError>> + Send>>
            + Send
            + Sync
            + 'static,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        info!(
            batch_window_ms = config.batch_window_ms,
            max_batch_size = config.max_batch_size,
            enable_cache = config.enable_cache,
            "Entity batcher initialized"
        );

        Self {
            config,
            loader: Arc::new(Box::new(loader)),
            batch_state: Arc::new(Mutex::new(None)),
            cache: Arc::new(DashMap::new()),
            metrics,
        }
    }

    /// Load a single entity
    pub async fn load(&self, key: K) -> Result<Option<V>, BatchError> {
        if !self.config.enabled {
            // Batching disabled, load directly
            let result = (self.loader)(vec![key.clone()]).await?;
            return Ok(result.get(&key).cloned());
        }

        // Check cache first
        if self.config.enable_cache {
            if let Some(entry) = self.cache.get(&key) {
                let entry: DashMapRef<'_, K, CacheEntry<V>> = entry;
                let cache_entry = entry.value();
                if cache_entry.expires_at > Instant::now() {
                    self.metrics.incr("bff.federation.batch.cache_hit", &[]);
                    return Ok(cache_entry.value.clone());
                }
                // Expired, remove
                drop(entry);
                self.cache.remove(&key);
            }
        }

        // Queue for batching
        let (sender, receiver) = oneshot::channel();

        {
            let mut state_guard = self.batch_state.lock().await;

            let state = state_guard.get_or_insert_with(|| {
                // Start new batch
                let started_at = Instant::now();

                // Schedule batch execution after window
                let batch_state_clone = Arc::clone(&self.batch_state);
                let loader_clone = Arc::clone(&self.loader);
                let cache_clone = Arc::clone(&self.cache);
                let config_clone = self.config.clone();
                let metrics_clone = self.metrics.clone();

                let handle = tokio::spawn(async move {
                    sleep(Duration::from_millis(config_clone.batch_window_ms)).await;
                    Self::execute_batch(
                        batch_state_clone,
                        loader_clone,
                        cache_clone,
                        &config_clone,
                        metrics_clone,
                    )
                    .await;
                });

                BatchState {
                    pending: Vec::new(),
                    started_at,
                    scheduler_handle: Some(handle),
                }
            });

            state.pending.push(PendingRequest { key, sender });

            // Check if we should execute early (max batch size reached)
            if state.pending.len() >= self.config.max_batch_size {
                // Cancel the scheduled execution
                if let Some(handle) = state.scheduler_handle.take() {
                    handle.abort();
                }

                // Take ownership of the state (should always succeed as we hold the lock)
                let state = state_guard
                    .take()
                    .ok_or_else(|| BatchError::new("Batch state already consumed"))?;
                drop(state_guard);

                // Execute immediately
                Self::execute_batch_immediate(
                    state,
                    Arc::clone(&self.loader),
                    Arc::clone(&self.cache),
                    &self.config,
                    self.metrics.clone(),
                )
                .await;
            }
        }

        // Wait for result
        receiver
            .await
            .map_err(|_| BatchError::new("Batch cancelled"))?
    }

    /// Load multiple entities
    pub async fn load_many(&self, keys: &[K]) -> Result<HashMap<K, V>, BatchError> {
        let futures: Vec<_> = keys.iter().map(|k| self.load(k.clone())).collect();

        let results = join_all(futures).await;

        let mut map = HashMap::new();
        for (key, result) in keys.iter().zip(results) {
            if let Some(value) = result? {
                map.insert(key.clone(), value);
            }
        }

        Ok(map)
    }

    /// Execute a batch
    async fn execute_batch(
        batch_state: Arc<Mutex<Option<BatchState<K, V>>>>,
        loader: Arc<BatchLoaderFn<K, V>>,
        cache: Arc<DashMap<K, CacheEntry<V>>>,
        config: &BatchConfig,
        metrics: Option<Arc<MetricsClient>>,
    ) {
        let state = {
            let mut guard = batch_state.lock().await;
            guard.take()
        };

        if let Some(state) = state {
            Self::execute_batch_immediate(state, loader, cache, config, metrics).await;
        }
    }

    /// Execute a batch immediately
    async fn execute_batch_immediate(
        state: BatchState<K, V>,
        loader: Arc<BatchLoaderFn<K, V>>,
        cache: Arc<DashMap<K, CacheEntry<V>>>,
        config: &BatchConfig,
        metrics: Option<Arc<MetricsClient>>,
    ) {
        let pending = state.pending;

        if pending.is_empty() {
            return;
        }

        // Collect unique keys
        let mut keys: Vec<K> = pending.iter().map(|p| p.key.clone()).collect();
        keys.sort_by(|a, b| format!("{:?}", a).cmp(&format!("{:?}", b)));
        keys.dedup();

        let batch_size = keys.len();
        let total_requests = pending.len();

        debug!(
            batch_size = batch_size,
            total_requests = total_requests,
            "Executing batch"
        );

        if let Some(ref m) = metrics {
            m.increment("bff.federation.batch.execute", &[]);
            m.histogram("bff.federation.batch.size", batch_size as f64, &[]);
            m.histogram("bff.federation.batch.requests", total_requests as f64, &[]);
        }

        // Execute the batch loader
        let result = loader(keys.clone()).await;

        // Populate cache and distribute results
        let expires_at = Instant::now() + Duration::from_millis(config.cache_ttl_ms);

        match result {
            Ok(values) => {
                // Cache all values (including None for missing keys)
                for key in &keys {
                    let value = values.get(key).cloned();
                    cache.insert(
                        key.clone(),
                        CacheEntry {
                            value: value.clone(),
                            expires_at,
                        },
                    );
                }

                // Distribute results to waiting requests
                for pending_req in pending {
                    let value = values.get(&pending_req.key).cloned();
                    let _ = pending_req.sender.send(Ok(value));
                }
            }
            Err(e) => {
                // Distribute error to all waiting requests
                for pending_req in pending {
                    let _ = pending_req.sender.send(Err(e.clone()));
                }

                metrics.incr("bff.federation.batch.error", &[]);
            }
        }
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        self.cache.clear();
        debug!("Batch cache cleared");
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> BatchCacheStats {
        BatchCacheStats {
            entries: self.cache.len(),
        }
    }
}

/// Batch cache statistics
#[derive(Debug, Clone)]
pub struct BatchCacheStats {
    /// Number of cached entries
    pub entries: usize,
}

/// Factory for creating subgraph-specific batchers
pub struct SubgraphBatcherFactory {
    /// Default configuration
    config: BatchConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl SubgraphBatcherFactory {
    /// Create a new factory
    pub fn new(config: BatchConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    /// Create a batcher for entity representation fetches
    ///
    /// Used for Apollo Federation's `_entities` query batching.
    pub fn create_entity_batcher<V>(
        &self,
        subgraph_name: &str,
        fetch_entities: impl Fn(
                Vec<serde_json::Value>,
            ) -> Pin<
                Box<dyn Future<Output = Result<HashMap<serde_json::Value, V>, BatchError>> + Send>,
            > + Send
            + Sync
            + 'static,
    ) -> EntityBatcher<serde_json::Value, V>
    where
        V: Clone + Send + Sync + 'static,
    {
        info!(subgraph = %subgraph_name, "Creating entity batcher");

        EntityBatcher::new(self.config.clone(), fetch_entities, self.metrics.clone())
    }
}

/// Helper to build entity representations for batched _entities queries
pub struct EntityRepresentationBuilder;

impl EntityRepresentationBuilder {
    /// Build an entity representation for batching
    pub fn build(typename: &str, key_field: &str, key_value: &str) -> serde_json::Value {
        serde_json::json!({
            "__typename": typename,
            key_field: key_value
        })
    }

    /// Build an entity representation with multiple key fields
    pub fn build_composite(
        typename: &str,
        keys: &[(&str, serde_json::Value)],
    ) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "__typename": typename
        });

        if let Some(map) = obj.as_object_mut() {
            for (key, value) in keys {
                map.insert((*key).to_string(), value.clone());
            }
        }

        obj
    }

    /// Build the _entities query for batched fetches
    pub fn build_entities_query(
        representations: &[serde_json::Value],
        selection: &str,
    ) -> (String, serde_json::Value) {
        let query = format!(
            r#"
            query EntitiesBatch($representations: [_Any!]!) {{
                _entities(representations: $representations) {{
                    ... on {} {{
                        {}
                    }}
                }}
            }}
            "#,
            "ENTITY_TYPE", // This gets replaced per actual type
            selection
        );

        let variables = serde_json::json!({
            "representations": representations
        });

        (query, variables)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_batch_config_defaults() {
        let config = BatchConfig::default();
        assert!(config.enabled);
        assert_eq!(config.batch_window_ms, 10);
        assert_eq!(config.max_batch_size, 100);
    }

    #[tokio::test]
    async fn test_entity_batcher_single_load() {
        let loader = |keys: Vec<String>| {
            Box::pin(async move {
                let mut map = HashMap::new();
                for key in keys {
                    map.insert(key.clone(), format!("value-{}", key));
                }
                Ok(map)
            })
                as Pin<Box<dyn Future<Output = Result<HashMap<String, String>, BatchError>> + Send>>
        };

        let batcher = EntityBatcher::new(
            BatchConfig {
                enabled: false, // Disable batching for simple test
                ..Default::default()
            },
            loader,
            None,
        );

        let result = batcher.load("key1".to_string()).await.unwrap();
        assert_eq!(result, Some("value-key1".to_string()));
    }

    #[tokio::test]
    async fn test_entity_batcher_load_many() {
        let loader = |keys: Vec<String>| {
            Box::pin(async move {
                let mut map = HashMap::new();
                for key in keys {
                    map.insert(key.clone(), format!("value-{}", key));
                }
                Ok(map)
            })
                as Pin<Box<dyn Future<Output = Result<HashMap<String, String>, BatchError>> + Send>>
        };

        let batcher = EntityBatcher::new(
            BatchConfig {
                enabled: false,
                ..Default::default()
            },
            loader,
            None,
        );

        let result = batcher
            .load_many(&["a".to_string(), "b".to_string()])
            .await
            .unwrap();

        assert_eq!(result.len(), 2);
        assert_eq!(result.get("a"), Some(&"value-a".to_string()));
        assert_eq!(result.get("b"), Some(&"value-b".to_string()));
    }

    #[tokio::test]
    async fn test_entity_representation_builder() {
        let rep = EntityRepresentationBuilder::build("User", "id", "user-123");
        assert_eq!(rep["__typename"], "User");
        assert_eq!(rep["id"], "user-123");

        let rep = EntityRepresentationBuilder::build_composite(
            "Product",
            &[
                ("sku", serde_json::json!("ABC123")),
                ("warehouse", serde_json::json!("US-WEST")),
            ],
        );
        assert_eq!(rep["__typename"], "Product");
        assert_eq!(rep["sku"], "ABC123");
        assert_eq!(rep["warehouse"], "US-WEST");
    }

    #[test]
    fn test_batch_error() {
        let err = BatchError::new("test error");
        assert_eq!(err.message, "test error");
        assert!(err.failed_keys.is_empty());

        let err = BatchError::with_keys("partial failure", vec!["key1".to_string()]);
        assert_eq!(err.failed_keys.len(), 1);
    }
}
