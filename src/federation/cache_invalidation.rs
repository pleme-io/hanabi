#![allow(dead_code)]
//! Event-Driven Cache Invalidation
//!
//! Provides real-time cache invalidation across multiple BFF pods using Redis pub/sub.
//! When a mutation modifies an entity, an invalidation event is published to Redis,
//! and all BFF instances evict matching cache entries.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │     BFF Pod 1   │     │     BFF Pod 2   │     │     BFF Pod 3   │
//! │                 │     │                 │     │                 │
//! │ Mutation ───────┼────►│ Redis Pub/Sub   │◄────┼──── Mutation    │
//! │    │            │     │                 │     │        │        │
//! │    ▼            │     │                 │     │        ▼        │
//! │ Publish Event   │     │ bff:cache:inv:* │     │ Publish Event   │
//! │                 │     │                 │     │                 │
//! │ ◄─Subscribe─────┼─────┤ (broadcasts to  │─────┼────Subscribe──► │
//! │    │            │     │  all pods)      │     │        │        │
//! │    ▼            │     │                 │     │        ▼        │
//! │ Evict L1/L2     │     └─────────────────┘     │ Evict L1/L2     │
//! └─────────────────┘                             └─────────────────┘
//! ```
//!
//! # Event Types
//!
//! - **Entity Invalidation**: Invalidate by entity type and ID (e.g., "User:123")
//! - **Pattern Invalidation**: Invalidate by prefix pattern (e.g., "Product:*")
//! - **Tag Invalidation**: Invalidate by cache tag (e.g., all "cart" related)
//!
//! # Usage
//!
//! ```rust,ignore
//! // After a mutation completes, publish invalidation
//! invalidator.publish(InvalidationEvent::entity("User", "123", product)).await;
//!
//! // Pattern-based invalidation
//! invalidator.publish(InvalidationEvent::pattern("Product:*", product)).await;
//!
//! // Tag-based invalidation
//! invalidator.publish(InvalidationEvent::tag("cart", product)).await;
//! ```

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::metrics::{MetricsClient, MetricsExt};

/// Redis channel prefix for cache invalidation events
const REDIS_CHANNEL_PREFIX: &str = "bff:cache:invalidation";

/// Event types for cache invalidation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvalidationEvent {
    /// Invalidate a specific entity by type and ID
    Entity {
        /// Entity type (e.g., "User", "Product", "Booking")
        entity_type: String,
        /// Entity ID
        entity_id: String,
        /// Product scope
        product: String,
        /// Pod that originated this event
        source_pod: String,
        /// Timestamp in milliseconds
        timestamp_ms: u64,
    },

    /// Invalidate by key pattern (prefix match)
    Pattern {
        /// Pattern to match (e.g., "Product:*", "User:123:*")
        pattern: String,
        /// Product scope
        product: String,
        /// Pod that originated this event
        source_pod: String,
        /// Timestamp in milliseconds
        timestamp_ms: u64,
    },

    /// Invalidate by cache tag
    Tag {
        /// Tag name (e.g., "cart", "session", "catalog")
        tag: String,
        /// Product scope
        product: String,
        /// Pod that originated this event
        source_pod: String,
        /// Timestamp in milliseconds
        timestamp_ms: u64,
    },

    /// Full cache flush (use sparingly)
    Flush {
        /// Product scope (None = all products)
        product: Option<String>,
        /// Reason for flush
        reason: String,
        /// Pod that originated this event
        source_pod: String,
        /// Timestamp in milliseconds
        timestamp_ms: u64,
    },
}

impl InvalidationEvent {
    /// Create a new entity invalidation event
    pub fn entity(entity_type: &str, entity_id: &str, product: &str, pod_id: &str) -> Self {
        Self::Entity {
            entity_type: entity_type.to_string(),
            entity_id: entity_id.to_string(),
            product: product.to_string(),
            source_pod: pod_id.to_string(),
            timestamp_ms: current_timestamp_ms(),
        }
    }

    /// Create a new pattern invalidation event
    pub fn pattern(pattern: &str, product: &str, pod_id: &str) -> Self {
        Self::Pattern {
            pattern: pattern.to_string(),
            product: product.to_string(),
            source_pod: pod_id.to_string(),
            timestamp_ms: current_timestamp_ms(),
        }
    }

    /// Create a new tag invalidation event
    pub fn tag(tag: &str, product: &str, pod_id: &str) -> Self {
        Self::Tag {
            tag: tag.to_string(),
            product: product.to_string(),
            source_pod: pod_id.to_string(),
            timestamp_ms: current_timestamp_ms(),
        }
    }

    /// Create a flush event
    pub fn flush(product: Option<&str>, reason: &str, pod_id: &str) -> Self {
        Self::Flush {
            product: product.map(|s| s.to_string()),
            reason: reason.to_string(),
            source_pod: pod_id.to_string(),
            timestamp_ms: current_timestamp_ms(),
        }
    }

    /// Get the product scope for this event
    pub fn product(&self) -> Option<&str> {
        match self {
            Self::Entity { product, .. } => Some(product),
            Self::Pattern { product, .. } => Some(product),
            Self::Tag { product, .. } => Some(product),
            Self::Flush { product, .. } => product.as_deref(),
        }
    }

    /// Get the source pod for this event
    pub fn source_pod(&self) -> &str {
        match self {
            Self::Entity { source_pod, .. } => source_pod,
            Self::Pattern { source_pod, .. } => source_pod,
            Self::Tag { source_pod, .. } => source_pod,
            Self::Flush { source_pod, .. } => source_pod,
        }
    }

    /// Generate cache key(s) to invalidate based on this event
    pub fn cache_keys(&self) -> Vec<String> {
        match self {
            Self::Entity {
                entity_type,
                entity_id,
                ..
            } => {
                vec![format!("{}:{}", entity_type, entity_id)]
            }
            Self::Pattern { pattern, .. } => {
                // Pattern is used for prefix invalidation
                vec![pattern.trim_end_matches('*').to_string()]
            }
            Self::Tag { tag, .. } => {
                vec![format!("tag:{}", tag)]
            }
            Self::Flush { .. } => {
                // Flush doesn't use specific keys
                vec![]
            }
        }
    }

    /// Check if this is a pattern-based invalidation
    pub fn is_pattern(&self) -> bool {
        matches!(self, Self::Pattern { .. })
    }

    /// Check if this is a flush event
    pub fn is_flush(&self) -> bool {
        matches!(self, Self::Flush { .. })
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Configuration for cache invalidation
#[derive(Debug, Clone)]
pub struct InvalidationConfig {
    /// Enable cache invalidation
    pub enabled: bool,

    /// Redis URL for pub/sub
    pub redis_url: String,

    /// Product scope for channel isolation
    pub product: String,

    /// Buffer size for local broadcast channel
    pub channel_buffer_size: usize,

    /// Pod identifier
    pub pod_id: String,

    /// Entity types to automatically invalidate on mutation
    /// Maps mutation name pattern to entity type
    pub mutation_patterns: Vec<MutationPattern>,

    /// Connection timeout in seconds (default: 5)
    pub connection_timeout_secs: u64,

    /// Reconnect delay in seconds after connection failure (default: 5)
    pub reconnect_delay_secs: u64,

    /// Mutation prefixes to detect entity types (e.g., ["create", "update", "delete"])
    pub mutation_prefixes: Vec<String>,
}

/// Pattern for extracting entity info from mutations
#[derive(Debug, Clone)]
pub struct MutationPattern {
    /// Mutation name pattern (supports * wildcard)
    pub pattern: String,

    /// Entity type to extract
    pub entity_type: String,

    /// JSON path to entity ID in response (e.g., "data.createUser.id")
    pub id_path: String,
}

impl Default for InvalidationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            redis_url: "redis://localhost:6379".to_string(),
            product: "myapp".to_string(),
            channel_buffer_size: 1000,
            pod_id: "unknown".to_string(),
            mutation_patterns: vec![
                // Default patterns for common mutations
                MutationPattern {
                    pattern: "create*".to_string(),
                    entity_type: "".to_string(), // Extracted from mutation name
                    id_path: "data.*.id".to_string(),
                },
                MutationPattern {
                    pattern: "update*".to_string(),
                    entity_type: "".to_string(),
                    id_path: "data.*.id".to_string(),
                },
                MutationPattern {
                    pattern: "delete*".to_string(),
                    entity_type: "".to_string(),
                    id_path: "data.*.id".to_string(),
                },
            ],
            connection_timeout_secs: 5,
            reconnect_delay_secs: 5,
            mutation_prefixes: vec![
                "create".to_string(),
                "update".to_string(),
                "delete".to_string(),
                "remove".to_string(),
                "add".to_string(),
                "set".to_string(),
            ],
        }
    }
}

/// Cache invalidator with Redis pub/sub support
///
/// Enables distributed cache invalidation across multiple BFF pods.
/// When a mutation completes, the invalidator publishes an event to Redis,
/// which is received by all pods (including the originating pod).
#[derive(Clone)]
pub struct CacheInvalidator {
    /// Local broadcast channel for in-process subscribers
    tx: broadcast::Sender<InvalidationEvent>,

    /// Redis connection for publishing (None if Redis unavailable)
    redis: Option<ConnectionManager>,

    /// Configuration
    config: InvalidationConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl CacheInvalidator {
    /// Create a new cache invalidator
    ///
    /// Spawns a background task to listen for Redis pub/sub messages
    /// and forward them to local subscribers.
    pub async fn new(config: InvalidationConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        let (tx, _) = broadcast::channel(config.channel_buffer_size);

        if !config.enabled {
            info!("Cache invalidation: disabled");
            return Self {
                tx,
                redis: None,
                config,
                metrics,
            };
        }

        // Connect to Redis
        let redis = match Self::connect_redis(&config.redis_url, config.connection_timeout_secs)
            .await
        {
            Ok(conn) => {
                info!(
                    redis_url = %config.redis_url,
                    product = %config.product,
                    "Cache invalidation: connected to Redis"
                );
                Some(conn)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Cache invalidation: Redis connection failed, falling back to local-only mode"
                );
                None
            }
        };

        let invalidator = Self {
            tx: tx.clone(),
            redis: redis.clone(),
            config: config.clone(),
            metrics: metrics.clone(),
        };

        // Spawn background task to receive Redis pub/sub messages
        if redis.is_some() {
            let channel = format!("{}:{}", REDIS_CHANNEL_PREFIX, config.product);
            let redis_url = config.redis_url.clone();
            let metrics_clone = metrics.clone();
            let pod_id = config.pod_id.clone();
            let reconnect_delay_secs = config.reconnect_delay_secs;

            tokio::spawn(async move {
                Self::redis_subscriber(
                    redis_url,
                    channel,
                    tx,
                    metrics_clone,
                    pod_id,
                    reconnect_delay_secs,
                )
                .await;
            });
        }

        invalidator
    }

    /// Connect to Redis with timeout
    async fn connect_redis(
        redis_url: &str,
        timeout_secs: u64,
    ) -> Result<ConnectionManager, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;

        let connection_future = ConnectionManager::new(client);
        match tokio::time::timeout(Duration::from_secs(timeout_secs), connection_future).await {
            Ok(result) => result,
            Err(_) => Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "Connection timeout",
            ))),
        }
    }

    /// Background task: Subscribe to Redis channel and forward to local broadcast
    async fn redis_subscriber(
        redis_url: String,
        channel: String,
        tx: broadcast::Sender<InvalidationEvent>,
        metrics: Option<Arc<MetricsClient>>,
        pod_id: String,
        reconnect_delay_secs: u64,
    ) {
        info!(channel = %channel, "Starting Redis pub/sub subscriber for cache invalidation");

        loop {
            match Self::subscribe_loop(&redis_url, &channel, &tx, &metrics, &pod_id).await {
                Ok(_) => {
                    warn!(channel = %channel, "Redis subscriber ended unexpectedly, reconnecting...");
                }
                Err(e) => {
                    error!(
                        channel = %channel,
                        error = %e,
                        reconnect_delay_secs = reconnect_delay_secs,
                        "Redis subscriber error, reconnecting..."
                    );
                    tokio::time::sleep(Duration::from_secs(reconnect_delay_secs)).await;
                }
            }
        }
    }

    /// Inner subscribe loop - reconnects on error
    async fn subscribe_loop(
        redis_url: &str,
        channel: &str,
        tx: &broadcast::Sender<InvalidationEvent>,
        metrics: &Option<Arc<MetricsClient>>,
        pod_id: &str,
    ) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(channel).await?;

        info!(channel = %channel, "Subscribed to Redis cache invalidation channel");

        metrics.incr("bff.cache.invalidation.redis.subscribed", &[]);

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = msg.get_payload()?;

            match serde_json::from_str::<InvalidationEvent>(&payload) {
                Ok(event) => {
                    // Skip events from our own pod (we already handled them locally)
                    if event.source_pod() == pod_id {
                        continue;
                    }

                    debug!(
                        event = ?event,
                        source_pod = %event.source_pod(),
                        "Received cache invalidation event from Redis"
                    );

                    metrics.incr("bff.cache.invalidation.redis.event_received", &[]);

                    // Forward to local subscribers
                    let _ = tx.send(event);
                }
                Err(e) => {
                    warn!(error = %e, payload = %payload, "Failed to deserialize invalidation event");
                    metrics.incr("bff.cache.invalidation.redis.deserialize_error", &[]);
                }
            }
        }

        Ok(())
    }

    /// Publish an invalidation event to all subscribers (local and remote pods)
    pub async fn publish(&self, event: InvalidationEvent) {
        debug!(event = ?event, "Publishing cache invalidation event");

        // Always send to local subscribers first
        let _ = self.tx.send(event.clone());

        // Publish to Redis if available
        if let Some(ref redis) = self.redis {
            let channel = format!("{}:{}", REDIS_CHANNEL_PREFIX, self.config.product);

            match serde_json::to_string(&event) {
                Ok(payload) => {
                    let mut redis = redis.clone();

                    match redis::cmd("PUBLISH")
                        .arg(&channel)
                        .arg(&payload)
                        .query_async::<i64>(&mut redis)
                        .await
                    {
                        Ok(subscribers) => {
                            debug!(
                                channel = %channel,
                                subscribers = subscribers,
                                "Published invalidation event to Redis"
                            );

                            self.metrics.incr("bff.cache.invalidation.redis.event_published", &[]);
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to publish invalidation event to Redis");

                            self.metrics.incr("bff.cache.invalidation.redis.publish_error", &[]);
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to serialize invalidation event");
                }
            }
        }
    }

    /// Publish an event synchronously (fire-and-forget via spawn)
    pub fn publish_sync(&self, event: InvalidationEvent) {
        let invalidator = self.clone();
        tokio::spawn(async move {
            invalidator.publish(event).await;
        });
    }

    /// Subscribe to receive invalidation events (local + remote via Redis)
    pub fn subscribe(&self) -> broadcast::Receiver<InvalidationEvent> {
        self.tx.subscribe()
    }

    /// Get the number of local subscribers
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Check if Redis is connected
    pub fn is_redis_connected(&self) -> bool {
        self.redis.is_some()
    }

    /// Get the Redis channel name
    pub fn channel(&self) -> String {
        format!("{}:{}", REDIS_CHANNEL_PREFIX, self.config.product)
    }

    /// Get the pod ID
    pub fn pod_id(&self) -> &str {
        &self.config.pod_id
    }

    /// Check if invalidation is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Extract entity info from a mutation response
    ///
    /// Returns (entity_type, entity_id) if extractable from the mutation name and response.
    pub fn extract_entity_from_mutation(
        &self,
        operation_name: Option<&str>,
        response: &serde_json::Value,
    ) -> Option<(String, String)> {
        let op_name = operation_name?;

        // Check mutation patterns
        for pattern in &self.config.mutation_patterns {
            if matches_pattern(&pattern.pattern, op_name) {
                // Extract entity type from mutation name if not specified
                let entity_type = if pattern.entity_type.is_empty() {
                    extract_entity_type_from_mutation(op_name, &self.config.mutation_prefixes)?
                } else {
                    pattern.entity_type.clone()
                };

                // Extract ID from response using JSON path
                let entity_id = extract_id_from_response(response, &pattern.id_path)?;

                return Some((entity_type, entity_id));
            }
        }

        None
    }
}

/// Check if a mutation name matches a pattern
fn matches_pattern(pattern: &str, name: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.to_lowercase().starts_with(&prefix.to_lowercase())
    } else {
        pattern.eq_ignore_ascii_case(name)
    }
}

/// Extract entity type from mutation name using configurable prefixes
/// e.g., "createUser" -> "User", "updateProduct" -> "Product"
fn extract_entity_type_from_mutation(mutation_name: &str, prefixes: &[String]) -> Option<String> {
    let lower = mutation_name.to_lowercase();
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            let rest = &mutation_name[prefix.len()..];
            if !rest.is_empty() {
                // Capitalize first letter
                let mut chars = rest.chars();
                let first = chars.next()?.to_uppercase().to_string();
                let remainder: String = chars.collect();
                return Some(format!("{}{}", first, remainder));
            }
        }
    }

    None
}

/// Extract ID from response using a simple JSON path
/// Supports paths like "data.createUser.id" or "data.*.id"
fn extract_id_from_response(response: &serde_json::Value, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = response;

    for part in parts {
        if part == "*" {
            // Wildcard: take first object value
            if let Some(obj) = current.as_object() {
                current = obj.values().next()?;
            } else {
                return None;
            }
        } else {
            current = current.get(part)?;
        }
    }

    // Convert to string
    match current {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_invalidation_event_entity() {
        let event = InvalidationEvent::entity("User", "123", "myapp", "pod-1");

        match event {
            InvalidationEvent::Entity {
                entity_type,
                entity_id,
                product,
                source_pod,
                ..
            } => {
                assert_eq!(entity_type, "User");
                assert_eq!(entity_id, "123");
                assert_eq!(product, "myapp");
                assert_eq!(source_pod, "pod-1");
            }
            _ => panic!("Expected Entity variant"),
        }
    }

    #[test]
    fn test_invalidation_event_pattern() {
        let event = InvalidationEvent::pattern("Product:*", "myapp", "pod-1");

        match event {
            InvalidationEvent::Pattern { pattern, .. } => {
                assert_eq!(pattern, "Product:*");
            }
            _ => panic!("Expected Pattern variant"),
        }
    }

    #[test]
    fn test_cache_keys_entity() {
        let event = InvalidationEvent::entity("User", "123", "myapp", "pod-1");
        let keys = event.cache_keys();
        assert_eq!(keys, vec!["User:123"]);
    }

    #[test]
    fn test_cache_keys_pattern() {
        let event = InvalidationEvent::pattern("Product:*", "myapp", "pod-1");
        let keys = event.cache_keys();
        assert_eq!(keys, vec!["Product:"]);
    }

    #[test]
    fn test_invalidation_event_tag() {
        let event = InvalidationEvent::tag("cart", "myapp", "pod-1");

        match event {
            InvalidationEvent::Tag {
                tag,
                product,
                source_pod,
                ..
            } => {
                assert_eq!(tag, "cart");
                assert_eq!(product, "myapp");
                assert_eq!(source_pod, "pod-1");
            }
            _ => panic!("Expected Tag variant"),
        }
    }

    #[test]
    fn test_cache_keys_tag() {
        let event = InvalidationEvent::tag("cart", "myapp", "pod-1");
        let keys = event.cache_keys();
        assert_eq!(keys, vec!["tag:cart"]);
    }

    #[test]
    fn test_cache_keys_flush() {
        let event = InvalidationEvent::flush(Some("myapp"), "deployment", "pod-1");
        let keys = event.cache_keys();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_event_accessors() {
        let entity = InvalidationEvent::entity("User", "123", "myapp", "pod-1");
        assert_eq!(entity.product(), Some("myapp"));
        assert_eq!(entity.source_pod(), "pod-1");
        assert!(!entity.is_pattern());
        assert!(!entity.is_flush());

        let pattern = InvalidationEvent::pattern("Product:*", "myapp", "pod-2");
        assert_eq!(pattern.product(), Some("myapp"));
        assert_eq!(pattern.source_pod(), "pod-2");
        assert!(pattern.is_pattern());
        assert!(!pattern.is_flush());

        let flush = InvalidationEvent::flush(None, "maintenance", "pod-3");
        assert_eq!(flush.product(), None);
        assert_eq!(flush.source_pod(), "pod-3");
        assert!(!flush.is_pattern());
        assert!(flush.is_flush());
    }

    #[test]
    fn test_event_serialization_tag() {
        let event = InvalidationEvent::tag("session", "myapp", "pod-1");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"tag\""));

        let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn test_matches_pattern() {
        assert!(matches_pattern("create*", "createUser"));
        assert!(matches_pattern("create*", "createProduct"));
        assert!(matches_pattern("update*", "updateBooking"));
        assert!(!matches_pattern("create*", "updateUser"));
        assert!(matches_pattern("deleteUser", "deleteUser"));
        assert!(!matches_pattern("deleteUser", "deleteProduct"));
    }

    #[test]
    fn test_extract_entity_type_from_mutation() {
        let prefixes = vec![
            "create".to_string(),
            "update".to_string(),
            "delete".to_string(),
        ];

        assert_eq!(
            extract_entity_type_from_mutation("createUser", &prefixes),
            Some("User".to_string())
        );
        assert_eq!(
            extract_entity_type_from_mutation("updateProduct", &prefixes),
            Some("Product".to_string())
        );
        assert_eq!(
            extract_entity_type_from_mutation("deleteBooking", &prefixes),
            Some("Booking".to_string())
        );
        assert_eq!(
            extract_entity_type_from_mutation("getUser", &prefixes),
            None
        );
    }

    #[test]
    fn test_extract_entity_type_custom_prefixes() {
        let prefixes = vec!["upsert".to_string(), "remove".to_string()];

        assert_eq!(
            extract_entity_type_from_mutation("upsertUser", &prefixes),
            Some("User".to_string())
        );
        assert_eq!(
            extract_entity_type_from_mutation("removeProduct", &prefixes),
            Some("Product".to_string())
        );
        // Default prefixes won't match
        assert_eq!(
            extract_entity_type_from_mutation("createUser", &prefixes),
            None
        );
    }

    #[test]
    fn test_extract_id_from_response() {
        let response = json!({
            "data": {
                "createUser": {
                    "id": "user-123",
                    "name": "Test User"
                }
            }
        });

        assert_eq!(
            extract_id_from_response(&response, "data.createUser.id"),
            Some("user-123".to_string())
        );

        assert_eq!(
            extract_id_from_response(&response, "data.*.id"),
            Some("user-123".to_string())
        );
    }

    #[test]
    fn test_extract_id_numeric() {
        let response = json!({
            "data": {
                "createProduct": {
                    "id": 456
                }
            }
        });

        assert_eq!(
            extract_id_from_response(&response, "data.createProduct.id"),
            Some("456".to_string())
        );
    }

    #[test]
    fn test_event_serialization() {
        let event = InvalidationEvent::entity("User", "123", "myapp", "pod-1");

        let json = serde_json::to_string(&event).unwrap();
        let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(event, parsed);
    }

    #[test]
    fn test_event_serialization_pattern() {
        let event = InvalidationEvent::pattern("Product:*", "myapp", "pod-1");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"pattern\""));

        let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }

    #[test]
    fn test_event_serialization_flush() {
        let event = InvalidationEvent::flush(Some("myapp"), "deployment", "pod-1");

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"flush\""));

        let parsed: InvalidationEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, parsed);
    }
}
