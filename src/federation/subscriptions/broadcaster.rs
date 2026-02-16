#![allow(dead_code)]
//! Subscription Event Broadcaster for Horizontal Scaling
//!
//! Uses Redis pub/sub to distribute subscription events across multiple BFF pods.
//! This enables horizontal scaling - events from any subgraph connection are
//! broadcast to all BFF instances, which then forward to their local clients.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
//! │     BFF Pod 1   │     │     BFF Pod 2   │     │     BFF Pod 3   │
//! │                 │     │                 │     │                 │
//! │ Subgraph WS ────┼────►│ Redis Pub/Sub   │◄────┼──── Subgraph WS │
//! │                 │     │                 │     │                 │
//! │ ◄───Local WS    │◄────┤ (broadcasts to  │────►│ Local WS───►    │
//! │                 │     │  all pods)      │     │                 │
//! └─────────────────┘     └─────────────────┘     └─────────────────┘
//! ```
//!
//! # Event Flow
//!
//! 1. Subgraph sends NEXT event to BFF pod (via pooled WebSocket connection)
//! 2. BFF pod publishes event to Redis channel (subscription-specific)
//! 3. All BFF pods subscribed to that channel receive the event
//! 4. Each pod forwards to local WebSocket clients subscribed to that query

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::metrics::{MetricsClient, MetricsExt};

/// Redis channel prefix for subscription events
const REDIS_CHANNEL_PREFIX: &str = "bff:subscriptions";

/// Event published to Redis for cross-pod distribution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionEvent {
    /// Subscription ID (matches client's subscription ID)
    pub subscription_id: String,

    /// Subgraph that generated this event
    pub subgraph: String,

    /// Event type: "next", "error", "complete"
    pub event_type: SubscriptionEventType,

    /// Payload data (GraphQL data or errors)
    pub payload: serde_json::Value,

    /// Timestamp when event was created
    pub timestamp_ms: u64,

    /// Pod ID that received the original event (for debugging)
    pub source_pod: String,
}

/// Type of subscription event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionEventType {
    /// Data event (graphql-ws "next")
    Next,
    /// Error event (graphql-ws "error")
    Error,
    /// Completion event (graphql-ws "complete")
    Complete,
}

impl SubscriptionEvent {
    /// Create a new NEXT event
    pub fn next(
        subscription_id: String,
        subgraph: String,
        data: serde_json::Value,
        pod_id: &str,
    ) -> Self {
        Self {
            subscription_id,
            subgraph,
            event_type: SubscriptionEventType::Next,
            payload: data,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            source_pod: pod_id.to_string(),
        }
    }

    /// Create a new ERROR event
    pub fn error(
        subscription_id: String,
        subgraph: String,
        errors: Vec<serde_json::Value>,
        pod_id: &str,
    ) -> Self {
        Self {
            subscription_id,
            subgraph,
            event_type: SubscriptionEventType::Error,
            payload: serde_json::json!(errors),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            source_pod: pod_id.to_string(),
        }
    }

    /// Create a new COMPLETE event
    pub fn complete(subscription_id: String, subgraph: String, pod_id: &str) -> Self {
        Self {
            subscription_id,
            subgraph,
            event_type: SubscriptionEventType::Complete,
            payload: serde_json::Value::Null,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            source_pod: pod_id.to_string(),
        }
    }
}

/// Configuration for the subscription broadcaster
#[derive(Debug, Clone)]
pub struct BroadcasterConfig {
    /// Redis URL for pub/sub
    pub redis_url: String,

    /// Product scope for channel isolation
    pub product: String,

    /// Buffer size for local broadcast channel
    pub channel_buffer_size: usize,

    /// Enable broadcaster (false = single-pod mode)
    pub enabled: bool,

    /// Pod identifier for event source tracking (loaded from HOSTNAME/POD_NAME at startup)
    pub pod_id: String,
}

impl Default for BroadcasterConfig {
    fn default() -> Self {
        Self {
            redis_url: "redis://localhost:6379".to_string(),
            product: "novaskyn".to_string(),
            channel_buffer_size: 1000,
            enabled: false,
            pod_id: "unknown".to_string(),
        }
    }
}

/// Broadcaster for subscription events with Redis pub/sub support
///
/// Enables event-driven subscriptions that work across multiple BFF pods.
/// Events published by any pod are received by all pods via Redis.
#[derive(Clone)]
pub struct SubscriptionEventBroadcaster {
    /// Local broadcast channel for in-process subscribers
    tx: broadcast::Sender<SubscriptionEvent>,

    /// Redis connection for publishing (None if Redis unavailable)
    redis: Option<ConnectionManager>,

    /// Configuration
    config: BroadcasterConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl SubscriptionEventBroadcaster {
    /// Create a new broadcaster with Redis pub/sub support
    ///
    /// Spawns a background task to listen for Redis pub/sub messages
    /// and forward them to local subscribers.
    ///
    /// # Arguments
    /// * `config` - Broadcaster configuration
    /// * `metrics` - Optional metrics client
    pub async fn new(config: BroadcasterConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        let (tx, _) = broadcast::channel(config.channel_buffer_size);

        if !config.enabled {
            info!("Subscription broadcaster: disabled (single-pod mode)");
            return Self {
                tx,
                redis: None,
                config,
                metrics,
            };
        }

        // Connect to Redis
        let redis = match Self::connect_redis(&config.redis_url).await {
            Ok(conn) => {
                info!(
                    redis_url = %config.redis_url,
                    product = %config.product,
                    "Subscription broadcaster: connected to Redis"
                );
                Some(conn)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Subscription broadcaster: Redis connection failed, falling back to single-pod mode"
                );
                None
            }
        };

        let broadcaster = Self {
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

            tokio::spawn(async move {
                Self::redis_subscriber(redis_url, channel, tx, metrics_clone, pod_id).await;
            });
        }

        broadcaster
    }

    /// Connect to Redis with retry
    async fn connect_redis(redis_url: &str) -> Result<ConnectionManager, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;

        // Try to connect with timeout
        let connection_future = ConnectionManager::new(client);
        match tokio::time::timeout(Duration::from_secs(5), connection_future).await {
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
        tx: broadcast::Sender<SubscriptionEvent>,
        metrics: Option<Arc<MetricsClient>>,
        pod_id: String,
    ) {
        info!(channel = %channel, "Starting Redis pub/sub subscriber for subscriptions");

        loop {
            match Self::subscribe_loop(&redis_url, &channel, &tx, &metrics, &pod_id).await {
                Ok(_) => {
                    warn!(channel = %channel, "Redis subscriber ended unexpectedly, reconnecting...");
                }
                Err(e) => {
                    error!(channel = %channel, error = %e, "Redis subscriber error, reconnecting in 5s...");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Inner subscribe loop - reconnects on error
    async fn subscribe_loop(
        redis_url: &str,
        channel: &str,
        tx: &broadcast::Sender<SubscriptionEvent>,
        metrics: &Option<Arc<MetricsClient>>,
        pod_id: &str,
    ) -> Result<(), redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        let mut pubsub = client.get_async_pubsub().await?;
        pubsub.subscribe(channel).await?;

        info!(channel = %channel, "Subscribed to Redis pub/sub channel");

        metrics.incr("bff.subscription.redis.subscribed", &[]);

        let mut stream = pubsub.on_message();
        while let Some(msg) = stream.next().await {
            let payload: String = msg.get_payload()?;

            match serde_json::from_str::<SubscriptionEvent>(&payload) {
                Ok(event) => {
                    // Skip events from our own pod (we already handled them locally)
                    if event.source_pod == pod_id {
                        continue;
                    }

                    debug!(
                        subscription_id = %event.subscription_id,
                        subgraph = %event.subgraph,
                        event_type = ?event.event_type,
                        source_pod = %event.source_pod,
                        "Received subscription event from Redis"
                    );

                    metrics.incr(
                        "bff.subscription.redis.event_received",
                        &[("subgraph", &event.subgraph)],
                    );

                    // Forward to local subscribers (ignore send errors - no subscribers)
                    let _ = tx.send(event);
                }
                Err(e) => {
                    warn!(error = %e, payload = %payload, "Failed to deserialize Redis message");
                    metrics.incr("bff.subscription.redis.deserialize_error", &[]);
                }
            }
        }

        Ok(())
    }

    /// Publish an event to all subscribers (local and remote pods)
    ///
    /// Serializes the event and publishes to Redis, which broadcasts to all pods.
    pub async fn publish(&self, event: SubscriptionEvent) {
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
                                subscription_id = %event.subscription_id,
                                "Published subscription event to Redis"
                            );

                            self.metrics.incr(
                                "bff.subscription.redis.event_published",
                                &[("subgraph", &event.subgraph)],
                            );
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to publish subscription event to Redis");

                            self.metrics.incr("bff.subscription.redis.publish_error", &[]);
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to serialize subscription event");
                }
            }
        }
    }

    /// Publish an event synchronously (fire-and-forget via spawn)
    ///
    /// Use this in the connection pool where you don't want to await Redis.
    pub fn publish_sync(&self, event: SubscriptionEvent) {
        let broadcaster = self.clone();
        tokio::spawn(async move {
            broadcaster.publish(event).await;
        });
    }

    /// Subscribe to receive events (local + remote via Redis)
    ///
    /// Returns a receiver that gets events from all pods via Redis.
    pub fn subscribe(&self) -> broadcast::Receiver<SubscriptionEvent> {
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

    /// Get the Redis channel name for this broadcaster
    pub fn channel(&self) -> String {
        format!("{}:{}", REDIS_CHANNEL_PREFIX, self.config.product)
    }

    /// Get the pod ID for this broadcaster
    pub fn pod_id(&self) -> &str {
        &self.config.pod_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let event = SubscriptionEvent::next(
            "sub-123".to_string(),
            "job-scheduler".to_string(),
            serde_json::json!({"jobs": []}),
            "test-pod",
        );

        assert_eq!(event.subscription_id, "sub-123");
        assert_eq!(event.subgraph, "job-scheduler");
        assert_eq!(event.event_type, SubscriptionEventType::Next);
        assert_eq!(event.source_pod, "test-pod");
    }

    #[test]
    fn test_channel_format() {
        let channel = format!("{}:{}", REDIS_CHANNEL_PREFIX, "novaskyn");
        assert_eq!(channel, "bff:subscriptions:novaskyn");
    }

    #[test]
    fn test_event_serialization() {
        let event = SubscriptionEvent::next(
            "sub-123".to_string(),
            "job-scheduler".to_string(),
            serde_json::json!({"jobs": []}),
            "test-pod",
        );

        let json = serde_json::to_string(&event).unwrap();
        let parsed: SubscriptionEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.subscription_id, event.subscription_id);
        assert_eq!(parsed.event_type, event.event_type);
    }
}
