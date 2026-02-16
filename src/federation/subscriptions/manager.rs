#![allow(dead_code)]
//! Subscription Manager - handles WebSocket connections to subgraphs
//!
//! Manages the lifecycle of subscription connections with connection multiplexing:
//! 1. Client sends `connection_init` → Manager prepares context
//! 2. Client sends `subscribe` → Manager routes through connection pool
//! 3. Connection pool manages multiplexed WebSocket connections
//! 4. Subgraph sends `next` → Manager forwards to client
//! 5. Client sends `complete` or disconnects → Manager cleans up
//!
//! # Connection Multiplexing
//!
//! The manager uses a connection pool to multiplex subscriptions:
//! - Multiple subscriptions share a single WebSocket per subgraph
//! - Pool manages connection lifecycle, health, and reconnection
//! - Reduces overhead from repeated TCP/TLS handshakes

use std::collections::HashMap;
use std::sync::Arc;

use crossbeam_utils::CachePadded;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info};

use super::broadcaster::SubscriptionEventBroadcaster;
use super::pool::{ConnectionPoolConfig, MultiplexedConnection, SubgraphConnectionPool};
use super::SubscriptionRouter;
use crate::federation::supergraph::Supergraph;
use crate::federation::types::{ExecutionContext, ServerMessage, SubscribePayload};
use crate::metrics::{MetricsClient, MetricsExt};

/// Manages subscription connections to subgraphs with connection pooling
pub struct SubscriptionManager {
    /// Subscription router for determining target subgraph
    router: SubscriptionRouter,

    /// Parsed supergraph with subgraph URLs
    supergraph: Arc<Supergraph>,

    /// Connection pool for multiplexed WebSocket connections
    pool: Arc<SubgraphConnectionPool>,

    /// Active subscription metadata by client subscription ID
    /// Maps subscription ID → (subgraph_name, connection_id)
    /// PERFORMANCE: Wrapped in CachePadded to prevent false sharing when multiple
    /// threads access subscription metadata concurrently (read-heavy workload)
    active_subscriptions: CachePadded<RwLock<HashMap<String, SubscriptionMetadata>>>,

    /// Optional metrics client for observability
    metrics: Option<Arc<MetricsClient>>,

    /// Optional broadcaster for Redis pub/sub (horizontal scaling)
    /// When present, subscription events are published to Redis for cross-pod distribution
    #[allow(dead_code)]
    broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
}

/// Metadata for an active subscription
struct SubscriptionMetadata {
    /// Subgraph name this subscription is routed to
    subgraph_name: String,

    /// Connection this subscription is using
    connection: Arc<MultiplexedConnection>,
}

impl SubscriptionManager {
    /// Create a new subscription manager with default pool configuration
    pub fn new(supergraph: Arc<Supergraph>, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self::with_pool_config(supergraph, metrics, ConnectionPoolConfig::default(), None)
    }

    /// Create a new subscription manager with custom pool configuration
    pub fn with_pool_config(
        supergraph: Arc<Supergraph>,
        metrics: Option<Arc<MetricsClient>>,
        pool_config: ConnectionPoolConfig,
        broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
    ) -> Self {
        let router = SubscriptionRouter::new(&supergraph);
        let pool = Arc::new(SubgraphConnectionPool::new(
            pool_config,
            metrics.clone(),
            broadcaster.clone(),
        ));

        // Emit initial metrics
        metrics.gauge(
            "bff.federation.subscription_routes",
            supergraph.subscription_routes.len() as f64,
            &[],
        );

        // Log broadcaster status
        if let Some(ref b) = broadcaster {
            if b.is_redis_connected() {
                info!("Subscription manager: Redis pub/sub enabled for horizontal scaling");
            } else {
                info!("Subscription manager: Redis pub/sub configured but not connected");
            }
        }

        Self {
            router,
            supergraph,
            pool,
            active_subscriptions: CachePadded::new(RwLock::new(HashMap::new())),
            metrics,
            broadcaster,
        }
    }

    /// Create a ConnectionPoolConfig from BFF FederationWebSocketConfig
    ///
    /// This is a convenience method to convert BFF configuration to pool config.
    pub fn pool_config_from_bff(
        ws_config: &crate::config::FederationWebSocketConfig,
    ) -> ConnectionPoolConfig {
        ConnectionPoolConfig {
            max_connections_per_subgraph: ws_config.max_connections_per_subgraph,
            max_subscriptions_per_connection: ws_config.max_subscriptions_per_connection,
            idle_timeout_secs: ws_config.idle_timeout_secs,
            ping_interval_secs: ws_config.ping_interval_secs,
            pong_timeout_secs: ws_config.pong_timeout_secs,
            reconnect_base_delay_ms: ws_config.reconnect_delay_ms,
            max_reconnect_attempts: ws_config.max_reconnect_attempts,
        }
    }

    /// Handle a subscription request from a client
    ///
    /// Returns a channel that will receive server messages to forward to client.
    /// Uses connection pooling to multiplex subscriptions over shared connections.
    pub async fn subscribe(
        &self,
        subscription_id: String,
        payload: SubscribePayload,
        context: ExecutionContext,
    ) -> Result<mpsc::Receiver<ServerMessage>, SubscriptionError> {
        // Route the subscription to the correct subgraph
        let subgraph_name = self.router.route(&payload.query).map_err(|e| {
            self.metrics.incr("bff.federation.subscription.routing_error", &[]);
            SubscriptionError::RoutingError(e.to_string())
        })?;

        let subgraph = self
            .supergraph
            .get_subgraph(&subgraph_name)
            .ok_or_else(|| {
                self.metrics.incr(
                    "bff.federation.subscription.subgraph_not_found",
                    &[("subgraph", &subgraph_name)],
                );
                SubscriptionError::SubgraphNotFound(subgraph_name.clone())
            })?;

        info!(
            subscription_id = %subscription_id,
            subgraph = %subgraph_name,
            ws_url = %subgraph.ws_url,
            "Routing subscription to subgraph via connection pool"
        );

        // Get or create a pooled connection for this subgraph
        let connection = self
            .pool
            .get_connection(subgraph, &context)
            .await
            .map_err(|e| {
                self.metrics.incr(
                    "bff.federation.subscription.pool_error",
                    &[("subgraph", &subgraph_name)],
                );
                SubscriptionError::ConnectionError(e.to_string())
            })?;

        // Subscribe through the multiplexed connection
        let receiver = connection
            .subscribe(subscription_id.clone(), payload)
            .await
            .map_err(|e| {
                self.metrics.incr(
                    "bff.federation.subscription.subscribe_error",
                    &[("subgraph", &subgraph_name)],
                );
                SubscriptionError::SubscriptionFailed(e.to_string())
            })?;

        // Store subscription metadata
        let metadata = SubscriptionMetadata {
            subgraph_name: subgraph_name.clone(),
            connection: connection.clone(),
        };

        self.active_subscriptions
            .write()
            .await
            .insert(subscription_id.clone(), metadata);

        // Emit metrics for active subscription
        if let Some(ref m) = self.metrics {
            m.increment(
                "bff.federation.subscription.started",
                &[("subgraph", &subgraph_name)],
            );
            let active_count = self.active_subscriptions.read().await.len();
            m.gauge(
                "bff.federation.subscriptions.active",
                active_count as f64,
                &[],
            );
        }

        info!(
            subscription_id = %subscription_id,
            subgraph = %subgraph_name,
            connection_id = connection.id,
            "Subscription established via pooled connection"
        );

        Ok(receiver)
    }

    /// Unsubscribe from an active subscription
    pub async fn unsubscribe(&self, subscription_id: &str) {
        if let Some(metadata) = self
            .active_subscriptions
            .write()
            .await
            .remove(subscription_id)
        {
            debug!(
                subscription_id = %subscription_id,
                subgraph = %metadata.subgraph_name,
                connection_id = metadata.connection.id,
                "Unsubscribing from pooled connection"
            );

            // Unsubscribe through the multiplexed connection
            metadata.connection.unsubscribe(subscription_id).await;

            // Emit metrics for subscription end
            if let Some(ref m) = self.metrics {
                m.increment(
                    "bff.federation.subscription.completed",
                    &[("subgraph", &metadata.subgraph_name)],
                );
                let active_count = self.active_subscriptions.read().await.len();
                m.gauge(
                    "bff.federation.subscriptions.active",
                    active_count as f64,
                    &[],
                );
            }
        }
    }

    /// Clean up all active subscriptions (e.g., when client disconnects)
    pub async fn cleanup_all(&self) {
        let mut subscriptions = self.active_subscriptions.write().await;

        for (id, metadata) in subscriptions.drain() {
            debug!(
                subscription_id = %id,
                subgraph = %metadata.subgraph_name,
                connection_id = metadata.connection.id,
                "Cleaning up subscription from pooled connection"
            );

            metadata.connection.unsubscribe(&id).await;
        }
    }

    /// Check if a subscription is active
    /// PERFORMANCE: Inlined for hot path - frequently called during message routing
    #[inline]
    pub async fn is_active(&self, subscription_id: &str) -> bool {
        self.active_subscriptions
            .read()
            .await
            .contains_key(subscription_id)
    }

    /// Get count of active subscriptions
    /// PERFORMANCE: Inlined for hot path - used in metrics collection
    #[inline]
    pub async fn active_count(&self) -> usize {
        self.active_subscriptions.read().await.len()
    }

    /// Get pool statistics for observability
    /// PERFORMANCE: Inlined for hot path - used in metrics collection
    #[inline]
    pub fn pool_stats(&self) -> PoolStats {
        PoolStats {
            total_connections: self.pool.total_connections(),
        }
    }

    /// Shutdown the subscription manager and connection pool
    pub async fn shutdown(&self) {
        info!("Shutting down subscription manager");
        self.cleanup_all().await;
        self.pool.shutdown().await;
    }
}

/// Pool statistics for observability
pub struct PoolStats {
    /// Total number of connections across all subgraphs
    pub total_connections: usize,
}

/// Errors that can occur during subscription management
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    #[error("Failed to route subscription: {0}")]
    RoutingError(String),

    #[error("Subgraph not found: {0}")]
    SubgraphNotFound(String),

    #[error("Failed to connect to subgraph: {0}")]
    ConnectionError(String),

    #[error("Subscription failed: {0}")]
    SubscriptionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_connections_per_subgraph, 4);
        assert_eq!(config.max_subscriptions_per_connection, 100);
    }
}
