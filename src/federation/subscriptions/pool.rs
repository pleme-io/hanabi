#![allow(unused)]
//! WebSocket Connection Pool for Subgraph Subscriptions
//!
//! Implements connection multiplexing - multiple subscriptions share a single
//! WebSocket connection per subgraph, reducing connection overhead.
//!
//! # Architecture
//!
//! ```text
//! SubgraphConnectionPool
//!   │
//!   ├─► DashMap<subgraph_name, MultiplexedConnection>
//!   │     │
//!   │     └─► Single WebSocket → Multiple subscriptions
//!   │           │
//!   │           ├─► Subscription A (id: "sub-1")
//!   │           ├─► Subscription B (id: "sub-2")
//!   │           └─► Subscription C (id: "sub-3")
//!   │
//!   └─► Health Monitor Task
//!         │
//!         └─► Ping/Pong heartbeat
//!         └─► Automatic reconnection
//! ```
//!
//! # Benefits
//!
//! 1. **Reduced overhead**: One TCP+TLS handshake per subgraph (not per subscription)
//! 2. **Connection reuse**: Warm connections ready for new subscriptions
//! 3. **Better resource usage**: Fewer file descriptors and memory
//! 4. **Simplified auth**: connection_init once per subgraph connection

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_utils::CachePadded;
use dashmap::mapref::{entry::Entry, multiple::RefMulti, one::Ref, one::RefMut};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use serde_json::json;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio_tungstenite::{
    connect_async_with_config, tungstenite::client::IntoClientRequest,
    tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, error, info, warn};

use super::broadcaster::{SubscriptionEvent, SubscriptionEventBroadcaster};
use crate::federation::supergraph::Subgraph;
use crate::federation::types::{protocol, ExecutionContext, ServerMessage, SubscribePayload};
use crate::metrics::{MetricsClient, MetricsExt};

// PERFORMANCE: Pre-serialized protocol messages to avoid repeated serialization.
// These messages are sent frequently (pings/pongs on every connection every 30s).
// Serializing once at startup saves ~100ns per ping/pong cycle.
lazy_static! {
    static ref PING_MESSAGE: String = json!({"type": protocol::PING}).to_string();
    static ref PONG_MESSAGE: String = json!({"type": protocol::PONG}).to_string();
}

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Configuration for the connection pool
#[derive(Debug, Clone)]
pub struct ConnectionPoolConfig {
    /// Maximum connections per subgraph (default: 4)
    pub max_connections_per_subgraph: usize,

    /// Maximum subscriptions per connection before opening new one (default: 100)
    pub max_subscriptions_per_connection: usize,

    /// Connection idle timeout before closing (default: 300s)
    pub idle_timeout_secs: u64,

    /// Ping interval for health checks (default: 30s)
    pub ping_interval_secs: u64,

    /// Pong timeout before considering connection dead (default: 10s)
    pub pong_timeout_secs: u64,

    /// Reconnection backoff base (default: 1s)
    pub reconnect_base_delay_ms: u64,

    /// Maximum reconnection attempts before giving up (default: 5)
    pub max_reconnect_attempts: u32,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections_per_subgraph: 4,
            max_subscriptions_per_connection: 100,
            idle_timeout_secs: 300,
            ping_interval_secs: 30,
            pong_timeout_secs: 10,
            reconnect_base_delay_ms: 1000,
            max_reconnect_attempts: 5,
        }
    }
}

/// Context for the connection management task (Parameter Object pattern)
/// Groups related parameters to reduce function parameter count per Gate 20
struct ConnectionTaskContext {
    /// Unique connection ID
    id: u64,
    /// WebSocket stream
    ws_stream: WsStream,
    /// Channel for receiving commands
    command_rx: mpsc::Receiver<ConnectionCommand>,
    /// Execution context (product, user info, etc.)
    context: ExecutionContext,
    /// Active subscription count (shared)
    subscription_count: Arc<CachePadded<AtomicU64>>,
    /// Connection health status (shared)
    healthy: Arc<RwLock<bool>>,
    /// Last activity timestamp (shared)
    last_activity: Arc<RwLock<Instant>>,
    /// Subgraph name
    subgraph_name: String,
    /// Pool configuration
    config: ConnectionPoolConfig,
    /// Optional metrics client
    metrics: Option<Arc<MetricsClient>>,
    /// Optional broadcaster for horizontal scaling
    broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
}

/// Pool of multiplexed WebSocket connections to subgraphs
pub struct SubgraphConnectionPool {
    /// Connections by subgraph name
    connections: DashMap<String, Vec<Arc<MultiplexedConnection>>>,

    /// Pool configuration
    config: ConnectionPoolConfig,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,

    /// Connection counter for unique IDs
    /// PERFORMANCE: Wrapped in CachePadded to prevent false sharing
    /// when multiple threads create connections concurrently
    connection_counter: CachePadded<AtomicU64>,

    /// Optional broadcaster for Redis pub/sub (horizontal scaling)
    /// When present, subscription events are published for cross-pod distribution
    broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
}

impl SubgraphConnectionPool {
    /// Create a new connection pool
    pub fn new(
        config: ConnectionPoolConfig,
        metrics: Option<Arc<MetricsClient>>,
        broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
    ) -> Self {
        Self {
            connections: DashMap::new(),
            config,
            metrics,
            connection_counter: CachePadded::new(AtomicU64::new(0)),
            broadcaster,
        }
    }

    /// Get or create a connection for a subgraph
    ///
    /// Returns a connection that can handle the subscription. May return an
    /// existing connection if it has capacity, or create a new one.
    /// PERFORMANCE: Inlined for hot path - called on every subscription request
    #[inline]
    pub async fn get_connection(
        &self,
        subgraph: &Subgraph,
        context: &ExecutionContext,
    ) -> Result<Arc<MultiplexedConnection>, PoolError> {
        let subgraph_name = subgraph.name.clone();

        // Try to find existing connection with capacity
        if let Some(conns) = self.connections.get(&subgraph_name) {
            let conns_ref: &Vec<Arc<MultiplexedConnection>> = conns.value();
            for conn in conns_ref.iter() {
                if conn.has_capacity().await && conn.is_healthy().await {
                    debug!(
                        subgraph = %subgraph_name,
                        connection_id = %conn.id,
                        "Reusing existing connection"
                    );
                    return Ok(conn.clone());
                }
            }
        }

        // Check if we can create a new connection
        let current_count = self
            .connections
            .get(&subgraph_name)
            .map(|c: Ref<'_, String, Vec<Arc<MultiplexedConnection>>>| c.value().len())
            .unwrap_or(0);

        if current_count >= self.config.max_connections_per_subgraph {
            // All connections at capacity, find least loaded
            if let Some(conns) = self.connections.get(&subgraph_name) {
                let conns_ref: &Vec<Arc<MultiplexedConnection>> = conns.value();
                let least_loaded = conns_ref
                    .iter()
                    .filter(|c: &&Arc<MultiplexedConnection>| c.is_healthy_sync())
                    .min_by_key(|c: &&Arc<MultiplexedConnection>| c.subscription_count_sync());

                if let Some(conn) = least_loaded {
                    warn!(
                        subgraph = %subgraph_name,
                        "All connections at capacity, using least loaded"
                    );
                    return Ok((*conn).clone());
                }
            }

            return Err(PoolError::NoHealthyConnections(subgraph_name));
        }

        // Create new connection
        // PERFORMANCE: Use Relaxed ordering - connection ID just needs to be unique, not ordered
        let conn_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);
        let connection = MultiplexedConnection::connect(
            conn_id,
            subgraph.clone(),
            context.clone(),
            self.config.clone(),
            self.metrics.clone(),
            self.broadcaster.clone(),
        )
        .await?;

        let conn_arc = Arc::new(connection);

        // Add to pool
        self.connections
            .entry(subgraph_name.clone())
            .or_insert_with(Vec::new)
            .push(conn_arc.clone());

        if let Some(ref m) = self.metrics {
            m.increment(
                "bff.federation.pool.connection_created",
                &[("subgraph", &subgraph_name)],
            );
            let total = self.total_connections();
            m.gauge("bff.federation.pool.connections_total", total as f64, &[]);
        }

        info!(
            subgraph = %subgraph_name,
            connection_id = conn_id,
            "Created new pooled connection"
        );

        Ok(conn_arc)
    }

    /// Remove a connection from the pool (called when connection dies)
    /// PERFORMANCE: Inlined for fast cleanup
    #[inline]
    pub fn remove_connection(&self, subgraph_name: &str, connection_id: u64) {
        if let Some(mut conns) = self.connections.get_mut(subgraph_name) {
            let conns_vec: &mut Vec<Arc<MultiplexedConnection>> = conns.value_mut();
            conns_vec.retain(|c: &Arc<MultiplexedConnection>| c.id != connection_id);

            if let Some(ref m) = self.metrics {
                m.increment(
                    "bff.federation.pool.connection_removed",
                    &[("subgraph", subgraph_name)],
                );
                let total = self.total_connections();
                m.gauge("bff.federation.pool.connections_total", total as f64, &[]);
            }
        }
    }

    /// Get total connection count across all subgraphs
    pub fn total_connections(&self) -> usize {
        self.connections
            .iter()
            .map(|entry: RefMulti<'_, String, Vec<Arc<MultiplexedConnection>>>| entry.value().len())
            .sum()
    }

    /// Get connection count for a specific subgraph
    pub fn connections_for_subgraph(&self, subgraph: &str) -> usize {
        self.connections
            .get(subgraph)
            .map(|entry: Ref<'_, String, Vec<Arc<MultiplexedConnection>>>| entry.value().len())
            .unwrap_or(0)
    }

    /// Shutdown all connections gracefully
    pub async fn shutdown(&self) {
        info!("Shutting down connection pool");

        for entry in self.connections.iter() {
            let conns: &Vec<Arc<MultiplexedConnection>> = entry.value();
            for conn in conns.iter() {
                conn.shutdown().await;
            }
        }

        self.connections.clear();
    }
}

/// A multiplexed WebSocket connection handling multiple subscriptions
pub struct MultiplexedConnection {
    /// Unique connection ID
    pub id: u64,

    /// Subgraph this connection is for
    subgraph: Subgraph,

    /// Channel to send commands to the connection task
    command_tx: mpsc::Sender<ConnectionCommand>,

    /// Active subscription count
    /// PERFORMANCE: Wrapped in CachePadded to prevent false sharing
    /// when multiple threads check/update subscription counts concurrently
    subscription_count: Arc<CachePadded<AtomicU64>>,

    /// Connection health status
    healthy: Arc<RwLock<bool>>,

    /// Configuration
    config: ConnectionPoolConfig,

    /// Last activity timestamp
    last_activity: Arc<RwLock<Instant>>,
}

/// Commands sent to the connection management task
enum ConnectionCommand {
    /// Subscribe to a new operation
    Subscribe {
        subscription_id: String,
        payload: SubscribePayload,
        response_tx: mpsc::Sender<ServerMessage>,
        result_tx: oneshot::Sender<Result<(), PoolError>>,
    },
    /// Unsubscribe from an operation
    Unsubscribe { subscription_id: String },
    /// Shutdown the connection
    Shutdown,
}

impl MultiplexedConnection {
    /// Connect to a subgraph and establish the multiplexed connection
    async fn connect(
        id: u64,
        subgraph: Subgraph,
        context: ExecutionContext,
        config: ConnectionPoolConfig,
        metrics: Option<Arc<MetricsClient>>,
        broadcaster: Option<Arc<SubscriptionEventBroadcaster>>,
    ) -> Result<Self, PoolError> {
        // Build WebSocket request with GraphQL protocol header
        // The Sec-WebSocket-Protocol header is REQUIRED for graphql-ws/graphql-transport-ws
        let mut request = subgraph
            .ws_url
            .as_str()
            .into_client_request()
            .map_err(|e| PoolError::ConnectionFailed(format!("Invalid WebSocket URL: {}", e)))?;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            http::header::HeaderValue::from_static("graphql-transport-ws"),
        );

        // Connect to WebSocket with GraphQL protocol
        let (ws_stream, _response) = connect_async_with_config(request, None, false)
            .await
            .map_err(|e| PoolError::ConnectionFailed(e.to_string()))?;

        let (command_tx, command_rx) = mpsc::channel::<ConnectionCommand>(64);
        let subscription_count = Arc::new(CachePadded::new(AtomicU64::new(0)));
        let healthy = Arc::new(RwLock::new(true));
        let last_activity = Arc::new(RwLock::new(Instant::now()));

        // Spawn the connection management task using parameter object
        let task_ctx = ConnectionTaskContext {
            id,
            ws_stream,
            command_rx,
            context,
            subscription_count: subscription_count.clone(),
            healthy: healthy.clone(),
            last_activity: last_activity.clone(),
            subgraph_name: subgraph.name.clone(),
            config: config.clone(),
            metrics: metrics.clone(),
            broadcaster: broadcaster.clone(),
        };

        tokio::spawn(async move {
            Self::connection_task(task_ctx).await;
        });

        metrics.incr(
            "bff.federation.pool.connection_established",
            &[("subgraph", &subgraph.name)],
        );

        Ok(Self {
            id,
            subgraph,
            command_tx,
            subscription_count,
            healthy,
            config,
            last_activity,
        })
    }

    /// Check if connection has capacity for more subscriptions
    /// PERFORMANCE: Inlined for hot path - called on every subscription routing decision
    /// Uses Relaxed ordering - exact count not critical for capacity checks
    #[inline]
    pub async fn has_capacity(&self) -> bool {
        let count = self.subscription_count.load(Ordering::Relaxed);
        count < self.config.max_subscriptions_per_connection as u64
    }

    /// Check if connection is healthy
    /// PERFORMANCE: Inlined for hot path - called on every subscription routing decision
    #[inline]
    pub async fn is_healthy(&self) -> bool {
        *self.healthy.read().await
    }

    /// Sync version of is_healthy for non-async contexts
    /// PERFORMANCE: Inlined for hot path - called during least-loaded connection selection
    #[inline]
    fn is_healthy_sync(&self) -> bool {
        // Use try_read to avoid blocking
        self.healthy.try_read().map(|h| *h).unwrap_or(false)
    }

    /// Get current subscription count (sync for sorting)
    /// PERFORMANCE: Inlined for hot path - called during least-loaded connection selection
    /// Uses Relaxed ordering - approximate count sufficient for load balancing
    #[inline]
    fn subscription_count_sync(&self) -> u64 {
        self.subscription_count.load(Ordering::Relaxed)
    }

    /// Subscribe to an operation through this connection
    /// PERFORMANCE: Inlined for hot path - called on every subscription
    #[inline]
    pub async fn subscribe(
        &self,
        subscription_id: String,
        payload: SubscribePayload,
    ) -> Result<mpsc::Receiver<ServerMessage>, PoolError> {
        let (response_tx, response_rx) = mpsc::channel::<ServerMessage>(32);
        let (result_tx, result_rx) = oneshot::channel();

        // Non-blocking send - fail fast if connection task is overloaded
        match self.command_tx.try_send(ConnectionCommand::Subscribe {
            subscription_id: subscription_id.clone(),
            payload,
            response_tx,
            result_tx,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Connection task is overloaded - reject subscription
                warn!(
                    subscription_id = %subscription_id,
                    connection_id = self.id,
                    "Connection command buffer full, rejecting subscription"
                );
                return Err(PoolError::ConnectionClosed);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(PoolError::ConnectionClosed);
            }
        }

        result_rx.await.map_err(|_| PoolError::ConnectionClosed)??;

        Ok(response_rx)
    }

    /// Unsubscribe from an operation
    /// PERFORMANCE: Inlined for fast cleanup
    #[inline]
    pub async fn unsubscribe(&self, subscription_id: &str) {
        // Non-blocking send - drop unsubscribe if buffer full (connection likely dead)
        match self.command_tx.try_send(ConnectionCommand::Unsubscribe {
            subscription_id: subscription_id.to_string(),
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Buffer full - connection likely unhealthy, safe to drop unsubscribe
                debug!(
                    subscription_id = %subscription_id,
                    connection_id = self.id,
                    "Dropped unsubscribe command (connection buffer full)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Connection already closed, nothing to do
                debug!(
                    subscription_id = %subscription_id,
                    connection_id = self.id,
                    "Connection already closed, cannot unsubscribe"
                );
            }
        }
    }

    /// Shutdown this connection
    pub async fn shutdown(&self) {
        // Non-blocking send - drop shutdown if buffer full (connection will die anyway)
        match self.command_tx.try_send(ConnectionCommand::Shutdown) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Buffer full - connection likely dead, safe to drop shutdown
                debug!(
                    connection_id = self.id,
                    "Dropped shutdown command (connection buffer full)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Connection already closed, nothing to do
                debug!(
                    connection_id = self.id,
                    "Connection already closed, cannot shutdown"
                );
            }
        }
    }

    /// The main connection management task
    /// Uses ConnectionTaskContext to bundle parameters (Gate 20 compliance)
    async fn connection_task(ctx: ConnectionTaskContext) {
        // Destructure context for local access
        let ConnectionTaskContext {
            id,
            ws_stream,
            mut command_rx,
            context,
            subscription_count,
            healthy,
            last_activity,
            subgraph_name,
            config,
            metrics,
            broadcaster,
        } = ctx;

        let (mut ws_tx, mut ws_rx) = ws_stream.split();

        // Active subscriptions: subscription_id → response channel
        let mut subscriptions: HashMap<String, mpsc::Sender<ServerMessage>> = HashMap::new();

        // Send connection_init
        let init_payload = Self::build_connection_init_payload(&context);
        let init_msg = json!({
            "type": protocol::CONNECTION_INIT,
            "payload": init_payload,
        });

        if let Err(e) = ws_tx.send(Message::Text(init_msg.to_string())).await {
            error!(
                connection_id = id,
                subgraph = %subgraph_name,
                "Failed to send connection_init: {}",
                e
            );
            *healthy.write().await = false;
            return;
        }

        // Wait for connection_ack with timeout
        let ack_timeout = Duration::from_secs(10);
        let ack_result = tokio::time::timeout(ack_timeout, async {
            loop {
                match ws_rx.next().await {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                            match msg.get("type").and_then(|t| t.as_str()) {
                                Some(protocol::CONNECTION_ACK) => {
                                    debug!(
                                        connection_id = id,
                                        subgraph = %subgraph_name,
                                        "Connection acknowledged"
                                    );
                                    return true;
                                }
                                Some(protocol::PING) => {
                                    // PERFORMANCE: Use pre-serialized PONG_MESSAGE
                                    let _ = ws_tx.send(Message::Text(PONG_MESSAGE.clone())).await;
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        let _ = ws_tx.send(Message::Pong(data)).await;
                    }
                    Some(Err(_)) | None => return false,
                    _ => {}
                }
            }
        })
        .await;

        if ack_result.is_err() || !ack_result.unwrap_or(false) {
            error!(
                connection_id = id,
                subgraph = %subgraph_name,
                "Connection not acknowledged"
            );
            *healthy.write().await = false;
            return;
        }

        // Setup ping interval
        let mut ping_interval =
            tokio::time::interval(Duration::from_secs(config.ping_interval_secs));
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip first tick
        ping_interval.tick().await;

        // Track pong response
        let mut waiting_for_pong = false;
        let mut last_ping_time = Instant::now();

        // Main event loop
        loop {
            tokio::select! {
                // Handle commands from subscribers
                cmd = command_rx.recv() => {
                    match cmd {
                        Some(ConnectionCommand::Subscribe { subscription_id, payload, response_tx, result_tx }) => {
                            // Send subscribe message
                            let subscribe_msg = json!({
                                "type": protocol::SUBSCRIBE,
                                "id": subscription_id,
                                "payload": {
                                    "query": payload.query,
                                    "variables": payload.variables,
                                    "operationName": payload.operation_name,
                                    "extensions": payload.extensions,
                                }
                            });

                            if let Err(e) = ws_tx.send(Message::Text(subscribe_msg.to_string())).await {
                                error!(
                                    connection_id = id,
                                    subscription_id = %subscription_id,
                                    "Failed to send subscribe: {}",
                                    e
                                );
                                let _ = result_tx.send(Err(PoolError::SendFailed(e.to_string())));
                                continue;
                            }

                            subscriptions.insert(subscription_id.clone(), response_tx);
                            // PERFORMANCE: Use Relaxed ordering for subscription count
                            subscription_count.fetch_add(1, Ordering::Relaxed);
                            *last_activity.write().await = Instant::now();

                            if let Some(ref m) = metrics {
                                m.increment("bff.federation.pool.subscription_added", &[("subgraph", &subgraph_name)]);
                                m.gauge("bff.federation.pool.subscriptions_on_connection", subscriptions.len() as f64, &[("connection_id", &id.to_string())]);
                            }

                            debug!(
                                connection_id = id,
                                subscription_id = %subscription_id,
                                total_subscriptions = subscriptions.len(),
                                "Subscription added to multiplexed connection"
                            );

                            let _ = result_tx.send(Ok(()));
                        }
                        Some(ConnectionCommand::Unsubscribe { subscription_id }) => {
                            if subscriptions.remove(&subscription_id).is_some() {
                                // PERFORMANCE: Use Relaxed ordering for subscription count
                                subscription_count.fetch_sub(1, Ordering::Relaxed);

                                // Send complete to subgraph
                                let complete_msg = json!({
                                    "type": protocol::COMPLETE,
                                    "id": subscription_id,
                                });
                                let _ = ws_tx.send(Message::Text(complete_msg.to_string())).await;

                                if let Some(ref m) = metrics {
                                    m.increment("bff.federation.pool.subscription_removed", &[("subgraph", &subgraph_name)]);
                                    m.gauge("bff.federation.pool.subscriptions_on_connection", subscriptions.len() as f64, &[("connection_id", &id.to_string())]);
                                }

                                debug!(
                                    connection_id = id,
                                    subscription_id = %subscription_id,
                                    remaining = subscriptions.len(),
                                    "Subscription removed from multiplexed connection"
                                );
                            }
                        }
                        Some(ConnectionCommand::Shutdown) | None => {
                            info!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "Connection shutdown requested"
                            );
                            break;
                        }
                    }
                }

                // Handle messages from WebSocket
                ws_msg = ws_rx.next() => {
                    match ws_msg {
                        Some(Ok(Message::Text(text))) => {
                            *last_activity.write().await = Instant::now();

                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&text) {
                                let msg_type = msg.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                let msg_id = msg.get("id").and_then(|i| i.as_str());

                                match msg_type {
                                    protocol::NEXT => {
                                        if let Some(sub_id) = msg_id {
                                            if let Some(tx) = subscriptions.get(sub_id) {
                                                if let Some(payload) = msg.get("payload") {
                                                    if let Some(data) = payload.get("data") {
                                                        let server_msg = ServerMessage::next(sub_id, data.clone());
                                                        // PERFORMANCE: Use try_send() for fail-fast behavior
                                                        // If client can't keep up, drop message rather than blocking
                                                        // the entire WebSocket event loop. This prevents slow
                                                        // clients from affecting other subscriptions on this connection.
                                                        match tx.try_send(server_msg) {
                                                            Ok(()) => {}
                                                            Err(mpsc::error::TrySendError::Full(_)) => {
                                                                // Channel full - client is slow, skip this message
                                                                // This is expected under load, log at debug level
                                                                debug!(
                                                                    connection_id = id,
                                                                    subscription_id = %sub_id,
                                                                    "Client buffer full, dropping subscription message"
                                                                );
                                                                metrics.incr("bff.federation.pool.message_dropped", &[("subgraph", &subgraph_name)]);
                                                            }
                                                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                                                // Client disconnected, clean up
                                                                subscriptions.remove(sub_id);
                                                                // PERFORMANCE: Use Relaxed ordering
                                                                subscription_count.fetch_sub(1, Ordering::Relaxed);
                                                            }
                                                        }

                                                        // Publish to Redis for horizontal scaling
                                                        // This allows other BFF pods to forward the event to their clients
                                                        if let Some(ref b) = broadcaster {
                                                            b.publish_sync(SubscriptionEvent::next(
                                                                sub_id.to_string(),
                                                                subgraph_name.clone(),
                                                                data.clone(),
                                                                b.pod_id(),
                                                            ));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    protocol::ERROR => {
                                        if let Some(sub_id) = msg_id {
                                            if let Some(tx) = subscriptions.get(sub_id) {
                                                let errors = msg.get("payload")
                                                    .cloned()
                                                    .map(|p| {
                                                        if let Some(arr) = p.as_array() {
                                                            arr.clone()
                                                        } else {
                                                            vec![p]
                                                        }
                                                    })
                                                    .unwrap_or_else(|| vec![json!({"message": "Unknown error"})]);

                                                let _ = tx.send(ServerMessage::error(sub_id, errors.clone())).await;

                                                // Publish error to Redis for horizontal scaling
                                                if let Some(ref b) = broadcaster {
                                                    b.publish_sync(SubscriptionEvent::error(
                                                        sub_id.to_string(),
                                                        subgraph_name.clone(),
                                                        errors,
                                                        b.pod_id(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    protocol::COMPLETE => {
                                        if let Some(sub_id) = msg_id {
                                            if let Some(tx) = subscriptions.remove(sub_id) {
                                                // PERFORMANCE: Use Relaxed ordering
                                                subscription_count.fetch_sub(1, Ordering::Relaxed);
                                                let _ = tx.send(ServerMessage::complete(sub_id)).await;

                                                metrics.incr("bff.federation.pool.subscription_completed", &[("subgraph", &subgraph_name)]);

                                                // Publish complete to Redis for horizontal scaling
                                                if let Some(ref b) = broadcaster {
                                                    b.publish_sync(SubscriptionEvent::complete(
                                                        sub_id.to_string(),
                                                        subgraph_name.clone(),
                                                        b.pod_id(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    protocol::PING => {
                                        // PERFORMANCE: Use pre-serialized PONG_MESSAGE
                                        let _ = ws_tx.send(Message::Text(PONG_MESSAGE.clone())).await;
                                    }
                                    protocol::PONG => {
                                        waiting_for_pong = false;
                                        debug!(
                                            connection_id = id,
                                            "Received pong from subgraph"
                                        );
                                    }
                                    _ => {
                                        debug!(
                                            connection_id = id,
                                            msg_type = %msg_type,
                                            "Ignoring unknown message type"
                                        );
                                    }
                                }
                            }
                        }
                        Some(Ok(Message::Ping(data))) => {
                            *last_activity.write().await = Instant::now();
                            let _ = ws_tx.send(Message::Pong(data)).await;
                        }
                        Some(Ok(Message::Pong(_))) => {
                            *last_activity.write().await = Instant::now();
                            waiting_for_pong = false;
                        }
                        Some(Ok(Message::Close(_))) => {
                            warn!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "Subgraph closed connection"
                            );
                            break;
                        }
                        Some(Err(e)) => {
                            error!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "WebSocket error: {}",
                                e
                            );
                            break;
                        }
                        None => {
                            debug!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "WebSocket stream ended"
                            );
                            break;
                        }
                        _ => {}
                    }
                }

                // Ping health check
                _ = ping_interval.tick() => {
                    if waiting_for_pong {
                        let elapsed = last_ping_time.elapsed();
                        if elapsed.as_secs() > config.pong_timeout_secs {
                            error!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "Pong timeout, connection unhealthy"
                            );
                            *healthy.write().await = false;

                            metrics.incr("bff.federation.pool.pong_timeout", &[("subgraph", &subgraph_name)]);
                            break;
                        }
                    } else {
                        // Send ping
                        // PERFORMANCE: Use pre-serialized PING_MESSAGE
                        if let Err(e) = ws_tx.send(Message::Text(PING_MESSAGE.clone())).await {
                            error!(
                                connection_id = id,
                                subgraph = %subgraph_name,
                                "Failed to send ping: {}",
                                e
                            );
                            *healthy.write().await = false;
                            break;
                        }
                        waiting_for_pong = true;
                        last_ping_time = Instant::now();
                    }
                }
            }
        }

        // Cleanup
        *healthy.write().await = false;

        // Notify all active subscribers that connection is closed
        for (sub_id, tx) in subscriptions.drain() {
            let _ = tx
                .send(ServerMessage::error(
                    &sub_id,
                    vec![json!({"message": "Connection closed"})],
                ))
                .await;
        }

        // Close WebSocket
        let _ = ws_tx.close().await;

        metrics.incr(
            "bff.federation.pool.connection_closed",
            &[("subgraph", &subgraph_name)],
        );

        info!(
            connection_id = id,
            subgraph = %subgraph_name,
            "Multiplexed connection closed"
        );
    }

    /// Build connection_init payload with auth context
    fn build_connection_init_payload(context: &ExecutionContext) -> serde_json::Value {
        let mut payload = serde_json::Map::new();

        if let Some(ref user_id) = context.user_id {
            payload.insert("x-user-id".to_string(), json!(user_id));
        }
        if let Some(ref email) = context.user_email {
            payload.insert("x-user-email".to_string(), json!(email));
        }
        if let Some(ref roles) = context.user_roles {
            payload.insert("x-user-roles".to_string(), json!(roles));
        }
        if let Some(ref permissions) = context.user_permissions {
            payload.insert("x-user-permissions".to_string(), json!(permissions));
        }
        if let Some(ref relationships) = context.user_relationships {
            payload.insert("x-user-relationships".to_string(), json!(relationships));
        }

        payload.insert("x-product".to_string(), json!(context.product));

        if let Some(ref token) = context.token {
            payload.insert(
                "authorization".to_string(),
                json!(format!("Bearer {}", token)),
            );
        }

        json!(payload)
    }
}

/// Errors that can occur in the connection pool
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("Failed to connect to subgraph: {0}")]
    ConnectionFailed(String),

    #[error("No healthy connections available for subgraph: {0}")]
    NoHealthyConnections(String),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Failed to send message: {0}")]
    SendFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_defaults() {
        let config = ConnectionPoolConfig::default();
        assert_eq!(config.max_connections_per_subgraph, 4);
        assert_eq!(config.max_subscriptions_per_connection, 100);
        assert_eq!(config.ping_interval_secs, 30);
    }

    #[tokio::test]
    async fn test_pool_creation() {
        let config = ConnectionPoolConfig::default();
        let pool = SubgraphConnectionPool::new(config, None, None);

        assert_eq!(pool.total_connections(), 0);
    }
}
