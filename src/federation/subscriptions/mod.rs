//! Subscription handling for GraphQL real-time data
//!
//! This module implements subscription transport support, including:
//! - **WebSocket**: Full-duplex, optimal for most clients
//! - **SSE (Server-Sent Events)**: Firewall-proof fallback for corporate environments
//!
//! # Architecture
//! ```text
//! Client
//!    │
//!    ├── WebSocket ─────────────────────┐
//!    │   (Upgrade: websocket)           │
//!    │                                  │
//!    └── SSE ─────────────────────────┐ │
//!        (Accept: text/event-stream)  │ │
//!                                     ▼ ▼
//!                    BFF Subscription Router
//!                            ↓
//!                    Connection Pool (shared)
//!                            ↓
//!                    Subgraph WebSocket
//!                            ↓
//!                    Events → Client
//! ```
//!
//! # When to Use SSE
//!
//! SSE is recommended when:
//! - Corporate firewalls block WebSocket upgrade requests
//! - HTTP/2 proxy doesn't support WebSocket
//! - Client needs automatic reconnection (built into EventSource)
//!
//! # Connection Multiplexing
//!
//! The connection pool manages WebSocket connections efficiently:
//! - Multiple subscriptions share a single WebSocket connection per subgraph
//! - Reduces connection overhead (TCP handshakes, TLS negotiation)
//! - Automatic health monitoring with ping/pong
//! - Graceful reconnection on connection failure
//!
//! # Horizontal Scaling (Redis Pub/Sub)
//!
//! For multiple BFF pods, events are distributed via Redis pub/sub:
//! - Subgraph event → Publish to Redis channel
//! - All BFF pods receive event → Forward to local WebSocket clients
//! - This enables scaling to many BFF replicas without sticky sessions
//!
//! # Protocols
//!
//! - **WebSocket**: graphql-ws (graphql-transport-ws) protocol
//! - **SSE**: graphql-sse "distinct connections mode" protocol

mod broadcaster;
mod manager;
#[allow(dead_code)]
mod pool;
#[allow(dead_code)]
mod router;
pub mod sse;

// Re-export types used by manager.rs internally
pub(crate) use router::SubscriptionRouter;

// Public exports
#[allow(unused_imports)]
pub use broadcaster::{
    BroadcasterConfig, SubscriptionEvent, SubscriptionEventBroadcaster, SubscriptionEventType,
};
pub use manager::SubscriptionManager;
pub use sse::{accepts_sse, graphql_sse_handler, SseConfig, SseError};

// Types for future use (when integrating with main application)
#[allow(unused_imports)]
pub use manager::{PoolStats, SubscriptionError};
