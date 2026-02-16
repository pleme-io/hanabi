//! BFF Federation Module
//!
//! This module implements GraphQL federation capabilities directly in the BFF,
//! eliminating the need for Hive Router. The BFF acts as a first-class GraphQL
//! federation router with native WebSocket subscription support.
//!
//! # Architecture
//!
//! The BFF handles all GraphQL operations directly:
//! - **Queries/Mutations**: Query planning → Plan execution → Response merging
//! - **Subscriptions**: Direct WebSocket connections to subgraphs with connection pooling
//!
//! # Execution Pipeline (All Steps Active)
//!
//! ```text
//! Request
//!    │
//!    ▼
//! ┌─────────────────┐
//! │  Rate Limiter   │ → Per-user, per-operation, per-subgraph limits
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Plugin Pre-Exec│ → TracingPlugin, MetricsPlugin hooks
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  APQ Lookup     │ → Resolve persisted query hash
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Security       │ → Depth/complexity validation
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Deduplication  │ → Coalesce concurrent identical queries
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Cache Check    │ → L1 (moka) → L2 (Redis) lookup
//! └────────┬────────┘
//!          │ MISS
//!          ▼
//! ┌─────────────────┐
//! │  Query Planner  │ → Create execution plan (cached)
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Plan Executor  │ → Execute against subgraphs (parallel)
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │  Cache Store    │ → Store in L1 + L2
//! └────────┬────────┘
//!          ▼
//! ┌─────────────────┐
//! │ Plugin Post-Exec│ → Response extensions, metrics
//! └────────┬────────┘
//!          ▼
//!       Response
//! ```
//!
//! # Configuration
//!
//! All features are enabled by default when `bff.mode: federation`:
//!
//! ```yaml
//! bff:
//!   mode: federation                    # Enable full federation mode
//!   federation:
//!     enabled: true
//!     supergraph_url: file:///etc/supergraph.graphql
//!     websocket:
//!       enabled: true
//!       path: /graphql/ws
//!     response_cache:
//!       enabled: true                   # L1 moka + L2 Redis
//!     apq:
//!       enabled: true                   # Automatic Persisted Queries
//!     rate_limit:
//!       enabled: true                   # Multi-level rate limiting
//!     security:
//!       enabled: true                   # Depth limiting, complexity analysis
//!     plugins:
//!       enabled: true                   # TracingPlugin, MetricsPlugin
//!     batching:
//!       enabled: true                   # Entity batching (N+1 prevention)
//! ```
//!
//! # Module Organization
//!
//! ## Core Modules
//! - `supergraph` - Supergraph SDL parsing and subgraph discovery
//! - `executor` - Main federation executor orchestrating all features
//! - `query_planner` - Query planning with field ownership tracking
//! - `plan_executor` - Plan execution with parallel subgraph calls
//! - `watcher` - Hot-reloadable supergraph configuration
//! - `types` - Shared types and graphql-ws protocol
//!
//! ## Performance Modules
//! - `cache` - Response caching with moka (L1 in-memory)
//! - `redis_cache` - Two-tier cache (L1 moka + L2 Redis)
//! - `deduplication` - Request coalescing with broadcast channels
//! - `apq` - Automatic Persisted Queries (SHA256 hash → query)
//! - `batch` - Entity batching with DataLoader pattern
//!
//! ## Security Modules
//! - `rate_limit` - Token bucket rate limiting via governor
//! - `security` - Depth limiting, complexity analysis, introspection control
//!
//! ## Extensibility Modules
//! - `plugins` - Plugin registry with lifecycle hooks
//! - `tracing_ext` - W3C Trace Context propagation
//!
//! ## Subscription Modules
//! - `subscriptions/router` - Subscription field → subgraph routing
//! - `subscriptions/manager` - Subscription lifecycle management
//! - `subscriptions/pool` - WebSocket connection pooling & multiplexing

// ============================================================================
// Core Modules (internal - only expose via pub use)
// ============================================================================
pub(crate) mod executor;
mod plan_executor;
mod query_planner;
pub(crate) mod supergraph;
pub(crate) mod types;
pub(crate) mod watcher;

// Hive Router Query Planner (production-grade Federation v2 planner)
pub(crate) mod hive_planner;

// ============================================================================
// Subscription Modules (partially public for WebSocket handlers)
// ============================================================================
pub(crate) mod subscriptions;

// ============================================================================
// Performance Modules (internal)
// ============================================================================
mod apq;
mod batch;
mod cache;
pub(crate) mod cache_invalidation;
mod deduplication;
mod entity_cache;
pub(crate) mod redis_cache;

// ============================================================================
// Security Modules (internal)
// Rate limiting is in crate::rate_limiting::federation
// ============================================================================
mod cost;
mod security;

// ============================================================================
// Load Shedding & Resilience Modules (pub(crate) for state.rs access)
// ============================================================================
pub(crate) mod load_shedding;

// ============================================================================
// Extensibility Modules (internal)
// ============================================================================
mod plugins;
mod tracing_ext;

// ============================================================================
// Public Re-exports (for integration tests)
// ============================================================================

// Supergraph types - used by main application and tests
pub use supergraph::Supergraph;
pub(crate) use watcher::{HotReloadableSupergraph, SupergraphReloadResult};

// Subscription management - used by WebSocket and SSE handlers
pub(crate) use subscriptions::{
    accepts_sse, graphql_sse_handler, BroadcasterConfig, SubscriptionEventBroadcaster,
    SubscriptionManager,
};
// SSE types for future use (currently SseConfig is built inline)
#[allow(unused_imports)]
pub(crate) use subscriptions::{SseConfig, SseError};

// Federation execution - main entry point for BFF federation mode
pub(crate) use executor::{FederationExecutor, FederationExecutorConfig, FederationRequest};

// Load shedding and resilience - used by state.rs and bff.rs
pub(crate) use load_shedding::{
    AdmissionResult, CircuitBreakerConfig, LoadShedder, LoadSheddingConfig, RejectionReason,
};

// Cache invalidation - event-driven cache clearing via Redis pub/sub
#[allow(unused_imports)] // Exported for future integration with executor
pub(crate) use cache_invalidation::{CacheInvalidator, InvalidationConfig, InvalidationEvent};
