//! Hanabi (花火) — GraphQL Federation BFF platform service
//!
//! Hanabi sits between frontend applications and backend microservices,
//! providing a unified GraphQL endpoint with built-in federation query
//! planning, OAuth authentication, session management, rate limiting,
//! WebSocket subscriptions, webhook processing, and static file serving. A
//! single deployment serves multiple products via `X-Product` header routing.
//!
//! Named after Japanese fireworks, for the brilliant gateway that lights up
//! the frontend experience.
//!
//! ── ★ WHY THIS PARAGRAPH IS WORDED CAREFULLY (2026-09-24) ────────────────
//! It previously read "Shared BFF Web Server … for serving React/Vite static
//! files", which led with the smallest of the jobs above and named neither
//! GraphQL nor federation. That understatement propagated: a stale row in
//! tatara's realization map described hanabi as "L7 proxy + L4 LB + cache +
//! circuit breaker", an agent believed it, and a fleet front door was designed
//! on the wrong picture. The authoritative sentence is `README.md`'s opening
//! line; this doc comment is its projection and the two must not drift.
//!
//! This library exposes internal modules for integration testing.
//! The main binary (main.rs) uses these modules directly via `mod` declarations.
//!
//! # Testing
//!
//! Integration tests in `/tests/` can access public items via:
//! ```rust
//! use hanabi::federation::Supergraph;
//! ```

// Core modules
pub mod auth;
pub mod config;
pub mod error;
pub mod memory;
pub mod metrics;
pub mod prometheus;
pub mod redis;
pub mod request_context;
pub mod resources;
pub mod state;
pub mod telemetry;

// Rate limiting (unified module)
pub mod rate_limiting;

// Federation
pub mod federation;

// BFF proxy + handlers
pub mod bff;
pub mod handlers;
pub mod health;
pub mod health_aggregator;
pub mod images;
pub mod middleware;
pub mod preflight;
pub mod webhooks;

// Router construction
pub mod router;
pub use router::{CoreMiddleware, CoreRoute, MiddlewareSlot};

// Extension points and composition
pub mod builder;
pub mod providers;
pub mod server;
pub mod traits;

// ── Proxy, L4, and service mesh — ALL THREE ARE DARK. ───────────────────
// Tier, measured 2026-09-24, so no reader has to find out the hard way:
//
//   proxy  IN-BINARY, UNREACHED. `mod proxy;` is in main.rs and
//          `AppConfig.proxy` deserializes, but nothing ever READS
//          `config.proxy` and `ProxyService` is constructed only in its own
//          tests. No axum handler exists. No websocket/upgrade support.
//   l4     LIBRARY-ONLY. There is no `mod l4;` in main.rs, so this is not in
//          the shipped binary at all. `run_tcp_proxy` is genuinely
//          implemented; nothing calls it, no `l4` field exists on AppConfig,
//          no backends are ever populated, and UDP is absent entirely.
//   mesh   LIBRARY-ONLY, and a DUPLICATE. Its CircuitBreaker is a simpler
//          unused copy of the live, tested, per-subgraph
//          `federation::load_shedding::CircuitBreakerRegistry` that
//          `state.rs` actually constructs. It also advertises rate limiting
//          it does not contain (that lives in `rate_limiting/`, and is wired).
//
// None of this is a defect in the code — it is unfinished work, and the
// wiring plan is tracked. It IS a defect to let a reader assume otherwise,
// which is how "hanabi is an L7/L4 proxy" became a believed fact.
pub mod l4;
pub mod mesh;
pub mod proxy;
