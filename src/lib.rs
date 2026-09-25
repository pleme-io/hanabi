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

// ── Proxy is WIRED; L4 and mesh are still dark. ─────────────────────────
// Tier, measured, so no reader has to find out the hard way. The asymmetry is
// the point: two of these three are unfinished work and one is not, and a
// header that lumped them together is how "hanabi is an L7/L4 proxy" became a
// believed fact in the first place.
//
//   proxy  WIRED as of 2026-09-24. `ProxyService` is constructed in
//          `builder.rs` behind `config.proxy.enabled`, so the reverse proxy is
//          enabled by CONFIGURATION rather than by editing code — which it was
//          not, for as long as `AppConfig.proxy` deserialized and nothing read
//          it. `proxy::handler::intercept` is the axum handler that was missing;
//          it is LAYERED rather than a fallback, so it claims only paths a
//          configured route matches and the SPA fallback is untouched.
//          `proxy::upgrade` carries `Upgrade`/WebSocket, which is what unblocked
//          the websocket-driven home UIs (Home Assistant, node-red, esphome,
//          music-assistant, go2rtc) that used to load and then hang.
//          Still absent: TLS termination (`Backend::url()` is http:// by
//          decision) and least-connections balancing (falls back to
//          round-robin, as it always did).
//   l4     LIBRARY-ONLY, still dark. There is no `mod l4;` in main.rs, so this
//          is not in the shipped binary at all. `run_tcp_proxy` is genuinely
//          implemented; nothing calls it, no `l4` field exists on AppConfig,
//          no backends are ever populated, and UDP is absent entirely.
//          `proxy::upgrade::tunnel` deliberately reuses its copy-loop SHAPE
//          rather than calling into it — the handshake, not the byte pump, is
//          what an upgrade needs, and importing a dark module to get a loop
//          would have made it look reached without making it work.
//   mesh   LIBRARY-ONLY, and a DUPLICATE. Its CircuitBreaker is a simpler
//          unused copy of the live, tested, per-subgraph
//          `federation::load_shedding::CircuitBreakerRegistry` that
//          `state.rs` actually constructs. It also advertises rate limiting
//          it does not contain (that lives in `rate_limiting/`, and is wired).
//          Retire rather than wire.
//
// `tests/dark_modules_test.rs` enforces every line above: each module's tier is
// asserted in BOTH directions, so wiring one or un-wiring one fails the gate
// instead of quietly aging this comment into a lie.
pub mod l4;
pub mod mesh;
pub mod proxy;
