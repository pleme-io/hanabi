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
//   l4     WIRED as of 2026-09-24, by a CALL rather than a constructor:
//          `mod l4;` ships it, `AppConfig.l4` deserializes, and
//          `server::run_server` calls `l4::spawn_all` behind `l4.enabled`,
//          sharing the one shutdown broadcast. It exists because Google Cast's
//          control channel is protobuf over TLS on :8009 and no L7 proxy can
//          carry that, while the media fetch beside it is plain HTTP `proxy`
//          already handles. Default OFF, so an existing config is unchanged.
//          UDP is still unimplemented and refused PER PROXY at spawn, never at
//          parse — narrowing the wire format would let one ignored line stop
//          the whole config loading.
//          `proxy::upgrade::tunnel` still reuses its copy-loop SHAPE rather
//          than calling into it: the handshake, not the byte pump, is what an
//          upgrade needs.
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
