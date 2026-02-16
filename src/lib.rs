//! Hanabi (花火) - Shared BFF Web Server
//!
//! High-performance web server for serving React/Vite static files with BFF
//! (Backend-for-Frontend) capabilities. Named after Japanese fireworks,
//! representing the brilliant gateway that lights up the frontend experience.
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
pub mod traits;
pub mod builder;
pub mod server;
pub mod providers;
