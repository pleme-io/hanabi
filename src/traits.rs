//! Extension point traits for composable BFF servers
//!
//! Products compose their BFF by implementing these traits and registering
//! them with [`ServerBuilder`](crate::builder::ServerBuilder). Hanabi merges
//! each provider's router into the final application.
//!
//! # Existing auth traits
//! [`crate::auth::traits`] defines `SessionStore` for auth internals.
//! These traits are server-level extension points for routing.

use std::sync::Arc;

use axum::Router;
use tracing::info;

use crate::state::AppState;

/// An OAuth provider that contributes its own routes to the BFF.
///
/// Implementors define the OAuth initiation, callback, and any
/// account-linking routes. The returned router is merged into the
/// application at the top level.
pub trait OAuthProvider: Send + Sync + 'static {
    /// Human-readable provider name (e.g. "Google", "Instagram").
    fn name(&self) -> &str;

    /// Build the Axum router containing this provider's routes.
    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>>;

    /// Log that this provider is configured. Called during startup.
    fn log_config(&self) {
        info!("     - {} OAuth: Configured", self.name());
    }
}

/// A webhook handler that contributes its own routes to the BFF.
///
/// Implementors define signature verification and forwarding logic.
/// The returned router is merged into the application at the top level.
pub trait WebhookHandler: Send + Sync + 'static {
    /// Human-readable handler name (e.g. "Stripe", "Meta").
    fn name(&self) -> &str;

    /// Build the Axum router containing this handler's routes.
    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>>;

    /// Log that this handler is configured. Called during startup.
    fn log_config(&self) {
        info!("     - {} webhook: Configured", self.name());
    }
}

/// A generic route extension for the BFF.
///
/// Use this for routes that don't fit OAuth or webhook categories
/// (e.g. geolocation, image proxy).
pub trait RouteExtension: Send + Sync + 'static {
    /// Human-readable extension name (e.g. "Geolocation", "ImageProxy").
    fn name(&self) -> &str;

    /// Build the Axum router containing this extension's routes.
    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>>;

    /// Log that this extension is configured. Called during startup.
    fn log_config(&self) {
        info!("     - {} extension: Configured", self.name());
    }
}
