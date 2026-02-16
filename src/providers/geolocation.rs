//! Geolocation route extension implementation

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::config::GeolocationConfig;
use crate::handlers::geolocation as geolocation_handler;
use crate::state::AppState;
use crate::traits::RouteExtension;

/// IP-based geolocation extension.
pub struct GeolocationExtension;

impl GeolocationExtension {
    /// Returns `Some(Self)` if geolocation is enabled, `None` otherwise.
    pub fn from_config(config: &GeolocationConfig) -> Option<Self> {
        if config.enabled {
            Some(Self)
        } else {
            None
        }
    }
}

impl RouteExtension for GeolocationExtension {
    fn name(&self) -> &str {
        "Geolocation"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route("/api/geolocation", get(geolocation_handler))
            .with_state(state)
    }
}
