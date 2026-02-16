//! Instagram OAuth provider implementation

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::auth::{instagram_oauth_callback, instagram_oauth_init};
use crate::config::BffOAuthConfig;
use crate::state::AppState;
use crate::traits::OAuthProvider;

/// Instagram OAuth provider for social integration (not login).
pub struct InstagramOAuth;

impl InstagramOAuth {
    /// Returns `Some(Self)` if Instagram OAuth is configured, `None` otherwise.
    pub fn from_config(config: &BffOAuthConfig) -> Option<Self> {
        if config.instagram.is_some() {
            Some(Self)
        } else {
            None
        }
    }
}

impl OAuthProvider for InstagramOAuth {
    fn name(&self) -> &str {
        "Instagram"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route("/api/social/instagram", get(instagram_oauth_init))
            .route(
                "/api/social/instagram/callback",
                get(instagram_oauth_callback),
            )
            .with_state(state)
    }

    fn log_config(&self) {
        tracing::info!("     - Instagram OAuth: Configured (social integration)");
    }
}
