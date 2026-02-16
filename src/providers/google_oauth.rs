//! Google OAuth provider implementation

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::auth::{
    google_oauth_callback, google_oauth_init, link_oauth_account, restore_oauth_account,
};
use crate::config::BffOAuthConfig;
use crate::state::AppState;
use crate::traits::OAuthProvider;

/// Google OAuth provider with account linking and restoration.
pub struct GoogleOAuth;

impl GoogleOAuth {
    /// Returns `Some(Self)` if Google OAuth is configured, `None` otherwise.
    pub fn from_config(config: &BffOAuthConfig) -> Option<Self> {
        if config.google.is_some() {
            Some(Self)
        } else {
            None
        }
    }
}

impl OAuthProvider for GoogleOAuth {
    fn name(&self) -> &str {
        "Google"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route("/api/auth/google", get(google_oauth_init))
            .route("/api/auth/google/callback", get(google_oauth_callback))
            .route("/api/auth/link-oauth-account", post(link_oauth_account))
            .route(
                "/api/auth/restore-oauth-account",
                post(restore_oauth_account),
            )
            .with_state(state)
    }
}
