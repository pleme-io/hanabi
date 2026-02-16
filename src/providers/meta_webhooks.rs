//! Meta (WhatsApp/Instagram) webhook handler implementation

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

use crate::config::BffWebhooksConfig;
use crate::state::AppState;
use crate::traits::WebhookHandler;
use crate::webhooks::meta::{handle_meta_webhook, verify_meta_webhook};

/// Meta webhook handler (WhatsApp Business API, Instagram Messaging).
pub struct MetaWebhooks;

impl MetaWebhooks {
    /// Returns `Some(Self)` if Meta webhooks are configured, `None` otherwise.
    pub fn from_config(config: &BffWebhooksConfig) -> Option<Self> {
        if config.meta.is_some() {
            Some(Self)
        } else {
            None
        }
    }
}

impl WebhookHandler for MetaWebhooks {
    fn name(&self) -> &str {
        "Meta"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route("/webhooks/meta", post(handle_meta_webhook))
            .route("/webhooks/meta", get(verify_meta_webhook))
            .with_state(state)
    }

    fn log_config(&self) {
        tracing::info!("     - Meta webhook: Configured (WhatsApp/Instagram)");
    }
}
