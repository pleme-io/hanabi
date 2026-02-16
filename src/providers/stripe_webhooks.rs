//! Stripe + PIX webhook handler implementation

use std::sync::Arc;

use axum::routing::post;
use axum::Router;

use crate::config::BffWebhooksConfig;
use crate::state::AppState;
use crate::traits::WebhookHandler;
use crate::webhooks::stripe::{handle_pix_webhook, handle_stripe_webhook};

/// Stripe + PIX webhook handler.
pub struct StripeWebhooks;

impl StripeWebhooks {
    /// Returns `Some(Self)` if Stripe webhooks are configured, `None` otherwise.
    pub fn from_config(config: &BffWebhooksConfig) -> Option<Self> {
        if config.stripe.is_some() {
            Some(Self)
        } else {
            None
        }
    }
}

impl WebhookHandler for StripeWebhooks {
    fn name(&self) -> &str {
        "Stripe"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route("/webhooks/stripe", post(handle_stripe_webhook))
            .route("/webhooks/pix", post(handle_pix_webhook))
            .with_state(state)
    }

    fn log_config(&self) {
        tracing::info!("     - Stripe/PIX webhook: Configured");
    }
}
