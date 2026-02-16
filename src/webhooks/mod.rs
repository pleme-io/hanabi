//! External Webhook Gateway Module
//!
//! Implements the BFF webhook gateway pattern for receiving external webhooks,
//! verifying signatures at the edge, and forwarding to internal services via
//! GraphQL mutations through Hive Router.
//!
//! # Architecture
//! ```text
//! External Provider → BFF (signature verification) → GraphQL mutation → Hive Router → Service
//! ```
//!
//! # Supported Providers
//! - **Stripe**: Payment webhooks (payment_intent.*, charge.*, subscription.*)
//! - **PIX**: Brazilian instant payment webhooks (via Stripe)
//! - **Meta**: WhatsApp Business API, Instagram Messaging webhooks
//!
//! # Security
//! - Signature verification happens at BFF (edge) - internal services never exposed publicly
//! - HMAC-SHA256 for Stripe (stripe-signature header)
//! - HMAC-SHA256 for Meta (x-hub-signature-256 header)
//! - Idempotency via Redis to prevent duplicate processing
//!
//! # Configuration
//! ```yaml
//! bff:
//!   webhooks:
//!     enabled: true
//!     stripe:
//!       webhook_secret: "${STRIPE_WEBHOOK_SECRET}"
//!     meta:
//!       app_secret: "${META_APP_SECRET}"
//!       verify_token: "${META_VERIFY_TOKEN}"
//!     service_token: "${WEBHOOK_SERVICE_TOKEN}"
//! ```

#[cfg(feature = "meta-webhooks")]
pub mod meta;
#[cfg(feature = "stripe-webhooks")]
pub mod stripe;

/// Build webhook routes for the BFF
///
/// Routes:
/// - POST /webhooks/stripe - Stripe payment webhooks (requires `stripe-webhooks` feature)
/// - POST /webhooks/pix - PIX payment webhooks (requires `stripe-webhooks` feature)
/// - POST /webhooks/meta - Meta webhooks (requires `meta-webhooks` feature)
/// - GET /webhooks/meta - Meta webhook verification challenge (requires `meta-webhooks` feature)
#[cfg(all(feature = "stripe-webhooks", feature = "meta-webhooks"))]
#[allow(dead_code)]
pub fn webhook_routes(state: std::sync::Arc<crate::state::AppState>) -> axum::Router<std::sync::Arc<crate::state::AppState>> {
    use axum::routing::{get, post};
    use axum::Router;
    Router::new()
        // Stripe webhooks
        .route("/webhooks/stripe", post(stripe::handle_stripe_webhook))
        .route("/webhooks/pix", post(stripe::handle_pix_webhook))
        // Meta webhooks (WhatsApp, Instagram)
        .route("/webhooks/meta", post(meta::handle_meta_webhook))
        .route("/webhooks/meta", get(meta::verify_meta_webhook))
        .with_state(state)
}
