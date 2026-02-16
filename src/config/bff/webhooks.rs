use serde::{Deserialize, Serialize};

/// Webhook gateway configuration
///
/// # External Webhook Gateway Pattern
/// BFF receives external webhooks, verifies signatures at the edge, and forwards
/// to internal services via GraphQL mutations through Hive Router.
///
/// Flow: External Provider → BFF (signature verification) → GraphQL mutation → Hive Router → Service
///
/// # Supported Providers
/// - **Stripe**: Payment webhooks (payment_intent.*, charge.*, subscription.*)
/// - **PIX**: Brazilian instant payment webhooks
/// - **Meta**: WhatsApp Business API, Instagram Messaging webhooks
///
/// # Security
/// - Signature verification happens at BFF (edge)
/// - Internal services never exposed publicly
/// - Service token used for machine-to-machine auth
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffWebhooksConfig {
    /// Enable webhook gateway
    #[serde(default)]
    pub enabled: bool,

    /// Stripe webhook configuration
    #[serde(default)]
    pub stripe: Option<StripeWebhookConfig>,

    /// Meta (WhatsApp/Instagram) webhook configuration
    #[serde(default)]
    pub meta: Option<MetaWebhookConfig>,

    /// Service token for machine-to-machine auth when calling GraphQL mutations
    /// Used in Authorization header when forwarding webhooks to Hive Router
    #[serde(default)]
    pub service_token: String,

    /// Idempotency TTL in seconds (prevent duplicate event processing)
    pub idempotency_ttl_secs: u64,
}

impl Default for BffWebhooksConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            stripe: None,
            meta: None,
            service_token: String::new(),
            idempotency_ttl_secs: 86400,
        }
    }
}

/// Stripe webhook configuration
///
/// # Multiple Webhook Destinations
/// Stripe supports multiple webhook destinations to the same URL with different payload styles:
/// - **Snapshot** (webhook_secret): Full event objects (221 events)
/// - **Thin** (thin_webhook_secret): Minimal payloads, requires API fetch for full data (2 events)
///
/// When verifying signatures, try `webhook_secret` first, then `thin_webhook_secret` as fallback.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StripeWebhookConfig {
    /// Primary Stripe webhook signing secret (whsec_...) - typically Snapshot payloads
    pub webhook_secret: String,

    /// Optional: Secondary webhook secret for Thin payload destinations
    /// Used as fallback when primary signature verification fails
    #[serde(default)]
    pub thin_webhook_secret: Option<String>,

    /// Optional: Separate PIX webhook secret (if different from main Stripe webhook)
    #[serde(default)]
    pub pix_webhook_secret: Option<String>,
}

/// Meta (WhatsApp/Instagram) webhook configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetaWebhookConfig {
    /// Meta App Secret (used for HMAC-SHA256 signature verification)
    pub app_secret: String,

    /// Meta webhook verification token (used for webhook URL verification)
    pub verify_token: String,
}
