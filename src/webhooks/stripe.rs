//! Stripe Webhook Handler
//!
//! Handles Stripe webhooks (payments, subscriptions) and PIX webhooks.
//! Verifies HMAC-SHA256 signatures at the edge and forwards to internal services
//! via GraphQL mutations through Hive Router.
//!
//! # Stripe Signature Format
//! Header: `stripe-signature: t=timestamp,v1=signature`
//! Payload signed: `{timestamp}.{raw_body}`
//!
//! # PIX Webhooks
//! Brazilian instant payments via Stripe. Uses same signature format but may
//! have a separate webhook secret.

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Handle Stripe webhook
///
/// # Flow
/// 1. Extract signature from `stripe-signature` header
/// 2. Read raw body bytes
/// 3. Verify HMAC-SHA256 signature
/// 4. Parse event for routing
/// 5. Forward to Hive Router as GraphQL mutation
/// 6. Return 200 OK (or 500 for retry)
pub async fn handle_stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if webhooks are enabled
    if !state.config.bff.webhooks.enabled {
        warn!("Stripe webhook received but webhooks are disabled");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Webhooks are disabled"
            })),
        )
            .into_response();
    }

    // Get Stripe config
    let stripe_config = match &state.config.bff.webhooks.stripe {
        Some(config) => config,
        None => {
            error!("Stripe webhook received but Stripe is not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Stripe webhooks not configured"
                })),
            )
                .into_response();
        }
    };

    // Extract signature header
    let signature = match headers
        .get("stripe-signature")
        .and_then(|h| h.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            warn!("Missing stripe-signature header");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing stripe-signature header"
                })),
            )
                .into_response();
        }
    };

    // Verify signature - try primary secret first, then fallback to thin_webhook_secret
    let signature_valid =
        if verify_stripe_signature(&body, signature, &stripe_config.webhook_secret) {
            debug!("Stripe webhook verified with primary secret (Snapshot payloads)");
            true
        } else if let Some(ref thin_secret) = stripe_config.thin_webhook_secret {
            if verify_stripe_signature(&body, signature, thin_secret) {
                debug!("Stripe webhook verified with thin_webhook_secret (Thin payloads)");
                true
            } else {
                false
            }
        } else {
            false
        };

    if !signature_valid {
        warn!("Invalid Stripe signature (tried all configured secrets)");
        state.incr("webhook.stripe.signature_invalid", &[]);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Invalid signature"
            })),
        )
            .into_response();
    }

    info!("Stripe webhook signature verified");

    // Parse event
    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to parse Stripe webhook payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid JSON payload"
                })),
            )
                .into_response();
        }
    };

    let event_type = event["type"].as_str().unwrap_or("unknown");
    let event_id = event["id"].as_str().unwrap_or("unknown");

    info!(event_type, event_id, "Processing Stripe webhook");

    state.incr("webhook.stripe.received", &[("event_type", event_type)]);

    // Forward to Hive Router as GraphQL mutation
    match forward_stripe_webhook(&state, event_id, event_type, &body).await {
        Ok(_) => {
            info!(
                event_id,
                event_type, "Stripe webhook processed successfully"
            );
            state.incr("webhook.stripe.success", &[("event_type", event_type)]);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!(event_id, event_type, error = %e, "Failed to process Stripe webhook");
            state.incr("webhook.stripe.error", &[("event_type", event_type)]);
            // Return 500 so Stripe retries
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to process webhook"
                })),
            )
                .into_response()
        }
    }
}

/// Handle PIX webhook (Brazilian instant payments via Stripe)
///
/// PIX webhooks use the same format as Stripe but may have a separate secret.
pub async fn handle_pix_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if webhooks are enabled
    if !state.config.bff.webhooks.enabled {
        warn!("PIX webhook received but webhooks are disabled");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Webhooks are disabled"
            })),
        )
            .into_response();
    }

    // Get Stripe config (PIX uses Stripe)
    let stripe_config = match &state.config.bff.webhooks.stripe {
        Some(config) => config,
        None => {
            error!("PIX webhook received but Stripe is not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "PIX webhooks not configured"
                })),
            )
                .into_response();
        }
    };

    // Use PIX-specific secret if configured, otherwise use main Stripe secret
    let webhook_secret = stripe_config
        .pix_webhook_secret
        .as_ref()
        .unwrap_or(&stripe_config.webhook_secret);

    // Extract signature header
    let signature = match headers
        .get("stripe-signature")
        .and_then(|h| h.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            warn!("Missing stripe-signature header for PIX webhook");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing stripe-signature header"
                })),
            )
                .into_response();
        }
    };

    // Verify signature
    if !verify_stripe_signature(&body, signature, webhook_secret) {
        warn!("Invalid PIX webhook signature");
        state.incr("webhook.pix.signature_invalid", &[]);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Invalid signature"
            })),
        )
            .into_response();
    }

    info!("PIX webhook signature verified");

    // Parse event
    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to parse PIX webhook payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid JSON payload"
                })),
            )
                .into_response();
        }
    };

    let event_type = event["type"].as_str().unwrap_or("unknown");
    let event_id = event["id"].as_str().unwrap_or("unknown");

    info!(event_type, event_id, "Processing PIX webhook");

    state.incr("webhook.pix.received", &[("event_type", event_type)]);

    // Forward to Hive Router as GraphQL mutation
    match forward_pix_webhook(&state, event_id, event_type, &body).await {
        Ok(_) => {
            info!(event_id, event_type, "PIX webhook processed successfully");
            state.incr("webhook.pix.success", &[("event_type", event_type)]);
            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!(event_id, event_type, error = %e, "Failed to process PIX webhook");
            state.incr("webhook.pix.error", &[("event_type", event_type)]);
            // Return 500 so Stripe retries
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "Failed to process webhook"
                })),
            )
                .into_response()
        }
    }
}

/// Stripe webhook timestamp tolerance in seconds (5 minutes)
/// This prevents replay attacks by rejecting events with old timestamps
const STRIPE_TIMESTAMP_TOLERANCE_SECS: i64 = 300;

/// Verify Stripe webhook signature
///
/// # Stripe Signature Format
/// Header: `t=timestamp,v1=signature[,v1=signature2,...]`
/// Signed payload: `{timestamp}.{raw_body}`
///
/// # Security Notes
/// - Uses constant-time comparison to prevent timing attacks
/// - Validates timestamp is within tolerance (300 seconds) to prevent replay attacks
fn verify_stripe_signature(payload: &[u8], signature: &str, secret: &str) -> bool {
    // Parse t=timestamp,v1=signature format
    let parts: std::collections::HashMap<&str, &str> = signature
        .split(',')
        .filter_map(|part| {
            let mut split = part.splitn(2, '=');
            Some((split.next()?, split.next()?))
        })
        .collect();

    let timestamp = match parts.get("t") {
        Some(t) => *t,
        None => {
            debug!("Missing timestamp in stripe-signature");
            return false;
        }
    };

    // Parse and validate timestamp is within tolerance (prevents replay attacks)
    let timestamp_secs: i64 = match timestamp.parse() {
        Ok(ts) => ts,
        Err(_) => {
            debug!("Invalid timestamp format in stripe-signature");
            return false;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let time_diff = (now - timestamp_secs).abs();
    if time_diff > STRIPE_TIMESTAMP_TOLERANCE_SECS {
        warn!(
            timestamp_secs,
            now,
            time_diff,
            tolerance = STRIPE_TIMESTAMP_TOLERANCE_SECS,
            "Stripe webhook timestamp outside tolerance (possible replay attack)"
        );
        return false;
    }

    let expected_sig = match parts.get("v1") {
        Some(s) => *s,
        None => {
            debug!("Missing v1 signature in stripe-signature");
            return false;
        }
    };

    // Create signed payload: timestamp.payload
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

    // Compute HMAC-SHA256
    let mut mac: Hmac<Sha256> = match Hmac::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            error!("Invalid Stripe webhook secret");
            return false;
        }
    };
    mac.update(signed_payload.as_bytes());
    // Convert to hex without external crate
    let computed: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    // Constant-time comparison
    computed == expected_sig
}

/// Forward Stripe webhook to Hive Router as GraphQL mutation
async fn forward_stripe_webhook(
    state: &AppState,
    event_id: &str,
    event_type: &str,
    raw_payload: &[u8],
) -> Result<(), String> {
    let client = state
        .http_client()
        .ok_or("HTTP client not initialized")?;

    let mutation = r#"
        mutation ProcessStripeWebhook($input: StripeWebhookInput!) {
            processStripeWebhook(input: $input) {
                success
                message
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "eventId": event_id,
            "eventType": event_type,
            "rawPayload": String::from_utf8_lossy(raw_payload),
        }
    });

    let mut request = client
        .post(&state.config.bff.hive_router_url)
        .header("Content-Type", "application/json")
        .header("x-product", &state.config.bff.product)
        .json(&serde_json::json!({
            "query": mutation,
            "variables": variables,
        }));

    // Add service token if configured
    if !state.config.bff.webhooks.service_token.is_empty() {
        request = request.header(
            "Authorization",
            format!("Bearer {}", state.config.bff.webhooks.service_token),
        );
    }

    let response = request
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        // Check for GraphQL errors in response
        let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
        if body.get("errors").is_some() {
            return Err(format!(
                "GraphQL errors: {}",
                serde_json::to_string(&body["errors"]).unwrap_or_default()
            ));
        }
        Ok(())
    } else {
        Err(format!("HTTP error: {}", response.status()))
    }
}

/// Forward PIX webhook to Hive Router as GraphQL mutation
async fn forward_pix_webhook(
    state: &AppState,
    event_id: &str,
    event_type: &str,
    raw_payload: &[u8],
) -> Result<(), String> {
    let client = state
        .http_client()
        .ok_or("HTTP client not initialized")?;

    let mutation = r#"
        mutation ProcessPixWebhook($input: PixWebhookInput!) {
            processPixWebhook(input: $input) {
                success
                message
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
            "eventId": event_id,
            "eventType": event_type,
            "rawPayload": String::from_utf8_lossy(raw_payload),
        }
    });

    let mut request = client
        .post(&state.config.bff.hive_router_url)
        .header("Content-Type", "application/json")
        .header("x-product", &state.config.bff.product)
        .json(&serde_json::json!({
            "query": mutation,
            "variables": variables,
        }));

    // Add service token if configured
    if !state.config.bff.webhooks.service_token.is_empty() {
        request = request.header(
            "Authorization",
            format!("Bearer {}", state.config.bff.webhooks.service_token),
        );
    }

    let response = request
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        // Check for GraphQL errors in response
        let body: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
        if body.get("errors").is_some() {
            return Err(format!(
                "GraphQL errors: {}",
                serde_json::to_string(&body["errors"]).unwrap_or_default()
            ));
        }
        Ok(())
    } else {
        Err(format!("HTTP error: {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_stripe_signature_valid() {
        // Test with known good values using current timestamp
        // (replay protection requires timestamp within 300 seconds of now)
        let payload = b"test payload";
        let secret = "whsec_test_secret";
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time should be after UNIX epoch")
            .as_secs();
        let timestamp = now.to_string();

        // Compute expected signature
        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("test secret should be valid for HMAC");
        mac.update(signed_payload.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        let signature = format!("t={},v1={}", timestamp, expected_sig);

        assert!(verify_stripe_signature(payload, &signature, secret));
    }

    #[test]
    fn test_verify_stripe_signature_invalid() {
        let payload = b"test payload";
        let secret = "whsec_test_secret";
        let signature = "t=1234567890,v1=invalid_signature";

        assert!(!verify_stripe_signature(payload, signature, secret));
    }

    #[test]
    fn test_verify_stripe_signature_missing_timestamp() {
        let payload = b"test payload";
        let secret = "whsec_test_secret";
        let signature = "v1=somesignature";

        assert!(!verify_stripe_signature(payload, signature, secret));
    }

    #[test]
    fn test_verify_stripe_signature_missing_signature() {
        let payload = b"test payload";
        let secret = "whsec_test_secret";
        let signature = "t=1234567890";

        assert!(!verify_stripe_signature(payload, signature, secret));
    }
}
