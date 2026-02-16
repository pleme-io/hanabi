//! Meta Webhook Handler
//!
//! Handles Meta webhooks for WhatsApp Business API and Instagram Messaging.
//! Verifies HMAC-SHA256 signatures at the edge and forwards to internal services
//! via GraphQL mutations through Hive Router.
//!
//! # Meta Signature Format
//! Header: `x-hub-signature-256: sha256=signature`
//! Payload: Raw request body
//!
//! # Webhook Verification Challenge
//! GET request with `hub.mode`, `hub.challenge`, `hub.verify_token`
//!
//! # Object Types
//! - `whatsapp_business_account`: WhatsApp messages/statuses
//! - `instagram`: Instagram DMs/mentions

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tracing::{debug, error, info, warn};

use crate::state::AppState;

/// Query parameters for Meta webhook verification
#[derive(Debug, Deserialize)]
pub struct MetaVerifyParams {
    #[serde(rename = "hub.mode")]
    pub hub_mode: Option<String>,
    #[serde(rename = "hub.challenge")]
    pub hub_challenge: Option<String>,
    #[serde(rename = "hub.verify_token")]
    pub hub_verify_token: Option<String>,
}

/// Handle Meta webhook verification challenge
///
/// Meta sends a GET request to verify the webhook URL:
/// - hub.mode = "subscribe"
/// - hub.verify_token = configured token
/// - hub.challenge = random string to echo back
pub async fn verify_meta_webhook(
    State(state): State<Arc<AppState>>,
    Query(params): Query<MetaVerifyParams>,
) -> impl IntoResponse {
    // Check if webhooks are enabled
    if !state.config.bff.webhooks.enabled {
        warn!("Meta webhook verification received but webhooks are disabled");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Webhooks are disabled".to_string(),
        )
            .into_response();
    }

    // Get Meta config
    let meta_config = match &state.config.bff.webhooks.meta {
        Some(config) => config,
        None => {
            error!("Meta webhook verification received but Meta is not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Meta webhooks not configured".to_string(),
            )
                .into_response();
        }
    };

    // Verify the request
    let mode = params.hub_mode.unwrap_or_default();
    let challenge = params.hub_challenge.unwrap_or_default();
    let verify_token = params.hub_verify_token.unwrap_or_default();

    if mode == "subscribe" && verify_token == meta_config.verify_token {
        info!("Meta webhook verification successful");
        state.incr("webhook.meta.verification_success", &[]);
        // Return the challenge to complete verification
        challenge.into_response()
    } else {
        warn!(
            mode,
            expected_token = %meta_config.verify_token,
            received_token = %verify_token,
            "Meta webhook verification failed"
        );
        state.incr("webhook.meta.verification_failed", &[]);
        (StatusCode::FORBIDDEN, "Invalid verify token".to_string()).into_response()
    }
}

/// Handle Meta webhook events
///
/// # Flow
/// 1. Extract signature from `x-hub-signature-256` header
/// 2. Read raw body bytes
/// 3. Verify HMAC-SHA256 signature
/// 4. Parse payload to determine object type (whatsapp_business_account, instagram)
/// 5. Forward to appropriate GraphQL mutation via Hive Router
/// 6. Return 200 OK (always acknowledge to prevent retries)
pub async fn handle_meta_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Check if webhooks are enabled
    if !state.config.bff.webhooks.enabled {
        warn!("Meta webhook received but webhooks are disabled");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "Webhooks are disabled"
            })),
        )
            .into_response();
    }

    // Get Meta config
    let meta_config = match &state.config.bff.webhooks.meta {
        Some(config) => config,
        None => {
            error!("Meta webhook received but Meta is not configured");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Meta webhooks not configured"
                })),
            )
                .into_response();
        }
    };

    // Extract signature header
    let signature = match headers
        .get("x-hub-signature-256")
        .and_then(|h| h.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            warn!("Missing x-hub-signature-256 header");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Missing x-hub-signature-256 header"
                })),
            )
                .into_response();
        }
    };

    // Verify signature
    if !verify_meta_signature(&body, signature, &meta_config.app_secret) {
        warn!("Invalid Meta signature");
        state.incr("webhook.meta.signature_invalid", &[]);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "Invalid signature"
            })),
        )
            .into_response();
    }

    debug!("Meta webhook signature verified");

    // Parse payload
    let payload: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to parse Meta webhook payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid JSON payload"
                })),
            )
                .into_response();
        }
    };

    let object_type = payload["object"].as_str().unwrap_or("unknown");

    info!(object_type, "Processing Meta webhook");

    state.incr("webhook.meta.received", &[("object_type", object_type)]);

    // Route based on object type
    let result = match object_type {
        "whatsapp_business_account" => forward_whatsapp_webhook(&state, &body).await,
        "instagram" => forward_instagram_webhook(&state, &body).await,
        _ => {
            warn!(object_type, "Unknown Meta webhook object type");
            state.incr("webhook.meta.unknown_type", &[("object_type", object_type)]);
            // Acknowledge unknown events to prevent retries
            Ok(())
        }
    };

    // Always return 200 to Meta (even on processing errors) to prevent retries
    // of events we've already acknowledged. Errors are logged and can be monitored.
    match result {
        Ok(_) => {
            info!(object_type, "Meta webhook processed successfully");
            state.incr("webhook.meta.success", &[("object_type", object_type)]);
        }
        Err(e) => {
            error!(object_type, error = %e, "Failed to process Meta webhook");
            state.incr("webhook.meta.error", &[("object_type", object_type)]);
        }
    }

    // Always return 200 OK to Meta
    StatusCode::OK.into_response()
}

/// Verify Meta webhook signature
///
/// # Meta Signature Format
/// Header: `x-hub-signature-256: sha256=hex_signature`
/// Signature computed over raw request body using App Secret
fn verify_meta_signature(payload: &[u8], signature: &str, secret: &str) -> bool {
    let expected = match signature.strip_prefix("sha256=") {
        Some(s) => s,
        None => {
            debug!("Invalid Meta signature format (missing sha256= prefix)");
            return false;
        }
    };

    // Compute HMAC-SHA256
    let mut mac: Hmac<Sha256> = match Hmac::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            error!("Invalid Meta app secret");
            return false;
        }
    };
    mac.update(payload);
    let computed: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    // Constant-time comparison
    computed == expected
}

/// Forward WhatsApp webhook to Hive Router as GraphQL mutation
async fn forward_whatsapp_webhook(state: &AppState, raw_payload: &[u8]) -> Result<(), String> {
    let client = state
        .http_client()
        .ok_or("HTTP client not initialized")?;

    let mutation = r#"
        mutation ProcessWhatsAppWebhook($input: MetaWebhookInput!) {
            processWhatsAppWebhook(input: $input) {
                success
                message
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
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

/// Forward Instagram webhook to Hive Router as GraphQL mutation
async fn forward_instagram_webhook(state: &AppState, raw_payload: &[u8]) -> Result<(), String> {
    let client = state
        .http_client()
        .ok_or("HTTP client not initialized")?;

    let mutation = r#"
        mutation ProcessInstagramWebhook($input: MetaWebhookInput!) {
            processInstagramWebhook(input: $input) {
                success
                message
            }
        }
    "#;

    let variables = serde_json::json!({
        "input": {
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
    fn test_verify_meta_signature_valid() {
        let payload = b"test payload";
        let secret = "test_app_secret";

        // Compute expected signature
        let mut mac: Hmac<Sha256> =
            Hmac::new_from_slice(secret.as_bytes()).expect("test secret should be valid for HMAC");
        mac.update(payload);
        let expected_sig: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        let signature = format!("sha256={}", expected_sig);

        assert!(verify_meta_signature(payload, &signature, secret));
    }

    #[test]
    fn test_verify_meta_signature_invalid() {
        let payload = b"test payload";
        let secret = "test_app_secret";
        let signature = "sha256=invalid_signature";

        assert!(!verify_meta_signature(payload, signature, secret));
    }

    #[test]
    fn test_verify_meta_signature_missing_prefix() {
        let payload = b"test payload";
        let secret = "test_app_secret";
        let signature = "invalid_format";

        assert!(!verify_meta_signature(payload, signature, secret));
    }
}
