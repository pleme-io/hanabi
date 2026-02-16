//! Session invalidation event handling via NATS
//!
//! Subscribes to session invalidation events from the backend.
//! When a user is deleted, banned, or otherwise invalidated,
//! the backend publishes a SessionInvalidatedEvent and this module
//! clears all Redis sessions for that user.
//!
//! # Architecture
//!
//! ```text
//! Backend (NATS publish) ──► NATS JetStream ──► BFF (this module)
//!                                                      │
//!                                              SessionStore::delete_by_user_id()
//!                                                      │
//!                                                      ▼
//!                                              Redis: Delete all sessions
//! ```
//!
//! # Event Format
//!
//! The backend publishes events to `{product}.session.invalidated` subject:
//! ```json
//! {
//!   "user_id": "uuid",
//!   "reason": "hard_delete_user: staging reset",
//!   "invalidated_at": "2026-01-29T12:00:00Z"
//! }
//! ```

use chrono::{DateTime, Utc};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::BffSessionConfig;
use crate::redis::LazyRedisPool;

use super::session::SessionStore;

/// Event emitted when user sessions should be invalidated
///
/// This matches the SessionInvalidatedEvent from the product backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInvalidatedEvent {
    /// The user ID whose sessions should be invalidated
    pub user_id: String,
    /// Reason for invalidation (for audit logging)
    pub reason: String,
    /// When the invalidation was triggered
    pub invalidated_at: DateTime<Utc>,
}

/// Subscribe to session invalidation events from NATS
///
/// This function connects to NATS and subscribes to the session invalidation subject.
/// When events are received, it calls `SessionStore::delete_by_user_id()` to clear
/// all Redis sessions for the invalidated user.
///
/// # Arguments
/// * `nats_url` - NATS server URL (e.g., "nats://localhost:4222")
/// * `product` - Product identifier for NATS subject (e.g., "myapp" → "myapp.session.invalidated")
/// * `session_redis` - Lazy Redis pool for session operations
/// * `session_config` - Session configuration for SessionStore
///
/// # Returns
/// Result with () on success, or error message on failure
///
/// # Note
/// This function runs forever (until NATS connection drops).
/// It should be spawned as a background task.
pub async fn subscribe_session_invalidation(
    nats_url: &str,
    product: &str,
    session_redis: Arc<LazyRedisPool>,
    session_config: BffSessionConfig,
) -> Result<(), String> {
    let subject = format!("{}.session.invalidated", product);
    // Connect to NATS
    let client = async_nats::connect(nats_url)
        .await
        .map_err(|e| format!("Failed to connect to NATS at {}: {}", nats_url, e))?;

    info!(
        "Connected to NATS at {} for session invalidation events",
        nats_url
    );

    // Subscribe to session invalidation events
    let mut subscriber = client
        .subscribe(subject.to_string())
        .await
        .map_err(|e| format!("Failed to subscribe to {}: {}", subject, e))?;

    info!(
        "Subscribed to {} for session invalidation events",
        subject
    );

    // Process events
    while let Some(message) = subscriber.next().await {
        match serde_json::from_slice::<SessionInvalidatedEvent>(&message.payload) {
            Ok(event) => {
                info!(
                    user_id = %event.user_id,
                    reason = %event.reason,
                    "Received session invalidation event"
                );

                // Parse user_id as UUID
                let user_id = match Uuid::parse_str(&event.user_id) {
                    Ok(id) => id,
                    Err(e) => {
                        error!(
                            user_id = %event.user_id,
                            error = %e,
                            "Invalid user_id in session invalidation event"
                        );
                        continue;
                    }
                };

                // Get Redis connection and delete sessions
                match session_redis.get().await {
                    Some(conn) => {
                        let mut store = SessionStore::new(conn, session_config.clone());
                        match store.delete_by_user_id(&user_id).await {
                            Ok(count) => {
                                info!(
                                    user_id = %event.user_id,
                                    sessions_deleted = count,
                                    reason = %event.reason,
                                    "Successfully invalidated sessions for user"
                                );
                            }
                            Err(e) => {
                                error!(
                                    user_id = %event.user_id,
                                    error = %e,
                                    "Failed to invalidate sessions for user"
                                );
                            }
                        }
                    }
                    None => {
                        error!(
                            user_id = %event.user_id,
                            "Failed to get Redis connection for session invalidation"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    error = %e,
                    payload = ?String::from_utf8_lossy(&message.payload),
                    "Failed to deserialize session invalidation event"
                );
            }
        }
    }

    warn!("NATS session invalidation subscriber disconnected");
    Ok(())
}

/// Spawn the session invalidation subscriber as a background task
///
/// This is the main entry point for starting the NATS subscription.
/// It spawns a tokio task that runs the subscriber forever.
///
/// # Arguments
/// * `nats_url` - NATS server URL
/// * `product` - Product identifier for NATS subject
/// * `session_redis` - Lazy Redis pool for session operations
/// * `session_config` - Session configuration for SessionStore
///
/// # Returns
/// JoinHandle for the spawned task (can be used for graceful shutdown)
pub fn spawn_session_invalidation_subscriber(
    nats_url: String,
    product: String,
    session_redis: Arc<LazyRedisPool>,
    session_config: BffSessionConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match subscribe_session_invalidation(&nats_url, &product, session_redis.clone(), session_config.clone()).await {
                Ok(()) => {
                    warn!("Session invalidation subscriber exited normally, reconnecting in 5s...");
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Session invalidation subscriber error, reconnecting in 5s..."
                    );
                }
            }
            // Wait before reconnecting
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_deserialization() {
        let json = r#"{
            "user_id": "550e8400-e29b-41d4-a716-446655440000",
            "reason": "hard_delete_user: staging reset",
            "invalidated_at": "2026-01-29T12:00:00Z"
        }"#;

        let event: SessionInvalidatedEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.user_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(event.reason, "hard_delete_user: staging reset");
    }
}
