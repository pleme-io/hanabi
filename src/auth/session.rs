#![allow(dead_code)]
//! Session management for BFF authentication
//!
//! Sessions are stored in Redis with the following structure:
//! - Key: `session:{session_id}`
//! - Value: JSON-serialized Session struct
//! - TTL: Configurable (default 7 days, matches refresh token lifetime)
//!
//! # User Session Index
//!
//! For session invalidation by user_id (e.g., when user is deleted),
//! we maintain a Redis set for each user:
//! - Key: `user:sessions:{user_id}`
//! - Value: Set of session_ids
//! - Operations: SADD on create, SREM on delete, SMEMBERS + DEL for invalidate
//!
//! # Token Refresh
//! The BFF automatically refreshes tokens when:
//! - Access token is expired or within refresh_buffer_secs of expiry
//! - Refresh token is still valid
//!
//! This happens transparently - the frontend never knows about token refresh.
//!
//! # Performance Optimizations
//! - `#[inline]` on frequently called methods (is_token_expired, touch)
//! - Reusable ConnectionManager (cheaply cloneable Arc internally)
//! - JSON serialization cached where possible

use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::BffSessionConfig;

/// Session stored in Redis
///
/// Contains auth tokens and metadata for a user session.
/// Tokens are stored server-side only - browser only has session_id cookie.
///
/// # User Context Fields
///
/// The session stores user context (email, roles, permissions) extracted from
/// the login response. This allows the BFF to inject authorization headers
/// without decoding JWT tokens, supporting both JWT-based auth
/// and session-based auth (token_free_auth) with a single pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (also used as Redis key suffix)
    pub id: Uuid,

    /// User ID from auth service
    pub user_id: Uuid,

    /// JWT access token (short-lived, ~15 minutes)
    /// For token_free_auth: This is a random session token (NOT a JWT)
    /// For JWT mode: This is a JWT with embedded claims
    pub access_token: String,

    /// Refresh token (long-lived, ~7 days)
    pub refresh_token: String,

    /// When the access token expires
    pub token_expires_at: DateTime<Utc>,

    /// When this session was created
    pub created_at: DateTime<Utc>,

    /// Last activity timestamp (updated on each request)
    pub last_activity_at: DateTime<Utc>,

    /// Client IP address (for audit logging)
    pub ip_address: String,

    /// Client User-Agent (for audit logging)
    pub user_agent: String,

    // =========================================================================
    // User Context Fields (extracted from login response, not JWT decode)
    // These fields enable session-based auth for products using token-free mode
    // where the access_token is NOT a JWT with embedded claims.
    // =========================================================================
    /// User email address (extracted from login response)
    #[serde(default)]
    pub user_email: Option<String>,

    /// User roles (e.g., ["user", "staff"])
    #[serde(default)]
    pub roles: Vec<String>,

    /// User permissions (e.g., ["dashboard.read", "ads.moderate"])
    /// For staff users, this includes StaffRole::default_permissions()
    #[serde(default)]
    pub permissions: Vec<String>,

    /// Relationship-based access (e.g., { "products:owner": ["uuid1"] })
    /// Used for ownership checks in pleme-rbac
    #[serde(default)]
    pub relationships: Vec<String>,

    /// Staff role name (e.g., "admin", "moderator")
    /// Extracted from user.staffRole in login response
    #[serde(default)]
    pub staff_role: Option<String>,
}

/// User info returned to frontend (subset of session data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionUser {
    pub id: Uuid,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub roles: Vec<String>,
}

/// Errors that can occur during session operations
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Session not found")]
    NotFound,

    #[error("Session expired")]
    Expired,

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Token refresh failed: {0}")]
    RefreshFailed(String),

    #[error("Auth service error: {0}")]
    AuthService(String),

    #[error("Redis operation timed out after {0}s")]
    Timeout(u64),
}

/// User context extracted from login response
///
/// This struct is used to pass user context to Session::new()
/// without requiring all fields to be specified individually.
#[derive(Debug, Clone, Default)]
pub struct UserContext {
    pub email: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub relationships: Vec<String>,
    pub staff_role: Option<String>,
}

impl Session {
    /// Create a new session with user context
    ///
    /// # Arguments
    /// - `user_id`: User ID from auth service
    /// - `access_token`: Access token (JWT or session token)
    /// - `refresh_token`: Refresh token
    /// - `token_expires_at`: When the access token expires
    /// - `ip_address`: Client IP for audit logging
    /// - `user_agent`: Client User-Agent for audit logging
    /// - `user_context`: User context extracted from login response
    pub fn new(
        user_id: Uuid,
        access_token: String,
        refresh_token: String,
        token_expires_at: DateTime<Utc>,
        ip_address: String,
        user_agent: String,
    ) -> Self {
        Self::with_context(
            user_id,
            access_token,
            refresh_token,
            token_expires_at,
            ip_address,
            user_agent,
            UserContext::default(),
        )
    }

    /// Create a new session with full user context
    ///
    /// This is the preferred constructor when user context is available
    /// from the login response (email, roles, permissions, staff_role).
    pub fn with_context(
        user_id: Uuid,
        access_token: String,
        refresh_token: String,
        token_expires_at: DateTime<Utc>,
        ip_address: String,
        user_agent: String,
        user_context: UserContext,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            access_token,
            refresh_token,
            token_expires_at,
            created_at: now,
            last_activity_at: now,
            ip_address,
            user_agent,
            user_email: user_context.email,
            roles: user_context.roles,
            permissions: user_context.permissions,
            relationships: user_context.relationships,
            staff_role: user_context.staff_role,
        }
    }

    /// Check if the access token is expired or about to expire
    ///
    /// # Performance
    /// Inlined - called on every authenticated request
    #[inline]
    pub fn is_token_expired(&self, buffer_secs: u64) -> bool {
        let buffer = chrono::Duration::seconds(buffer_secs as i64);
        Utc::now() + buffer >= self.token_expires_at
    }

    /// Update the access token after refresh
    #[inline]
    pub fn update_tokens(
        &mut self,
        access_token: String,
        refresh_token: String,
        token_expires_at: DateTime<Utc>,
    ) {
        self.access_token = access_token;
        self.refresh_token = refresh_token;
        self.token_expires_at = token_expires_at;
        self.last_activity_at = Utc::now();
    }

    /// Update last activity timestamp
    ///
    /// # Performance
    /// Inlined - may be called frequently for session tracking
    #[inline]
    pub fn touch(&mut self) {
        self.last_activity_at = Utc::now();
    }
}

/// Session store operations
///
/// All Redis operations are wrapped in timeouts to prevent blocking requests
/// when Redis is slow or unavailable. The timeout is configured via
/// `BffSessionConfig::operation_timeout_secs` (default: 2s).
pub struct SessionStore {
    redis: ConnectionManager,
    config: BffSessionConfig,
    timeout: Duration,
}

impl SessionStore {
    /// Create a new session store
    pub fn new(redis: ConnectionManager, config: BffSessionConfig) -> Self {
        let timeout = Duration::from_secs(config.operation_timeout_secs);
        Self {
            redis,
            config,
            timeout,
        }
    }

    /// Build Redis key for a session
    ///
    /// # Performance
    /// Inlined to reduce overhead - called on every Redis operation.
    /// Note: Still allocates String, but format! is the most efficient approach
    /// for this pattern (concat! doesn't work with runtime Uuid).
    #[inline]
    fn key(&self, session_id: &Uuid) -> String {
        format!("{}{}", self.config.key_prefix, session_id)
    }

    /// Build Redis key for user's session index
    ///
    /// Returns key like "user:sessions:{user_id}" used to track all
    /// sessions for a user, enabling bulk invalidation.
    #[inline]
    fn user_sessions_key(&self, user_id: &Uuid) -> String {
        format!("user:sessions:{}", user_id)
    }

    /// Helper: wrap Redis operation in timeout
    /// PERFORMANCE: Inlined to reduce overhead on hot path
    #[inline]
    async fn with_timeout<T, F>(&self, op: F) -> Result<T, SessionError>
    where
        F: std::future::Future<Output = Result<T, redis::RedisError>>,
    {
        match tokio::time::timeout(self.timeout, op).await {
            Ok(result) => result.map_err(SessionError::Redis),
            Err(_elapsed) => {
                warn!(
                    "Redis operation timed out after {}s",
                    self.config.operation_timeout_secs
                );
                Err(SessionError::Timeout(self.config.operation_timeout_secs))
            }
        }
    }

    /// Create a new session and store it in Redis
    ///
    /// Also adds session_id to user's session index for bulk invalidation support.
    /// PERFORMANCE: Use pre-allocated buffer for serialization
    pub async fn create(&mut self, session: &Session) -> Result<(), SessionError> {
        let key = self.key(&session.id);
        let user_sessions_key = self.user_sessions_key(&session.user_id);

        // Pre-allocate buffer for session JSON (typical session ~400 bytes)
        let mut buffer = String::with_capacity(512);
        // SAFETY: serde_json::to_writer writes valid UTF-8 to String's internal buffer
        serde_json::to_writer(unsafe { buffer.as_mut_vec() }, session)?;

        debug!(
            "Creating session: {} for user: {}",
            session.id, session.user_id
        );

        let ttl = self.config.ttl_secs;
        self.with_timeout(self.redis.clone().set_ex::<_, _, ()>(&key, &buffer, ttl))
            .await?;

        // Add session_id to user's session index for bulk invalidation
        // TTL same as session so index entries don't outlive sessions
        self.with_timeout(
            self.redis
                .clone()
                .sadd::<_, _, ()>(&user_sessions_key, session.id.to_string()),
        )
        .await?;
        // Set TTL on the user sessions set (refresh on each new session)
        self.with_timeout(
            self.redis
                .clone()
                .expire::<_, ()>(&user_sessions_key, ttl as i64),
        )
        .await?;

        info!(
            "Session created: id={}, user_id={}, expires_in={}s",
            session.id, session.user_id, self.config.ttl_secs
        );

        Ok(())
    }

    /// Get a session by ID
    pub async fn get(&mut self, session_id: &Uuid) -> Result<Session, SessionError> {
        let key = self.key(session_id);

        let value: Option<String> = self.with_timeout(self.redis.clone().get(&key)).await?;

        match value {
            Some(v) => {
                let session: Session = serde_json::from_str(&v)?;
                debug!(
                    "Session retrieved: {} for user: {}",
                    session.id, session.user_id
                );
                Ok(session)
            }
            None => {
                debug!("Session not found: {}", session_id);
                Err(SessionError::NotFound)
            }
        }
    }

    /// Update a session in Redis (e.g., after token refresh)
    /// PERFORMANCE: Use pre-allocated buffer for serialization
    pub async fn update(&mut self, session: &Session) -> Result<(), SessionError> {
        let key = self.key(&session.id);

        // Pre-allocate buffer for session JSON
        let mut buffer = String::with_capacity(512);
        serde_json::to_writer(unsafe { buffer.as_mut_vec() }, session)?;

        // Get remaining TTL to preserve it
        let ttl: i64 = self.with_timeout(self.redis.clone().ttl(&key)).await?;

        if ttl <= 0 {
            // Session expired or doesn't exist
            return Err(SessionError::Expired);
        }

        debug!("Updating session: {} (TTL: {}s remaining)", session.id, ttl);

        self.with_timeout(
            self.redis
                .clone()
                .set_ex::<_, _, ()>(&key, &buffer, ttl as u64),
        )
        .await?;

        Ok(())
    }

    /// Delete a session (logout)
    pub async fn delete(&mut self, session_id: &Uuid) -> Result<(), SessionError> {
        let key = self.key(session_id);

        let deleted: i64 = self.with_timeout(self.redis.clone().del(&key)).await?;

        if deleted > 0 {
            info!("Session deleted: {}", session_id);
        } else {
            debug!("Session not found for deletion: {}", session_id);
        }

        // Note: We don't remove from user sessions index here because:
        // 1. We don't have user_id readily available (would require extra lookup)
        // 2. The set entries have TTL and will auto-expire
        // 3. delete_by_user_id handles index cleanup atomically

        Ok(())
    }

    /// Delete all sessions for a user (forced logout/invalidation)
    ///
    /// Called when a user is deleted or their credentials are compromised.
    /// Gets all session_ids from user's index and deletes them atomically.
    ///
    /// Returns the number of sessions deleted.
    pub async fn delete_by_user_id(&mut self, user_id: &Uuid) -> Result<u64, SessionError> {
        let user_sessions_key = self.user_sessions_key(user_id);

        // Get all session IDs for this user
        let session_ids: Vec<String> = self
            .with_timeout(self.redis.clone().smembers(&user_sessions_key))
            .await?;

        if session_ids.is_empty() {
            debug!("No sessions found for user: {}", user_id);
            return Ok(0);
        }

        let count = session_ids.len() as u64;

        // Build list of session keys to delete
        let session_keys: Vec<String> = session_ids
            .iter()
            .filter_map(|id| Uuid::parse_str(id).ok())
            .map(|id| self.key(&id))
            .collect();

        // Delete all session keys + the user sessions index
        let mut keys_to_delete = session_keys;
        keys_to_delete.push(user_sessions_key.clone());

        let deleted: i64 = self
            .with_timeout(self.redis.clone().del(&keys_to_delete))
            .await?;

        info!(
            "Sessions invalidated for user {}: {} sessions deleted ({} keys removed from Redis)",
            user_id, count, deleted
        );

        Ok(count)
    }

    /// Touch a session (update last_activity_at and reset TTL)
    /// PERFORMANCE: Use pre-allocated buffer for serialization
    pub async fn touch(&mut self, session_id: &Uuid) -> Result<Session, SessionError> {
        let mut session = self.get(session_id).await?;
        session.touch();

        // Reset TTL on activity
        let key = self.key(session_id);
        let mut buffer = String::with_capacity(512);
        serde_json::to_writer(unsafe { buffer.as_mut_vec() }, &session)?;

        let ttl = self.config.ttl_secs;
        self.with_timeout(self.redis.clone().set_ex::<_, _, ()>(&key, &buffer, ttl))
            .await?;

        Ok(session)
    }

    /// Get session and check if token needs refresh
    ///
    /// Returns (session, needs_refresh)
    pub async fn get_with_refresh_check(
        &mut self,
        session_id: &Uuid,
    ) -> Result<(Session, bool), SessionError> {
        let session = self.get(session_id).await?;
        let needs_refresh = session.is_token_expired(self.config.refresh_buffer_secs);

        if needs_refresh {
            debug!(
                "Session {} needs token refresh (expires_at: {}, buffer: {}s)",
                session.id, session.token_expires_at, self.config.refresh_buffer_secs
            );
        }

        Ok((session, needs_refresh))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(
            Uuid::new_v4(),
            "access_token".to_string(),
            "refresh_token".to_string(),
            Utc::now() + chrono::Duration::minutes(15),
            "127.0.0.1".to_string(),
            "Test Agent".to_string(),
        );

        assert!(!session.id.is_nil());
        assert!(!session.is_token_expired(0));
    }

    #[test]
    fn test_token_expiry_check() {
        let session = Session::new(
            Uuid::new_v4(),
            "access_token".to_string(),
            "refresh_token".to_string(),
            Utc::now() + chrono::Duration::seconds(30),
            "127.0.0.1".to_string(),
            "Test Agent".to_string(),
        );

        // Not expired with 0 buffer
        assert!(!session.is_token_expired(0));

        // Expired with 60 second buffer
        assert!(session.is_token_expired(60));
    }
}
