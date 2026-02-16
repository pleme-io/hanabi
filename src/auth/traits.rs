//! Authentication traits for dependency inversion
//!
//! These traits allow auth module to be used without creating
//! circular dependencies with state module.
#![allow(dead_code)]
//!
//! # Architecture
//!
//! The traits define abstract interfaces for authentication operations,
//! allowing other modules to depend on the interface rather than concrete
//! implementations. This breaks the state<->auth circular dependency.
//!
//! ```text
//! ┌─────────────────┐      ┌─────────────────┐
//! │   state module  │      │   auth module   │
//! │                 │      │                 │
//! │ impl SessionStore      │ SessionStore    │
//! │      trait      │◄─────│ trait (here)    │
//! │                 │      │                 │
//! └─────────────────┘      └─────────────────┘
//! ```

use async_trait::async_trait;
use std::sync::Arc;

/// Result type for auth operations
pub type AuthResult<T> = Result<T, AuthError>;

/// Auth-specific error type for trait operations
///
/// This is a simplified error type for the trait interface.
/// Concrete implementations may have richer error types that
/// convert into this.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// Session not found in storage
    #[error("Session not found")]
    SessionNotFound,

    /// Session has expired
    #[error("Session expired")]
    SessionExpired,

    /// Redis connection or operation error
    #[error("Redis error: {0}")]
    Redis(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal error (catch-all)
    #[error("Internal error: {0}")]
    Internal(String),

    /// Operation timed out
    #[error("Operation timed out after {0}s")]
    Timeout(u64),
}

/// Minimal session data structure for trait operations
///
/// This is a simplified view of session data for cross-module
/// communication. The full `Session` struct in `session.rs`
/// contains additional fields like tokens that shouldn't be
/// exposed through the trait interface.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier
    pub id: String,

    /// User ID from auth service
    pub user_id: String,

    /// Product context (e.g., "novaskyn", "myapp")
    pub product: String,

    /// When the session was created (Unix timestamp)
    pub created_at: i64,

    /// When the session expires (Unix timestamp)
    pub expires_at: i64,
}

/// Trait for session storage operations
///
/// Defines the abstract interface for session CRUD operations.
/// Implementations may use Redis, in-memory storage, or other backends.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for use across async tasks.
///
/// # Error Handling
///
/// All operations return `AuthResult` to allow consistent error handling
/// across different storage backends.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Get session by ID
    ///
    /// Returns `None` if session doesn't exist, `Err` on storage errors.
    async fn get(&self, session_id: &str) -> AuthResult<Option<SessionInfo>>;

    /// Store a session
    ///
    /// Creates or updates the session in storage.
    async fn store(&self, session: &SessionInfo) -> AuthResult<()>;

    /// Delete a session
    ///
    /// Removes the session from storage. No-op if session doesn't exist.
    async fn delete(&self, session_id: &str) -> AuthResult<()>;

    /// Refresh session TTL
    ///
    /// Extends the session expiration time without modifying other data.
    async fn refresh(&self, session_id: &str, ttl_secs: u64) -> AuthResult<()>;
}

/// Type alias for shared session store
pub type SharedSessionStore = Arc<dyn SessionStore>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_info_creation() {
        let session = SessionInfo {
            id: "test-session-id".to_string(),
            user_id: "user-123".to_string(),
            product: "novaskyn".to_string(),
            created_at: 1700000000,
            expires_at: 1700086400,
        };

        assert_eq!(session.id, "test-session-id");
        assert_eq!(session.user_id, "user-123");
        assert_eq!(session.product, "novaskyn");
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::SessionNotFound;
        assert_eq!(err.to_string(), "Session not found");

        let err = AuthError::Redis("connection refused".to_string());
        assert_eq!(err.to_string(), "Redis error: connection refused");

        let err = AuthError::Timeout(5);
        assert_eq!(err.to_string(), "Operation timed out after 5s");
    }

    #[test]
    fn test_session_info_serialization() {
        let session = SessionInfo {
            id: "sess-001".to_string(),
            user_id: "user-001".to_string(),
            product: "test-product".to_string(),
            created_at: 1700000000,
            expires_at: 1700086400,
        };

        let json = serde_json::to_string(&session).expect("serialization failed");
        let deserialized: SessionInfo =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(deserialized.id, session.id);
        assert_eq!(deserialized.user_id, session.user_id);
        assert_eq!(deserialized.product, session.product);
    }
}
