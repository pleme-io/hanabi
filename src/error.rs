//! Centralized error types and error handling
//!
//! This module provides consistent error types and GraphQL-compatible error responses
//! for the web server and BFF proxy.
//!
//! # Error Philosophy
//! - Errors are designed for GraphQL compatibility (errors array format)
//! - Extension codes for programmatic error handling (e.g., "BFF_DISABLED")
//! - Human-readable messages for debugging
//! - Metrics-friendly error categorization
#![allow(dead_code)]

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::fmt;

/// Error category for determining recovery action
///
/// Each category maps to a specific recovery strategy:
/// - Transient: Retry with exponential backoff
/// - Degraded: Circuit break + fallback
/// - Permanent: Fail fast, no retry
/// - Fatal: Graceful shutdown required
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Transient error - retry with exponential backoff
    Transient,
    /// Degraded state - circuit break + fallback
    Degraded,
    /// Permanent error - fail fast, no retry
    Permanent,
    /// Fatal error - graceful shutdown required
    Fatal,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transient => write!(f, "transient"),
            Self::Degraded => write!(f, "degraded"),
            Self::Permanent => write!(f, "permanent"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

/// Recovery action for error handling
///
/// Provides concrete recovery strategies based on error category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Retry with exponential backoff
    RetryWithBackoff {
        /// Maximum number of retry attempts
        max_attempts: u32,
        /// Base delay in milliseconds (will be multiplied by 2^attempt)
        base_delay_ms: u64,
    },
    /// Circuit break and use fallback
    CircuitBreakAndFallback,
    /// Fail immediately
    FailFast,
    /// Trigger graceful shutdown
    GracefulShutdown,
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RetryWithBackoff {
                max_attempts,
                base_delay_ms,
            } => {
                write!(
                    f,
                    "retry_with_backoff(max={}, base_delay={}ms)",
                    max_attempts, base_delay_ms
                )
            }
            Self::CircuitBreakAndFallback => write!(f, "circuit_break_and_fallback"),
            Self::FailFast => write!(f, "fail_fast"),
            Self::GracefulShutdown => write!(f, "graceful_shutdown"),
        }
    }
}

/// Application error type for BFF and web server operations
///
/// Provides structured errors with:
/// - HTTP status code
/// - Error code for programmatic handling
/// - Human-readable message
/// - Optional additional context
#[derive(Debug, Clone)]
pub struct AppError {
    /// HTTP status code to return
    pub status: StatusCode,

    /// Error code for programmatic handling (e.g., "BFF_DISABLED", "CONFIG_INVALID")
    pub code: String,

    /// Human-readable error message
    pub message: String,

    /// Optional additional context for debugging
    pub details: Option<String>,
}

impl AppError {
    /// Create a new application error
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    /// Add additional context to the error
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    // =========================================================================
    // Common Error Constructors
    // =========================================================================

    /// BFF is disabled via configuration
    pub fn bff_disabled() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BFF_DISABLED",
            "BFF is disabled. Configure frontend to use Hive Router directly.",
        )
    }

    /// BFF mode is set to "disabled"
    pub fn bff_mode_disabled() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "BFF_MODE_DISABLED",
            "BFF mode is disabled",
        )
    }

    /// Invalid BFF mode configuration
    pub fn bff_invalid_mode(mode: &str) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BFF_INVALID_MODE",
            "Invalid BFF mode configuration",
        )
        .with_details(format!("Unknown mode: {}", mode))
    }

    /// HTTP client not initialized
    pub fn http_client_not_initialized() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "BFF_CLIENT_ERROR",
            "BFF proxy not properly initialized",
        )
        .with_details("HTTP client not initialized - BFF cannot function without client")
    }

    /// Failed to reach upstream service (Hive Router)
    pub fn upstream_error(error: impl fmt::Display) -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "BFF_UPSTREAM_ERROR",
            format!("Failed to reach Hive Router: {}", error),
        )
    }

    /// Upstream service timeout
    pub fn upstream_timeout() -> Self {
        Self::new(
            StatusCode::GATEWAY_TIMEOUT,
            "BFF_UPSTREAM_TIMEOUT",
            "Hive Router request timed out",
        )
    }

    /// Failed to parse upstream response
    pub fn parse_error(error: impl fmt::Display) -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "BFF_PARSE_ERROR",
            "Failed to parse upstream response",
        )
        .with_details(format!("Parse error: {}", error))
    }

    /// Configuration validation error
    pub fn config_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR", message)
    }

    /// File not found error
    pub fn not_found(path: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", "Resource not found")
            .with_details(path.into())
    }

    /// Internal server error with context
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", message)
    }

    // =========================================================================
    // Error Categorization
    // =========================================================================

    /// Determine the error category based on error code
    ///
    /// Categories determine recovery strategy:
    /// - Transient: Network issues, timeouts - retry with backoff
    /// - Degraded: Service issues - circuit break + fallback
    /// - Permanent: Client errors - fail fast
    /// - Fatal: Configuration/initialization errors - graceful shutdown
    pub fn category(&self) -> ErrorCategory {
        match self.code.as_str() {
            // Transient errors - retry with exponential backoff
            "BFF_UPSTREAM_TIMEOUT" => ErrorCategory::Transient,
            "BFF_UPSTREAM_ERROR" => {
                // Network errors are transient, but could be degraded for 5xx
                // Default to transient since upstream_error is typically connection issues
                ErrorCategory::Transient
            }

            // Degraded state - circuit break + fallback
            "INTERNAL_ERROR" => ErrorCategory::Degraded,

            // Permanent errors - fail fast, no retry
            "BFF_DISABLED" => ErrorCategory::Permanent,
            "BFF_MODE_DISABLED" => ErrorCategory::Permanent,
            "BFF_PARSE_ERROR" => ErrorCategory::Permanent,
            "NOT_FOUND" => ErrorCategory::Permanent,

            // Fatal errors - graceful shutdown required
            "CONFIG_ERROR" => ErrorCategory::Fatal,
            "BFF_INVALID_MODE" => ErrorCategory::Fatal,
            "BFF_CLIENT_ERROR" => ErrorCategory::Fatal,

            // Default to degraded for unknown errors (safe default)
            _ => ErrorCategory::Degraded,
        }
    }

    /// Get the recommended recovery action for this error
    ///
    /// Maps error category to concrete recovery strategy.
    pub fn recovery_action(&self) -> RecoveryAction {
        match self.category() {
            ErrorCategory::Transient => RecoveryAction::RetryWithBackoff {
                max_attempts: 3,
                base_delay_ms: 100,
            },
            ErrorCategory::Degraded => RecoveryAction::CircuitBreakAndFallback,
            ErrorCategory::Permanent => RecoveryAction::FailFast,
            ErrorCategory::Fatal => RecoveryAction::GracefulShutdown,
        }
    }

    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        self.category() == ErrorCategory::Transient
    }

    /// Check if this error requires circuit breaking
    pub fn requires_circuit_break(&self) -> bool {
        self.category() == ErrorCategory::Degraded
    }

    /// Check if this error is fatal and requires shutdown
    pub fn is_fatal(&self) -> bool {
        self.category() == ErrorCategory::Fatal
    }

    /// Emit metrics for this error
    pub fn emit_metrics(&self, metrics: &crate::metrics::MetricsClient) {
        let category_tag = match self.category() {
            ErrorCategory::Transient => "transient",
            ErrorCategory::Degraded => "degraded",
            ErrorCategory::Permanent => "permanent",
            ErrorCategory::Fatal => "fatal",
        };

        metrics.increment(
            "error.total",
            &[("category", category_tag), ("code", &self.code)],
        );

        // Additional metrics for specific recovery actions
        match self.recovery_action() {
            RecoveryAction::RetryWithBackoff { max_attempts, .. } => {
                metrics.increment(
                    "error.retryable",
                    &[("max_attempts", &max_attempts.to_string())],
                );
            }
            RecoveryAction::CircuitBreakAndFallback => {
                metrics.increment("error.circuit_break_triggered", &[]);
            }
            _ => {}
        }
    }
}

/// Emit metric for retry attempt
pub fn emit_retry_metric(metrics: &crate::metrics::MetricsClient, attempt: u32, succeeded: bool) {
    if succeeded {
        metrics.increment(
            "healing.retry.succeeded",
            &[("attempt", &attempt.to_string())],
        );
    } else {
        metrics.increment(
            "healing.retry.attempt",
            &[("attempt", &attempt.to_string())],
        );
    }
}

/// Emit metric for retry exhaustion
pub fn emit_retry_exhausted_metric(metrics: &crate::metrics::MetricsClient, total_attempts: u32) {
    metrics.increment(
        "healing.retry.exhausted",
        &[("attempts", &total_attempts.to_string())],
    );
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)?;
        if let Some(details) = &self.details {
            write!(f, " ({})", details)?;
        }
        Ok(())
    }
}

impl std::error::Error for AppError {}

/// Convert AppError into an Axum HTTP response
///
/// Returns a JSON response in GraphQL errors format:
/// ```json
/// {
///   "errors": [{
///     "message": "Error message",
///     "extensions": {
///       "code": "ERROR_CODE",
///       "details": "Optional details"
///     }
///   }]
/// }
/// ```
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let mut error_obj = json!({
            "message": self.message,
            "extensions": {
                "code": self.code,
            }
        });

        // Add details if present
        if let Some(details) = self.details {
            if let Some(extensions) = error_obj.get_mut("extensions") {
                if let Some(ext_obj) = extensions.as_object_mut() {
                    ext_obj.insert("details".to_string(), Value::String(details));
                }
            }
        }

        let body = json!({
            "errors": [error_obj]
        });

        (self.status, Json(body)).into_response()
    }
}

/// Result type alias using AppError
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = AppError::bff_disabled();
        assert_eq!(
            format!("{}", error),
            "[BFF_DISABLED] BFF is disabled. Configure frontend to use Hive Router directly."
        );
    }

    #[test]
    fn test_error_with_details() {
        let error =
            AppError::internal("Something went wrong").with_details("Database connection failed");
        assert!(format!("{}", error).contains("Database connection failed"));
    }

    #[test]
    fn test_error_response_format() {
        let error = AppError::bff_disabled();
        let response = error.into_response();

        // Response should be 503 Service Unavailable
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // =========================================================================
    // Error Categorization Tests
    // =========================================================================

    #[test]
    fn test_transient_error_category() {
        // Upstream timeout should be transient
        let error = AppError::upstream_timeout();
        assert_eq!(error.category(), ErrorCategory::Transient);
        assert!(error.is_retryable());
        assert!(!error.is_fatal());

        // Upstream error should be transient
        let error = AppError::upstream_error("connection refused");
        assert_eq!(error.category(), ErrorCategory::Transient);
        assert!(error.is_retryable());
    }

    #[test]
    fn test_degraded_error_category() {
        // Internal error should be degraded
        let error = AppError::internal("something went wrong");
        assert_eq!(error.category(), ErrorCategory::Degraded);
        assert!(error.requires_circuit_break());
        assert!(!error.is_retryable());
    }

    #[test]
    fn test_permanent_error_category() {
        // BFF disabled should be permanent
        let error = AppError::bff_disabled();
        assert_eq!(error.category(), ErrorCategory::Permanent);
        assert!(!error.is_retryable());

        // Not found should be permanent
        let error = AppError::not_found("/some/path");
        assert_eq!(error.category(), ErrorCategory::Permanent);

        // Parse error should be permanent
        let error = AppError::parse_error("invalid json");
        assert_eq!(error.category(), ErrorCategory::Permanent);
    }

    #[test]
    fn test_fatal_error_category() {
        // Config error should be fatal
        let error = AppError::config_error("missing required field");
        assert_eq!(error.category(), ErrorCategory::Fatal);
        assert!(error.is_fatal());

        // HTTP client not initialized should be fatal
        let error = AppError::http_client_not_initialized();
        assert_eq!(error.category(), ErrorCategory::Fatal);
        assert!(error.is_fatal());

        // Invalid BFF mode should be fatal
        let error = AppError::bff_invalid_mode("unknown");
        assert_eq!(error.category(), ErrorCategory::Fatal);
    }

    #[test]
    fn test_recovery_action_retry() {
        let error = AppError::upstream_timeout();
        let action = error.recovery_action();

        match action {
            RecoveryAction::RetryWithBackoff {
                max_attempts,
                base_delay_ms,
            } => {
                assert_eq!(max_attempts, 3);
                assert_eq!(base_delay_ms, 100);
            }
            _ => panic!("Expected RetryWithBackoff for transient error"),
        }
    }

    #[test]
    fn test_recovery_action_circuit_break() {
        let error = AppError::internal("service error");
        assert_eq!(
            error.recovery_action(),
            RecoveryAction::CircuitBreakAndFallback
        );
    }

    #[test]
    fn test_recovery_action_fail_fast() {
        let error = AppError::not_found("/missing");
        assert_eq!(error.recovery_action(), RecoveryAction::FailFast);
    }

    #[test]
    fn test_recovery_action_shutdown() {
        let error = AppError::config_error("fatal config issue");
        assert_eq!(error.recovery_action(), RecoveryAction::GracefulShutdown);
    }

    #[test]
    fn test_error_category_display() {
        assert_eq!(format!("{}", ErrorCategory::Transient), "transient");
        assert_eq!(format!("{}", ErrorCategory::Degraded), "degraded");
        assert_eq!(format!("{}", ErrorCategory::Permanent), "permanent");
        assert_eq!(format!("{}", ErrorCategory::Fatal), "fatal");
    }

    #[test]
    fn test_recovery_action_display() {
        assert_eq!(
            format!(
                "{}",
                RecoveryAction::RetryWithBackoff {
                    max_attempts: 3,
                    base_delay_ms: 100
                }
            ),
            "retry_with_backoff(max=3, base_delay=100ms)"
        );
        assert_eq!(
            format!("{}", RecoveryAction::CircuitBreakAndFallback),
            "circuit_break_and_fallback"
        );
        assert_eq!(format!("{}", RecoveryAction::FailFast), "fail_fast");
        assert_eq!(
            format!("{}", RecoveryAction::GracefulShutdown),
            "graceful_shutdown"
        );
    }
}
