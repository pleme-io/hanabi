#![allow(dead_code)]
//! Unified Request Context
//!
//! This module implements the **Request Context** pattern - a single source of truth
//! that flows through the entire request lifecycle, providing:
//!
//! - **Deadline propagation**: Every operation knows how much time remains
//! - **Cancellation**: All child operations cancel when the request ends
//! - **Observability**: Trace context flows through all operations
//! - **User context**: Auth info available everywhere
//!
//! # Architecture
//!
//! The Request Context follows [gRPC's deadline propagation](https://grpc.io/docs/guides/deadlines/)
//! and [Envoy's request lifecycle](https://www.envoyproxy.io/docs/envoy/latest/intro/life_of_a_request)
//! patterns:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        REQUEST LIFECYCLE                                    │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                                                                             │
//! │  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐     │
//! │  │   INGRESS   │ → │  ADMISSION  │ → │  PROCESSING │ → │   UPSTREAM  │     │
//! │  │   Layer     │   │   Layer     │   │   Layer     │   │   Layer     │     │
//! │  └─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘     │
//! │        │                 │                 │                 │             │
//! │        │                 │                 │                 │             │
//! │        ▼                 ▼                 ▼                 ▼             │
//! │  ┌─────────────────────────────────────────────────────────────────────┐   │
//! │  │                      REQUEST CONTEXT                                │   │
//! │  │  • deadline: Instant (when request MUST complete)                   │   │
//! │  │  • cancel_token: CancellationToken (for request-scoped cancel)      │   │
//! │  │  • trace_id: String (for observability)                             │   │
//! │  │  • user_id: Option<String> (from auth)                              │   │
//! │  │  • start_time: Instant (for latency tracking)                       │   │
//! │  └─────────────────────────────────────────────────────────────────────┘   │
//! │                                                                             │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust
//! // Create context at request entry
//! let ctx = RequestContext::new(Duration::from_secs(30));
//!
//! // Check deadline before any operation
//! if ctx.is_expired() {
//!     return Err(Error::DeadlineExceeded);
//! }
//!
//! // Use remaining time for operations
//! tokio::time::timeout(ctx.remaining(), async_operation()).await?;
//!
//! // Operations can check for cancellation
//! tokio::select! {
//!     result = work() => result,
//!     _ = ctx.cancelled() => Err(Error::Cancelled),
//! }
//! ```
//!
//! # References
//!
//! - [gRPC Deadlines](https://grpc.io/docs/guides/deadlines/)
//! - [Envoy Request Lifecycle](https://www.envoyproxy.io/docs/envoy/latest/intro/life_of_a_request)
//! - [Google SRE - Handling Overload](https://sre.google/sre-book/handling-overload/)
//! - [Tokio CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ============================================================================
// Request Context
// ============================================================================

/// Unified request context that flows through the entire request lifecycle.
///
/// This is the single source of truth for:
/// - **Deadline**: When this request MUST complete (absolute time)
/// - **Cancellation**: Token for request-scoped cancellation
/// - **Observability**: Trace ID for distributed tracing
/// - **Identity**: User information from auth
///
/// # Design Principles
///
/// 1. **Immutable after creation**: Context is created once and shared
/// 2. **Cheap to clone**: Uses Arc internally for shared state
/// 3. **Non-blocking checks**: All methods are O(1) and never block
/// 4. **Hierarchical cancellation**: Child contexts inherit parent's deadline/cancellation
#[derive(Clone)]
pub struct RequestContext {
    inner: Arc<RequestContextInner>,
}

struct RequestContextInner {
    /// Unique request ID for tracing
    request_id: Uuid,

    /// Absolute deadline - when this request MUST complete
    /// All operations should check this before starting work
    deadline: Instant,

    /// Cancellation token for request-scoped cancellation
    /// When cancelled, all child operations should stop
    cancel_token: CancellationToken,

    /// Request start time for latency measurement
    start_time: Instant,

    /// User ID from authentication (if authenticated)
    user_id: Option<String>,

    /// Trace ID for distributed tracing (W3C Trace Context)
    trace_id: Option<String>,

    /// Product scope (e.g., "novaskyn", "myapp")
    product: String,
}

impl RequestContext {
    /// Create a new request context with the given timeout.
    ///
    /// The deadline is calculated as `now + timeout`.
    pub fn new(timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            inner: Arc::new(RequestContextInner {
                request_id: Uuid::new_v4(),
                deadline: now + timeout,
                cancel_token: CancellationToken::new(),
                start_time: now,
                user_id: None,
                trace_id: None,
                product: String::new(),
            }),
        }
    }

    /// Create a context with all fields specified (for advanced use cases).
    pub fn with_details(
        timeout: Duration,
        user_id: Option<String>,
        trace_id: Option<String>,
        product: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            inner: Arc::new(RequestContextInner {
                request_id: Uuid::new_v4(),
                deadline: now + timeout,
                cancel_token: CancellationToken::new(),
                start_time: now,
                user_id,
                trace_id,
                product,
            }),
        }
    }

    /// Create a child context that inherits deadline and cancellation.
    ///
    /// The child context:
    /// - Has same deadline as parent (or earlier if specified)
    /// - Gets cancelled when parent is cancelled
    /// - Has its own request ID (for sub-request tracing)
    pub fn child(&self) -> Self {
        Self {
            inner: Arc::new(RequestContextInner {
                request_id: Uuid::new_v4(),
                deadline: self.inner.deadline, // Inherit deadline
                cancel_token: self.inner.cancel_token.child_token(), // Child token
                start_time: Instant::now(),
                user_id: self.inner.user_id.clone(),
                trace_id: self.inner.trace_id.clone(),
                product: self.inner.product.clone(),
            }),
        }
    }

    /// Create a child context with a tighter deadline.
    ///
    /// The actual deadline will be the minimum of the parent's deadline
    /// and `now + timeout`.
    pub fn child_with_timeout(&self, timeout: Duration) -> Self {
        let now = Instant::now();
        let child_deadline = now + timeout;
        let effective_deadline = self.inner.deadline.min(child_deadline);

        Self {
            inner: Arc::new(RequestContextInner {
                request_id: Uuid::new_v4(),
                deadline: effective_deadline,
                cancel_token: self.inner.cancel_token.child_token(),
                start_time: now,
                user_id: self.inner.user_id.clone(),
                trace_id: self.inner.trace_id.clone(),
                product: self.inner.product.clone(),
            }),
        }
    }

    // ========================================================================
    // Deadline Methods
    // ========================================================================

    /// Check if the deadline has passed.
    ///
    /// This is a fast O(1) check. Use it before starting any operation.
    #[inline]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.inner.deadline
    }

    /// Get the remaining time until deadline.
    ///
    /// Returns `Duration::ZERO` if deadline has passed.
    #[inline]
    pub fn remaining(&self) -> Duration {
        self.inner
            .deadline
            .saturating_duration_since(Instant::now())
    }

    /// Get the absolute deadline.
    #[inline]
    pub fn deadline(&self) -> Instant {
        self.inner.deadline
    }

    /// Check if there's enough time remaining for an operation.
    ///
    /// Returns `true` if `remaining() >= required_time`.
    #[inline]
    pub fn has_time_for(&self, required_time: Duration) -> bool {
        self.remaining() >= required_time
    }

    // ========================================================================
    // Cancellation Methods
    // ========================================================================

    /// Cancel this request context.
    ///
    /// All child contexts will also be cancelled.
    pub fn cancel(&self) {
        self.inner.cancel_token.cancel();
    }

    /// Check if this context has been cancelled.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel_token.is_cancelled()
    }

    /// Wait until this context is cancelled.
    ///
    /// This is useful in `tokio::select!` to cancel an operation.
    pub async fn cancelled(&self) {
        self.inner.cancel_token.cancelled().await
    }

    /// Get a clone of the cancellation token.
    ///
    /// Useful for passing to spawned tasks.
    pub fn cancel_token(&self) -> CancellationToken {
        self.inner.cancel_token.clone()
    }

    // ========================================================================
    // Identity & Tracing
    // ========================================================================

    /// Get the request ID.
    #[inline]
    pub fn request_id(&self) -> Uuid {
        self.inner.request_id
    }

    /// Get the user ID if authenticated.
    #[inline]
    pub fn user_id(&self) -> Option<&str> {
        self.inner.user_id.as_deref()
    }

    /// Get the trace ID for distributed tracing.
    #[inline]
    pub fn trace_id(&self) -> Option<&str> {
        self.inner.trace_id.as_deref()
    }

    /// Get the product scope.
    #[inline]
    pub fn product(&self) -> &str {
        &self.inner.product
    }

    // ========================================================================
    // Metrics
    // ========================================================================

    /// Get elapsed time since request start.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.inner.start_time.elapsed()
    }

    /// Get the request start time.
    #[inline]
    pub fn start_time(&self) -> Instant {
        self.inner.start_time
    }
}

impl std::fmt::Debug for RequestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestContext")
            .field("request_id", &self.inner.request_id)
            .field("remaining", &self.remaining())
            .field("is_cancelled", &self.is_cancelled())
            .field("user_id", &self.inner.user_id)
            .finish()
    }
}

// ============================================================================
// Extension Trait for Easy Integration
// ============================================================================

/// Extension trait for operations that respect request context.
///
/// Provides helper methods for running async operations with context-aware
/// deadline and cancellation.
pub trait RequestContextExt {
    /// Run an async operation with context deadline and cancellation.
    ///
    /// Returns `Err(ContextError::DeadlineExceeded)` if deadline is reached.
    /// Returns `Err(ContextError::Cancelled)` if context is cancelled.
    fn run_with_context<F, T, E>(
        &self,
        ctx: &RequestContext,
        operation: F,
    ) -> impl std::future::Future<Output = Result<T, ContextError<E>>> + Send
    where
        F: std::future::Future<Output = Result<T, E>> + Send,
        T: Send,
        E: Send;
}

/// Error type for context-aware operations.
#[derive(Debug)]
pub enum ContextError<E> {
    /// The operation's deadline was exceeded
    DeadlineExceeded,

    /// The context was cancelled
    Cancelled,

    /// The operation failed with its own error
    Operation(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ContextError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContextError::DeadlineExceeded => write!(f, "deadline exceeded"),
            ContextError::Cancelled => write!(f, "request cancelled"),
            ContextError::Operation(e) => write!(f, "{}", e),
        }
    }
}

impl<E: std::error::Error> std::error::Error for ContextError<E> {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = RequestContext::new(Duration::from_secs(30));

        assert!(!ctx.is_expired());
        assert!(!ctx.is_cancelled());
        assert!(ctx.remaining() <= Duration::from_secs(30));
        assert!(ctx.remaining() > Duration::from_secs(29));
    }

    #[test]
    fn test_context_expiry() {
        let ctx = RequestContext::new(Duration::from_millis(1));

        // Wait for deadline to pass
        std::thread::sleep(Duration::from_millis(5));

        assert!(ctx.is_expired());
        assert_eq!(ctx.remaining(), Duration::ZERO);
    }

    #[test]
    fn test_context_cancellation() {
        let ctx = RequestContext::new(Duration::from_secs(30));

        assert!(!ctx.is_cancelled());

        ctx.cancel();

        assert!(ctx.is_cancelled());
    }

    #[test]
    fn test_child_context_inherits_deadline() {
        let parent = RequestContext::new(Duration::from_secs(10));
        let child = parent.child();

        // Child should have same deadline
        assert_eq!(parent.deadline(), child.deadline());

        // Different request IDs
        assert_ne!(parent.request_id(), child.request_id());
    }

    #[test]
    fn test_child_context_inherits_cancellation() {
        let parent = RequestContext::new(Duration::from_secs(30));
        let child = parent.child();

        assert!(!child.is_cancelled());

        // Cancel parent
        parent.cancel();

        // Child should also be cancelled
        assert!(child.is_cancelled());
    }

    #[test]
    fn test_child_with_tighter_deadline() {
        let parent = RequestContext::new(Duration::from_secs(30));
        let child = parent.child_with_timeout(Duration::from_secs(5));

        // Child should have tighter deadline
        assert!(child.deadline() < parent.deadline());
        assert!(child.remaining() <= Duration::from_secs(5));
    }

    #[test]
    fn test_has_time_for() {
        let ctx = RequestContext::new(Duration::from_secs(10));

        assert!(ctx.has_time_for(Duration::from_secs(5)));
        assert!(!ctx.has_time_for(Duration::from_secs(15)));
    }

    #[tokio::test]
    async fn test_cancelled_future() {
        let ctx = RequestContext::new(Duration::from_secs(30));
        let ctx_clone = ctx.clone();

        // Spawn task to cancel after delay
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            ctx_clone.cancel();
        });

        // Wait for cancellation
        ctx.cancelled().await;

        assert!(ctx.is_cancelled());
    }
}
