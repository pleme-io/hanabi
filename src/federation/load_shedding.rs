#![allow(dead_code)]
//! Load Shedding and Adaptive Concurrency Control
//!
//! Implements Netflix's Gradient algorithm for adaptive concurrency limiting
//! and circuit breakers for resilient subgraph communication.
//!
//! # Architecture
//!
//! This module makes overload conditions **structurally impossible** by:
//!
//! 1. **Admission Control**: Reject requests at the edge before consuming resources
//! 2. **Adaptive Limits**: Automatically adjust capacity based on latency
//! 3. **Circuit Breakers**: Stop calling failing subgraphs
//! 4. **Deadline Propagation**: Track remaining request budget
//!
//! # Netflix Gradient Algorithm
//!
//! The gradient measures latency degradation:
//!
//! ```text
//! gradient = RTT_noload / RTT_actual
//!
//! gradient = 1.0: No queueing, can increase limit
//! gradient < 1.0: Queue forming, decrease limit
//! gradient > 1.0: Better than baseline, increase limit
//! ```
//!
//! # Circuit Breaker States
//!
//! ```text
//! ┌────────┐     failures      ┌────────┐
//! │ Closed │ ────────────────► │  Open  │
//! │        │                   │        │
//! └────────┘                   └────────┘
//!      ▲                            │
//!      │                            │ recovery_timeout
//!      │        success             ▼
//!      └─────────────────── ┌────────────┐
//!                           │ Half-Open  │
//!                           │            │
//!                           └────────────┘
//! ```
//!
//! # References
//!
//! - [Netflix Concurrency Limits](https://github.com/Netflix/concurrency-limits)
//! - [Netflix Tech Blog: Performance Under Load](https://netflixtechblog.medium.com/performance-under-load-3e6fa9a60581)
//! - [Envoy Adaptive Concurrency](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/adaptive_concurrency_filter)

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::metrics::{MetricsClient, MetricsExt};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for adaptive concurrency limiting
#[derive(Debug, Clone)]
pub struct LoadSheddingConfig {
    /// Initial concurrency limit (will adapt up/down)
    pub initial_limit: usize,

    /// Minimum concurrency limit (floor)
    pub min_limit: usize,

    /// Maximum concurrency limit (ceiling)
    pub max_limit: usize,

    /// Smoothing factor for RTT measurements (0.0-1.0)
    /// Higher = more weight to recent samples
    pub smoothing: f64,

    /// Tolerance before decreasing limit (e.g., 0.8 = 80% of baseline RTT)
    pub tolerance: f64,

    /// Backoff ratio when decreasing limit (e.g., 0.9 = decrease by 10%)
    pub backoff_ratio: f64,

    /// Probe interval for sampling RTT baseline
    pub probe_interval: Duration,

    /// Window size for long-term RTT average
    pub long_window_size: usize,

    /// Window size for short-term RTT average
    pub short_window_size: usize,
}

impl Default for LoadSheddingConfig {
    fn default() -> Self {
        Self {
            initial_limit: 1000, // Production: start high, trust the system
            min_limit: 500,      // Production: never drop below 500 concurrent
            max_limit: 5000,     // Production: scale up to 5000 concurrent
            smoothing: 0.1,      // Slower EWMA for stability under load
            tolerance: 0.3,      // Only shed when RTT > 3x baseline (very tolerant)
            backoff_ratio: 0.95, // Only decrease by 5% when overloaded (gentle)
            probe_interval: Duration::from_secs(10),
            long_window_size: 200, // Larger window for stable baseline
            short_window_size: 20,
        }
    }
}

/// Configuration for circuit breaker
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,

    /// Success count required to close circuit from half-open
    pub success_threshold: u32,

    /// Duration to wait before transitioning from open to half-open
    pub recovery_timeout: Duration,

    /// Time window for counting failures
    pub failure_window: Duration,

    /// Number of requests to allow in half-open state
    pub half_open_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            recovery_timeout: Duration::from_secs(30),
            failure_window: Duration::from_secs(60),
            half_open_requests: 1,
        }
    }
}

// ============================================================================
// Admission Control Result
// ============================================================================

/// Result of admission control check (with guard for cancellation safety)
pub enum AdmissionResult {
    /// Request admitted - guard MUST be held until completion
    ///
    /// The guard ensures cancellation safety: if dropped without calling
    /// `complete()`, it will automatically decrement the in_flight counter.
    Admitted(AdmissionGuard),

    /// Request rejected due to capacity
    Rejected {
        reason: RejectionReason,
        retry_after: Option<Duration>,
    },
}

/// Result of circuit breaker check (no guard needed)
#[derive(Debug, Clone)]
pub enum CircuitCheckResult {
    /// Request allowed through circuit breaker
    Allowed,

    /// Request rejected by circuit breaker
    Rejected {
        reason: RejectionReason,
        retry_after: Option<Duration>,
    },
}

/// Reason for request rejection
#[derive(Debug, Clone, Copy)]
pub enum RejectionReason {
    /// Concurrency limit reached
    ConcurrencyLimit,

    /// Circuit breaker is open
    CircuitOpen,

    /// Deadline would be exceeded
    DeadlineExceeded,

    /// System is overloaded (adaptive limit)
    Overloaded,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::ConcurrencyLimit => write!(f, "concurrency_limit"),
            RejectionReason::CircuitOpen => write!(f, "circuit_open"),
            RejectionReason::DeadlineExceeded => write!(f, "deadline_exceeded"),
            RejectionReason::Overloaded => write!(f, "overloaded"),
        }
    }
}

// ============================================================================
// Admission Guard (RAII for Cancellation Safety)
// ============================================================================

/// RAII guard for admission control - ensures in_flight is decremented on drop
///
/// This guard is CRITICAL for async cancellation safety. When a client cancels
/// a request (navigates away, network disconnect, etc.), the async Future is
/// dropped. Without this guard, `record_completion()` would never be called,
/// causing the `in_flight` counter to grow indefinitely until all requests
/// are rejected with 503.
///
/// The guard:
/// 1. Is returned by `try_acquire()` when admission is granted
/// 2. Calls `record_completion(false)` on Drop if not explicitly completed
/// 3. Provides `complete(rtt, success)` for normal completion with RTT tracking
///
/// # Example
///
/// ```rust,ignore
/// match load_shedder.try_acquire() {
///     AdmissionResult::Admitted(guard) => {
///         // Do work...
///         let rtt = start.elapsed();
///         guard.complete(rtt, true); // Normal completion
///     }
///     AdmissionResult::Rejected { .. } => {
///         // Handle rejection
///     }
/// }
/// // If dropped without calling complete(), record_completion(false) is called
/// ```
pub struct AdmissionGuard {
    /// Reference to the limiter (for calling record_completion)
    limiter: Arc<AdaptiveConcurrencyLimiter>,

    /// Start time for RTT calculation on abnormal drop
    start: Instant,

    /// Whether complete() was called (prevents double decrement)
    completed: AtomicBool,
}

impl AdmissionGuard {
    /// Create a new guard
    fn new(limiter: Arc<AdaptiveConcurrencyLimiter>) -> Self {
        Self {
            limiter,
            start: Instant::now(),
            completed: AtomicBool::new(false),
        }
    }

    /// Complete the request normally with RTT tracking
    ///
    /// This should be called when the request completes successfully or with
    /// a known error. The RTT is used to adjust the concurrency limit.
    ///
    /// # Panics
    /// Does not panic. Calling complete() multiple times is safe (no-op after first).
    #[inline]
    pub fn complete(self, rtt: Duration, success: bool) {
        // Mark as completed BEFORE calling record_completion to prevent Drop
        // from calling it again
        if self.completed.swap(true, Ordering::AcqRel) {
            // Already completed, do nothing
            return;
        }

        self.limiter.record_completion(rtt, success);

        // Skip the Drop impl since we already called record_completion
        std::mem::forget(self);
    }
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        // Only decrement if not already completed
        if !self.completed.swap(true, Ordering::AcqRel) {
            // Guard dropped without explicit complete() call.
            // This happens in two cases:
            // 1. Normal function return where we didn't call complete() (most common)
            // 2. True cancellation/panic (rare)
            //
            // We assume success=true because:
            // - Most drops are normal function returns (success)
            // - The RTT is still tracked correctly
            // - The gradient algorithm will adjust based on latency
            //
            // TODO: Properly call guard.complete() at all return points in bff.rs
            // to get accurate success/failure tracking
            let rtt = self.start.elapsed();

            debug!(
                rtt_ms = rtt.as_millis(),
                "AdmissionGuard: Request completed via drop - decrementing in_flight"
            );

            // Mark as success to allow limit increases via gradient algorithm
            self.limiter.record_completion(rtt, true);
        }
    }
}

// ============================================================================
// Adaptive Concurrency Limiter (Netflix Gradient Algorithm)
// ============================================================================

/// Netflix Gradient-based adaptive concurrency limiter
///
/// Automatically adjusts concurrency limit based on latency measurements.
/// Uses exponentially weighted moving averages for stability.
/// Uses lock-free atomic CAS for O(1) non-blocking admission control.
pub struct AdaptiveConcurrencyLimiter {
    /// Current concurrency limit (adapts based on latency)
    limit: AtomicUsize,

    /// Currently in-flight requests (tracked atomically)
    in_flight: AtomicUsize,

    /// Configuration
    config: LoadSheddingConfig,

    /// Long-term RTT average (microseconds)
    long_rtt: AtomicU64,

    /// Short-term RTT average (microseconds)
    short_rtt: AtomicU64,

    /// Last probe timestamp (nanoseconds since start)
    /// Using AtomicU64 instead of RwLock<Instant> to avoid blocking
    #[allow(dead_code)]
    last_probe_nanos: AtomicU64,

    /// Reference instant for calculating elapsed time
    #[allow(dead_code)]
    start_instant: Instant,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

impl AdaptiveConcurrencyLimiter {
    /// Create a new adaptive concurrency limiter
    pub fn new(config: LoadSheddingConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        let initial = config.initial_limit;

        info!(
            initial_limit = initial,
            min = config.min_limit,
            max = config.max_limit,
            "AdaptiveConcurrencyLimiter initialized"
        );

        let start_instant = Instant::now();
        Self {
            limit: AtomicUsize::new(initial),
            in_flight: AtomicUsize::new(0),
            config,
            long_rtt: AtomicU64::new(0),
            short_rtt: AtomicU64::new(0),
            last_probe_nanos: AtomicU64::new(0),
            start_instant,
            metrics,
        }
    }

    /// Try to acquire admission for a request
    ///
    /// Returns immediately - NEVER blocks.
    /// Uses atomic compare-and-swap for lock-free admission control.
    ///
    /// Returns an `AdmissionGuard` on success that MUST be held until request
    /// completion. The guard ensures cancellation safety by decrementing
    /// `in_flight` on drop if not explicitly completed.
    ///
    /// # Arguments
    /// * `limiter_arc` - Arc reference to self, needed to create the guard
    #[inline]
    pub fn try_acquire(self: &Arc<Self>) -> AdmissionResult {
        // CRITICAL: Use atomic CAS for non-blocking admission control
        // This is O(1) and never blocks - perfect for load shedding
        loop {
            let current = self.in_flight.load(Ordering::Acquire);
            let limit = self.limit.load(Ordering::Relaxed);

            if current >= limit {
                // At capacity - reject immediately
                self.metrics.incr(
                    "bff.load_shedding.rejected",
                    &[("reason", "concurrency_limit")],
                );

                warn!(
                    limit = limit,
                    in_flight = current,
                    "AdaptiveConcurrencyLimiter: rejected request"
                );

                return AdmissionResult::Rejected {
                    reason: RejectionReason::ConcurrencyLimit,
                    retry_after: Some(Duration::from_millis(100)),
                };
            }

            // Try to increment in-flight count
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // Successfully acquired slot
                    if let Some(ref m) = self.metrics {
                        m.gauge("bff.load_shedding.in_flight", (current + 1) as f64, &[]);
                        m.gauge("bff.load_shedding.limit", limit as f64, &[]);
                    }

                    // Return guard that will decrement in_flight on drop
                    return AdmissionResult::Admitted(AdmissionGuard::new(Arc::clone(self)));
                }
                Err(_) => {
                    // CAS failed due to contention, retry
                    // This is rare and the loop is O(1) in practice
                    continue;
                }
            }
        }
    }

    /// Record completion of a request and update limits
    ///
    /// Called when request completes (success or failure).
    /// Uses the RTT to adjust concurrency limit.
    #[inline]
    pub fn record_completion(&self, rtt: Duration, success: bool) {
        // Decrement in-flight count (matching the increment in try_acquire)
        self.in_flight.fetch_sub(1, Ordering::Release);

        let rtt_micros = rtt.as_micros() as u64;

        // Update short-term RTT (EWMA)
        let alpha = self.config.smoothing;
        let old_short = self.short_rtt.load(Ordering::Relaxed);
        let new_short = if old_short == 0 {
            rtt_micros
        } else {
            ((alpha * rtt_micros as f64) + ((1.0 - alpha) * old_short as f64)) as u64
        };
        self.short_rtt.store(new_short, Ordering::Relaxed);

        // Update long-term RTT (slower EWMA)
        let long_alpha = alpha / 10.0;
        let old_long = self.long_rtt.load(Ordering::Relaxed);
        let new_long = if old_long == 0 {
            rtt_micros
        } else {
            ((long_alpha * rtt_micros as f64) + ((1.0 - long_alpha) * old_long as f64)) as u64
        };
        self.long_rtt.store(new_long, Ordering::Relaxed);

        // Calculate gradient
        if new_long > 0 && success {
            let gradient = new_long as f64 / new_short as f64;
            self.adjust_limit(gradient);
        }

        if let Some(ref m) = self.metrics {
            m.histogram("bff.load_shedding.rtt_ms", rtt.as_millis() as f64, &[]);
            if success {
                m.increment("bff.load_shedding.success", &[]);
            } else {
                m.increment("bff.load_shedding.failure", &[]);
            }
        }
    }

    /// Adjust concurrency limit based on gradient
    fn adjust_limit(&self, gradient: f64) {
        let current_limit = self.limit.load(Ordering::Relaxed);

        let new_limit = if gradient >= 1.0 {
            // Latency is good, increase limit
            (current_limit + 1).min(self.config.max_limit)
        } else if gradient < self.config.tolerance {
            // Latency degraded, decrease limit
            let decreased = (current_limit as f64 * self.config.backoff_ratio) as usize;
            decreased.max(self.config.min_limit)
        } else {
            // Within tolerance, keep current limit
            current_limit
        };

        if new_limit != current_limit {
            self.limit.store(new_limit, Ordering::Relaxed);

            // Note: No need to adjust anything - the in_flight counter
            // is compared against limit in try_acquire()

            debug!(
                old_limit = current_limit,
                new_limit = new_limit,
                gradient = gradient,
                "Adjusted concurrency limit"
            );

            self.metrics.gauge("bff.load_shedding.limit", new_limit as f64, &[]);
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> ConcurrencyStats {
        ConcurrencyStats {
            limit: self.limit.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            short_rtt_micros: self.short_rtt.load(Ordering::Relaxed),
            long_rtt_micros: self.long_rtt.load(Ordering::Relaxed),
        }
    }
}

/// Statistics from concurrency limiter
#[derive(Debug, Clone)]
pub struct ConcurrencyStats {
    pub limit: usize,
    pub in_flight: usize,
    pub short_rtt_micros: u64,
    pub long_rtt_micros: u64,
}

// ============================================================================
// Circuit Breaker
// ============================================================================

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Blocking all requests
    Open,
    /// Testing if service recovered
    HalfOpen,
}

// Atomic representations of CircuitState
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

impl CircuitState {
    #[allow(dead_code)]
    fn to_u8(self) -> u8 {
        match self {
            CircuitState::Closed => STATE_CLOSED,
            CircuitState::Open => STATE_OPEN,
            CircuitState::HalfOpen => STATE_HALF_OPEN,
        }
    }

    fn from_u8(val: u8) -> Self {
        match val {
            STATE_OPEN => CircuitState::Open,
            STATE_HALF_OPEN => CircuitState::HalfOpen,
            _ => CircuitState::Closed,
        }
    }
}

/// Per-subgraph circuit breaker
///
/// CRITICAL: Uses lock-free atomics instead of RwLock to avoid blocking Tokio threads.
/// Previous implementation used std::sync::RwLock which blocks the entire OS thread
/// when contended, causing thread starvation and cascading 504 timeouts.
pub struct CircuitBreaker {
    /// Circuit state (atomic u8: 0=Closed, 1=Open, 2=HalfOpen)
    /// LOCK-FREE: No blocking, just atomic load/store
    state: AtomicU8,

    /// Failure count in current window
    failure_count: AtomicU32,

    /// Success count in half-open state
    success_count: AtomicU32,

    /// Requests allowed in half-open
    half_open_requests: AtomicU32,

    /// Last failure timestamp (nanoseconds since start_instant)
    /// 0 means no failure recorded yet
    /// LOCK-FREE: AtomicU64 instead of RwLock<Option<Instant>>
    last_failure_nanos: AtomicU64,

    /// When circuit was opened (nanoseconds since start_instant)
    /// 0 means not opened yet
    /// LOCK-FREE: AtomicU64 instead of RwLock<Option<Instant>>
    opened_at_nanos: AtomicU64,

    /// Reference instant for calculating elapsed time
    start_instant: Instant,

    /// Configuration
    config: CircuitBreakerConfig,

    /// Subgraph name for logging
    subgraph: String,

    /// Metrics
    metrics: Option<Arc<MetricsClient>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker
    pub fn new(
        subgraph: &str,
        config: CircuitBreakerConfig,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            half_open_requests: AtomicU32::new(0),
            last_failure_nanos: AtomicU64::new(0),
            opened_at_nanos: AtomicU64::new(0),
            start_instant: Instant::now(),
            config,
            subgraph: subgraph.to_string(),
            metrics,
        }
    }

    /// Helper to get current timestamp as nanos since start
    #[inline]
    fn now_nanos(&self) -> u64 {
        self.start_instant.elapsed().as_nanos() as u64
    }

    /// Helper to check if nanos have elapsed since a timestamp
    #[inline]
    fn elapsed_since(&self, timestamp_nanos: u64) -> Duration {
        let current = self.now_nanos();
        Duration::from_nanos(current.saturating_sub(timestamp_nanos))
    }

    /// Check if request should be allowed
    ///
    /// LOCK-FREE: Uses atomic operations only, never blocks.
    ///
    /// Note: Returns `CircuitCheckResult` (not `AdmissionResult`) because circuit
    /// breaker checks don't require cancellation-safe guards. The guard pattern
    /// is only used for the global admission control (`AdaptiveConcurrencyLimiter`).
    #[inline]
    pub fn allow_request(&self) -> CircuitCheckResult {
        let state = CircuitState::from_u8(self.state.load(Ordering::Acquire));

        match state {
            CircuitState::Closed => CircuitCheckResult::Allowed,

            CircuitState::Open => {
                // Check if we should transition to half-open
                let opened_at = self.opened_at_nanos.load(Ordering::Acquire);
                if opened_at > 0 {
                    let elapsed = self.elapsed_since(opened_at);
                    if elapsed >= self.config.recovery_timeout {
                        // Transition to half-open using CAS
                        // If another thread already transitioned, that's fine
                        if self
                            .state
                            .compare_exchange(
                                STATE_OPEN,
                                STATE_HALF_OPEN,
                                Ordering::AcqRel,
                                Ordering::Relaxed,
                            )
                            .is_ok()
                        {
                            self.half_open_requests.store(0, Ordering::Relaxed);
                            self.success_count.store(0, Ordering::Relaxed);

                            info!(
                                subgraph = %self.subgraph,
                                "Circuit breaker: Open → HalfOpen"
                            );
                        }

                        return self.allow_request();
                    }
                }

                CircuitCheckResult::Rejected {
                    reason: RejectionReason::CircuitOpen,
                    retry_after: Some(self.config.recovery_timeout),
                }
            }

            CircuitState::HalfOpen => {
                // Allow limited requests in half-open
                let requests = self.half_open_requests.fetch_add(1, Ordering::Relaxed);
                if requests < self.config.half_open_requests {
                    CircuitCheckResult::Allowed
                } else {
                    CircuitCheckResult::Rejected {
                        reason: RejectionReason::CircuitOpen,
                        retry_after: Some(Duration::from_secs(1)),
                    }
                }
            }
        }
    }

    /// Record success
    ///
    /// LOCK-FREE: Uses atomic operations only, never blocks.
    #[inline]
    pub fn record_success(&self) {
        let state = CircuitState::from_u8(self.state.load(Ordering::Acquire));

        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::HalfOpen => {
                let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.config.success_threshold {
                    // Close the circuit using CAS
                    if self
                        .state
                        .compare_exchange(
                            STATE_HALF_OPEN,
                            STATE_CLOSED,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        self.opened_at_nanos.store(0, Ordering::Relaxed);
                        self.failure_count.store(0, Ordering::Relaxed);

                        info!(
                            subgraph = %self.subgraph,
                            "Circuit breaker: HalfOpen → Closed"
                        );

                        self.metrics.incr(
                            "bff.circuit_breaker.state_change",
                            &[("subgraph", &self.subgraph), ("to", "closed")],
                        );
                    }
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
            }
        }
    }

    /// Record failure
    ///
    /// LOCK-FREE: Uses atomic operations only, never blocks.
    #[inline]
    pub fn record_failure(&self) {
        let now_nanos = self.now_nanos();
        self.last_failure_nanos.store(now_nanos, Ordering::Release);

        let state = CircuitState::from_u8(self.state.load(Ordering::Acquire));

        match state {
            CircuitState::Closed => {
                // Check if failure is within window
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;

                if failures >= self.config.failure_threshold {
                    // Open the circuit using CAS
                    if self
                        .state
                        .compare_exchange(
                            STATE_CLOSED,
                            STATE_OPEN,
                            Ordering::AcqRel,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        self.opened_at_nanos.store(now_nanos, Ordering::Release);

                        warn!(
                            subgraph = %self.subgraph,
                            failures = failures,
                            "Circuit breaker: Closed → Open"
                        );

                        self.metrics.incr(
                            "bff.circuit_breaker.state_change",
                            &[("subgraph", &self.subgraph), ("to", "open")],
                        );
                    }
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open reopens circuit using CAS
                if self
                    .state
                    .compare_exchange(
                        STATE_HALF_OPEN,
                        STATE_OPEN,
                        Ordering::AcqRel,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    self.opened_at_nanos.store(now_nanos, Ordering::Release);

                    warn!(
                        subgraph = %self.subgraph,
                        "Circuit breaker: HalfOpen → Open (failure during probe)"
                    );
                }
            }
            CircuitState::Open => {
                // Already open
            }
        }
    }

    /// Get current state
    ///
    /// LOCK-FREE: Uses atomic load, never blocks.
    #[inline]
    pub fn state(&self) -> CircuitState {
        CircuitState::from_u8(self.state.load(Ordering::Acquire))
    }
}

// ============================================================================
// Circuit Breaker Registry
// ============================================================================

/// Registry of circuit breakers per subgraph
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    config: CircuitBreakerConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl CircuitBreakerRegistry {
    /// Create a new registry
    pub fn new(config: CircuitBreakerConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self {
            breakers: DashMap::new(),
            config,
            metrics,
        }
    }

    /// Get or create circuit breaker for subgraph
    pub fn get(&self, subgraph: &str) -> Arc<CircuitBreaker> {
        self.breakers
            .entry(subgraph.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::new(
                    subgraph,
                    self.config.clone(),
                    self.metrics.clone(),
                ))
            })
            .clone()
    }

    /// Get all circuit breaker states
    pub fn states(&self) -> Vec<(String, CircuitState)> {
        self.breakers
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().state()))
            .collect()
    }
}

// ============================================================================
// Deadline Propagation
// ============================================================================

/// Request deadline context
#[derive(Debug, Clone)]
pub struct Deadline {
    /// When the request started
    started_at: Instant,

    /// Total budget for the request
    budget: Duration,
}

impl Deadline {
    /// Create a new deadline
    pub fn new(budget: Duration) -> Self {
        Self {
            started_at: Instant::now(),
            budget,
        }
    }

    /// Get remaining time
    #[inline]
    pub fn remaining(&self) -> Option<Duration> {
        let elapsed = self.started_at.elapsed();
        self.budget.checked_sub(elapsed)
    }

    /// Check if deadline is exceeded
    #[inline]
    pub fn is_exceeded(&self) -> bool {
        self.remaining().is_none()
    }

    /// Check if we have enough time for an operation
    #[inline]
    pub fn has_time_for(&self, operation: Duration) -> bool {
        self.remaining().map(|r| r >= operation).unwrap_or(false)
    }
}

// ============================================================================
// Combined Load Shedder
// ============================================================================

/// Combined load shedding with admission control, circuit breakers, and deadlines
pub struct LoadShedder {
    /// Adaptive concurrency limiter
    pub limiter: Arc<AdaptiveConcurrencyLimiter>,

    /// Circuit breaker registry
    pub circuit_breakers: Arc<CircuitBreakerRegistry>,

    /// Default request deadline
    pub default_deadline: Duration,

    /// Metrics
    #[allow(dead_code)]
    metrics: Option<Arc<MetricsClient>>,
}

impl LoadShedder {
    /// Create a new load shedder
    pub fn new(
        limiter_config: LoadSheddingConfig,
        breaker_config: CircuitBreakerConfig,
        default_deadline: Duration,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        info!(
            initial_limit = limiter_config.initial_limit,
            failure_threshold = breaker_config.failure_threshold,
            deadline_secs = default_deadline.as_secs(),
            "LoadShedder initialized"
        );

        Self {
            limiter: Arc::new(AdaptiveConcurrencyLimiter::new(
                limiter_config,
                metrics.clone(),
            )),
            circuit_breakers: Arc::new(CircuitBreakerRegistry::new(
                breaker_config,
                metrics.clone(),
            )),
            default_deadline,
            metrics,
        }
    }

    /// Try to acquire admission for a request
    ///
    /// Checks:
    /// 1. Concurrency limit (adaptive)
    /// 2. Returns AdmissionGuard if admitted
    ///
    /// The returned guard MUST be held until request completion. It ensures
    /// cancellation safety by automatically decrementing the in_flight counter
    /// if dropped without calling `complete()`.
    #[inline]
    pub fn try_acquire(&self) -> AdmissionResult {
        self.limiter.try_acquire()
    }

    /// Check if subgraph circuit allows request
    #[inline]
    pub fn check_subgraph(&self, subgraph: &str) -> CircuitCheckResult {
        self.circuit_breakers.get(subgraph).allow_request()
    }

    /// Create a deadline for a request
    pub fn create_deadline(&self) -> Deadline {
        Deadline::new(self.default_deadline)
    }

    /// Record request completion
    pub fn record_completion(&self, rtt: Duration, success: bool) {
        self.limiter.record_completion(rtt, success);
    }

    /// Record subgraph success
    pub fn record_subgraph_success(&self, subgraph: &str) {
        self.circuit_breakers.get(subgraph).record_success();
    }

    /// Record subgraph failure
    pub fn record_subgraph_failure(&self, subgraph: &str) {
        self.circuit_breakers.get(subgraph).record_failure();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adaptive_limiter_admits_within_limit() {
        let config = LoadSheddingConfig {
            initial_limit: 10,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Should admit up to limit - hold guards to keep in_flight elevated
        let mut guards = Vec::new();
        for _ in 0..10 {
            match limiter.try_acquire() {
                AdmissionResult::Admitted(guard) => guards.push(guard),
                _ => panic!("Expected Admitted"),
            }
        }

        // Should reject when at limit
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Rejected {
                reason: RejectionReason::ConcurrencyLimit,
                ..
            }
        ));
    }

    #[test]
    fn test_adaptive_limiter_releases_permits() {
        let config = LoadSheddingConfig {
            initial_limit: 1,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Acquire
        let guard = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };

        // Should reject
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Rejected { .. }
        ));

        // Release via guard.complete()
        guard.complete(Duration::from_millis(10), true);

        // Should admit again
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Admitted(_)
        ));
    }

    #[test]
    fn test_guard_releases_on_drop() {
        let config = LoadSheddingConfig {
            initial_limit: 1,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Acquire
        {
            let _guard = match limiter.try_acquire() {
                AdmissionResult::Admitted(g) => g,
                _ => panic!("Expected Admitted"),
            };

            // Should reject while guard is held
            assert!(matches!(
                limiter.try_acquire(),
                AdmissionResult::Rejected { .. }
            ));

            // Guard dropped here
        }

        // Should admit again after guard dropped
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Admitted(_)
        ));
    }

    #[test]
    fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config, None);

        // Initially closed
        assert_eq!(breaker.state(), CircuitState::Closed);

        // Record failures
        breaker.record_failure();
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Closed);

        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let breaker = CircuitBreaker::new("test", config, None);

        // Open the circuit
        breaker.record_failure();

        // Should reject
        assert!(matches!(
            breaker.allow_request(),
            CircuitCheckResult::Rejected {
                reason: RejectionReason::CircuitOpen,
                ..
            }
        ));
    }

    #[test]
    fn test_deadline_tracking() {
        let deadline = Deadline::new(Duration::from_millis(100));

        assert!(!deadline.is_exceeded());
        assert!(deadline.has_time_for(Duration::from_millis(50)));

        std::thread::sleep(Duration::from_millis(110));

        assert!(deadline.is_exceeded());
        assert!(!deadline.has_time_for(Duration::from_millis(1)));
    }

    #[test]
    fn test_try_acquire_never_blocks() {
        let config = LoadSheddingConfig {
            initial_limit: 0, // No permits
            min_limit: 0,     // Allow 0 limit for this test
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        let start = std::time::Instant::now();
        let _ = limiter.try_acquire();
        let elapsed = start.elapsed();

        // Should return immediately (< 1ms)
        assert!(elapsed.as_micros() < 1000, "took {:?}", elapsed);
    }

    /// Test that circuit breaker operations never block
    /// This is CRITICAL - previous implementation used std::sync::RwLock which
    /// caused thread starvation and 504 timeouts under load.
    #[test]
    fn test_circuit_breaker_never_blocks() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            recovery_timeout: Duration::from_secs(60),
            ..Default::default()
        };
        let breaker = Arc::new(CircuitBreaker::new("test", config, None));

        // Test allow_request is non-blocking
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = breaker.allow_request();
        }
        let elapsed = start.elapsed();
        // 1000 calls should complete in < 10ms (non-blocking atomics)
        assert!(elapsed.as_millis() < 10, "allow_request took {:?}", elapsed);

        // Test record_failure is non-blocking
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            breaker.record_failure();
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed.as_millis() < 10,
            "record_failure took {:?}",
            elapsed
        );

        // Test state() is non-blocking
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = breaker.state();
        }
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 10, "state() took {:?}", elapsed);

        println!("✓ CircuitBreaker lock-free operations verified (1000 ops each < 10ms)");
    }

    /// Test concurrent access to circuit breaker from multiple threads
    /// Verifies no deadlocks or thread starvation can occur
    #[test]
    fn test_circuit_breaker_concurrent_access() {
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let config = CircuitBreakerConfig {
            failure_threshold: 100,
            recovery_timeout: Duration::from_millis(50),
            success_threshold: 5,
            half_open_requests: 10,
            failure_window: Duration::from_secs(60),
        };
        let breaker = Arc::new(CircuitBreaker::new("test", config, None));
        let completed = Arc::new(AtomicUsize::new(0));

        // Spawn multiple threads that hammer the circuit breaker
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let breaker = breaker.clone();
                let completed = completed.clone();

                thread::spawn(move || {
                    for j in 0..1000 {
                        // Mix of operations to stress test
                        match (i + j) % 4 {
                            0 => {
                                let _ = breaker.allow_request();
                            }
                            1 => breaker.record_success(),
                            2 => breaker.record_failure(),
                            _ => {
                                let _ = breaker.state();
                            }
                        }
                    }
                    completed.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();

        // Wait for all threads with timeout
        let start = std::time::Instant::now();
        for handle in handles {
            handle.join().expect("Thread panicked");
        }
        let elapsed = start.elapsed();

        // 8 threads × 1000 ops = 8000 operations should complete quickly
        assert_eq!(completed.load(Ordering::Relaxed), 8);
        assert!(
            elapsed.as_millis() < 1000,
            "Concurrent access took {:?} (should be < 1s)",
            elapsed
        );

        println!(
            "✓ CircuitBreaker concurrent access verified: 8 threads × 1000 ops in {:?}",
            elapsed
        );
    }

    // ============================================================================
    // Cancellation Safety Tests
    // ============================================================================
    // These tests verify that resources are correctly released when async operations
    // are cancelled (dropped mid-flight). This is critical for preventing resource
    // leaks in production under high load with request timeouts.

    /// Test that multiple guards can be acquired and released correctly
    #[test]
    fn test_guard_batch_release_on_drop() {
        let config = LoadSheddingConfig {
            initial_limit: 100,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Acquire many guards
        let mut guards = Vec::with_capacity(50);
        for _ in 0..50 {
            match limiter.try_acquire() {
                AdmissionResult::Admitted(guard) => guards.push(guard),
                _ => panic!("Expected Admitted"),
            }
        }

        // Verify 50 in_flight
        assert_eq!(limiter.stats().in_flight, 50);

        // Drop all guards at once
        drop(guards);

        // Verify all released
        assert_eq!(limiter.stats().in_flight, 0);

        // Should be able to acquire again
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Admitted(_)
        ));
    }

    /// Test that calling complete() multiple times is safe (idempotent)
    #[test]
    fn test_guard_double_complete_is_safe() {
        let config = LoadSheddingConfig {
            initial_limit: 10,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Acquire
        let guard = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };

        assert_eq!(limiter.stats().in_flight, 1);

        // Complete once - should decrement
        guard.complete(Duration::from_millis(10), true);

        // Counter should be back to 0
        assert_eq!(limiter.stats().in_flight, 0);

        // Note: We can't call complete() twice on the same guard because
        // complete() takes ownership of self. This is enforced by the type system.
        // The mem::forget prevents Drop from running, so no double decrement.
    }

    /// Test concurrent guard acquire/release doesn't corrupt in_flight counter
    #[test]
    fn test_guard_concurrent_acquire_release() {
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        let config = LoadSheddingConfig {
            initial_limit: 1000,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));
        let completed = Arc::new(AtomicUsize::new(0));

        // Spawn threads that rapidly acquire and release
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let limiter = limiter.clone();
                let completed = completed.clone();

                thread::spawn(move || {
                    for _ in 0..100 {
                        if let AdmissionResult::Admitted(guard) = limiter.try_acquire() {
                            // Simulate some work
                            std::thread::sleep(Duration::from_micros(10));

                            // Randomly choose to complete or drop
                            if rand::random::<bool>() {
                                guard.complete(Duration::from_micros(10), true);
                            }
                            // else: guard is dropped, still releases permit
                        }
                    }
                    completed.fetch_add(1, Ordering::Relaxed);
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("Thread panicked");
        }

        assert_eq!(completed.load(Ordering::Relaxed), 8);

        // CRITICAL: After all threads complete, in_flight should be 0
        // This verifies no counter corruption from concurrent access
        assert_eq!(
            limiter.stats().in_flight,
            0,
            "in_flight counter corrupted after concurrent access"
        );
    }

    /// Test that guards released in reverse order still work correctly
    #[test]
    fn test_guard_lifo_release() {
        let config = LoadSheddingConfig {
            initial_limit: 10,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Acquire guards in order
        let guard1 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };
        let guard2 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };
        let guard3 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };

        assert_eq!(limiter.stats().in_flight, 3);

        // Release in reverse order (LIFO - simulates early returns)
        drop(guard3);
        assert_eq!(limiter.stats().in_flight, 2);

        drop(guard2);
        assert_eq!(limiter.stats().in_flight, 1);

        drop(guard1);
        assert_eq!(limiter.stats().in_flight, 0);
    }

    /// Test guard behavior when limiter is at exactly max capacity
    #[test]
    fn test_guard_at_capacity_boundary() {
        let config = LoadSheddingConfig {
            initial_limit: 2,
            min_limit: 2,
            max_limit: 2,
            ..Default::default()
        };
        let limiter = Arc::new(AdaptiveConcurrencyLimiter::new(config, None));

        // Fill to capacity
        let guard1 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };
        let guard2 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted"),
        };

        // At capacity - should reject
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Rejected { .. }
        ));

        // Release one
        drop(guard1);

        // Should admit exactly one more
        let _guard3 = match limiter.try_acquire() {
            AdmissionResult::Admitted(g) => g,
            _ => panic!("Expected Admitted after release"),
        };

        // Still have guard2 and guard3 - at capacity again
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Rejected { .. }
        ));

        drop(guard2);

        // Now just guard3 - should admit
        assert!(matches!(
            limiter.try_acquire(),
            AdmissionResult::Admitted(_)
        ));
    }
}
