#![allow(dead_code)]
//! Federation Tracing Extensions
//!
//! Provides distributed tracing support for GraphQL federation operations.
//! Integrates with the `tracing` crate and supports trace context propagation.
//!
//! # Features
//!
//! - **Span creation**: Create spans for federation operations with standard attributes
//! - **Context propagation**: Extract/inject trace context from/to HTTP headers
//! - **Operation tracking**: Track subscription lifecycle, cache hits, dedup events
//!
//! # Trace Context Propagation
//!
//! Follows W3C Trace Context specification for header propagation:
//! - `traceparent`: Primary trace context header
//! - `tracestate`: Optional vendor-specific state
//!
//! # Example
//!
//! ```rust
//! use crate::federation::tracing_ext::{FederationSpan, TraceContext};
//!
//! // Extract trace context from incoming request
//! let ctx = TraceContext::from_headers(&headers);
//!
//! // Create a span for a federation operation
//! let span = FederationSpan::subscription_route("OnProductUpdated", "product-catalog");
//! span.set_attribute("subscription.id", &subscription_id);
//!
//! // Propagate context to subgraph request
//! let headers = ctx.to_headers();
//! ```

use std::collections::HashMap;
use std::time::Instant;

use tracing::{debug, info, span, Level, Span};

/// Trace context for distributed tracing
///
/// Represents W3C Trace Context propagated between services.
#[derive(Debug, Clone, Default)]
pub struct TraceContext {
    /// W3C traceparent header value
    pub trace_parent: Option<String>,

    /// W3C tracestate header value
    pub trace_state: Option<String>,

    /// Additional baggage items
    pub baggage: HashMap<String, String>,
}

impl TraceContext {
    /// Create empty trace context
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract trace context from HTTP headers
    pub fn from_headers(headers: &HashMap<String, String>) -> Self {
        Self {
            trace_parent: headers.get("traceparent").cloned(),
            trace_state: headers.get("tracestate").cloned(),
            baggage: Self::parse_baggage(headers.get("baggage")),
        }
    }

    /// Extract trace context from Axum headers
    pub fn from_http_headers(headers: &http::HeaderMap) -> Self {
        Self {
            trace_parent: headers
                .get("traceparent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            trace_state: headers
                .get("tracestate")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string()),
            baggage: headers
                .get("baggage")
                .and_then(|v| v.to_str().ok())
                .map(Self::parse_baggage_str)
                .unwrap_or_default(),
        }
    }

    /// Convert trace context to HTTP headers for propagation
    pub fn to_headers(&self) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        if let Some(ref tp) = self.trace_parent {
            headers.insert("traceparent".to_string(), tp.clone());
        }

        if let Some(ref ts) = self.trace_state {
            headers.insert("tracestate".to_string(), ts.clone());
        }

        if !self.baggage.is_empty() {
            let baggage_str = self
                .baggage
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            headers.insert("baggage".to_string(), baggage_str);
        }

        headers
    }

    /// Add a baggage item
    pub fn with_baggage(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.baggage.insert(key.into(), value.into());
        self
    }

    /// Get a baggage item
    pub fn get_baggage(&self, key: &str) -> Option<&String> {
        self.baggage.get(key)
    }

    /// Check if context has trace information
    pub fn has_trace(&self) -> bool {
        self.trace_parent.is_some()
    }

    fn parse_baggage(header: Option<&String>) -> HashMap<String, String> {
        header
            .map(|s| Self::parse_baggage_str(s.as_str()))
            .unwrap_or_default()
    }

    fn parse_baggage_str(s: &str) -> HashMap<String, String> {
        s.split(',')
            .filter_map(|item| {
                let mut parts = item.splitn(2, '=');
                let key = parts.next()?.trim();
                let value = parts.next()?.trim();
                Some((key.to_string(), value.to_string()))
            })
            .collect()
    }
}

/// Federation operation span for tracing
///
/// Wraps a `tracing::Span` with federation-specific attributes and timing.
pub struct FederationSpan {
    span: Span,
    start_time: Instant,
    operation_type: OperationType,
}

/// Type of federation operation being traced
#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    /// Routing a subscription to a subgraph
    SubscriptionRoute,
    /// Establishing connection to subgraph
    SubgraphConnect,
    /// Sending subscription message
    SubscriptionSend,
    /// Receiving subscription message
    SubscriptionReceive,
    /// Cache lookup
    CacheLookup,
    /// Cache store
    CacheStore,
    /// Deduplication check
    DeduplicationCheck,
    /// Query execution
    QueryExecute,
}

impl OperationType {
    fn as_str(&self) -> &'static str {
        match self {
            OperationType::SubscriptionRoute => "subscription.route",
            OperationType::SubgraphConnect => "subgraph.connect",
            OperationType::SubscriptionSend => "subscription.send",
            OperationType::SubscriptionReceive => "subscription.receive",
            OperationType::CacheLookup => "cache.lookup",
            OperationType::CacheStore => "cache.store",
            OperationType::DeduplicationCheck => "dedup.check",
            OperationType::QueryExecute => "query.execute",
        }
    }
}

impl FederationSpan {
    /// Create a new federation span
    fn new(operation_type: OperationType, name: &str) -> Self {
        let span = span!(
            Level::INFO,
            "federation",
            operation = %operation_type.as_str(),
            name = %name
        );

        Self {
            span,
            start_time: Instant::now(),
            operation_type,
        }
    }

    /// Create a span for subscription routing
    pub fn subscription_route(operation_name: &str, target_subgraph: &str) -> Self {
        let span = Self::new(OperationType::SubscriptionRoute, operation_name);
        span.span.record("subgraph", target_subgraph);
        span
    }

    /// Create a span for subgraph connection
    pub fn subgraph_connect(subgraph_name: &str, url: &str) -> Self {
        let span = Self::new(OperationType::SubgraphConnect, subgraph_name);
        span.span.record("url", url);
        span
    }

    /// Create a span for subscription message send
    pub fn subscription_send(subscription_id: &str) -> Self {
        Self::new(OperationType::SubscriptionSend, subscription_id)
    }

    /// Create a span for subscription message receive
    pub fn subscription_receive(subscription_id: &str) -> Self {
        Self::new(OperationType::SubscriptionReceive, subscription_id)
    }

    /// Create a span for cache lookup
    pub fn cache_lookup(operation_name: Option<&str>) -> Self {
        Self::new(
            OperationType::CacheLookup,
            operation_name.unwrap_or("anonymous"),
        )
    }

    /// Create a span for cache store
    pub fn cache_store(operation_name: Option<&str>) -> Self {
        Self::new(
            OperationType::CacheStore,
            operation_name.unwrap_or("anonymous"),
        )
    }

    /// Create a span for deduplication check
    pub fn deduplication_check(operation_name: Option<&str>) -> Self {
        Self::new(
            OperationType::DeduplicationCheck,
            operation_name.unwrap_or("anonymous"),
        )
    }

    /// Create a span for query execution
    pub fn query_execute(operation_name: Option<&str>, subgraph: &str) -> Self {
        let span = Self::new(
            OperationType::QueryExecute,
            operation_name.unwrap_or("anonymous"),
        );
        span.span.record("subgraph", subgraph);
        span
    }

    /// Set an attribute on the span
    pub fn set_attribute(&self, key: &str, value: &str) {
        self.span.record(key, value);
    }

    /// Set a numeric attribute on the span
    pub fn set_attribute_i64(&self, key: &str, value: i64) {
        self.span.record(key, value);
    }

    /// Set a boolean attribute on the span
    pub fn set_attribute_bool(&self, key: &str, value: bool) {
        self.span.record(key, value);
    }

    /// Mark the span as successful
    pub fn success(self) {
        let duration_ms = self.start_time.elapsed().as_millis();
        info!(
            parent: &self.span,
            duration_ms = duration_ms,
            status = "ok",
            "Federation operation completed"
        );
    }

    /// Mark the span as failed with an error
    pub fn error(self, error: &str) {
        let duration_ms = self.start_time.elapsed().as_millis();
        tracing::error!(
            parent: &self.span,
            duration_ms = duration_ms,
            status = "error",
            error = %error,
            "Federation operation failed"
        );
    }

    /// Get the underlying tracing span
    pub fn span(&self) -> &Span {
        &self.span
    }

    /// Get elapsed time in milliseconds
    pub fn elapsed_ms(&self) -> u128 {
        self.start_time.elapsed().as_millis()
    }

    /// Get the operation type
    pub fn operation_type(&self) -> OperationType {
        self.operation_type
    }
}

/// Federation event for structured logging
#[derive(Debug)]
pub struct FederationEvent {
    /// Event type
    pub event_type: FederationEventType,
    /// Operation name (if applicable)
    pub operation_name: Option<String>,
    /// Subgraph name (if applicable)
    pub subgraph: Option<String>,
    /// Subscription ID (if applicable)
    pub subscription_id: Option<String>,
    /// Connection ID (if applicable)
    pub connection_id: Option<u64>,
    /// Duration in milliseconds (if applicable)
    pub duration_ms: Option<u128>,
    /// Additional context
    pub context: HashMap<String, String>,
}

/// Type of federation event
#[derive(Debug, Clone, Copy)]
pub enum FederationEventType {
    /// Subscription started
    SubscriptionStarted,
    /// Subscription message received
    SubscriptionMessage,
    /// Subscription completed
    SubscriptionCompleted,
    /// Subscription error
    SubscriptionError,
    /// Connection established
    ConnectionEstablished,
    /// Connection closed
    ConnectionClosed,
    /// Connection error
    ConnectionError,
    /// Cache hit
    CacheHit,
    /// Cache miss
    CacheMiss,
    /// Cache store
    CacheStored,
    /// Deduplication leader
    DeduplicationLeader,
    /// Deduplication waiter
    DeduplicationWaiter,
    /// Deduplication completed
    DeduplicationCompleted,
}

impl FederationEvent {
    /// Create a new federation event
    pub fn new(event_type: FederationEventType) -> Self {
        Self {
            event_type,
            operation_name: None,
            subgraph: None,
            subscription_id: None,
            connection_id: None,
            duration_ms: None,
            context: HashMap::new(),
        }
    }

    /// Set operation name
    pub fn with_operation(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }

    /// Set subgraph name
    pub fn with_subgraph(mut self, name: impl Into<String>) -> Self {
        self.subgraph = Some(name.into());
        self
    }

    /// Set subscription ID
    pub fn with_subscription_id(mut self, id: impl Into<String>) -> Self {
        self.subscription_id = Some(id.into());
        self
    }

    /// Set connection ID
    pub fn with_connection_id(mut self, id: u64) -> Self {
        self.connection_id = Some(id);
        self
    }

    /// Set duration
    pub fn with_duration_ms(mut self, duration: u128) -> Self {
        self.duration_ms = Some(duration);
        self
    }

    /// Add context
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Emit the event as a structured log
    pub fn emit(self) {
        let event_name = match self.event_type {
            FederationEventType::SubscriptionStarted => "subscription.started",
            FederationEventType::SubscriptionMessage => "subscription.message",
            FederationEventType::SubscriptionCompleted => "subscription.completed",
            FederationEventType::SubscriptionError => "subscription.error",
            FederationEventType::ConnectionEstablished => "connection.established",
            FederationEventType::ConnectionClosed => "connection.closed",
            FederationEventType::ConnectionError => "connection.error",
            FederationEventType::CacheHit => "cache.hit",
            FederationEventType::CacheMiss => "cache.miss",
            FederationEventType::CacheStored => "cache.stored",
            FederationEventType::DeduplicationLeader => "dedup.leader",
            FederationEventType::DeduplicationWaiter => "dedup.waiter",
            FederationEventType::DeduplicationCompleted => "dedup.completed",
        };

        debug!(
            event = %event_name,
            operation = ?self.operation_name,
            subgraph = ?self.subgraph,
            subscription_id = ?self.subscription_id,
            connection_id = ?self.connection_id,
            duration_ms = ?self.duration_ms,
            context = ?self.context,
            "Federation event"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_from_headers() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string(),
        );
        headers.insert("tracestate".to_string(), "congo=t61rcWkgMzE".to_string());
        headers.insert(
            "baggage".to_string(),
            "userId=alice,serverNode=prod-1".to_string(),
        );

        let ctx = TraceContext::from_headers(&headers);

        assert!(ctx.has_trace());
        assert_eq!(
            ctx.trace_parent,
            Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".to_string())
        );
        assert_eq!(ctx.trace_state, Some("congo=t61rcWkgMzE".to_string()));
        assert_eq!(ctx.get_baggage("userId"), Some(&"alice".to_string()));
        assert_eq!(ctx.get_baggage("serverNode"), Some(&"prod-1".to_string()));
    }

    #[test]
    fn test_trace_context_to_headers() {
        let ctx = TraceContext {
            trace_parent: Some("00-traceid-spanid-01".to_string()),
            trace_state: Some("vendor=state".to_string()),
            baggage: HashMap::from([("key1".to_string(), "value1".to_string())]),
        };

        let headers = ctx.to_headers();

        assert_eq!(
            headers.get("traceparent"),
            Some(&"00-traceid-spanid-01".to_string())
        );
        assert_eq!(headers.get("tracestate"), Some(&"vendor=state".to_string()));
        assert!(headers.get("baggage").unwrap().contains("key1=value1"));
    }

    #[test]
    fn test_empty_trace_context() {
        let ctx = TraceContext::new();
        assert!(!ctx.has_trace());
        assert!(ctx.to_headers().is_empty());
    }

    #[test]
    fn test_baggage_builder() {
        let ctx = TraceContext::new()
            .with_baggage("userId", "alice")
            .with_baggage("requestId", "req-123");

        assert_eq!(ctx.get_baggage("userId"), Some(&"alice".to_string()));
        assert_eq!(ctx.get_baggage("requestId"), Some(&"req-123".to_string()));
    }

    #[test]
    fn test_federation_event_builder() {
        let event = FederationEvent::new(FederationEventType::SubscriptionStarted)
            .with_operation("onProductUpdated")
            .with_subgraph("product-catalog")
            .with_subscription_id("sub-123")
            .with_connection_id(42)
            .with_context("client", "web-app");

        assert_eq!(event.operation_name, Some("onProductUpdated".to_string()));
        assert_eq!(event.subgraph, Some("product-catalog".to_string()));
        assert_eq!(event.subscription_id, Some("sub-123".to_string()));
        assert_eq!(event.connection_id, Some(42));
        assert_eq!(event.context.get("client"), Some(&"web-app".to_string()));
    }
}
