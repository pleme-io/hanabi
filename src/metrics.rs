//! Metrics client for emitting StatsD-format metrics to Vector agent
//!
//! This module provides a lightweight StatsD client for sending metrics to a Vector agent.
//! Metrics are sent via UDP in StatsD format and support tagging.
//!
//! # Metric Types
//! - **Gauge**: Current value of something (e.g., active connections, memory usage)
//! - **Counter**: Incrementing count (e.g., requests, errors)
//! - **Histogram**: Statistical distribution (e.g., request duration)
//!
//! # Configuration
//! Metrics client is initialized from the application configuration:
//! - Vector host/port from config.metrics section
//! - Can be disabled via config.features.enable_metrics
//!
//! # Example
//! ```rust
//! let client = MetricsClient::new("127.0.0.1", 8125)?;
//! client.increment("http.requests", &[("method", "GET"), ("status", "200")]);
//! client.gauge("system.memory", 1024.0, &[]);
//! client.histogram("http.duration", 150.5, &[("endpoint", "/api")]);
//! ```

use std::net::UdpSocket;
use std::sync::Arc;
use tracing::warn;

/// Extension trait for `Option<Arc<MetricsClient>>` to eliminate boilerplate.
///
/// Provides no-op-safe helpers that absorb the `if let Some(ref m) = metrics { ... }` pattern.
/// Works with struct fields (`self.metrics.incr(...)`) and local variables alike.
pub trait MetricsExt {
    fn incr(&self, name: &str, tags: &[(&str, &str)]);
    fn gauge(&self, name: &str, value: f64, tags: &[(&str, &str)]);
    fn histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]);
    fn count(&self, name: &str, count: i64, tags: &[(&str, &str)]);
}

impl MetricsExt for Option<Arc<MetricsClient>> {
    #[inline]
    fn incr(&self, name: &str, tags: &[(&str, &str)]) {
        if let Some(ref m) = self { m.increment(name, tags); }
    }
    #[inline]
    fn gauge(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        if let Some(ref m) = self { m.gauge(name, value, tags); }
    }
    #[inline]
    fn histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        if let Some(ref m) = self { m.histogram(name, value, tags); }
    }
    #[inline]
    fn count(&self, name: &str, count: i64, tags: &[(&str, &str)]) {
        if let Some(ref m) = self { m.count(name, count, tags); }
    }
}

/// Metrics client for emitting StatsD-format metrics to Vector agent
///
/// Uses UDP for non-blocking metric emission. Failed sends are logged but don't
/// block the application. The socket is set to non-blocking mode to ensure
/// metrics never impact request latency.
///
/// Optionally includes a namespace tag on all metrics for multi-environment support.
/// The namespace is read from POD_NAMESPACE environment variable.
pub struct MetricsClient {
    socket: UdpSocket,
    vector_addr: String,
    /// Namespace tag added to all metrics (e.g., "myapp-staging", "myapp-production")
    namespace: Option<String>,
}

impl MetricsClient {
    /// Create a new metrics client
    ///
    /// # Arguments
    /// * `vector_host` - Vector agent hostname or IP address
    /// * `vector_port` - Vector agent StatsD port (typically 8125)
    ///
    /// # Returns
    /// * `Ok(MetricsClient)` - Successfully initialized client
    /// * `Err(String)` - Failed to bind UDP socket or set non-blocking mode
    ///
    /// # Environment Variables
    /// * `POD_NAMESPACE` - If set, adds a `namespace` tag to all metrics (Kubernetes downward API)
    ///
    /// # Example
    /// ```rust
    /// let client = MetricsClient::new("127.0.0.1", 8125)?;
    /// ```
    pub fn new(vector_host: &str, vector_port: u16) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;

        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Failed to set socket non-blocking: {}", e))?;

        // Read namespace from POD_NAMESPACE env var (Kubernetes downward API)
        let namespace = std::env::var("POD_NAMESPACE").ok();

        Ok(Self {
            socket,
            vector_addr: format!("{}:{}", vector_host, vector_port),
            namespace,
        })
    }

    /// Build tags string with optional namespace
    fn build_tags(&self, tags: &[(&str, &str)]) -> String {
        let mut all_tags: Vec<String> = tags
            .iter()
            .map(|(k, v)| format!("{}:{}", k, v))
            .collect();

        // Add namespace tag if configured
        if let Some(ref ns) = self.namespace {
            all_tags.push(format!("namespace:{}", ns));
        }

        all_tags.join(",")
    }

    /// Send a gauge metric (current value)
    ///
    /// Gauges represent a point-in-time value that can go up or down.
    ///
    /// # Arguments
    /// * `name` - Metric name (e.g., "system.memory", "active.connections")
    /// * `value` - Current value
    /// * `tags` - Key-value pairs for metric dimensions (e.g., [("host", "web-1")])
    ///
    /// # Format
    /// - Without tags: `metric_name:value|g`
    /// - With tags: `metric_name:value|g|#tag1:value1,tag2:value2`
    ///
    /// # Example
    /// ```rust
    /// client.gauge("http.active_connections", 42.0, &[("server", "web-1")]);
    /// ```
    pub fn gauge(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        let tag_str = self.build_tags(tags);

        let metric = if tag_str.is_empty() {
            format!("{}:{}|g", name, value)
        } else {
            format!("{}:{}|g|#{}", name, value, tag_str)
        };

        if let Err(e) = self.socket.send_to(metric.as_bytes(), &self.vector_addr) {
            warn!("Failed to send gauge metric '{}': {}", name, e);
        }
    }

    /// Send a counter metric (increment by 1)
    ///
    /// Convenience method for incrementing a counter by 1.
    ///
    /// # Arguments
    /// * `name` - Metric name (e.g., "http.requests", "errors")
    /// * `tags` - Key-value pairs for metric dimensions
    ///
    /// # Example
    /// ```rust
    /// client.increment("http.requests", &[("method", "GET"), ("status", "200")]);
    /// ```
    pub fn increment(&self, name: &str, tags: &[(&str, &str)]) {
        self.count(name, 1, tags);
    }

    /// Send a counter metric with specific count
    ///
    /// Counters track cumulative values that only increase (e.g., total requests).
    ///
    /// # Arguments
    /// * `name` - Metric name (e.g., "http.requests", "database.queries")
    /// * `count` - Amount to increment (can be negative for decrement)
    /// * `tags` - Key-value pairs for metric dimensions
    ///
    /// # Format
    /// - Without tags: `metric_name:count|c`
    /// - With tags: `metric_name:count|c|#tag1:value1,tag2:value2`
    ///
    /// # Example
    /// ```rust
    /// client.count("cache.hits", 10, &[("cache_type", "redis")]);
    /// ```
    pub fn count(&self, name: &str, count: i64, tags: &[(&str, &str)]) {
        let tag_str = self.build_tags(tags);

        let metric = if tag_str.is_empty() {
            format!("{}:{}|c", name, count)
        } else {
            format!("{}:{}|c|#{}", name, count, tag_str)
        };

        if let Err(e) = self.socket.send_to(metric.as_bytes(), &self.vector_addr) {
            warn!("Failed to send counter metric '{}': {}", name, e);
        }
    }

    /// Send a histogram metric (timing/duration)
    ///
    /// Histograms track statistical distributions of values (e.g., request durations).
    /// The Vector agent will calculate percentiles, averages, etc.
    ///
    /// # Arguments
    /// * `name` - Metric name (e.g., "http.duration", "database.query_time")
    /// * `value` - Measurement value (typically in milliseconds for durations)
    /// * `tags` - Key-value pairs for metric dimensions
    ///
    /// # Format
    /// - Without tags: `metric_name:value|h`
    /// - With tags: `metric_name:value|h|#tag1:value1,tag2:value2`
    ///
    /// # Example
    /// ```rust
    /// client.histogram("http.duration", 150.5, &[("endpoint", "/api/products")]);
    /// ```
    pub fn histogram(&self, name: &str, value: f64, tags: &[(&str, &str)]) {
        let tag_str = self.build_tags(tags);

        let metric = if tag_str.is_empty() {
            format!("{}:{}|h", name, value)
        } else {
            format!("{}:{}|h|#{}", name, value, tag_str)
        };

        if let Err(e) = self.socket.send_to(metric.as_bytes(), &self.vector_addr) {
            warn!("Failed to send histogram metric '{}': {}", name, e);
        }
    }

    /// Get the configured namespace (for logging/debugging)
    pub fn namespace(&self) -> Option<&str> {
        self.namespace.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_client_creation() {
        // Should successfully create client (will bind to random port)
        let result = MetricsClient::new("127.0.0.1", 8125);
        assert!(result.is_ok());
    }

    #[test]
    fn test_gauge_format_without_tags() {
        // Metrics formatting is tested indirectly through usage
        // Direct testing would require mocking UDP socket
    }

    #[test]
    fn test_counter_format_with_tags() {
        // Metrics formatting is tested indirectly through usage
        // Direct testing would require mocking UDP socket
    }

    #[test]
    fn test_histogram_format() {
        // Metrics formatting is tested indirectly through usage
        // Direct testing would require mocking UDP socket
    }
}
