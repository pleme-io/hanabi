//! Prometheus metrics for frontend telemetry
//!
//! This module provides Prometheus-format metrics that are scraped by Prometheus
//! via the `/metrics` endpoint. These metrics are designed to match the Grafana
//! dashboard expectations for frontend observability.
//!
//! # Metrics Exposed
//!
//! ## Web Vitals (Histograms)
//! - `frontend_lcp_seconds` - Largest Contentful Paint
//! - `frontend_cls` - Cumulative Layout Shift (unitless)
//! - `frontend_inp_seconds` - Interaction to Next Paint
//! - `frontend_fcp_seconds` - First Contentful Paint
//! - `frontend_ttfb_seconds` - Time to First Byte
//!
//! ## Rating Counters
//! - `frontend_vitals_good_total` - Count of "good" ratings per metric
//! - `frontend_vitals_needs_improvement_total` - Count of "needs-improvement" ratings
//! - `frontend_vitals_poor_total` - Count of "poor" ratings
//!
//! ## Event Counters
//! - `frontend_events_total` - User interaction events
//! - `frontend_errors_total` - Frontend errors
//! - `frontend_telemetry_events_received_total` - Total telemetry events received
//!
//! # Labels
//!
//! All metrics include these labels for filtering:
//! - `namespace` - Kubernetes namespace (e.g., "myapp-staging")
//! - `product` - Product identifier (e.g., "myapp")
//! - `page` - Sanitized page path (e.g., "/products/:id")

use once_cell::sync::Lazy;
use prometheus::{
    register_counter_vec, register_histogram_vec, CounterVec, Encoder, HistogramVec, TextEncoder,
};

// =============================================================================
// WEB VITALS HISTOGRAMS
// =============================================================================

/// LCP (Largest Contentful Paint) histogram in milliseconds
/// Good: <2500ms, Needs Improvement: 2500-4000ms, Poor: >4000ms
pub static FRONTEND_LCP: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "frontend_lcp",
        "Largest Contentful Paint in milliseconds",
        &["namespace", "product", "page"],
        // Buckets aligned with Web Vitals thresholds (in milliseconds)
        vec![
            500.0, 1000.0, 1500.0, 2000.0, 2500.0, 3000.0, 3500.0, 4000.0, 5000.0, 7500.0, 10000.0
        ]
    )
    .expect("Failed to create frontend_lcp histogram")
});

/// CLS (Cumulative Layout Shift) histogram (unitless score)
/// Good: <0.1, Needs Improvement: 0.1-0.25, Poor: >0.25
pub static FRONTEND_CLS: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "frontend_cls",
        "Cumulative Layout Shift score",
        &["namespace", "product", "page"],
        // Buckets aligned with CLS thresholds
        vec![0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.25, 0.5, 1.0]
    )
    .expect("Failed to create frontend_cls histogram")
});

/// INP (Interaction to Next Paint) histogram in milliseconds
/// Good: <200ms, Needs Improvement: 200-500ms, Poor: >500ms
pub static FRONTEND_INP: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "frontend_inp",
        "Interaction to Next Paint in milliseconds",
        &["namespace", "product", "page"],
        // Buckets aligned with INP thresholds (in milliseconds)
        vec![50.0, 100.0, 150.0, 200.0, 300.0, 400.0, 500.0, 750.0, 1000.0, 2000.0]
    )
    .expect("Failed to create frontend_inp histogram")
});

/// FCP (First Contentful Paint) histogram in milliseconds
/// Good: <1800ms, Needs Improvement: 1800-3000ms, Poor: >3000ms
pub static FRONTEND_FCP: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "frontend_fcp",
        "First Contentful Paint in milliseconds",
        &["namespace", "product", "page"],
        // Buckets aligned with FCP thresholds (in milliseconds)
        vec![500.0, 1000.0, 1500.0, 1800.0, 2000.0, 2500.0, 3000.0, 4000.0, 5000.0, 7500.0]
    )
    .expect("Failed to create frontend_fcp histogram")
});

/// TTFB (Time to First Byte) histogram in milliseconds
/// Good: <800ms, Needs Improvement: 800-1800ms, Poor: >1800ms
pub static FRONTEND_TTFB: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "frontend_ttfb",
        "Time to First Byte in milliseconds",
        &["namespace", "product", "page"],
        // Buckets aligned with TTFB thresholds (in milliseconds)
        vec![100.0, 200.0, 400.0, 600.0, 800.0, 1000.0, 1200.0, 1500.0, 1800.0, 2500.0, 5000.0]
    )
    .expect("Failed to create frontend_ttfb histogram")
});

// =============================================================================
// WEB VITALS RATING COUNTERS
// =============================================================================

/// Counter for "good" Web Vitals ratings
pub static FRONTEND_VITALS_GOOD: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_vitals_good_total",
        "Count of good Web Vitals ratings",
        &["namespace", "product", "metric", "page"]
    )
    .expect("Failed to create frontend_vitals_good_total counter")
});

/// Counter for "needs-improvement" Web Vitals ratings
pub static FRONTEND_VITALS_NEEDS_IMPROVEMENT: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_vitals_needs_improvement_total",
        "Count of needs-improvement Web Vitals ratings",
        &["namespace", "product", "metric", "page"]
    )
    .expect("Failed to create frontend_vitals_needs_improvement_total counter")
});

/// Counter for "poor" Web Vitals ratings
pub static FRONTEND_VITALS_POOR: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_vitals_poor_total",
        "Count of poor Web Vitals ratings",
        &["namespace", "product", "metric", "page"]
    )
    .expect("Failed to create frontend_vitals_poor_total counter")
});

// =============================================================================
// EVENT COUNTERS
// =============================================================================

/// Counter for frontend user events
pub static FRONTEND_EVENTS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_events_total",
        "Count of frontend user events",
        &["namespace", "product", "name", "page"]
    )
    .expect("Failed to create frontend_events_total counter")
});

/// Counter for frontend errors
pub static FRONTEND_ERRORS: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_errors_total",
        "Count of frontend errors",
        &["namespace", "product", "name", "page"]
    )
    .expect("Failed to create frontend_errors_total counter")
});

/// Counter for total telemetry events received
pub static FRONTEND_TELEMETRY_EVENTS_RECEIVED: Lazy<CounterVec> = Lazy::new(|| {
    register_counter_vec!(
        "frontend_telemetry_events_received_total",
        "Total telemetry events received from frontend",
        &["namespace", "product"]
    )
    .expect("Failed to create frontend_telemetry_events_received_total counter")
});

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/// Record a Web Vital metric value
///
/// # Arguments
/// * `metric_name` - The Web Vital name (LCP, CLS, INP, FCP, TTFB)
/// * `value` - The raw value from the browser (milliseconds for timing metrics, unitless for CLS)
/// * `rating` - The rating from web-vitals library ("good", "needs-improvement", "poor")
/// * `namespace` - Kubernetes namespace
/// * `product` - Product identifier
/// * `page` - Sanitized page path
pub fn record_web_vital(
    metric_name: &str,
    value: f64,
    rating: &str,
    namespace: &str,
    product: &str,
    page: &str,
) {
    // Record histogram observation (value is already in the correct unit from browser)
    match metric_name {
        "LCP" => {
            FRONTEND_LCP
                .with_label_values(&[namespace, product, page])
                .observe(value);
        }
        "CLS" => {
            FRONTEND_CLS
                .with_label_values(&[namespace, product, page])
                .observe(value);
        }
        "INP" => {
            FRONTEND_INP
                .with_label_values(&[namespace, product, page])
                .observe(value);
        }
        "FCP" => {
            FRONTEND_FCP
                .with_label_values(&[namespace, product, page])
                .observe(value);
        }
        "TTFB" => {
            FRONTEND_TTFB
                .with_label_values(&[namespace, product, page])
                .observe(value);
        }
        _ => {
            // Unknown metric, skip
            tracing::warn!(metric = metric_name, "Unknown Web Vital metric");
        }
    }

    // Record rating counter
    match rating {
        "good" => {
            FRONTEND_VITALS_GOOD
                .with_label_values(&[namespace, product, metric_name, page])
                .inc();
        }
        "needs-improvement" => {
            FRONTEND_VITALS_NEEDS_IMPROVEMENT
                .with_label_values(&[namespace, product, metric_name, page])
                .inc();
        }
        "poor" => {
            FRONTEND_VITALS_POOR
                .with_label_values(&[namespace, product, metric_name, page])
                .inc();
        }
        _ => {
            // Unknown rating, default to poor
            FRONTEND_VITALS_POOR
                .with_label_values(&[namespace, product, metric_name, page])
                .inc();
        }
    }
}

/// Record a frontend event
pub fn record_frontend_event(namespace: &str, product: &str, event_name: &str, page: &str) {
    FRONTEND_EVENTS
        .with_label_values(&[namespace, product, event_name, page])
        .inc();
}

/// Record a frontend error
pub fn record_frontend_error(namespace: &str, product: &str, error_name: &str, page: &str) {
    FRONTEND_ERRORS
        .with_label_values(&[namespace, product, error_name, page])
        .inc();
}

/// Record telemetry events received count
pub fn record_telemetry_received(namespace: &str, product: &str, count: u64) {
    FRONTEND_TELEMETRY_EVENTS_RECEIVED
        .with_label_values(&[namespace, product])
        .inc_by(count as f64);
}

/// Render all Prometheus metrics as text for the /metrics endpoint
pub fn render_metrics() -> String {
    // Force lazy initialization of all metrics
    // This ensures they appear in output even with zero values
    let _ = &*FRONTEND_LCP;
    let _ = &*FRONTEND_CLS;
    let _ = &*FRONTEND_INP;
    let _ = &*FRONTEND_FCP;
    let _ = &*FRONTEND_TTFB;
    let _ = &*FRONTEND_VITALS_GOOD;
    let _ = &*FRONTEND_VITALS_NEEDS_IMPROVEMENT;
    let _ = &*FRONTEND_VITALS_POOR;
    let _ = &*FRONTEND_EVENTS;
    let _ = &*FRONTEND_ERRORS;
    let _ = &*FRONTEND_TELEMETRY_EVENTS_RECEIVED;

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();

    encoder
        .encode(&metric_families, &mut buffer)
        .expect("Failed to encode metrics");

    String::from_utf8(buffer).expect("Metrics are valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_web_vital_lcp() {
        // Record a good LCP value (2000ms = 2s)
        record_web_vital("LCP", 2000.0, "good", "test-staging", "test-product", "/home");

        // Verify metric was recorded (we can't easily check the value, but this shouldn't panic)
    }

    #[test]
    fn test_record_web_vital_cls() {
        // Record a CLS value (unitless, should not be divided by 1000)
        record_web_vital("CLS", 0.05, "good", "test-staging", "test-product", "/products");
    }

    #[test]
    fn test_render_metrics() {
        let output = render_metrics();
        // Should contain our metric names
        assert!(
            output.contains("frontend_lcp") || output.contains("# HELP"),
            "Metrics output should contain Prometheus format"
        );
    }
}
