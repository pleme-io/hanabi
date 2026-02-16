//! Health Aggregator Module
//!
//! Provides direct service health polling for product microservices.
//! Bypasses the search service and calls each service's /health or /ready endpoint directly.
//!
//! # Architecture
//! - BFF calls each service's health endpoint directly via HTTP
//! - Frontend calls `directServiceHealth` GraphQL query through BFF
//! - This provides an alternative to the search service's aggregation
//!
//! # Service Health Endpoints
//! Most services expose:
//! - `/health` - Basic health check (HTTP 200 = healthy)
//! - `/ready` - Readiness check (HTTP 200 = ready to serve traffic)
//!
//! # Configuration
//! Services to monitor are defined in the product's YAML config under
//! `health_aggregator.services`. When no services are configured, this
//! endpoint returns an empty array.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::config::ServiceHealthConfig;
use crate::state::AppState;

/// Service health status from direct endpoint polling
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHealthDirect {
    /// Service name (e.g., "auth", "cart", "order")
    pub service_name: String,

    /// Display name for UI (e.g., "Authentication Service")
    pub display_name: String,

    /// Service category
    pub category: String,

    /// Health status (healthy, unhealthy, unknown)
    pub status: HealthStatus,

    /// Latency in milliseconds (time to respond to health check)
    pub latency_ms: Option<u64>,

    /// Error message if unhealthy
    pub error: Option<String>,

    /// Timestamp of health check
    pub checked_at: String,
}

/// Health status enum
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Poll a single service's health endpoint
#[inline]
async fn poll_service_health(
    client: &reqwest::Client,
    service: &ServiceHealthConfig,
) -> ServiceHealthDirect {
    let start = Instant::now();
    let url = format!("{}{}", service.base_url, service.health_path);

    debug!("Polling service health: {} at {}", service.name, url);

    match client
        .get(&url)
        .timeout(Duration::from_secs(5)) // 5s timeout per service
        .send()
        .await
    {
        Ok(response) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let status = response.status();

            if status.is_success() {
                info!(
                    "Service {} healthy ({}ms): {}",
                    service.name, latency_ms, url
                );
                ServiceHealthDirect {
                    service_name: service.name.clone(),
                    display_name: service.display_name.clone(),
                    category: service.category.clone(),
                    status: HealthStatus::Healthy,
                    latency_ms: Some(latency_ms),
                    error: None,
                    checked_at: chrono::Utc::now().to_rfc3339(),
                }
            } else {
                warn!(
                    "Service {} unhealthy (HTTP {}): {}",
                    service.name, status, url
                );
                ServiceHealthDirect {
                    service_name: service.name.clone(),
                    display_name: service.display_name.clone(),
                    category: service.category.clone(),
                    status: HealthStatus::Unhealthy,
                    latency_ms: Some(latency_ms),
                    error: Some(format!("HTTP {}", status)),
                    checked_at: chrono::Utc::now().to_rfc3339(),
                }
            }
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            error!(
                "Service {} health check failed: {} - {}",
                service.name, url, e
            );
            ServiceHealthDirect {
                service_name: service.name.clone(),
                display_name: service.display_name.clone(),
                category: service.category.clone(),
                status: HealthStatus::Unhealthy,
                latency_ms: Some(latency_ms),
                error: Some(e.to_string()),
                checked_at: chrono::Utc::now().to_rfc3339(),
            }
        }
    }
}

/// Handler for direct service health aggregation
///
/// This endpoint polls all configured services directly and returns their health status.
/// Services are configured via `health_aggregator.services` in the product's YAML config.
/// When no services are configured, returns an empty array.
///
/// # Response Format
/// Returns a JSON array of ServiceHealthDirect objects.
///
/// # Performance
/// - Polls all services in parallel using tokio::spawn
/// - 5s timeout per service
/// - Total response time ~= slowest service health check time
pub async fn direct_service_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let services = &state.config.health_aggregator.services;

    if services.is_empty() {
        debug!("Health aggregator: no services configured, returning empty array");
        return (StatusCode::OK, Json(Vec::<ServiceHealthDirect>::new())).into_response();
    }

    info!(
        "Direct service health check requested ({} services)",
        services.len()
    );

    // Get HTTP client from state
    let client = match state.http_client() {
        Some(c) => c.clone(),
        None => {
            error!("HTTP client not initialized - cannot poll services (BFF may be disabled)");
            state.incr("health_aggregator.http_client_unavailable", &[]);
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "errors": [{
                        "message": "Health aggregator unavailable - HTTP client not initialized",
                        "extensions": {
                            "code": "SERVICE_UNAVAILABLE",
                            "retryAfter": 5
                        }
                    }]
                })),
            )
                .into_response();
        }
    };

    // Poll all services in parallel
    let start = Instant::now();
    let mut tasks = Vec::new();

    for service in services {
        let client = client.clone();
        let service = service.clone();
        tasks.push(tokio::spawn(async move {
            poll_service_health(&client, &service).await
        }));
    }

    // Wait for all health checks to complete
    let mut results = Vec::new();
    for task in tasks {
        match task.await {
            Ok(health) => results.push(health),
            Err(e) => {
                error!("Health check task panicked: {}", e);
            }
        }
    }

    let total_latency = start.elapsed();
    info!(
        "Direct service health check completed: {} services, {}ms total",
        results.len(),
        total_latency.as_millis()
    );

    // Emit metrics
    state.histogram(
        "health_aggregator.poll.latency",
        total_latency.as_millis() as f64,
        &[],
    );
    state.gauge(
        "health_aggregator.services.total",
        results.len() as f64,
        &[],
    );
    let healthy_count = results
        .iter()
        .filter(|r| matches!(r.status, HealthStatus::Healthy))
        .count();
    state.gauge(
        "health_aggregator.services.healthy",
        healthy_count as f64,
        &[],
    );

    (StatusCode::OK, Json(results)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialization() {
        let healthy = ServiceHealthDirect {
            service_name: "test".to_string(),
            display_name: "Test Service".to_string(),
            category: "core".to_string(),
            status: HealthStatus::Healthy,
            latency_ms: Some(42),
            error: None,
            checked_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_value(&healthy).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["serviceName"], "test");
    }
}
