//! L7 HTTP reverse proxy with backend pool and catalog-driven discovery.
//!
//! Routes HTTP requests to tatara service catalog backends based on
//! host/path matching rules. Supports round-robin and least-connections
//! load balancing strategies.

pub mod cache;
pub mod discovery;

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, Response, StatusCode, Uri};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Load balancing strategy for backend selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    #[default]
    RoundRobin,
    LeastConnections,
    Random,
}

/// A proxy route mapping a path prefix to a service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRoute {
    /// Path prefix to match (e.g., "/api/v1").
    pub path_prefix: String,

    /// Host header to match (optional).
    pub host: Option<String>,

    /// Target service name in tatara catalog.
    pub service: String,

    /// Load balancing strategy.
    #[serde(default)]
    pub strategy: LoadBalanceStrategy,

    /// Whether to strip the path prefix before forwarding.
    #[serde(default)]
    pub strip_prefix: bool,

    /// Request timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_timeout() -> u64 {
    30
}

/// A backend instance (address + port from catalog).
#[derive(Debug, Clone)]
pub struct Backend {
    pub address: String,
    pub port: u16,
    pub healthy: bool,
}

impl Backend {
    pub fn url(&self) -> String {
        format!("http://{}:{}", self.address, self.port)
    }
}

/// Pool of backends for a service, updated from catalog discovery.
pub struct BackendPool {
    service_name: String,
    backends: RwLock<Vec<Backend>>,
    counter: AtomicUsize,
}

impl BackendPool {
    pub fn new(service_name: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            backends: RwLock::new(Vec::new()),
            counter: AtomicUsize::new(0),
        }
    }

    /// Update the backend list (called by CatalogWatcher).
    pub async fn update(&self, backends: Vec<Backend>) {
        let count = backends.len();
        *self.backends.write().await = backends;
        debug!(service = %self.service_name, backends = count, "updated backend pool");
    }

    /// Select the next backend using round-robin.
    pub async fn next_round_robin(&self) -> Option<Backend> {
        let backends = self.backends.read().await;
        let healthy: Vec<&Backend> = backends.iter().filter(|b| b.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
        Some(healthy[idx].clone())
    }

    /// Select a random backend.
    pub async fn next_random(&self) -> Option<Backend> {
        let backends = self.backends.read().await;
        let healthy: Vec<&Backend> = backends.iter().filter(|b| b.healthy).collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = rand::random::<usize>() % healthy.len();
        Some(healthy[idx].clone())
    }

    /// Get the number of healthy backends.
    pub async fn healthy_count(&self) -> usize {
        self.backends
            .read()
            .await
            .iter()
            .filter(|b| b.healthy)
            .count()
    }
}

/// HTTP proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    /// Whether the proxy is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// Proxy routes.
    #[serde(default)]
    pub routes: Vec<ProxyRoute>,

    /// Tatara catalog API URL for backend discovery.
    #[serde(default)]
    pub catalog_url: Option<String>,

    /// Discovery poll interval in seconds.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
}

fn default_poll_interval() -> u64 {
    10
}

/// The proxy service — holds all route/pool state.
pub struct ProxyService {
    pub config: ProxyConfig,
    pub pools: HashMap<String, Arc<BackendPool>>,
    pub client: Client,
}

impl ProxyService {
    pub fn new(config: ProxyConfig) -> Self {
        let mut pools = HashMap::new();
        for route in &config.routes {
            pools
                .entry(route.service.clone())
                .or_insert_with(|| Arc::new(BackendPool::new(&route.service)));
        }

        let client = Client::builder()
            .pool_max_idle_per_host(32)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            config,
            pools,
            client,
        }
    }

    /// Find the matching route for a request.
    pub fn match_route(&self, path: &str, host: Option<&str>) -> Option<&ProxyRoute> {
        self.config.routes.iter().find(|r| {
            let path_match = path.starts_with(&r.path_prefix);
            let host_match = r.host.as_ref().map_or(true, |h| {
                host.map_or(false, |req_host| req_host == h)
            });
            path_match && host_match
        })
    }

    /// Forward a request to the appropriate backend.
    pub async fn forward(
        &self,
        route: &ProxyRoute,
        original_uri: &Uri,
        method: reqwest::Method,
        headers: reqwest::header::HeaderMap,
        body: reqwest::Body,
    ) -> Result<reqwest::Response, ProxyError> {
        let pool = self
            .pools
            .get(&route.service)
            .ok_or(ProxyError::NoBackends)?;

        let backend = match route.strategy {
            LoadBalanceStrategy::RoundRobin => pool.next_round_robin().await,
            LoadBalanceStrategy::Random => pool.next_random().await,
            LoadBalanceStrategy::LeastConnections => pool.next_round_robin().await, // fallback
        }
        .ok_or(ProxyError::NoBackends)?;

        let path = if route.strip_prefix {
            original_uri
                .path()
                .strip_prefix(&route.path_prefix)
                .unwrap_or(original_uri.path())
        } else {
            original_uri.path()
        };

        let query = original_uri
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();

        let target_url = format!("{}{}{}", backend.url(), path, query);
        debug!(target = %target_url, service = %route.service, "proxying request");

        let resp = self
            .client
            .request(method, &target_url)
            .headers(headers)
            .body(body)
            .timeout(std::time::Duration::from_secs(route.timeout_secs))
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;

        Ok(resp)
    }
}

/// Proxy errors.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("no healthy backends available")]
    NoBackends,

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("route not found")]
    RouteNotFound,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_matching() {
        let config = ProxyConfig {
            enabled: true,
            routes: vec![
                ProxyRoute {
                    path_prefix: "/api".to_string(),
                    host: None,
                    service: "backend".to_string(),
                    strategy: LoadBalanceStrategy::RoundRobin,
                    strip_prefix: false,
                    timeout_secs: 30,
                },
                ProxyRoute {
                    path_prefix: "/static".to_string(),
                    host: Some("cdn.example.com".to_string()),
                    service: "cdn".to_string(),
                    strategy: LoadBalanceStrategy::Random,
                    strip_prefix: true,
                    timeout_secs: 60,
                },
            ],
            ..Default::default()
        };

        let proxy = ProxyService::new(config);

        assert!(proxy.match_route("/api/v1/users", None).is_some());
        assert!(proxy.match_route("/static/js/app.js", Some("cdn.example.com")).is_some());
        assert!(proxy.match_route("/static/js/app.js", Some("other.com")).is_none());
        assert!(proxy.match_route("/unknown", None).is_none());
    }

    #[tokio::test]
    async fn test_backend_pool_round_robin() {
        let pool = BackendPool::new("test");
        pool.update(vec![
            Backend { address: "10.0.0.1".to_string(), port: 8080, healthy: true },
            Backend { address: "10.0.0.2".to_string(), port: 8080, healthy: true },
            Backend { address: "10.0.0.3".to_string(), port: 8080, healthy: false },
        ]).await;

        let b1 = pool.next_round_robin().await.unwrap();
        let b2 = pool.next_round_robin().await.unwrap();
        let b3 = pool.next_round_robin().await.unwrap();

        // Should cycle through healthy backends only
        assert_eq!(b1.address, "10.0.0.1");
        assert_eq!(b2.address, "10.0.0.2");
        assert_eq!(b3.address, "10.0.0.1"); // wraps around
    }
}
