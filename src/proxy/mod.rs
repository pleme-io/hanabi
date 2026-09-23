//! L7 HTTP reverse proxy with backend pool and catalog-driven discovery.
//!
//! Routes HTTP requests to backends based on host/path matching rules, with
//! round-robin, random and (pending) least-connections selection.
//!
//! ## Two ways to find a backend, and why
//!
//! `service` names a tatara catalog entry, discovered and health-checked by
//! [`discovery`]. That is the right shape for a cluster; it is the WRONG shape
//! for a home node, where the upstreams are fixed loopback ports and there is
//! no catalog to ask. A route may therefore carry `upstreams` instead — static
//! `host:port` strings, seeded at construction. Without this arm there is no
//! code path at all for a machine with no service catalog, which is every
//! machine this proxy would front today.
//!
//! ## Tier-honest
//!
//! * Forwarded headers and hop-by-hop stripping: DONE (see
//!   [`ProxyService::prepare_headers`]) — this is what makes a downstream's
//!   `trusted_proxies` mean anything.
//! * WebSocket / HTTP upgrade: **NOT SUPPORTED**. `reqwest` cannot proxy an
//!   `Upgrade`, and Home Assistant, node-red, esphome, music-assistant and
//!   go2rtc are all websocket-driven, so their pages would load and then hang
//!   forever. Carrying them means replacing this forwarder with `hyper-util`
//!   plus `hyper::upgrade::on` on both halves. Until then this proxy is honest
//!   for plain HTTP only, and that limit is the reason it is not yet wired
//!   into a front door.
//! * TLS termination: none, by decision. Nothing here terminates.

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

    /// Pool key. With `upstreams` empty this is also the tatara catalog
    /// service name to discover; with `upstreams` set it is just the name.
    pub service: String,

    /// Static upstreams as `host:port`, for a node with no service catalog.
    /// When non-empty, discovery is not consulted for this route.
    #[serde(default)]
    pub upstreams: Vec<String>,

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
    /// A pool seeded at construction, for static upstreams. Sync, because it
    /// runs in `ProxyService::new` before any runtime exists.
    pub fn with_backends(service_name: &str, backends: Vec<Backend>) -> Self {
        Self {
            service_name: service_name.to_string(),
            backends: RwLock::new(backends),
            counter: AtomicUsize::new(0),
        }
    }

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
            // A route with static upstreams is usable immediately; one without
            // stays empty until discovery fills it.
            let seeded: Vec<Backend> = route
                .upstreams
                .iter()
                .filter_map(|u| parse_upstream(u))
                .collect();
            if seeded.len() != route.upstreams.len() {
                warn!(
                    service = %route.service,
                    "one or more upstreams could not be parsed as host:port and were dropped"
                );
            }
            pools.entry(route.service.clone()).or_insert_with(|| {
                if seeded.is_empty() {
                    Arc::new(BackendPool::new(&route.service))
                } else {
                    Arc::new(BackendPool::with_backends(&route.service, seeded.clone()))
                }
            });
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
            let host_match = r
                .host
                .as_ref()
                .map_or(true, |h| host.map_or(false, |req_host| req_host == h));
            path_match && host_match
        })
    }

    /// The headers an upstream should actually see.
    ///
    /// The inbound map is NOT forwarded verbatim. Three things happen, and all
    /// three are load-bearing:
    ///
    /// 1. hop-by-hop headers are dropped ([`HOP_BY_HOP`]) — they describe the
    ///    client's connection to US, not ours to the upstream;
    /// 2. `Host` is rewritten to the backend, because the upstream is
    ///    addressed by its own authority;
    /// 3. the forwarded-for chain is extended, not replaced. `X-Forwarded-For`
    ///    APPENDS (a proxy that overwrites it erases the client), and
    ///    `X-Forwarded-Proto` / `X-Forwarded-Host` / `X-Real-IP` record what
    ///    the client actually asked for.
    ///
    /// Point 3 is what a downstream's `trusted_proxies` reads. Without it, an
    /// application behind this proxy either rejects the request or attributes
    /// every one of them to the proxy's own address.
    pub fn prepare_headers(
        &self,
        mut headers: reqwest::header::HeaderMap,
        backend: &Backend,
        client_ip: Option<std::net::IpAddr>,
        scheme: &str,
    ) -> reqwest::header::HeaderMap {
        use reqwest::header::{HeaderName, HeaderValue};

        let original_host = headers
            .get(reqwest::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        for name in HOP_BY_HOP {
            headers.remove(*name);
        }

        if let Ok(v) = HeaderValue::from_str(&format!("{}:{}", backend.address, backend.port)) {
            headers.insert(reqwest::header::HOST, v);
        }

        if let Some(ip) = client_ip {
            let xff = HeaderName::from_static("x-forwarded-for");
            let chain = match headers.get(&xff).and_then(|v| v.to_str().ok()) {
                Some(existing) => format!("{existing}, {ip}"),
                None => ip.to_string(),
            };
            if let Ok(v) = HeaderValue::from_str(&chain) {
                headers.insert(xff, v);
            }
            if let Ok(v) = HeaderValue::from_str(&ip.to_string()) {
                headers.insert(HeaderName::from_static("x-real-ip"), v);
            }
        }

        if let Ok(v) = HeaderValue::from_str(scheme) {
            headers.insert(HeaderName::from_static("x-forwarded-proto"), v);
        }
        if let Some(h) = original_host {
            if let Ok(v) = HeaderValue::from_str(&h) {
                headers.insert(HeaderName::from_static("x-forwarded-host"), v);
            }
        }

        headers
    }

    /// Forward a request to the appropriate backend.
    ///
    /// ★ PLAIN HTTP ONLY. An `Upgrade` cannot be carried by `reqwest`, so a
    /// websocket route reaches the upstream and then stalls. See the module
    /// header.
    pub async fn forward(
        &self,
        route: &ProxyRoute,
        original_uri: &Uri,
        method: reqwest::Method,
        headers: reqwest::header::HeaderMap,
        body: reqwest::Body,
        client_ip: Option<std::net::IpAddr>,
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

        let scheme = original_uri.scheme_str().unwrap_or("http");
        let headers = self.prepare_headers(headers, &backend, client_ip, scheme);

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

/// `host:port` -> a Backend. Returns None rather than guessing a port: a
/// silently-defaulted 80 would proxy to the wrong service on a home node where
/// every upstream is a distinct loopback port.
pub fn parse_upstream(s: &str) -> Option<Backend> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some(Backend {
        address: host.to_string(),
        port,
        healthy: true,
    })
}

/// Headers that belong to ONE hop and must never be forwarded (RFC 9110
/// §7.6.1). Forwarding `Connection` or `Upgrade` makes an upstream negotiate
/// with the proxy's own connection state; forwarding `Transfer-Encoding` on a
/// re-framed body corrupts it.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

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
                    upstreams: vec![],
                    strategy: LoadBalanceStrategy::RoundRobin,
                    strip_prefix: false,
                    timeout_secs: 30,
                },
                ProxyRoute {
                    path_prefix: "/static".to_string(),
                    host: Some("cdn.example.com".to_string()),
                    service: "cdn".to_string(),
                    upstreams: vec![],
                    strategy: LoadBalanceStrategy::Random,
                    strip_prefix: true,
                    timeout_secs: 60,
                },
            ],
            ..Default::default()
        };

        let proxy = ProxyService::new(config);

        assert!(proxy.match_route("/api/v1/users", None).is_some());
        assert!(proxy
            .match_route("/static/js/app.js", Some("cdn.example.com"))
            .is_some());
        assert!(proxy
            .match_route("/static/js/app.js", Some("other.com"))
            .is_none());
        assert!(proxy.match_route("/unknown", None).is_none());
    }

    #[tokio::test]
    async fn test_backend_pool_round_robin() {
        let pool = BackendPool::new("test");
        pool.update(vec![
            Backend {
                address: "10.0.0.1".to_string(),
                port: 8080,
                healthy: true,
            },
            Backend {
                address: "10.0.0.2".to_string(),
                port: 8080,
                healthy: true,
            },
            Backend {
                address: "10.0.0.3".to_string(),
                port: 8080,
                healthy: false,
            },
        ])
        .await;

        let b1 = pool.next_round_robin().await.unwrap();
        let b2 = pool.next_round_robin().await.unwrap();
        let b3 = pool.next_round_robin().await.unwrap();

        // Should cycle through healthy backends only
        assert_eq!(b1.address, "10.0.0.1");
        assert_eq!(b2.address, "10.0.0.2");
        assert_eq!(b3.address, "10.0.0.1"); // wraps around
    }

    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::net::IpAddr;

    fn route(prefix: &str, upstreams: &[&str]) -> ProxyRoute {
        ProxyRoute {
            path_prefix: prefix.to_string(),
            host: None,
            service: "ha".to_string(),
            upstreams: upstreams.iter().map(|s| s.to_string()).collect(),
            strategy: LoadBalanceStrategy::RoundRobin,
            strip_prefix: false,
            timeout_secs: 30,
        }
    }

    fn service(routes: Vec<ProxyRoute>) -> ProxyService {
        ProxyService::new(ProxyConfig {
            enabled: true,
            routes,
            catalog_url: None,
            poll_interval_secs: 10,
        })
    }

    #[test]
    fn an_upstream_without_a_port_is_refused_not_defaulted() {
        // A silently-defaulted :80 would proxy to the wrong service on a node
        // where every upstream is a distinct loopback port.
        assert!(parse_upstream("127.0.0.1").is_none());
        assert!(parse_upstream(":8123").is_none());
        assert!(parse_upstream("127.0.0.1:not-a-port").is_none());
        let b = parse_upstream("127.0.0.1:8123").expect("host:port parses");
        assert_eq!(b.address, "127.0.0.1");
        assert_eq!(b.port, 8123);
        assert!(b.healthy);
    }

    #[tokio::test]
    async fn static_upstreams_make_a_route_usable_with_no_catalog() {
        // The whole point of the static arm: no discovery has run, and the
        // pool already has a backend.
        let svc = service(vec![route("/", &["127.0.0.1:8123"])]);
        let pool = svc.pools.get("ha").expect("pool seeded");
        assert_eq!(pool.healthy_count().await, 1);
        let b = pool.next_round_robin().await.expect("a backend");
        assert_eq!(b.url(), "http://127.0.0.1:8123");
    }

    #[tokio::test]
    async fn a_route_without_upstreams_waits_for_discovery() {
        let svc = service(vec![route("/", &[])]);
        assert_eq!(svc.pools.get("ha").unwrap().healthy_count().await, 0);
    }

    #[test]
    fn hop_by_hop_headers_do_not_reach_the_upstream() {
        let svc = service(vec![route("/", &["127.0.0.1:8123"])]);
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("upgrade"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("accept", HeaderValue::from_static("text/html"));
        let b = parse_upstream("127.0.0.1:8123").unwrap();

        let out = svc.prepare_headers(h, &b, None, "http");

        for gone in ["connection", "upgrade", "transfer-encoding"] {
            assert!(out.get(gone).is_none(), "{gone} must not be forwarded");
        }
        assert_eq!(out.get("accept").unwrap(), "text/html");
    }

    #[test]
    fn the_forwarded_chain_is_appended_never_replaced() {
        // A proxy that overwrites X-Forwarded-For erases the client, which is
        // exactly what a downstream's trusted_proxies then mis-attributes.
        let svc = service(vec![route("/", &["127.0.0.1:8123"])]);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7"));
        let b = parse_upstream("127.0.0.1:8123").unwrap();
        let ip: IpAddr = "192.168.50.243".parse().unwrap();

        let out = svc.prepare_headers(h, &b, Some(ip), "https");

        assert_eq!(
            out.get("x-forwarded-for").unwrap(),
            "203.0.113.7, 192.168.50.243"
        );
        assert_eq!(out.get("x-real-ip").unwrap(), "192.168.50.243");
        assert_eq!(out.get("x-forwarded-proto").unwrap(), "https");
    }

    #[test]
    fn host_is_rewritten_to_the_backend_and_preserved_as_forwarded_host() {
        let svc = service(vec![route("/", &["127.0.0.1:8123"])]);
        let mut h = HeaderMap::new();
        h.insert(
            "host",
            HeaderValue::from_static("ha.plo.natal.pleme.internal"),
        );
        let b = parse_upstream("127.0.0.1:8123").unwrap();

        let out = svc.prepare_headers(h, &b, None, "http");

        assert_eq!(out.get("host").unwrap(), "127.0.0.1:8123");
        assert_eq!(
            out.get("x-forwarded-host").unwrap(),
            "ha.plo.natal.pleme.internal",
            "the name the client asked for must survive the rewrite"
        );
    }

    #[test]
    fn a_route_matches_by_prefix_and_host() {
        let mut ha = route("/ha", &["127.0.0.1:8123"]);
        ha.host = Some("plo.example".to_string());
        let svc = service(vec![ha]);

        assert!(svc
            .match_route("/ha/lovelace", Some("plo.example"))
            .is_some());
        assert!(svc
            .match_route("/ha/lovelace", Some("other.example"))
            .is_none());
        assert!(svc.match_route("/other", Some("plo.example")).is_none());
    }
}
