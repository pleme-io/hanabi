//! L4 TCP/UDP load balancer for non-HTTP services.
//!
//! Proxies raw TCP/UDP connections to backend pools discovered
//! from tatara's service catalog. Used for databases, NATS, Redis, etc.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// L4 load balancer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct L4Config {
    /// Whether L4 load balancing is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// L4 proxy definitions.
    #[serde(default)]
    pub proxies: Vec<L4Proxy>,
}

/// A single L4 proxy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4Proxy {
    /// Human-readable name.
    pub name: String,

    /// Protocol (tcp or udp).
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Local listen address and port.
    pub listen: String,

    /// Target service name in tatara catalog.
    pub service: String,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

/// Backend address for L4 proxying.
#[derive(Debug, Clone)]
pub struct L4Backend {
    pub address: String,
    pub port: u16,
}

impl L4Backend {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// L4 backend pool with round-robin selection.
pub struct L4BackendPool {
    backends: RwLock<Vec<L4Backend>>,
    counter: AtomicUsize,
}

impl L4BackendPool {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(Vec::new()),
            counter: AtomicUsize::new(0),
        }
    }

    pub async fn update(&self, backends: Vec<L4Backend>) {
        *self.backends.write().await = backends;
    }

    pub async fn next(&self) -> Option<L4Backend> {
        let backends = self.backends.read().await;
        if backends.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[idx].clone())
    }
}

/// Run a TCP proxy listener, forwarding connections to backends.
pub async fn run_tcp_proxy(
    listen_addr: &str,
    pool: Arc<L4BackendPool>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(name, listen = %listen_addr, "L4 TCP proxy listening");

    loop {
        let (inbound, peer_addr) = listener.accept().await?;
        let pool = pool.clone();
        let name = name.to_string();

        tokio::spawn(async move {
            let backend = match pool.next().await {
                Some(b) => b,
                None => {
                    warn!(name = %name, "no backends available");
                    return;
                }
            };

            debug!(
                name = %name,
                peer = %peer_addr,
                backend = %backend.addr(),
                "proxying TCP connection"
            );

            match TcpStream::connect(backend.addr()).await {
                Ok(outbound) => {
                    let (mut ri, mut wi) = tokio::io::split(inbound);
                    let (mut ro, mut wo) = tokio::io::split(outbound);

                    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
                    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

                    tokio::select! {
                        r = client_to_server => {
                            if let Err(e) = r { debug!(error = %e, "client->server copy ended"); }
                        }
                        r = server_to_client => {
                            if let Err(e) = r { debug!(error = %e, "server->client copy ended"); }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        name = %name,
                        backend = %backend.addr(),
                        error = %e,
                        "failed to connect to backend"
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_pool_round_robin() {
        let pool = L4BackendPool::new();
        pool.update(vec![
            L4Backend { address: "10.0.0.1".to_string(), port: 5432 },
            L4Backend { address: "10.0.0.2".to_string(), port: 5432 },
        ]).await;

        let b1 = pool.next().await.unwrap();
        let b2 = pool.next().await.unwrap();
        let b3 = pool.next().await.unwrap();

        assert_eq!(b1.address, "10.0.0.1");
        assert_eq!(b2.address, "10.0.0.2");
        assert_eq!(b3.address, "10.0.0.1");
    }
}
