//! Catalog-driven backend discovery for the proxy.

use super::{Backend, BackendPool};
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Watches tatara's catalog API and updates backend pools.
pub struct CatalogWatcher {
    catalog_url: String,
    client: Client,
    pools: HashMap<String, Arc<BackendPool>>,
    poll_interval: Duration,
}

#[derive(Debug, Deserialize)]
struct CatalogServiceEntry {
    address: String,
    port: u16,
    health: String,
}

impl CatalogWatcher {
    pub fn new(
        catalog_url: &str,
        pools: HashMap<String, Arc<BackendPool>>,
        poll_interval_secs: u64,
    ) -> Self {
        Self {
            catalog_url: catalog_url.to_string(),
            client: Client::new(),
            pools,
            poll_interval: Duration::from_secs(poll_interval_secs),
        }
    }

    /// Start the polling loop.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        info!(catalog_url = %self.catalog_url, "starting catalog watcher");
        loop {
            tokio::select! {
                _ = tokio::time::sleep(self.poll_interval) => {
                    self.poll_all().await;
                }
                _ = shutdown.changed() => {
                    info!("catalog watcher shutting down");
                    return;
                }
            }
        }
    }

    async fn poll_all(&self) {
        for (service_name, pool) in &self.pools {
            match self.fetch_service(service_name).await {
                Ok(backends) => pool.update(backends).await,
                Err(e) => warn!(service = %service_name, error = %e, "catalog poll failed"),
            }
        }
    }

    async fn fetch_service(&self, service_name: &str) -> Result<Vec<Backend>, String> {
        let url = format!(
            "{}/v1/health/service/{}?passing=true",
            self.catalog_url, service_name
        );

        let resp = self
            .client
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("catalog returned {}", resp.status()));
        }

        let entries: Vec<CatalogServiceEntry> =
            resp.json().await.map_err(|e| e.to_string())?;

        Ok(entries
            .into_iter()
            .map(|e| Backend {
                address: e.address,
                port: e.port,
                healthy: e.health == "passing",
            })
            .collect())
    }
}
