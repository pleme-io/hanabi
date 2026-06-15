//! Hanabi (花火) - Shared BFF Web Server
//!
//! High-performance web server for serving React/Vite static files with BFF
//! (Backend-for-Frontend) capabilities. Named after Japanese fireworks,
//! representing the brilliant gateway that lights up the frontend experience.

// PERFORMANCE: Use jemalloc as global allocator for 5x faster multi-threaded allocation
#[cfg(all(not(target_env = "msvc"), feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;

use tracing::{info, warn};

// Module declarations
mod auth;
mod bff;
mod builder;
mod config;
mod degraded;
mod error;
mod federation;
mod handlers;
mod health;
mod health_aggregator;
pub mod images;
mod memory;
mod metrics;
mod middleware;
mod preflight;
mod prometheus;
mod providers;
mod rate_limiting;
mod redis;
mod request_context;
mod resources;
mod router;
mod server;
mod state;
mod traits;
mod webhooks;

use config::AppConfig;
use preflight::PreflightChecks;

use pleme_notifications::{
    DependencyStatus, NotificationClient, PodIdentity, StartupReport, PhaseStatus, StartupPhase,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_target(false).init();

    info!("=== Web Server (Pure Rust Stack) ===");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // RESILIENCE: a bad/missing config must NOT CrashLoop the pod. Fall back to a
    // minimal config (sane bind ports) and carry the reason into degraded mode so
    // the failure is served explicitly instead of forcing a log investigation.
    let (config, startup_reason): (Arc<AppConfig>, Option<String>) = match AppConfig::load() {
        Ok(c) => (Arc::new(c), None),
        Err(e) => {
            warn!("Config load failed: {e} — starting in DEGRADED mode");
            (
                Arc::new(degraded_fallback_config()),
                Some(format!("Configuration load failed: {e}")),
            )
        }
    };

    let runtime = if config.server.worker_threads > 0 {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.server.worker_threads)
            .thread_name(format!("{}-worker", config.server.service_name))
            .enable_all()
            .build()?
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .thread_name(format!("{}-worker", config.server.service_name))
            .enable_all()
            .build()?
    };

    runtime.block_on(async_main(config, startup_reason))
}

/// A minimal, always-valid config used only when the real config fails to load,
/// so the degraded server can still bind reachable, scrapeable ports.
fn degraded_fallback_config() -> AppConfig {
    let mut c: AppConfig = serde_yaml::from_str("{}")
        .expect("an empty YAML document must deserialize into a defaulted AppConfig");
    if c.server.http_port == 0 {
        c.server.http_port = 8081;
    }
    if c.server.health_port == 0 {
        c.server.health_port = 8080;
    }
    if c.server.bind_address.is_empty() {
        c.server.bind_address = "0.0.0.0".to_string();
    }
    if c.server.service_name.is_empty() {
        c.server.service_name =
            std::env::var("SERVICE_NAME").unwrap_or_else(|_| "hanabi".to_string());
    }
    c
}

async fn async_main(
    config: Arc<AppConfig>,
    startup_reason: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    server::init_logging(&config);

    info!("=== {} (Pure Rust Stack) ===", config.server.service_name);
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // RESILIENCE: collect any startup-failure reason instead of exiting. A
    // misconfigured hanabi binds its ports and serves an explicit error page
    // (see `degraded`) rather than CrashLooping invisibly — the failure reason
    // is visible in the browser, in `curl`, and on /health/ready + /metrics.
    let mut startup_failure = startup_reason;

    // Download webapp(s) from S3 sources if configured (before preflight checks)
    if startup_failure.is_none() {
        for source in &config.server.webapp_sources {
            if let Err(e) = download_webapp_from_s3(source).await {
                startup_failure = Some(format!(
                    "Failed to download webapp '{}' from S3: {}",
                    source.display_name(),
                    e
                ));
                break;
            }
        }
    }

    // Preflight checks (static assets present, optional React-bundle integrity).
    if startup_failure.is_none() {
        if let Err(e) = PreflightChecks::run_all(&config) {
            startup_failure = Some(format!("Preflight checks failed: {}", e));
        }
    }

    // If anything failed, notify + enter degraded mode (bind ports, serve the
    // explicit reason). Never exit(1) / CrashLoop.
    if let Some(reason) = startup_failure {
        tracing::error!("{reason}");

        let notifier = NotificationClient::from_env(&config.server.service_name);
        let pod_identity = PodIdentity::from_env();
        let report = StartupReport {
            service_name: config.server.service_name.clone(),
            image_tag: std::env::var("IMAGE_TAG")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| std::env::var("GIT_SHA").ok().filter(|s| !s.is_empty()))
                .unwrap_or_else(|| "unknown".to_string()),
            pod_identity,
            cluster_name: std::env::var("DISCORD_CLUSTER_NAME")
                .unwrap_or_else(|_| "unknown".to_string()),
            environment: std::env::var("ENVIRONMENT")
                .unwrap_or_else(|_| "unknown".to_string()),
            total_duration: std::time::Duration::ZERO,
            phases: vec![StartupPhase {
                name: "startup".into(),
                duration: std::time::Duration::ZERO,
                status: PhaseStatus::Failed(reason.clone()),
                detail: None,
            }],
            dependency_status: DependencyStatus::default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".to_string()),
            run_mode: "bff".to_string(),
        };
        notifier.notify_startup_failure(&report, &reason);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        return degraded::run_degraded(&config, reason).await;
    }

    #[allow(unused_mut)]
    let mut sb = builder::ServerBuilder::from_config(config.clone());

    // Register built-in providers based on config
    #[cfg(feature = "google-oauth")]
    if config.bff.oauth.enabled {
        if let Some(p) = providers::google_oauth::GoogleOAuth::from_config(&config.bff.oauth) {
            sb = sb.with_oauth(p);
        }
    }

    #[cfg(feature = "instagram-oauth")]
    if config.bff.oauth.enabled {
        if let Some(p) =
            providers::instagram_oauth::InstagramOAuth::from_config(&config.bff.oauth)
        {
            sb = sb.with_oauth(p);
        }
    }

    #[cfg(feature = "stripe-webhooks")]
    if config.bff.webhooks.enabled {
        if let Some(h) =
            providers::stripe_webhooks::StripeWebhooks::from_config(&config.bff.webhooks)
        {
            sb = sb.with_webhook(h);
        }
    }

    #[cfg(feature = "meta-webhooks")]
    if config.bff.webhooks.enabled {
        if let Some(h) =
            providers::meta_webhooks::MetaWebhooks::from_config(&config.bff.webhooks)
        {
            sb = sb.with_webhook(h);
        }
    }

    #[cfg(feature = "geolocation")]
    if let Some(ext) =
        providers::geolocation::GeolocationExtension::from_config(&config.geolocation)
    {
        sb = sb.with_extension(ext);
    }

    #[cfg(feature = "image-proxy")]
    {
        sb = sb.with_extension(providers::image_proxy::ImageProxyExtension::new());
    }

    sb.build().await.run().await
}

/// Download a webapp archive from S3 and extract it to the source's target directory.
///
/// Uses the `rust-s3` crate to fetch a tar.gz archive from the configured
/// S3 endpoint and extracts it to `target_dir`. This allows decoupling webapp
/// deployments from the BFF container image.
async fn download_webapp_from_s3(
    source: &config::WebappS3Source,
) -> Result<(), Box<dyn std::error::Error>> {
    use flate2::read::GzDecoder;
    use s3::creds::Credentials;
    use s3::{Bucket, Region};
    use std::io::Cursor;
    use tar::Archive;

    info!(
        "Downloading webapp '{}' from S3: {}/{}/{}",
        source.display_name(),
        source.endpoint,
        source.bucket,
        source.key
    );

    let region = Region::Custom {
        region: source.region.clone(),
        endpoint: source.endpoint.clone(),
    };

    // Credentials are OPTIONAL. When no access key is configured, pull
    // anonymously — the case for an internal-network S3 endpoint whose data
    // plane needs no SigV4 (e.g. armázem M0, the pleme-io any-storage→S3
    // gateway, reached over a ClusterIP Service + NetworkPolicy). When a key
    // IS configured, authenticate normally (MinIO/RustFS/Garage with creds).
    let credentials = match (source.get_access_key(), source.get_secret_key()) {
        (Some(access_key), Some(secret_key)) => {
            Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)?
        }
        (None, None) => {
            info!(
                "No S3 credentials configured for webapp source '{}' — pulling anonymously",
                source.display_name()
            );
            Credentials::anonymous()?
        }
        _ => {
            return Err(format!(
                "S3 credentials half-configured for webapp source '{}' — set BOTH access and secret key, or NEITHER (anonymous)",
                source.display_name()
            )
            .into());
        }
    };

    let bucket = Bucket::new(&source.bucket, region, credentials)?;
    let bucket = if source.path_style {
        bucket.with_path_style()
    } else {
        bucket
    };

    let response = bucket.get_object(&source.key).await?;

    if response.status_code() != 200 {
        return Err(format!(
            "S3 returned status {} for {}/{}",
            response.status_code(),
            source.bucket,
            source.key
        )
        .into());
    }

    let bytes = response.bytes();
    info!(
        "Downloaded {} bytes for '{}', extracting to {}",
        bytes.len(),
        source.display_name(),
        source.target_dir
    );

    // Create target_dir if it doesn't exist
    std::fs::create_dir_all(&source.target_dir)?;

    // Extract tar.gz archive
    let cursor = Cursor::new(bytes);
    let gz = GzDecoder::new(cursor);
    let mut archive = Archive::new(gz);
    archive.unpack(&source.target_dir)?;

    info!(
        "Webapp '{}' extracted to {}",
        source.display_name(),
        source.target_dir
    );
    Ok(())
}
