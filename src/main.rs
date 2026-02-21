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

    let config = Arc::new(AppConfig::load()?);

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

    runtime.block_on(async_main(config))
}

async fn async_main(config: Arc<AppConfig>) -> Result<(), Box<dyn std::error::Error>> {
    server::init_logging(&config);

    info!("=== {} (Pure Rust Stack) ===", config.server.service_name);
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Download webapp(s) from S3 sources if configured (before preflight checks)
    for source in &config.server.webapp_sources {
        if let Err(e) = download_webapp_from_s3(source).await {
            tracing::error!(
                "Failed to download webapp '{}' from S3: {}",
                source.display_name(),
                e
            );
            std::process::exit(1);
        }
    }

    if let Err(e) = PreflightChecks::run_all(&config) {
        tracing::error!("Preflight checks failed: {}", e);

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
                name: "preflight".into(),
                duration: std::time::Duration::ZERO,
                status: PhaseStatus::Failed(e.to_string()),
                detail: None,
            }],
            dependency_status: DependencyStatus::default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".to_string()),
            run_mode: "bff".to_string(),
        };
        notifier.notify_startup_failure(&report, &e.to_string());
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        std::process::exit(1);
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

    let access_key = source.get_access_key().ok_or_else(|| {
        format!(
            "S3 access key not configured for webapp source '{}' (set access_key or access_key_env)",
            source.display_name()
        )
    })?;
    let secret_key = source.get_secret_key().ok_or_else(|| {
        format!(
            "S3 secret key not configured for webapp source '{}' (set secret_key or secret_key_env)",
            source.display_name()
        )
    })?;

    let credentials = Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)?;

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
