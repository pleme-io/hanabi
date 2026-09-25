//! Server lifecycle management
//!
//! Extracted from `main.rs` to enable reuse by the [`ServerBuilder`](crate::builder::ServerBuilder).
//! Contains listener binding, dual-port serving, graceful shutdown, and logging setup.

use std::net::SocketAddr;

use axum::Router;
use socket2::{Domain, Socket, Type};
use tracing::{error, info, warn};

use crate::config::AppConfig;
use crate::state::AppState;

/// Initialize structured logging from configuration.
///
/// Sets up `tracing_subscriber` with module-level directives and optional JSON format.
pub fn init_logging(config: &AppConfig) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        let mut filter = tracing_subscriber::EnvFilter::new(&config.logging.level);
        for (module, level) in &config.logging.module_levels {
            match format!("{}={}", module, level).parse() {
                Ok(directive) => {
                    filter = filter.add_directive(directive);
                }
                Err(_) => {
                    warn!(
                        "Invalid module level directive: {}={}, skipping",
                        module, level
                    );
                }
            }
        }
        filter
    });

    if config.logging.format == "json" {
        if let Err(e) = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(config.logging.include_target)
                .with_current_span(true)
                .with_thread_ids(config.logging.include_thread_ids)
                .with_file(config.logging.include_location)
                .with_line_number(config.logging.include_location)
                .finish(),
        ) {
            warn!(
                "Could not reinitialize logging to JSON format: {} - continuing with pretty format",
                e
            );
        }
    }
}

/// Log startup configuration summary.
pub fn log_startup_info(state: &AppState, config: &AppConfig) {
    info!(
        "🚀 Starting {} v{}",
        config.server.service_name, config.server.service_version
    );
    info!("   Environment: {}", config.environment);
    info!(
        "   HTTP Port: {} - Static file server ({})",
        config.server.http_port, config.server.static_dir
    );
    info!(
        "   Health Port: {} - Health check endpoints",
        config.server.health_port
    );

    let worker_count = if config.server.worker_threads > 0 {
        config.server.worker_threads
    } else {
        num_cpus::get()
    };

    let max_concurrent = state
        .resource_manager()
        .map(|rm| rm.optimized.max_concurrent_requests)
        .unwrap_or(config.server.max_concurrent_connections);

    let concurrency_source = if state.resource_manager().is_some() {
        "auto-optimized"
    } else {
        "configured"
    };

    info!("   Performance:");
    info!("     - Worker threads: {}", worker_count);
    info!(
        "     - Max concurrent requests: {} ({})",
        max_concurrent, concurrency_source
    );
    info!(
        "     - Request timeout: {}s",
        config.server.request_timeout_secs
    );
    info!("     - TCP_NODELAY: {}", config.server.tcp_nodelay);
    info!(
        "     - Compression: Brotli={}, Gzip={}",
        config.compression.enable_brotli, config.compression.enable_gzip
    );

    if config.features.enable_metrics {
        info!(
            "   Metrics: Emitting to {}:{} (prefix: {})",
            config.metrics.vector_host, config.metrics.vector_port, config.metrics.prefix
        );
    } else {
        info!("   Metrics: Disabled");
    }
}

/// Bind HTTP and health check TCP listeners with performance tuning.
pub fn bind_listeners(
    config: &AppConfig,
) -> Result<(tokio::net::TcpListener, tokio::net::TcpListener), Box<dyn std::error::Error>> {
    let http_bind_addr: SocketAddr =
        format!("{}:{}", config.server.bind_address, config.server.http_port).parse()?;
    let health_bind_addr: SocketAddr = format!(
        "{}:{}",
        config.server.bind_address, config.server.health_port
    )
    .parse()?;

    let http_socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    http_socket.set_nodelay(config.server.tcp_nodelay)?;
    http_socket.set_reuse_address(config.network.reuse_address)?;
    http_socket.bind(&http_bind_addr.into())?;
    http_socket.listen(config.network.http_backlog)?;
    http_socket.set_nonblocking(true)?;
    let static_listener = tokio::net::TcpListener::from_std(http_socket.into())?;

    let health_socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    health_socket.set_nodelay(true)?;
    health_socket.set_reuse_address(config.network.reuse_address)?;
    health_socket.bind(&health_bind_addr.into())?;
    health_socket.listen(config.network.health_backlog)?;
    health_socket.set_nonblocking(true)?;
    let health_listener = tokio::net::TcpListener::from_std(health_socket.into())?;

    Ok((static_listener, health_listener))
}

/// Run the dual-port server with graceful shutdown.
///
/// `app_router` is served on the HTTP port, `health_router` on the health port.
pub async fn run_server(
    config: &AppConfig,
    app_router: Router,
    health_router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let (static_listener, health_listener) = bind_listeners(config)?;

    info!("✓ All systems ready");

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    // ── L4 proxies share the ONE drain signal ──────────────────────────────
    // Spawned here rather than anywhere else precisely because this function
    // already owns `shutdown_tx`. A second lifecycle would mean the raw-TCP
    // listeners kept accepting while the HTTP servers drained — and L4 is
    // stateful, so an abandoned tunnel is a peer left hanging rather than a
    // request the client retries.
    //
    // Config-gated and empty by default: `l4.enabled = false` returns no
    // handles, so a node that has not asked for L4 is byte-identical to before.
    let l4_handles = crate::l4::spawn_all(&config.l4, &shutdown_tx);
    if !l4_handles.is_empty() {
        info!(count = l4_handles.len(), "✓ L4 proxies listening");
    }

    let static_server = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            axum::serve(
                static_listener,
                app_router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                shutdown_rx.recv().await.ok();
            })
            .await
        })
    };

    let health_server = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            axum::serve(
                health_listener,
                health_router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                shutdown_rx.recv().await.ok();
            })
            .await
        })
    };

    shutdown_signal().await;

    let _ = shutdown_tx.send(());
    info!("Shutdown signal broadcasted to all servers");

    let (static_result, health_result) = tokio::join!(static_server, health_server);
    static_result??;
    health_result??;

    // L4 listeners stop ACCEPTING on the same signal; await them so the process
    // does not exit while one is still unwinding. In-flight tunnels live on
    // their own spawned tasks and are allowed to finish — a raw TCP session cut
    // at process exit leaves the peer hanging, which for a Cast control channel
    // means a speaker unresponsive until it reconnects.
    for h in l4_handles {
        if let Err(e) = h.await {
            warn!(error = %e, "an L4 proxy task did not shut down cleanly");
        }
    }

    info!("✓ Graceful shutdown complete");
    Ok(())
}

/// Graceful drain signal handler (SIGTERM + SIGINT).
///
/// Thin wrapper over `tsunagu::ShutdownController::install()` — kept as a
/// free function because the existing call sites (above) are structured
/// around a single await point inside `run_servers`. Once those call sites
/// migrate to the token API directly, this helper can be deleted.
pub async fn shutdown_signal() {
    tsunagu::ShutdownController::install().token().wait().await;
}
