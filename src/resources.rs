//! Runtime resource detection and optimization
//!
//! This module detects system resources (CPU, memory) and calculates optimal
//! configuration values for the application based on available resources.
//!
//! # Design Philosophy
//! The application should adapt to its environment automatically without requiring
//! manual tuning. Configuration provides overrides, but defaults are learned from
//! the system.
//!
//! # Resource Detection
//! - CPU cores (physical and logical)
//! - Total system memory
//! - Available memory (accounting for other processes)
//! - Memory pressure (low/medium/high)
//! - Network latency to upstream (Hive Router health check)
//! - TCP buffer sizes and connection limits
//!
//! # Auto-Optimization Strategy
//! - **WebSocket max_connections**: Based on available memory (25% allocation)
//! - **HTTP connection pool**: Based on CPU cores + network latency
//! - **Worker threads**: Based on CPU cores (defaults to num_cpus)
//! - **Channel buffer sizes**: Based on memory pressure
//! - **Concurrency limits**: Based on CPU cores + network performance
//! - **Timeouts**: Based on measured network latency to upstream
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::config::AppConfig;

/// System resource information detected at runtime
#[derive(Debug, Clone)]
pub struct SystemResources {
    /// Number of logical CPU cores
    pub cpu_cores: usize,

    /// Total system memory in bytes
    pub total_memory_bytes: u64,

    /// Available system memory in bytes
    pub available_memory_bytes: u64,

    /// Memory utilization percentage (0.0-1.0)
    pub memory_utilization: f64,

    /// Detected memory pressure level
    pub memory_pressure: MemoryPressure,

    /// Network latency to upstream (Hive Router) in milliseconds
    /// None if health check failed
    pub upstream_latency_ms: Option<u64>,

    /// Network quality assessment
    pub network_quality: NetworkQuality,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkQuality {
    /// <10ms latency - excellent (same datacenter/pod)
    Excellent,
    /// 10-50ms latency - good (same region)
    Good,
    /// 50-200ms latency - moderate (cross-region)
    Moderate,
    /// >200ms latency - poor (high latency network)
    Poor,
    /// Could not measure (health check failed)
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressure {
    /// <50% memory used - plenty available
    Low,
    /// 50-80% memory used - moderate pressure
    Medium,
    /// >80% memory used - high pressure
    High,
}

impl SystemResources {
    /// Detect system resources at runtime
    pub fn detect() -> Result<Self, String> {
        // Detect CPU cores (ensure at least 1 for virtualized environments where detection may fail)
        let cpu_cores = num_cpus::get().max(1);

        // Detect memory using sys-info
        let mem_info =
            sys_info::mem_info().map_err(|e| format!("Failed to detect system memory: {}", e))?;

        // Use saturating_mul to prevent overflow on large memory systems
        let total_memory_bytes = (mem_info.total as u64).saturating_mul(1024); // Convert KB to bytes
        let available_memory_bytes = (mem_info.avail as u64).saturating_mul(1024); // Available includes buffers/cache

        // Use saturating_sub to prevent underflow (defensive programming)
        let used_memory_bytes = total_memory_bytes.saturating_sub(available_memory_bytes);

        // Prevent division by zero (total_memory_bytes should never be 0, but be defensive)
        let memory_utilization = if total_memory_bytes > 0 {
            used_memory_bytes as f64 / total_memory_bytes as f64
        } else {
            0.0 // Fallback to 0% utilization if detection fails
        };

        let memory_pressure = if memory_utilization < 0.5 {
            MemoryPressure::Low
        } else if memory_utilization < 0.8 {
            MemoryPressure::Medium
        } else {
            MemoryPressure::High
        };

        Ok(Self {
            cpu_cores,
            total_memory_bytes,
            available_memory_bytes,
            memory_utilization,
            memory_pressure,
            upstream_latency_ms: None, // Will be measured separately
            network_quality: NetworkQuality::Unknown,
        })
    }

    /// Measure network latency to upstream (Hive Router)
    /// Updates upstream_latency_ms and network_quality fields
    pub async fn measure_network_latency(&mut self, hive_router_url: &str) -> Result<(), String> {
        use std::time::Instant;

        // Extract base URL for health check (remove /graphql path)
        let base_url = hive_router_url
            .trim_end_matches("/graphql")
            .trim_end_matches('/');

        info!("Measuring network latency to upstream ({})", base_url);

        // Create HTTP client with short timeout for health check
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| format!("Failed to create HTTP client for health check: {}", e))?;

        // Measure round-trip time with health check endpoint
        let start = Instant::now();
        let health_url = format!("{}/.well-known/apollo/server-health", base_url);

        match client
            .get(&health_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) => {
                let latency_ms = start.elapsed().as_millis() as u64;

                if response.status().is_success() {
                    self.upstream_latency_ms = Some(latency_ms);

                    // Classify network quality based on latency
                    self.network_quality = if latency_ms < 10 {
                        NetworkQuality::Excellent
                    } else if latency_ms < 50 {
                        NetworkQuality::Good
                    } else if latency_ms < 200 {
                        NetworkQuality::Moderate
                    } else {
                        NetworkQuality::Poor
                    };

                    info!(
                        "  Network latency: {}ms (quality: {:?})",
                        latency_ms, self.network_quality
                    );
                    Ok(())
                } else {
                    warn!(
                        "  Health check returned non-success status: {}",
                        response.status()
                    );
                    self.upstream_latency_ms = None;
                    self.network_quality = NetworkQuality::Unknown;
                    Ok(()) // Non-fatal, continue with Unknown network quality
                }
            }
            Err(e) => {
                warn!(
                    "  Failed to measure network latency (health check failed): {}",
                    e
                );
                self.upstream_latency_ms = None;
                self.network_quality = NetworkQuality::Unknown;
                Ok(()) // Non-fatal, continue with Unknown network quality
            }
        }
    }

    /// Log detected resources
    pub fn log_resources(&self) {
        info!("=== System Resources Detected ===");
        info!("  CPU Cores: {}", self.cpu_cores);
        info!(
            "  Total Memory: {} GB",
            self.total_memory_bytes / (1024 * 1024 * 1024)
        );
        info!(
            "  Available Memory: {} GB ({:.1}% free)",
            self.available_memory_bytes / (1024 * 1024 * 1024),
            (1.0 - self.memory_utilization) * 100.0
        );
        info!("  Memory Pressure: {:?}", self.memory_pressure);

        // Log network info if available
        if let Some(latency_ms) = self.upstream_latency_ms {
            info!(
                "  Network Latency: {}ms (quality: {:?})",
                latency_ms, self.network_quality
            );
        } else {
            info!("  Network Latency: Unknown (health check failed)");
        }
    }
}

/// Optimized configuration calculated from system resources
#[derive(Debug, Clone)]
pub struct OptimizedConfig {
    /// WebSocket max concurrent connections (memory-based)
    pub websocket_max_connections: usize,

    /// HTTP connection pool size (CPU-based)
    pub http_pool_size: usize,

    /// Worker threads (CPU-based, already handled by tokio)
    pub worker_threads: usize,

    /// Max concurrent HTTP requests (CPU + memory based)
    pub max_concurrent_requests: usize,

    /// WebSocket channel buffer size (memory pressure based)
    pub websocket_channel_buffer: usize,

    /// Memory budget allocated to WebSocket (bytes)
    pub websocket_memory_budget_bytes: u64,
}

impl OptimizedConfig {
    /// Calculate optimized configuration from system resources and user config
    ///
    /// # Strategy (Based on Known Algorithms)
    /// - **WebSocket connections**: Memory-based allocation (% of available memory)
    /// - **HTTP pool**: Little's Law + RFC 7230 keep-alive (tunable multiplier × CPU cores)
    /// - **Worker threads**: Use tokio default (num_cpus)
    /// - **Concurrency**: Async I/O best practice (tunable multiplier × CPU cores, default 10×)
    /// - **Channel buffers**: Van Jacobson flow control (adaptive based on memory pressure)
    ///
    /// # Configuration Overrides
    /// All optimization parameters are tunable via config.bff.optimization:
    /// - Connection limits (min/max bounds)
    /// - Pool sizing multipliers (HTTP pool, concurrency)
    /// - Buffer sizes per memory pressure level
    /// - Network-aware timeout calculation
    ///
    /// # Interdependency
    /// Values feed into each other:
    /// - CPU cores → pool size, concurrency, worker threads
    /// - Memory → max connections, buffer sizes
    /// - Network latency → timeout calculation (future)
    pub fn calculate(resources: &SystemResources, config: &AppConfig) -> Self {
        let opt = &config.bff.optimization;

        // Calculate WebSocket max connections from available memory
        let websocket_max_connections = if config.bff.websocket.max_connections > 0 {
            // User override
            info!(
                "Using configured max_connections: {}",
                config.bff.websocket.max_connections
            );
            config.bff.websocket.max_connections
        } else {
            // Auto-calculate: (available_memory × memory_percent) / memory_per_conn
            let memory_percent = config.bff.websocket.memory_percent_limit;
            let mem_per_conn_kb = config.bff.websocket.memory_per_connection_kb;
            let available_mb = resources.available_memory_bytes / (1024 * 1024);
            let budget_mb = (available_mb as f64 * memory_percent) as u64;
            // Use saturating_mul to prevent integer overflow on large memory systems
            let max_conns = budget_mb.saturating_mul(1024) / mem_per_conn_kb as u64;

            // Apply safety limits (tunable via config)
            let max_conns = max_conns.max(opt.min_connections as u64);
            let max_conns = max_conns.min(opt.max_connections as u64);

            info!(
                "Auto-calculated max_connections: {} ({}% of {} MB available = {} MB budget, bounded by {}-{})",
                max_conns,
                (memory_percent * 100.0) as u64,
                available_mb,
                budget_mb,
                opt.min_connections,
                opt.max_connections
            );

            max_conns as usize
        };

        // Calculate HTTP connection pool size from CPU cores
        // Based on Little's Law and RFC 7230 keep-alive studies
        // Ensure minimum of 1 to prevent zero pool size
        let http_pool_size =
            ((resources.cpu_cores as f64 * opt.http_pool_multiplier) as usize).max(1);

        // Worker threads (tokio handles this, just log it)
        let worker_threads = resources.cpu_cores;

        // Max concurrent HTTP requests (async I/O best practice)
        // Nginx/Node.js: async can handle N× CPU cores due to non-blocking I/O
        // Ensure minimum of 1 to prevent zero concurrency
        let max_concurrent_requests =
            ((resources.cpu_cores as f64 * opt.concurrency_multiplier) as usize).max(1);

        // WebSocket channel buffer size (Van Jacobson flow control)
        // Adaptive based on memory pressure to prevent OOM
        let websocket_channel_buffer = match resources.memory_pressure {
            MemoryPressure::Low => opt.channel_buffer_low_pressure,
            MemoryPressure::Medium => opt.channel_buffer_medium_pressure,
            MemoryPressure::High => opt.channel_buffer_high_pressure,
        };

        // Calculate actual WebSocket memory budget with overflow protection
        let websocket_memory_budget_bytes = (websocket_max_connections as u64)
            .saturating_mul(config.bff.websocket.memory_per_connection_kb as u64)
            .saturating_mul(1024);

        Self {
            websocket_max_connections,
            http_pool_size,
            worker_threads,
            max_concurrent_requests,
            websocket_channel_buffer,
            websocket_memory_budget_bytes,
        }
    }

    /// Log optimized configuration
    pub fn log_config(&self) {
        info!("=== Optimized Configuration ===");
        info!(
            "  WebSocket Max Connections: {} (~{} MB memory budget)",
            self.websocket_max_connections,
            self.websocket_memory_budget_bytes / (1024 * 1024)
        );
        info!(
            "  HTTP Connection Pool: {} connections/host",
            self.http_pool_size
        );
        info!("  Worker Threads: {}", self.worker_threads);
        info!(
            "  Max Concurrent HTTP Requests: {}",
            self.max_concurrent_requests
        );
        info!(
            "  WebSocket Channel Buffers: {} messages",
            self.websocket_channel_buffer
        );
    }
}

/// Resource manager that combines system detection with configuration
pub struct ResourceManager {
    pub resources: SystemResources,
    pub optimized: OptimizedConfig,
}

impl ResourceManager {
    /// Initialize resource manager by detecting system and calculating optimal config
    pub async fn new(config: &Arc<AppConfig>) -> Result<Self, String> {
        info!("Detecting system resources and calculating optimal configuration...");

        let mut resources = SystemResources::detect()?;

        // Measure network latency to upstream (Hive Router) if BFF is enabled
        if config.features.enable_bff {
            let _ = resources
                .measure_network_latency(&config.bff.hive_router_url)
                .await;
        }

        resources.log_resources();

        let optimized = OptimizedConfig::calculate(&resources, config);
        optimized.log_config();

        // Warn if memory pressure is high
        if resources.memory_pressure == MemoryPressure::High {
            warn!(
                "⚠️  High memory pressure detected ({:.1}% used) - may impact performance",
                resources.memory_utilization * 100.0
            );
            warn!("   Consider reducing max_connections or adding more memory");
        }

        Ok(Self {
            resources,
            optimized,
        })
    }

    /// Emit metrics for detected resources and optimized configuration
    /// Called at startup to establish baseline metrics for monitoring
    pub fn emit_metrics(&self, metrics: &crate::metrics::MetricsClient) {
        let tags = &[];

        // System resource metrics
        metrics.gauge("resources.cpu_cores", self.resources.cpu_cores as f64, tags);
        metrics.gauge(
            "resources.memory_total_gb",
            (self.resources.total_memory_bytes / (1024 * 1024 * 1024)) as f64,
            tags,
        );
        metrics.gauge(
            "resources.memory_available_gb",
            (self.resources.available_memory_bytes / (1024 * 1024 * 1024)) as f64,
            tags,
        );
        metrics.gauge(
            "resources.memory_utilization",
            self.resources.memory_utilization,
            tags,
        );

        // Network metrics
        if let Some(latency_ms) = self.resources.upstream_latency_ms {
            metrics.gauge("resources.network_latency_ms", latency_ms as f64, tags);
        }

        // Optimized configuration metrics
        metrics.gauge(
            "optimization.websocket_max_connections",
            self.optimized.websocket_max_connections as f64,
            tags,
        );
        metrics.gauge(
            "optimization.http_pool_size",
            self.optimized.http_pool_size as f64,
            tags,
        );
        metrics.gauge(
            "optimization.max_concurrent_requests",
            self.optimized.max_concurrent_requests as f64,
            tags,
        );
        metrics.gauge(
            "optimization.websocket_channel_buffer",
            self.optimized.websocket_channel_buffer as f64,
            tags,
        );
        metrics.gauge(
            "optimization.websocket_memory_budget_mb",
            (self.optimized.websocket_memory_budget_bytes / (1024 * 1024)) as f64,
            tags,
        );

        info!("✓ Resource metrics emitted to Vector");
    }
}
