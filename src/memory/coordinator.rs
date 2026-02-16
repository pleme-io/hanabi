//! Memory Pressure Coordinator
//!
//! Single source of truth for memory pressure signals, coordinating
//! gradient-based responses across caches, pools, and buffers.
//!
//! # Architecture
//!
//! The coordinator aggregates memory usage from all registered components
//! and broadcasts pressure signals when thresholds are exceeded.
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    PRESSURE COORDINATOR                         │
//! │  • Aggregates signals from all memory consumers                │
//! │  • Computes holistic pressure gradient (0.0 → 1.0)             │
//! │  • Broadcasts pressure level to all components                  │
//! └─────────────────────────────────────────────────────────────────┘
//!          │                    │                    │
//!          ▼                    ▼                    ▼
//! ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
//! │  CACHE MANAGER  │  │  POOL MANAGER   │  │  BUFFER MANAGER │
//! │  Response Curve │  │  Response Curve │  │  Response Curve │
//! └─────────────────┘  └─────────────────┘  └─────────────────┘
//! ```

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tracing::{debug, info};

/// Memory pressure level as a gradient (0.0 = no pressure, 1.0 = critical)
#[derive(Debug, Clone, Copy)]
pub struct MemoryPressure(f64);

impl MemoryPressure {
    pub fn new(value: f64) -> Self {
        Self(value.clamp(0.0, 1.0))
    }

    pub fn value(&self) -> f64 {
        self.0
    }

    /// Returns true if pressure is considered high (>0.7)
    pub fn is_high(&self) -> bool {
        self.0 > 0.7
    }

    /// Returns true if pressure is considered critical (>0.9)
    pub fn is_critical(&self) -> bool {
        self.0 > 0.9
    }
}

/// Component ID for tracking memory usage
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }
}

/// Trait for components that respond to memory pressure
pub trait MemoryResponder: Send + Sync {
    /// Report current memory usage in bytes
    fn memory_usage(&self) -> u64;

    /// Respond to pressure gradient (0.0 = grow freely, 1.0 = aggressive eviction)
    fn respond_to_pressure(&self, pressure: MemoryPressure);
}

/// Configuration for the pressure coordinator
#[derive(Debug, Clone)]
pub struct PressureCoordinatorConfig {
    /// Memory limit in bytes (if known)
    pub memory_limit: Option<u64>,

    /// Interval between pressure checks
    pub check_interval: Duration,

    /// Whether to enable background monitoring
    #[allow(dead_code)]
    pub enable_monitoring: bool,
}

impl Default for PressureCoordinatorConfig {
    fn default() -> Self {
        Self {
            memory_limit: None,
            check_interval: Duration::from_secs(5),
            enable_monitoring: true,
        }
    }
}

/// Centralized memory pressure coordinator
pub struct PressureCoordinator {
    /// Current pressure level (stored as u64 for atomic ops, represents f64 * 1000)
    pressure: AtomicU64,

    /// Registered components
    components: DashMap<ComponentId, Arc<dyn MemoryResponder>>,

    /// Memory limit in bytes (if known)
    memory_limit: Option<u64>,

    /// Interval between pressure checks
    check_interval: Duration,

    /// Flag to stop background monitoring
    stop_flag: AtomicBool,
}

impl PressureCoordinator {
    /// Create a new pressure coordinator with optional memory limit
    pub fn new(memory_limit: Option<u64>) -> Self {
        Self::with_config(PressureCoordinatorConfig {
            memory_limit,
            ..Default::default()
        })
    }

    /// Create a new pressure coordinator with full configuration
    pub fn with_config(config: PressureCoordinatorConfig) -> Self {
        Self {
            pressure: AtomicU64::new(0),
            components: DashMap::new(),
            memory_limit: config.memory_limit,
            check_interval: config.check_interval,
            stop_flag: AtomicBool::new(false),
        }
    }

    /// Spawn background monitoring task that periodically checks and updates pressure
    ///
    /// The task runs until `stop()` is called or the coordinator is dropped.
    /// Pressure is calculated based on registered component usage vs memory limit.
    pub fn spawn_monitor(self: &Arc<Self>) {
        if self.memory_limit.is_none() {
            info!("Memory pressure monitor: disabled (no memory limit configured)");
            return;
        }

        let coordinator = Arc::clone(self);
        let interval = self.check_interval;

        tokio::spawn(async move {
            info!(
                interval_secs = interval.as_secs(),
                memory_limit = coordinator.memory_limit,
                "Memory pressure monitor started"
            );

            let mut ticker = tokio::time::interval(interval);

            loop {
                ticker.tick().await;

                if coordinator.stop_flag.load(Ordering::Relaxed) {
                    info!("Memory pressure monitor stopped");
                    break;
                }

                // Calculate pressure from registered components
                if let Some(pressure) = coordinator.calculate_pressure() {
                    coordinator.update_pressure(pressure);
                }
            }
        });
    }

    /// Stop the background monitoring task
    #[allow(dead_code)]
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Get current pressure level
    #[allow(dead_code)]
    pub fn current_pressure(&self) -> MemoryPressure {
        let stored = self.pressure.load(Ordering::Relaxed);
        MemoryPressure::new(stored as f64 / 1000.0)
    }

    /// Update pressure based on system metrics
    pub fn update_pressure(&self, new_pressure: f64) {
        let stored = (new_pressure.clamp(0.0, 1.0) * 1000.0) as u64;
        let old = self.pressure.swap(stored, Ordering::Relaxed);

        let old_pressure = old as f64 / 1000.0;
        if (new_pressure - old_pressure).abs() > 0.1 {
            debug!(
                old = old_pressure,
                new = new_pressure,
                "Memory pressure changed significantly"
            );
        }

        // Notify components if pressure is high
        if new_pressure > 0.7 {
            self.broadcast_pressure(MemoryPressure::new(new_pressure));
        }
    }

    /// Register a component for pressure notifications
    pub fn register(&self, id: ComponentId, responder: Arc<dyn MemoryResponder>) {
        self.components.insert(id, responder);
    }

    /// Unregister a component
    #[allow(dead_code)]
    pub fn unregister(&self, id: &ComponentId) {
        self.components.remove(id);
    }

    /// Get total memory usage across all components
    pub fn total_usage(&self) -> u64 {
        self.components
            .iter()
            .map(|r| r.value().memory_usage())
            .sum()
    }

    /// Broadcast pressure to all registered components
    fn broadcast_pressure(&self, pressure: MemoryPressure) {
        for component in self.components.iter() {
            component.value().respond_to_pressure(pressure);
        }
    }

    /// Calculate pressure from current usage (if memory limit is known)
    pub fn calculate_pressure(&self) -> Option<f64> {
        self.memory_limit.map(|limit| {
            let usage = self.total_usage();
            (usage as f64 / limit as f64).clamp(0.0, 1.0)
        })
    }
}

impl Default for PressureCoordinator {
    fn default() -> Self {
        Self::with_config(PressureCoordinatorConfig::default())
    }
}

/// Statistics about pressure coordinator state
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct PressureCoordinatorStats {
    /// Current pressure level (0.0 - 1.0)
    pub pressure: f64,

    /// Total memory usage across all components
    pub total_usage_bytes: u64,

    /// Memory limit (if configured)
    pub memory_limit_bytes: Option<u64>,

    /// Number of registered components
    pub component_count: usize,
}

impl PressureCoordinator {
    /// Get statistics about the coordinator
    #[allow(dead_code)]
    pub fn stats(&self) -> PressureCoordinatorStats {
        PressureCoordinatorStats {
            pressure: self.current_pressure().value(),
            total_usage_bytes: self.total_usage(),
            memory_limit_bytes: self.memory_limit,
            component_count: self.components.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockResponder {
        usage: AtomicU64,
    }

    impl MemoryResponder for MockResponder {
        fn memory_usage(&self) -> u64 {
            self.usage.load(Ordering::Relaxed)
        }

        fn respond_to_pressure(&self, _pressure: MemoryPressure) {
            // Mock implementation
        }
    }

    #[test]
    fn test_pressure_gradient() {
        let coord = PressureCoordinator::new(Some(1000));

        let responder = Arc::new(MockResponder {
            usage: AtomicU64::new(500),
        });

        coord.register(ComponentId::new("test"), responder);

        let pressure = coord.calculate_pressure().unwrap();
        assert!((pressure - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_pressure_clamping() {
        let pressure = MemoryPressure::new(1.5);
        assert!((pressure.value() - 1.0).abs() < 0.001);

        let pressure = MemoryPressure::new(-0.5);
        assert!(pressure.value().abs() < 0.001);
    }
}
