//! Adaptive Memory Management
//!
//! Provides gradient-based memory pressure coordination following Netflix patterns.

mod coordinator;

pub use coordinator::{ComponentId, MemoryPressure, MemoryResponder, PressureCoordinator};
