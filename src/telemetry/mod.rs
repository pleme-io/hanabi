//! Telemetry module for distributed tracing
//!
//! Provides OpenTelemetry integration when the `otel` feature is enabled.
//!
//! # Usage
//!
//! ```rust
//! use hanabi::telemetry;
//!
//! // Initialize tracing with OTel (if enabled)
//! telemetry::init(&config)?;
//!
//! // Shutdown on exit
//! telemetry::shutdown();
//! ```

#[cfg(feature = "otel")]
mod otel;

#[cfg(feature = "otel")]
pub use otel::{init, shutdown};

/// No-op initialization when OTel feature is disabled
#[cfg(not(feature = "otel"))]
pub fn init(_config: &crate::config::AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("OpenTelemetry: disabled (compile with --features otel to enable)");
    Ok(())
}

/// No-op shutdown when OTel feature is disabled
#[cfg(not(feature = "otel"))]
pub fn shutdown() {
    // No-op
}
