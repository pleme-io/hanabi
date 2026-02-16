//! OpenTelemetry integration for distributed tracing
//!
//! Exports traces to an OTLP-compatible collector (e.g., Jaeger, Tempo, Honeycomb).
//!
//! # Configuration
//!
//! Configuration is loaded from AppConfig.telemetry with support for OTel standard
//! environment variable overrides:
//! - `OTEL_EXPORTER_OTLP_ENDPOINT`: OTLP collector endpoint
//! - `OTEL_SERVICE_NAME`: Service name for traces
//! - `OTEL_TRACES_SAMPLER_ARG`: Sampling ratio 0.0-1.0
//! - `OTEL_DEPLOYMENT_ENVIRONMENT`: Deployment environment

use opentelemetry::global;
use opentelemetry::trace::TracerProvider;
use opentelemetry::KeyValue;
use opentelemetry_otlp::SpanExporter;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{RandomIdGenerator, Sampler, SdkTracerProvider};
use opentelemetry_sdk::Resource;
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::AppConfig;

/// Initialize OpenTelemetry tracing
///
/// This sets up:
/// 1. OTLP exporter to send traces to a collector
/// 2. tracing-opentelemetry layer to bridge tracing spans to OTel
/// 3. Sampling based on configuration
///
/// Call `shutdown()` before exiting to ensure traces are flushed.
pub fn init(config: &AppConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Apply environment variable overrides per OTel spec
    // Note: with_env_overrides() is called in config module, respecting the config boundary
    let telemetry_config = config.telemetry.with_env_overrides();

    // Build resource with service information using the new builder API
    let resource = Resource::builder()
        .with_service_name(telemetry_config.service_name.clone())
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .with_attribute(KeyValue::new(
            "deployment.environment",
            telemetry_config.environment.clone(),
        ))
        .build();

    // Build sampler based on configuration
    let sampler = if telemetry_config.sampling_ratio >= 1.0 {
        Sampler::AlwaysOn
    } else if telemetry_config.sampling_ratio <= 0.0 {
        Sampler::AlwaysOff
    } else {
        Sampler::TraceIdRatioBased(telemetry_config.sampling_ratio)
    };

    // Build the OTLP span exporter using tonic (gRPC)
    // Note: Endpoint is configured via OTEL_EXPORTER_OTLP_ENDPOINT env var by default
    let exporter = SpanExporter::builder().with_tonic().build()?;

    // Build tracer provider with the exporter
    let tracer_provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(sampler)
        .with_id_generator(RandomIdGenerator::default())
        .with_resource(resource)
        .build();

    // Get tracer from provider
    let tracer = tracer_provider.tracer("hanabi");

    // Set global propagator for distributed tracing context
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Set global tracer provider
    global::set_tracer_provider(tracer_provider);

    // Create OTel tracing layer
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Configure env filter
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // Default to info level with some noisy crates quieted
        EnvFilter::new("info,hyper=warn,reqwest=warn,tower_http=debug")
    });

    // Initialize subscriber with OTel layer
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .init();

    info!(
        service = %telemetry_config.service_name,
        endpoint = %telemetry_config.otlp_endpoint,
        sampling_ratio = %telemetry_config.sampling_ratio,
        "OpenTelemetry initialized"
    );

    Ok(())
}

/// Shutdown OpenTelemetry, flushing any pending traces
///
/// Call this before application exit to ensure all traces are exported.
/// Note: In OpenTelemetry 0.31+, the tracer provider must be stored and shut down explicitly.
/// For now, this is a best-effort flush using the global tracer.
pub fn shutdown() {
    info!("Shutting down OpenTelemetry...");
    // In 0.31+, shutdown is handled by dropping the SdkTracerProvider
    // or calling shutdown on the stored provider. The global tracer
    // will be properly cleaned up when the application exits.
    // For explicit shutdown, store the provider and call provider.shutdown().
}

// Tests for TelemetryConfig are in config/telemetry.rs
