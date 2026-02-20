#![allow(dead_code)]
//! Custom Plugins System
//!
//! Tower-based middleware system for extending federation behavior.
//! Inspired by Apollo Router's plugin architecture and Hive Gateway's Envelop hooks.
//!
//! # Plugin Lifecycle
//!
//! ```text
//! Request → [Pre-Parse] → [Parse] → [Validate] → [Pre-Execute] → Execute → [Post-Execute] → Response
//!              │            │           │             │                          │
//!              └────────────┴───────────┴─────────────┴──────────────────────────┘
//!                                    Plugin Hooks
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use plugins::{Plugin, PluginContext, PluginRegistry};
//!
//! struct LoggingPlugin;
//!
//! impl Plugin for LoggingPlugin {
//!     fn name(&self) -> &'static str { "logging" }
//!
//!     fn on_request(&self, ctx: &mut PluginContext) -> PluginResult<()> {
//!         info!("Request: {}", ctx.operation_name.unwrap_or("anonymous"));
//!         Ok(())
//!     }
//! }
//!
//! let registry = PluginRegistry::new()
//!     .register(Arc::new(LoggingPlugin));
//! ```
//!
//! # Built-in Plugins
//!
//! - `SecurityPlugin` - Depth/complexity/introspection validation
//! - `TracingPlugin` - OpenTelemetry span creation
//! - `CachePlugin` - Response caching
//! - `RateLimitPlugin` - Request rate limiting

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use serde_json::Value;
use thiserror::Error;
use tracing::{debug, info, Span};

use crate::metrics::{MetricsClient, MetricsExt};

/// Plugin execution errors
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("Plugin '{name}' failed: {message}")]
    ExecutionError { name: String, message: String },

    #[error("Plugin '{name}' rejected request: {reason}")]
    RequestRejected { name: String, reason: String },

    #[error("Plugin configuration error: {0}")]
    ConfigError(String),

    #[error("Plugin not found: {0}")]
    NotFound(String),
}

/// Result type for plugin operations
pub type PluginResult<T> = Result<T, PluginError>;

/// Plugin execution stage
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStage {
    /// Before parsing the GraphQL document
    PreParse,
    /// After parsing, before validation
    PostParse,
    /// Before executing the operation
    PreExecute,
    /// After execution, before sending response
    PostExecute,
    /// On subscription start
    OnSubscriptionStart,
    /// On subscription data
    OnSubscriptionData,
    /// On subscription end
    OnSubscriptionEnd,
    /// On error (any stage)
    OnError,
}

/// Request context passed to plugins
///
/// Contains all information about the current request that plugins
/// might need to read or modify.
#[derive(Debug, Clone)]
pub struct PluginContext {
    /// Unique request ID
    pub request_id: String,

    /// GraphQL operation string
    pub query: String,

    /// Operation name (if provided)
    pub operation_name: Option<String>,

    /// Variables (if provided)
    pub variables: Option<Value>,

    /// Extensions from the request
    pub extensions: HashMap<String, Value>,

    /// User ID (if authenticated)
    pub user_id: Option<String>,

    /// User roles (if authenticated)
    pub user_roles: Vec<String>,

    /// Product scope
    pub product: String,

    /// Client IP address
    pub client_ip: Option<String>,

    /// Request headers (key → value)
    pub headers: HashMap<String, String>,

    /// Plugin-specific data storage
    pub plugin_data: HashMap<String, Value>,

    /// Request start time
    pub start_time: Instant,

    /// Current tracing span
    pub span: Option<Span>,

    /// Whether request was cached
    pub cache_hit: bool,

    /// Whether request was deduplicated
    pub deduplicated: bool,

    /// Calculated query depth (set by security plugin)
    pub query_depth: Option<usize>,

    /// Calculated query complexity (set by security plugin)
    pub query_complexity: Option<u32>,
}

impl PluginContext {
    /// Create a new plugin context
    pub fn new(
        request_id: String,
        query: String,
        operation_name: Option<String>,
        variables: Option<Value>,
        product: String,
    ) -> Self {
        Self {
            request_id,
            query,
            operation_name,
            variables,
            extensions: HashMap::new(),
            user_id: None,
            user_roles: vec![],
            product,
            client_ip: None,
            headers: HashMap::new(),
            plugin_data: HashMap::new(),
            start_time: Instant::now(),
            span: None,
            cache_hit: false,
            deduplicated: false,
            query_depth: None,
            query_complexity: None,
        }
    }

    /// Get plugin-specific data
    pub fn get_data<T: serde::de::DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.plugin_data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Set plugin-specific data
    pub fn set_data<T: serde::Serialize>(&mut self, key: &str, value: T) {
        if let Ok(v) = serde_json::to_value(value) {
            self.plugin_data.insert(key.to_string(), v);
        }
    }

    /// Get request duration so far
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

/// Response context for post-execution plugins
#[derive(Debug, Clone, Default)]
pub struct PluginResponse {
    /// Response data
    pub data: Option<Value>,

    /// Response errors
    pub errors: Vec<Value>,

    /// Response extensions
    pub extensions: HashMap<String, Value>,

    /// Whether the response should be cached
    pub cacheable: bool,

    /// Cache TTL in seconds (if cacheable)
    pub cache_ttl_secs: Option<u64>,
}

/// Plugin trait
///
/// Implement this trait to create custom plugins.
/// All methods have default no-op implementations.
pub trait Plugin: Send + Sync {
    /// Plugin name (used for logging and metrics)
    fn name(&self) -> &'static str;

    /// Plugin priority (lower = earlier execution)
    /// Default: 100
    fn priority(&self) -> i32 {
        100
    }

    /// Called before parsing the GraphQL document
    fn on_pre_parse(&self, _ctx: &mut PluginContext) -> PluginResult<()> {
        Ok(())
    }

    /// Called after parsing, before validation
    fn on_post_parse(&self, _ctx: &mut PluginContext) -> PluginResult<()> {
        Ok(())
    }

    /// Called before executing the operation
    fn on_pre_execute(&self, _ctx: &mut PluginContext) -> PluginResult<()> {
        Ok(())
    }

    /// Called after execution, can modify response
    fn on_post_execute(
        &self,
        _ctx: &PluginContext,
        _response: &mut PluginResponse,
    ) -> PluginResult<()> {
        Ok(())
    }

    /// Called when a subscription starts
    fn on_subscription_start(&self, _ctx: &mut PluginContext) -> PluginResult<()> {
        Ok(())
    }

    /// Called for each subscription data event
    fn on_subscription_data(&self, _ctx: &PluginContext, _data: &mut Value) -> PluginResult<()> {
        Ok(())
    }

    /// Called when a subscription ends
    fn on_subscription_end(&self, _ctx: &PluginContext) -> PluginResult<()> {
        Ok(())
    }

    /// Called when an error occurs
    fn on_error(&self, _ctx: &PluginContext, _error: &PluginError) -> PluginResult<()> {
        Ok(())
    }
}

/// Plugin registry
///
/// Manages registered plugins and executes them in priority order.
pub struct PluginRegistry {
    /// Registered plugins (sorted by priority)
    plugins: Vec<Arc<dyn Plugin>>,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,

    /// Whether plugin errors should abort the request
    fail_fast: bool,
}

impl PluginRegistry {
    /// Create a new plugin registry
    pub fn new(metrics: Option<Arc<MetricsClient>>) -> Self {
        Self {
            plugins: Vec::new(),
            metrics,
            fail_fast: true,
        }
    }

    /// Set whether plugin errors should abort the request
    pub fn fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Register a plugin
    pub fn register(mut self, plugin: Arc<dyn Plugin>) -> Self {
        info!(
            plugin = plugin.name(),
            priority = plugin.priority(),
            "Registering plugin"
        );

        self.plugins.push(plugin);

        // Sort by priority (lower first)
        self.plugins.sort_by_key(|p| p.priority());

        self
    }

    /// Get registered plugin count
    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    /// Execute pre-parse hooks
    pub fn execute_pre_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.execute_stage(PluginStage::PreParse, |p| p.on_pre_parse(ctx))
    }

    /// Execute post-parse hooks
    pub fn execute_post_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.execute_stage(PluginStage::PostParse, |p| p.on_post_parse(ctx))
    }

    /// Execute pre-execute hooks
    pub fn execute_pre_execute(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.execute_stage(PluginStage::PreExecute, |p| p.on_pre_execute(ctx))
    }

    /// Execute post-execute hooks
    pub fn execute_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        self.execute_stage(PluginStage::PostExecute, |p| {
            p.on_post_execute(ctx, response)
        })
    }

    /// Execute subscription start hooks
    pub fn execute_subscription_start(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.execute_stage(PluginStage::OnSubscriptionStart, |p| {
            p.on_subscription_start(ctx)
        })
    }

    /// Execute subscription data hooks
    pub fn execute_subscription_data(
        &self,
        ctx: &PluginContext,
        data: &mut Value,
    ) -> PluginResult<()> {
        self.execute_stage(PluginStage::OnSubscriptionData, |p| {
            p.on_subscription_data(ctx, data)
        })
    }

    /// Execute subscription end hooks
    pub fn execute_subscription_end(&self, ctx: &PluginContext) -> PluginResult<()> {
        self.execute_stage(PluginStage::OnSubscriptionEnd, |p| {
            p.on_subscription_end(ctx)
        })
    }

    /// Execute error hooks
    pub fn execute_on_error(&self, ctx: &PluginContext, error: &PluginError) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_error(ctx, error) {
                debug!(
                    plugin = plugin.name(),
                    error = %e,
                    "Error in on_error hook"
                );
            }
        }
    }

    /// Execute a stage with all plugins
    fn execute_stage<F>(&self, stage: PluginStage, mut execute: F) -> PluginResult<()>
    where
        F: FnMut(&dyn Plugin) -> PluginResult<()>,
    {
        let start = Instant::now();
        let stage_name = format!("{:?}", stage);

        for plugin in &self.plugins {
            let plugin_start = Instant::now();

            match execute(plugin.as_ref()) {
                Ok(()) => {
                    self.metrics.histogram(
                        "bff.federation.plugin.duration_ms",
                        plugin_start.elapsed().as_millis() as f64,
                        &[("plugin", plugin.name()), ("stage", &stage_name)],
                    );
                }
                Err(e) => {
                    self.metrics.incr(
                        "bff.federation.plugin.error",
                        &[("plugin", plugin.name()), ("stage", &stage_name)],
                    );

                    if self.fail_fast {
                        return Err(e);
                    } else {
                        debug!(
                            plugin = plugin.name(),
                            stage = stage_name,
                            error = %e,
                            "Plugin error (continuing)"
                        );
                    }
                }
            }
        }

        self.metrics.histogram(
            "bff.federation.plugin.stage_duration_ms",
            start.elapsed().as_millis() as f64,
            &[("stage", &stage_name)],
        );

        Ok(())
    }
}

// ============================================================================
// Built-in Plugins
// ============================================================================

/// Security plugin
///
/// Implements depth limiting, complexity analysis, and introspection control.
pub struct SecurityPlugin {
    depth_limiter: Option<super::security::DepthLimiter>,
    complexity_analyzer: Option<super::security::ComplexityAnalyzer>,
    introspection_controller: Option<super::security::IntrospectionController>,
}

impl SecurityPlugin {
    /// Create a new security plugin
    pub fn new(
        depth_config: Option<super::security::DepthLimitConfig>,
        complexity_config: Option<super::security::ComplexityConfig>,
        introspection_config: Option<super::security::IntrospectionConfig>,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        Self {
            depth_limiter: depth_config
                .map(|c| super::security::DepthLimiter::new(c, metrics.clone())),
            complexity_analyzer: complexity_config
                .map(|c| super::security::ComplexityAnalyzer::new(c, metrics.clone())),
            introspection_controller: introspection_config
                .map(|c| super::security::IntrospectionController::new(c, metrics)),
        }
    }
}

impl Plugin for SecurityPlugin {
    fn name(&self) -> &'static str {
        "security"
    }

    fn priority(&self) -> i32 {
        // Run early to reject invalid queries quickly
        10
    }

    fn on_pre_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        // Check introspection
        if let Some(ref controller) = self.introspection_controller {
            let headers: Vec<(String, String)> = ctx
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();

            controller
                .validate(&ctx.query, ctx.client_ip.as_deref(), &headers)
                .map_err(|e| PluginError::RequestRejected {
                    name: self.name().to_string(),
                    reason: e.to_string(),
                })?;
        }

        // Check depth
        if let Some(ref limiter) = self.depth_limiter {
            let depth = limiter
                .validate(&ctx.query, ctx.operation_name.as_deref())
                .map_err(|e| PluginError::RequestRejected {
                    name: self.name().to_string(),
                    reason: e.to_string(),
                })?;

            ctx.query_depth = Some(depth);
        }

        // Check complexity
        if let Some(ref analyzer) = self.complexity_analyzer {
            let complexity = analyzer
                .validate(&ctx.query, ctx.operation_name.as_deref())
                .map_err(|e| PluginError::RequestRejected {
                    name: self.name().to_string(),
                    reason: e.to_string(),
                })?;

            ctx.query_complexity = Some(complexity);
        }

        Ok(())
    }
}

/// Tracing plugin
///
/// Creates OpenTelemetry spans for GraphQL operations.
#[allow(dead_code)]
pub struct TracingPlugin {
    /// Include query in span attributes
    include_query: bool,
    /// Include variables in span attributes
    include_variables: bool,
}

impl TracingPlugin {
    /// Create a new tracing plugin
    pub fn new(include_query: bool, include_variables: bool) -> Self {
        Self {
            include_query,
            include_variables,
        }
    }
}

impl Plugin for TracingPlugin {
    fn name(&self) -> &'static str {
        "tracing"
    }

    fn priority(&self) -> i32 {
        // Run very early to capture full request lifecycle
        5
    }

    fn on_pre_execute(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        use tracing::info_span;

        let span = info_span!(
            "graphql.execute",
            request_id = %ctx.request_id,
            operation_name = ctx.operation_name.as_deref().unwrap_or("anonymous"),
            product = %ctx.product,
            user_id = ctx.user_id.as_deref(),
            query_depth = ctx.query_depth,
            query_complexity = ctx.query_complexity,
        );

        if self.include_query {
            span.record("query", &ctx.query);
        }

        ctx.span = Some(span);

        Ok(())
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        // Add timing extension
        response.extensions.insert(
            "tracing".to_string(),
            serde_json::json!({
                "execution_ms": ctx.elapsed_ms(),
                "cache_hit": ctx.cache_hit,
                "deduplicated": ctx.deduplicated,
            }),
        );

        Ok(())
    }
}

/// Metrics plugin
///
/// Records Prometheus metrics for GraphQL operations.
pub struct MetricsPlugin {
    metrics: Arc<MetricsClient>,
}

impl MetricsPlugin {
    /// Create a new metrics plugin
    pub fn new(metrics: Arc<MetricsClient>) -> Self {
        Self { metrics }
    }
}

impl Plugin for MetricsPlugin {
    fn name(&self) -> &'static str {
        "metrics"
    }

    fn priority(&self) -> i32 {
        // Run early to capture all requests
        15
    }

    fn on_pre_execute(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        self.metrics.increment(
            "bff.federation.request.started",
            &[
                (
                    "operation",
                    ctx.operation_name.as_deref().unwrap_or("anonymous"),
                ),
                ("product", &ctx.product),
            ],
        );
        Ok(())
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        let status = if response.errors.is_empty() {
            "success"
        } else {
            "error"
        };

        self.metrics.increment(
            "bff.federation.request.completed",
            &[
                (
                    "operation",
                    ctx.operation_name.as_deref().unwrap_or("anonymous"),
                ),
                ("product", &ctx.product),
                ("status", status),
            ],
        );

        self.metrics.histogram(
            "bff.federation.request.duration_ms",
            ctx.elapsed_ms() as f64,
            &[
                (
                    "operation",
                    ctx.operation_name.as_deref().unwrap_or("anonymous"),
                ),
                ("product", &ctx.product),
            ],
        );

        if ctx.cache_hit {
            self.metrics
                .increment("bff.federation.request.cache_hit", &[]);
        }

        if ctx.deduplicated {
            self.metrics
                .increment("bff.federation.request.deduplicated", &[]);
        }

        Ok(())
    }

    fn on_error(&self, ctx: &PluginContext, error: &PluginError) -> PluginResult<()> {
        self.metrics.increment(
            "bff.federation.request.error",
            &[
                (
                    "operation",
                    ctx.operation_name.as_deref().unwrap_or("anonymous"),
                ),
                ("product", &ctx.product),
                (
                    "error_type",
                    match error {
                        PluginError::ExecutionError { .. } => "execution",
                        PluginError::RequestRejected { .. } => "rejected",
                        PluginError::ConfigError(_) => "config",
                        PluginError::NotFound(_) => "not_found",
                    },
                ),
            ],
        );
        Ok(())
    }
}

// ============================================================================
// Additional Built-in Plugins
// ============================================================================

/// Request ID plugin configuration
#[derive(Debug, Clone)]
pub struct RequestIdConfig {
    /// Header name to check for incoming request ID
    pub header_name: String,
    /// Prefix for generated request IDs
    pub prefix: String,
    /// Include request ID in response headers
    pub include_in_response: bool,
    /// Response header name
    pub response_header_name: String,
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header_name: "x-request-id".to_string(),
            prefix: "req".to_string(),
            include_in_response: true,
            response_header_name: "x-request-id".to_string(),
        }
    }
}

/// Request ID plugin
///
/// Generates or propagates request IDs for distributed tracing.
/// If a request ID header is present, it's used; otherwise, a new one is generated.
pub struct RequestIdPlugin {
    config: RequestIdConfig,
}

impl RequestIdPlugin {
    /// Create a new request ID plugin
    pub fn new(config: RequestIdConfig) -> Self {
        Self { config }
    }
}

impl Plugin for RequestIdPlugin {
    fn name(&self) -> &'static str {
        "request-id"
    }

    fn priority(&self) -> i32 {
        // Run very early to establish request ID
        1
    }

    fn on_pre_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        // Check if request ID already exists from header
        if let Some(existing_id) = ctx.headers.get(&self.config.header_name) {
            ctx.request_id = existing_id.clone();
        } else if ctx.request_id.is_empty() {
            // Generate a new request ID
            ctx.request_id = format!(
                "{}-{}-{}",
                self.config.prefix,
                chrono::Utc::now().timestamp_millis(),
                &uuid::Uuid::new_v4().to_string()[..8]
            );
        }

        ctx.set_data("request_id_plugin.id", ctx.request_id.clone());
        Ok(())
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        if self.config.include_in_response {
            response
                .extensions
                .insert("requestId".to_string(), serde_json::json!(ctx.request_id));
        }
        Ok(())
    }
}

/// Logging plugin configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level for requests: "debug", "info", "warn"
    pub level: String,
    /// Include query in logs (may expose sensitive data)
    pub include_query: bool,
    /// Include variables in logs (may expose sensitive data)
    pub include_variables: bool,
    /// Include response data in logs (may expose sensitive data)
    pub include_response: bool,
    /// Maximum query length to log (truncate longer queries)
    pub max_query_length: usize,
    /// Log slow queries (over threshold_ms)
    pub log_slow_queries: bool,
    /// Slow query threshold in milliseconds
    pub slow_query_threshold_ms: u64,
    /// Operations to exclude from logging (e.g., introspection)
    pub exclude_operations: Vec<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            include_query: false,
            include_variables: false,
            include_response: false,
            max_query_length: 500,
            log_slow_queries: true,
            slow_query_threshold_ms: 1000,
            exclude_operations: vec!["IntrospectionQuery".to_string()],
        }
    }
}

/// Logging plugin
///
/// Structured logging for GraphQL operations with configurable verbosity.
pub struct LoggingPlugin {
    config: LoggingConfig,
}

impl LoggingPlugin {
    /// Create a new logging plugin
    pub fn new(config: LoggingConfig) -> Self {
        Self { config }
    }

    fn should_log(&self, operation_name: Option<&str>) -> bool {
        if let Some(name) = operation_name {
            !self.config.exclude_operations.iter().any(|e| e == name)
        } else {
            true
        }
    }

    fn truncate_query(&self, query: &str) -> String {
        if query.len() > self.config.max_query_length {
            format!("{}...(truncated)", &query[..self.config.max_query_length])
        } else {
            query.to_string()
        }
    }
}

impl Plugin for LoggingPlugin {
    fn name(&self) -> &'static str {
        "logging"
    }

    fn priority(&self) -> i32 {
        // Run after request-id plugin
        3
    }

    fn on_pre_execute(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        if !self.should_log(ctx.operation_name.as_deref()) {
            return Ok(());
        }

        let query_info = if self.config.include_query {
            Some(self.truncate_query(&ctx.query))
        } else {
            None
        };

        let vars_info = if self.config.include_variables {
            ctx.variables.as_ref().map(|v| v.to_string())
        } else {
            None
        };

        match self.config.level.as_str() {
            "debug" => debug!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                user_id = ctx.user_id.as_deref(),
                product = %ctx.product,
                query = query_info,
                variables = vars_info,
                "GraphQL request started"
            ),
            "warn" => tracing::warn!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                "GraphQL request started"
            ),
            _ => info!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                user_id = ctx.user_id.as_deref(),
                product = %ctx.product,
                "GraphQL request started"
            ),
        }

        Ok(())
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        if !self.should_log(ctx.operation_name.as_deref()) {
            return Ok(());
        }

        let duration_ms = ctx.elapsed_ms();
        let is_slow = duration_ms > self.config.slow_query_threshold_ms;
        let error_count = response.errors.len();

        if is_slow && self.config.log_slow_queries {
            tracing::warn!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                duration_ms = duration_ms,
                threshold_ms = self.config.slow_query_threshold_ms,
                errors = error_count,
                "Slow GraphQL query detected"
            );
        } else {
            info!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                duration_ms = duration_ms,
                errors = error_count,
                cache_hit = ctx.cache_hit,
                "GraphQL request completed"
            );
        }

        Ok(())
    }

    fn on_error(&self, ctx: &PluginContext, error: &PluginError) -> PluginResult<()> {
        tracing::error!(
            request_id = %ctx.request_id,
            operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
            error = %error,
            "GraphQL request error"
        );
        Ok(())
    }
}

/// Error masking plugin configuration
#[derive(Debug, Clone)]
pub struct ErrorMaskingConfig {
    /// Mask internal errors in production
    pub mask_internal_errors: bool,
    /// Generic message for masked errors
    pub masked_message: String,
    /// Error codes to never mask (always show to client)
    pub passthrough_codes: Vec<String>,
    /// Include error code in masked errors
    pub include_code: bool,
    /// Include request ID in error message for support reference
    pub include_request_id: bool,
}

impl Default for ErrorMaskingConfig {
    fn default() -> Self {
        Self {
            mask_internal_errors: true,
            masked_message: "An internal error occurred".to_string(),
            passthrough_codes: vec![
                "UNAUTHENTICATED".to_string(),
                "FORBIDDEN".to_string(),
                "BAD_REQUEST".to_string(),
                "NOT_FOUND".to_string(),
                "VALIDATION_ERROR".to_string(),
            ],
            include_code: true,
            include_request_id: true,
        }
    }
}

/// Error masking plugin
///
/// Masks internal errors in production to prevent information leakage.
/// Client-safe errors (validation, auth) pass through unchanged.
pub struct ErrorMaskingPlugin {
    config: ErrorMaskingConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl ErrorMaskingPlugin {
    /// Create a new error masking plugin
    pub fn new(config: ErrorMaskingConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    fn should_mask(&self, error: &Value) -> bool {
        if !self.config.mask_internal_errors {
            return false;
        }

        // Check if error has a passthrough code
        if let Some(extensions) = error.get("extensions") {
            if let Some(code) = extensions.get("code").and_then(|c| c.as_str()) {
                return !self.config.passthrough_codes.contains(&code.to_string());
            }
        }

        // Default to masking if no code or code not in passthrough list
        true
    }

    fn mask_error(&self, error: &Value, request_id: &str) -> Value {
        let mut masked = serde_json::json!({
            "message": self.config.masked_message,
        });

        if self.config.include_code {
            let code = error
                .get("extensions")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .unwrap_or("INTERNAL_SERVER_ERROR");

            masked["extensions"] = serde_json::json!({
                "code": code,
            });
        }

        if self.config.include_request_id {
            if let Some(ext) = masked.get_mut("extensions") {
                ext["requestId"] = serde_json::json!(request_id);
            } else {
                masked["extensions"] = serde_json::json!({
                    "requestId": request_id,
                });
            }
        }

        masked
    }
}

impl Plugin for ErrorMaskingPlugin {
    fn name(&self) -> &'static str {
        "error-masking"
    }

    fn priority(&self) -> i32 {
        // Run late, after other plugins have processed errors
        900
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        let mut masked_count = 0;

        response.errors = response
            .errors
            .iter()
            .map(|error| {
                if self.should_mask(error) {
                    masked_count += 1;
                    self.mask_error(error, &ctx.request_id)
                } else {
                    error.clone()
                }
            })
            .collect();

        if masked_count > 0 {
            self.metrics.incr(
                "bff.federation.plugin.errors_masked",
                &[("count", &masked_count.to_string())],
            );
        }

        Ok(())
    }
}

/// Performance plugin configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Slow query threshold in milliseconds
    pub slow_query_threshold_ms: u64,
    /// Very slow query threshold (critical alert)
    pub critical_threshold_ms: u64,
    /// Track query performance by operation name
    pub track_by_operation: bool,
    /// Maximum operations to track (prevent memory bloat)
    pub max_tracked_operations: usize,
    /// Include performance hints in response extensions
    pub include_hints: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            slow_query_threshold_ms: 500,
            critical_threshold_ms: 2000,
            track_by_operation: true,
            max_tracked_operations: 1000,
            include_hints: true,
        }
    }
}

/// Performance plugin
///
/// Monitors query performance and provides insights.
pub struct PerformancePlugin {
    config: PerformanceConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl PerformancePlugin {
    /// Create a new performance plugin
    pub fn new(config: PerformanceConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }
}

impl Plugin for PerformancePlugin {
    fn name(&self) -> &'static str {
        "performance"
    }

    fn priority(&self) -> i32 {
        200
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        let duration_ms = ctx.elapsed_ms();
        let operation = ctx.operation_name.as_deref().unwrap_or("anonymous");

        // Categorize performance
        let (category, hints) = if duration_ms > self.config.critical_threshold_ms {
            self.metrics.incr(
                "bff.federation.performance.critical_slow_query",
                &[("operation", operation)],
            );
            tracing::error!(
                request_id = %ctx.request_id,
                operation = operation,
                duration_ms = duration_ms,
                threshold_ms = self.config.critical_threshold_ms,
                "Critical: Very slow GraphQL query"
            );
            (
                "critical",
                vec![
                    "Consider adding caching",
                    "Review query complexity",
                    "Check N+1 queries",
                ],
            )
        } else if duration_ms > self.config.slow_query_threshold_ms {
            self.metrics.incr(
                "bff.federation.performance.slow_query",
                &[("operation", operation)],
            );
            tracing::warn!(
                request_id = %ctx.request_id,
                operation = operation,
                duration_ms = duration_ms,
                threshold_ms = self.config.slow_query_threshold_ms,
                "Warning: Slow GraphQL query"
            );
            ("slow", vec!["Consider optimizing this query"])
        } else {
            ("ok", vec![])
        };

        // Record histogram
        self.metrics.histogram(
            "bff.federation.performance.query_duration_ms",
            duration_ms as f64,
            &[("operation", operation), ("category", category)],
        );

        // Add performance hints to response
        if self.config.include_hints && !hints.is_empty() {
            response.extensions.insert(
                "performance".to_string(),
                serde_json::json!({
                    "duration_ms": duration_ms,
                    "category": category,
                    "hints": hints,
                }),
            );
        }

        Ok(())
    }
}

/// Cost tracking plugin configuration
#[derive(Debug, Clone)]
pub struct CostTrackingConfig {
    /// Track cost by user
    pub track_by_user: bool,
    /// Track cost by operation
    pub track_by_operation: bool,
    /// Include cost in response extensions
    pub include_in_response: bool,
    /// Cost budget per user per hour (0 = unlimited)
    pub user_hourly_budget: u32,
    /// Warn when approaching budget (percentage, e.g., 80)
    pub budget_warning_threshold: u8,
}

impl Default for CostTrackingConfig {
    fn default() -> Self {
        Self {
            track_by_user: true,
            track_by_operation: true,
            include_in_response: true,
            user_hourly_budget: 0, // Unlimited by default
            budget_warning_threshold: 80,
        }
    }
}

/// Cost tracking plugin
///
/// Tracks query costs for billing, quotas, and usage analytics.
pub struct CostTrackingPlugin {
    config: CostTrackingConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl CostTrackingPlugin {
    /// Create a new cost tracking plugin
    pub fn new(config: CostTrackingConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }
}

impl Plugin for CostTrackingPlugin {
    fn name(&self) -> &'static str {
        "cost-tracking"
    }

    fn priority(&self) -> i32 {
        250
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        // Cost is based on complexity if available, otherwise estimated from depth
        let cost = ctx
            .query_complexity
            .unwrap_or_else(|| ctx.query_depth.map(|d| d as u32 * 10).unwrap_or(1));

        let operation = ctx.operation_name.as_deref().unwrap_or("anonymous");
        let user_id = ctx.user_id.as_deref().unwrap_or("anonymous");

        // Track metrics
        if let Some(ref m) = self.metrics {
            if self.config.track_by_user && ctx.user_id.is_some() {
                m.histogram(
                    "bff.federation.cost.by_user",
                    cost as f64,
                    &[("user_id", user_id)],
                );
            }

            if self.config.track_by_operation {
                m.histogram(
                    "bff.federation.cost.by_operation",
                    cost as f64,
                    &[("operation", operation)],
                );
            }

            m.increment("bff.federation.cost.total", &[("product", &ctx.product)]);
        }

        // Include in response
        if self.config.include_in_response {
            response.extensions.insert(
                "cost".to_string(),
                serde_json::json!({
                    "estimated": cost,
                    "complexity": ctx.query_complexity,
                    "depth": ctx.query_depth,
                }),
            );
        }

        Ok(())
    }
}

/// Response extensions plugin configuration
#[derive(Debug, Clone)]
pub struct ResponseExtensionsConfig {
    /// Include server timestamp
    pub include_timestamp: bool,
    /// Include server version
    pub include_version: bool,
    /// Server version string
    pub version: String,
    /// Include cache status
    pub include_cache_status: bool,
    /// Custom static extensions
    pub custom_extensions: HashMap<String, Value>,
}

impl Default for ResponseExtensionsConfig {
    fn default() -> Self {
        Self {
            include_timestamp: true,
            include_version: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            include_cache_status: true,
            custom_extensions: HashMap::new(),
        }
    }
}

/// Response extensions plugin
///
/// Adds metadata to GraphQL response extensions.
pub struct ResponseExtensionsPlugin {
    config: ResponseExtensionsConfig,
}

impl ResponseExtensionsPlugin {
    /// Create a new response extensions plugin
    pub fn new(config: ResponseExtensionsConfig) -> Self {
        Self { config }
    }
}

impl Plugin for ResponseExtensionsPlugin {
    fn name(&self) -> &'static str {
        "response-extensions"
    }

    fn priority(&self) -> i32 {
        // Run late to capture all data
        800
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        if self.config.include_timestamp {
            response.extensions.insert(
                "timestamp".to_string(),
                serde_json::json!(chrono::Utc::now().to_rfc3339()),
            );
        }

        if self.config.include_version {
            response.extensions.insert(
                "serverVersion".to_string(),
                serde_json::json!(self.config.version),
            );
        }

        if self.config.include_cache_status {
            response.extensions.insert(
                "cache".to_string(),
                serde_json::json!({
                    "hit": ctx.cache_hit,
                    "deduplicated": ctx.deduplicated,
                }),
            );
        }

        // Add custom extensions
        for (key, value) in &self.config.custom_extensions {
            response.extensions.insert(key.clone(), value.clone());
        }

        Ok(())
    }
}

/// Audit plugin configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Operations to audit (empty = all)
    pub audited_operations: Vec<String>,
    /// Operations to never audit
    pub excluded_operations: Vec<String>,
    /// Audit mutations only
    pub mutations_only: bool,
    /// Include query in audit log
    pub include_query: bool,
    /// Include variables in audit log (may contain sensitive data)
    pub include_variables: bool,
    /// Include response status
    pub include_response_status: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            audited_operations: vec![], // All operations
            excluded_operations: vec!["IntrospectionQuery".to_string()],
            mutations_only: false,
            include_query: true,
            include_variables: false,
            include_response_status: true,
        }
    }
}

/// Audit plugin
///
/// Provides audit logging for compliance and security monitoring.
pub struct AuditPlugin {
    config: AuditConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl AuditPlugin {
    /// Create a new audit plugin
    pub fn new(config: AuditConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    fn should_audit(&self, ctx: &PluginContext) -> bool {
        let operation = ctx.operation_name.as_deref().unwrap_or("anonymous");

        // Check exclusions
        if self
            .config
            .excluded_operations
            .contains(&operation.to_string())
        {
            return false;
        }

        // Check mutations only
        if self.config.mutations_only && !ctx.query.trim_start().starts_with("mutation") {
            return false;
        }

        // Check specific operations
        if !self.config.audited_operations.is_empty() {
            return self
                .config
                .audited_operations
                .contains(&operation.to_string());
        }

        true
    }
}

impl Plugin for AuditPlugin {
    fn name(&self) -> &'static str {
        "audit"
    }

    fn priority(&self) -> i32 {
        // Run late to capture final state
        850
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        if !self.should_audit(ctx) {
            return Ok(());
        }

        let operation = ctx.operation_name.as_deref().unwrap_or("anonymous");
        let user_id = ctx.user_id.as_deref().unwrap_or("anonymous");
        let success = response.errors.is_empty();

        // Structured audit log
        info!(
            target: "audit",
            request_id = %ctx.request_id,
            operation = operation,
            user_id = user_id,
            product = %ctx.product,
            client_ip = ctx.client_ip.as_deref(),
            duration_ms = ctx.elapsed_ms(),
            success = success,
            error_count = response.errors.len(),
            query = if self.config.include_query { Some(&ctx.query) } else { None },
            "GraphQL operation audited"
        );

        self.metrics.incr(
            "bff.federation.audit.logged",
            &[
                ("operation", operation),
                ("success", if success { "true" } else { "false" }),
            ],
        );

        Ok(())
    }
}

/// Header propagation plugin configuration
#[derive(Debug, Clone)]
pub struct HeaderPropagationConfig {
    /// Headers to propagate from client to subgraphs
    pub propagate_headers: Vec<String>,
    /// Headers to add to all responses
    pub response_headers: HashMap<String, String>,
    /// Remove sensitive headers from being propagated
    pub remove_headers: Vec<String>,
    /// Rename headers (from → to)
    pub rename_headers: HashMap<String, String>,
}

impl Default for HeaderPropagationConfig {
    fn default() -> Self {
        let mut response_headers = HashMap::new();
        response_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());

        Self {
            propagate_headers: vec![
                "x-correlation-id".to_string(),
                "x-request-id".to_string(),
                "accept-language".to_string(),
            ],
            response_headers,
            remove_headers: vec!["authorization".to_string(), "cookie".to_string()],
            rename_headers: HashMap::new(),
        }
    }
}

/// Header propagation plugin
///
/// Controls which headers pass between client, BFF, and subgraphs.
pub struct HeaderPropagationPlugin {
    config: HeaderPropagationConfig,
}

impl HeaderPropagationPlugin {
    /// Create a new header propagation plugin
    pub fn new(config: HeaderPropagationConfig) -> Self {
        Self { config }
    }
}

impl Plugin for HeaderPropagationPlugin {
    fn name(&self) -> &'static str {
        "header-propagation"
    }

    fn priority(&self) -> i32 {
        2 // Run very early, after request-id
    }

    fn on_pre_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        // Store propagatable headers
        let propagatable: HashMap<String, String> = ctx
            .headers
            .iter()
            .filter(|(k, _)| {
                let key_lower = k.to_lowercase();
                self.config
                    .propagate_headers
                    .iter()
                    .any(|h| h.to_lowercase() == key_lower)
                    && !self
                        .config
                        .remove_headers
                        .iter()
                        .any(|h| h.to_lowercase() == key_lower)
            })
            .map(|(k, v)| {
                // Apply renames
                let new_key = self
                    .config
                    .rename_headers
                    .get(k)
                    .cloned()
                    .unwrap_or_else(|| k.clone());
                (new_key, v.clone())
            })
            .collect();

        ctx.set_data("propagatable_headers", propagatable);
        Ok(())
    }

    fn on_post_execute(
        &self,
        _ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        // Add configured response headers
        for (key, value) in &self.config.response_headers {
            response
                .extensions
                .insert(format!("header:{}", key), serde_json::json!(value));
        }
        Ok(())
    }
}

/// Operation timeout plugin configuration
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Default timeout in milliseconds
    pub default_timeout_ms: u64,
    /// Per-operation timeouts (operation name → timeout ms)
    pub operation_timeouts: HashMap<String, u64>,
    /// Include timeout info in response
    pub include_in_response: bool,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        let mut operation_timeouts = HashMap::new();
        // Introspection should be fast
        operation_timeouts.insert("IntrospectionQuery".to_string(), 5000);

        Self {
            default_timeout_ms: 30000, // 30 seconds
            operation_timeouts,
            include_in_response: false,
        }
    }
}

/// Operation timeout plugin
///
/// Enforces per-operation timeout limits.
pub struct TimeoutPlugin {
    config: TimeoutConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl TimeoutPlugin {
    /// Create a new timeout plugin
    pub fn new(config: TimeoutConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    fn get_timeout(&self, operation: Option<&str>) -> u64 {
        if let Some(op) = operation {
            self.config
                .operation_timeouts
                .get(op)
                .copied()
                .unwrap_or(self.config.default_timeout_ms)
        } else {
            self.config.default_timeout_ms
        }
    }
}

impl Plugin for TimeoutPlugin {
    fn name(&self) -> &'static str {
        "timeout"
    }

    fn priority(&self) -> i32 {
        4 // Run early
    }

    fn on_pre_execute(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        let timeout_ms = self.get_timeout(ctx.operation_name.as_deref());
        ctx.set_data("timeout_ms", timeout_ms);
        Ok(())
    }

    fn on_post_execute(
        &self,
        ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        let timeout_ms = self.get_timeout(ctx.operation_name.as_deref());
        let duration_ms = ctx.elapsed_ms();

        // Check if operation exceeded timeout
        if duration_ms > timeout_ms {
            self.metrics.incr(
                "bff.federation.timeout.exceeded",
                &[(
                    "operation",
                    ctx.operation_name.as_deref().unwrap_or("anonymous"),
                )],
            );

            tracing::warn!(
                request_id = %ctx.request_id,
                operation = ctx.operation_name.as_deref().unwrap_or("anonymous"),
                duration_ms = duration_ms,
                timeout_ms = timeout_ms,
                "Operation exceeded timeout (completed late)"
            );
        }

        if self.config.include_in_response {
            response.extensions.insert(
                "timeout".to_string(),
                serde_json::json!({
                    "limit_ms": timeout_ms,
                    "elapsed_ms": duration_ms,
                    "exceeded": duration_ms > timeout_ms,
                }),
            );
        }

        Ok(())
    }
}

/// Query allow list plugin configuration
#[derive(Debug, Clone)]
pub struct AllowListConfig {
    /// Enable strict mode (reject queries not in allow list)
    pub strict_mode: bool,
    /// Allowed operation names
    pub allowed_operations: Vec<String>,
    /// Allowed query hashes (SHA256)
    pub allowed_hashes: Vec<String>,
    /// Log blocked queries
    pub log_blocked: bool,
}

impl Default for AllowListConfig {
    fn default() -> Self {
        Self {
            strict_mode: false,
            allowed_operations: vec![],
            allowed_hashes: vec![],
            log_blocked: true,
        }
    }
}

/// Query allow list plugin
///
/// Restricts queries to a predefined allow list for security.
pub struct AllowListPlugin {
    config: AllowListConfig,
    metrics: Option<Arc<MetricsClient>>,
}

impl AllowListPlugin {
    /// Create a new allow list plugin
    pub fn new(config: AllowListConfig, metrics: Option<Arc<MetricsClient>>) -> Self {
        Self { config, metrics }
    }

    fn hash_query(query: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(query.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

impl Plugin for AllowListPlugin {
    fn name(&self) -> &'static str {
        "allow-list"
    }

    fn priority(&self) -> i32 {
        8 // Run early, after security
    }

    fn on_pre_parse(&self, ctx: &mut PluginContext) -> PluginResult<()> {
        if !self.config.strict_mode {
            return Ok(());
        }

        let operation = ctx.operation_name.as_deref().unwrap_or("");
        let query_hash = Self::hash_query(&ctx.query);

        // Check if operation or hash is allowed
        let operation_allowed = self
            .config
            .allowed_operations
            .contains(&operation.to_string())
            || self.config.allowed_operations.is_empty();
        let hash_allowed = self.config.allowed_hashes.contains(&query_hash)
            || self.config.allowed_hashes.is_empty();

        if !operation_allowed && !hash_allowed {
            if self.config.log_blocked {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    operation = operation,
                    query_hash = query_hash,
                    "Query blocked by allow list"
                );
            }

            self.metrics.incr("bff.federation.allowlist.blocked", &[]);

            return Err(PluginError::RequestRejected {
                name: self.name().to_string(),
                reason: "Query not in allow list".to_string(),
            });
        }

        Ok(())
    }
}

/// Sanitization plugin configuration
#[derive(Debug, Clone)]
pub struct SanitizationConfig {
    /// Remove __typename from responses
    pub remove_typename: bool,
    /// Remove null fields from responses
    pub remove_nulls: bool,
    /// Fields to always remove from responses
    pub remove_fields: Vec<String>,
    /// Redact fields (replace with "[REDACTED]")
    pub redact_fields: Vec<String>,
}

impl Default for SanitizationConfig {
    fn default() -> Self {
        Self {
            remove_typename: false,
            remove_nulls: false,
            remove_fields: vec![],
            redact_fields: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
            ],
        }
    }
}

/// Sanitization plugin
///
/// Sanitizes response data for security and cleanliness.
pub struct SanitizationPlugin {
    config: SanitizationConfig,
}

impl SanitizationPlugin {
    /// Create a new sanitization plugin
    pub fn new(config: SanitizationConfig) -> Self {
        Self { config }
    }

    fn sanitize_value(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                // Remove specified fields
                for field in &self.config.remove_fields {
                    map.remove(field);
                }

                // Remove __typename if configured
                if self.config.remove_typename {
                    map.remove("__typename");
                }

                // Redact fields
                for field in &self.config.redact_fields {
                    if map.contains_key(field) {
                        map.insert(field.clone(), serde_json::json!("[REDACTED]"));
                    }
                }

                // Remove nulls if configured
                if self.config.remove_nulls {
                    map.retain(|_, v| !v.is_null());
                }

                // Recursively sanitize nested objects
                for (_, v) in map.iter_mut() {
                    self.sanitize_value(v);
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.sanitize_value(item);
                }
            }
            _ => {}
        }
    }
}

impl Plugin for SanitizationPlugin {
    fn name(&self) -> &'static str {
        "sanitization"
    }

    fn priority(&self) -> i32 {
        950 // Run very late, just before response
    }

    fn on_post_execute(
        &self,
        _ctx: &PluginContext,
        response: &mut PluginResponse,
    ) -> PluginResult<()> {
        if let Some(ref mut data) = response.data {
            self.sanitize_value(data);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestPlugin {
        name: &'static str,
        priority: i32,
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> i32 {
            self.priority
        }
    }

    #[test]
    fn test_plugin_registry_ordering() {
        let registry = PluginRegistry::new(None)
            .register(Arc::new(TestPlugin {
                name: "low",
                priority: 100,
            }))
            .register(Arc::new(TestPlugin {
                name: "high",
                priority: 10,
            }))
            .register(Arc::new(TestPlugin {
                name: "medium",
                priority: 50,
            }));

        assert_eq!(registry.plugin_count(), 3);
        assert_eq!(registry.plugins[0].name(), "high");
        assert_eq!(registry.plugins[1].name(), "medium");
        assert_eq!(registry.plugins[2].name(), "low");
    }

    #[test]
    fn test_plugin_context_data() {
        let mut ctx = PluginContext::new(
            "test-123".to_string(),
            "query { user }".to_string(),
            None,
            None,
            "myapp".to_string(),
        );

        ctx.set_data("custom_key", "custom_value");
        let value: Option<String> = ctx.get_data("custom_key");

        assert_eq!(value, Some("custom_value".to_string()));
    }

    #[test]
    fn test_error_masking() {
        let config = ErrorMaskingConfig::default();
        let plugin = ErrorMaskingPlugin::new(config, None);

        // Internal error should be masked
        let internal_error = serde_json::json!({
            "message": "Database connection failed at line 123",
            "extensions": {
                "code": "INTERNAL_SERVER_ERROR"
            }
        });
        assert!(plugin.should_mask(&internal_error));

        // Auth error should not be masked
        let auth_error = serde_json::json!({
            "message": "Invalid credentials",
            "extensions": {
                "code": "UNAUTHENTICATED"
            }
        });
        assert!(!plugin.should_mask(&auth_error));
    }

    #[test]
    fn test_sanitization() {
        let config = SanitizationConfig {
            remove_typename: true,
            remove_nulls: true,
            remove_fields: vec!["internalId".to_string()],
            redact_fields: vec!["password".to_string()],
        };
        let plugin = SanitizationPlugin::new(config);

        let mut data = serde_json::json!({
            "__typename": "User",
            "id": "123",
            "name": "Test",
            "password": "secret123",
            "internalId": "internal-456",
            "optional": null
        });

        plugin.sanitize_value(&mut data);

        assert!(!data.as_object().unwrap().contains_key("__typename"));
        assert!(!data.as_object().unwrap().contains_key("internalId"));
        assert!(!data.as_object().unwrap().contains_key("optional"));
        assert_eq!(data["password"], "[REDACTED]");
        assert_eq!(data["id"], "123");
    }
}
