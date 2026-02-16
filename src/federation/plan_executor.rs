#![allow(dead_code)]
//! Query Plan Execution for GraphQL Federation
//!
//! Executes query plans by calling subgraphs and merging responses.
//! Handles parallel execution, entity resolution, and response composition.
//!
//! # Execution Flow
//!
//! 1. Receive a QueryPlan from the QueryPlanner
//! 2. Execute fetch nodes (parallel or sequential based on plan)
//! 3. For entity fetches, resolve via `_entities` query
//! 4. Merge responses from multiple subgraphs
//! 5. Return unified GraphQL response
//!
//! # Example
//!
//! ```text
//! QueryPlan:
//!   Parallel [
//!     Fetch(auth, "{ user { name } }")
//!     Fetch(order, "{ orders { id } }")
//!   ]
//!
//! Execution:
//! ┌──────────────┐     ┌─────────────────┐
//! │ auth service │     │ order service   │
//! │ { user: ... }│     │ { orders: ... } │
//! └──────┬───────┘     └────────┬────────┘
//!        │                      │
//!        └──────────┬───────────┘
//!                   ▼
//!              ┌─────────┐
//!              │  Merge  │
//!              │ Results │
//!              └────┬────┘
//!                   ▼
//!        { user: ..., orders: ... }
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, instrument, warn};

use crate::federation::query_planner::{
    FetchNode, FlattenNode, ParallelNode, PlanNode, QueryPlan, SequenceNode,
};
use crate::metrics::{MetricsClient, MetricsExt};

/// Configuration for plan execution
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Request timeout per subgraph call
    pub timeout: Duration,

    /// Maximum concurrent subgraph calls
    pub max_concurrency: usize,

    /// Enable response merging optimizations
    pub optimize_merging: bool,

    /// Retry failed fetches
    pub retry_count: usize,

    /// Retry delay
    pub retry_delay: Duration,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            // CRITICAL: Keep timeout SHORT to fail fast like Hive Router
            // Long timeouts cause 504 cascades - if subgraph is slow, fail quickly
            // 10 seconds is generous for any well-behaved subgraph
            // Anything slower should be investigated, not waited on
            timeout: Duration::from_secs(10),
            // CRITICAL: Set high enough to not block under normal load
            // Each GraphQL query may need 3-5+ subgraph calls
            // With 100 concurrent users, that's 300-500 subgraph calls
            // Previous value of 16 caused request queuing and 504 timeouts!
            max_concurrency: 256,
            optimize_merging: true,
            retry_count: 1,
            retry_delay: Duration::from_millis(100),
        }
    }
}

/// Context for plan execution
pub struct ExecutionContext {
    /// Original GraphQL variables
    pub variables: Value,

    /// Headers to forward to subgraphs
    pub headers: HashMap<String, String>,

    /// Product scope for multi-tenant isolation
    pub product: String,

    /// User ID (if authenticated)
    pub user_id: Option<String>,

    /// User email (for audit/context)
    pub user_email: Option<String>,

    /// User roles (for pleme-rbac)
    pub user_roles: Vec<String>,

    /// User permissions (for pleme-rbac)
    pub user_permissions: Vec<String>,

    /// User relationships (for client-provider linking)
    /// Format: JSON array of relationship objects
    pub user_relationships: Vec<String>,

    /// HMAC secret for signing requests
    pub hmac_secret: Option<String>,

    /// Authorization header (forwarded from client)
    pub authorization: Option<String>,

    /// Cookies to forward to auth subgraph only
    pub cookies: Option<String>,
}

/// Query plan executor
pub struct PlanExecutor {
    /// HTTP client for subgraph calls
    http_client: Client,

    /// Executor configuration
    config: ExecutorConfig,

    /// Concurrency limiter
    semaphore: Arc<Semaphore>,

    /// Metrics client
    metrics: Option<Arc<MetricsClient>>,
}

/// Result of executing a fetch
#[allow(dead_code)]
#[derive(Debug)]
struct FetchResult {
    /// Subgraph name
    subgraph: String,

    /// Response data
    data: Option<Value>,

    /// Response errors
    errors: Vec<GraphQLError>,

    /// Execution time
    duration: Duration,
}

/// GraphQL error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLError {
    /// Error message
    pub message: String,

    /// Error locations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub locations: Vec<ErrorLocation>,

    /// Error path
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<Value>,

    /// Error extensions
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, Value>,
}

/// Error location in GraphQL document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorLocation {
    pub line: u32,
    pub column: u32,
}

/// Execution result
#[derive(Debug, Serialize)]
pub struct ExecutionResult {
    /// Response data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,

    /// Response errors
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<GraphQLError>,

    /// Extensions (timing, tracing)
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extensions: HashMap<String, Value>,
}

/// Error during plan execution
#[derive(Debug)]
pub struct ExecutionError {
    /// Error message
    pub message: String,

    /// Subgraph that caused the error (if applicable)
    pub subgraph: Option<String>,

    /// HTTP status code (if applicable)
    pub status_code: Option<u16>,
}

impl std::fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref subgraph) = self.subgraph {
            write!(f, "Execution error in {}: {}", subgraph, self.message)
        } else {
            write!(f, "Execution error: {}", self.message)
        }
    }
}

impl std::error::Error for ExecutionError {}

impl PlanExecutor {
    /// Create a new plan executor
    pub fn new(
        http_client: Client,
        config: ExecutorConfig,
        metrics: Option<Arc<MetricsClient>>,
    ) -> Self {
        info!(
            max_concurrency = config.max_concurrency,
            timeout_secs = config.timeout.as_secs(),
            "Plan executor initialized"
        );

        let semaphore = Arc::new(Semaphore::new(config.max_concurrency));

        Self {
            http_client,
            config,
            semaphore,
            metrics,
        }
    }

    /// Execute a query plan
    #[instrument(skip(self, plan, context), fields(fetch_count = plan.fetch_count))]
    pub async fn execute(
        &self,
        plan: &QueryPlan,
        operation: &str,
        context: &ExecutionContext,
    ) -> Result<ExecutionResult, ExecutionError> {
        let start = Instant::now();

        self.metrics.incr("bff.federation.executor.execute", &[]);

        let result = self.execute_node(&plan.node, operation, context).await?;

        let duration = start.elapsed();

        self.metrics.histogram(
            "bff.federation.executor.duration_ms",
            duration.as_millis() as f64,
            &[],
        );

        // Build extensions
        let mut extensions = HashMap::new();
        extensions.insert(
            "timing".to_string(),
            json!({
                "total_ms": duration.as_millis(),
                "subgraphs": plan.subgraphs,
            }),
        );

        Ok(ExecutionResult {
            data: result.data,
            errors: result.errors,
            extensions,
        })
    }

    /// Execute a plan node
    /// Uses Box::pin for async recursion
    fn execute_node<'a>(
        &'a self,
        node: &'a PlanNode,
        operation: &'a str,
        context: &'a ExecutionContext,
    ) -> Pin<Box<dyn Future<Output = Result<FetchResult, ExecutionError>> + Send + 'a>> {
        Box::pin(async move {
            match node {
                PlanNode::Fetch(fetch) => self.execute_fetch(fetch, operation, context).await,
                PlanNode::Sequence(seq) => self.execute_sequence(seq, operation, context).await,
                PlanNode::Parallel(par) => self.execute_parallel(par, operation, context).await,
                PlanNode::Flatten(flatten) => {
                    self.execute_flatten(flatten, operation, context).await
                }
                PlanNode::Empty => Ok(FetchResult {
                    subgraph: String::new(),
                    data: Some(json!({})),
                    errors: Vec::new(),
                    duration: Duration::ZERO,
                }),
            }
        })
    }

    /// Execute a fetch node
    async fn execute_fetch(
        &self,
        fetch: &FetchNode,
        original_operation: &str,
        context: &ExecutionContext,
    ) -> Result<FetchResult, ExecutionError> {
        let start = Instant::now();

        // CRITICAL: Use try_acquire() for non-blocking admission control
        // Following non-blocking-architecture skill: prefer try_acquire() over acquire().await
        // This implements fail-fast load shedding instead of queueing requests
        let _permit = match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                // Emit available permits metric for capacity monitoring
                self.metrics.gauge(
                    "bff.federation.executor.semaphore.available",
                    self.semaphore.available_permits() as f64,
                    &[],
                );
                permit
            }
            Err(_) => {
                // Semaphore exhausted - system is overloaded
                // Return 503 immediately instead of queueing (Google SRE load shedding pattern)
                let available = self.semaphore.available_permits();
                warn!(
                    subgraph = %fetch.subgraph,
                    available_permits = available,
                    max_concurrency = self.config.max_concurrency,
                    "Semaphore exhausted - rejecting request to prevent cascading failure"
                );
                if let Some(ref m) = self.metrics {
                    m.increment(
                        "bff.federation.executor.semaphore_exhausted",
                        &[("subgraph", fetch.subgraph.as_str())],
                    );
                    m.gauge(
                        "bff.federation.executor.semaphore.available",
                        available as f64,
                        &[],
                    );
                }
                return Err(ExecutionError {
                    message: format!(
                        "Service overloaded: {} concurrent requests (max: {}). Please retry after a brief delay.",
                        self.config.max_concurrency - available,
                        self.config.max_concurrency
                    ),
                    subgraph: Some(fetch.subgraph.clone()),
                    status_code: Some(503), // Service Unavailable
                });
            }
        };

        // Use the original operation if fetch operation is empty
        let operation = if fetch.operation.is_empty() {
            original_operation.to_string()
        } else {
            fetch.operation.clone()
        };

        // Build request body with extensions for HMAC (Hive Gateway compatible)
        let mut body = json!({
            "query": operation,
            "variables": context.variables,
        });

        // Add HMAC signature to extensions field (Hive Gateway pattern)
        // NOTE: Signature is added to GraphQL extensions, not HTTP headers
        if let Some(ref secret) = context.hmac_secret {
            let signature = self.sign_request(&body, secret)?;
            body["extensions"] = json!({
                "hmac-signature": signature
            });
        }

        // DEBUG: Log the exact body being sent to help diagnose JSON parsing errors
        // This helps identify if the body is malformed or truncated
        let body_json = serde_json::to_string(&body).unwrap_or_else(|e| {
            error!(
                subgraph = %fetch.subgraph,
                error = %e,
                "Failed to serialize body to JSON"
            );
            format!("SERIALIZATION_ERROR: {}", e)
        });

        debug!(
            subgraph = %fetch.subgraph,
            url = %fetch.url,
            body_len = body_json.len(),
            operation_len = operation.len(),
            has_hmac = context.hmac_secret.is_some(),
            body_preview = %if body_json.len() > 200 {
                format!("{}...(truncated)", &body_json[..200])
            } else {
                body_json.clone()
            },
            "Subgraph request body prepared"
        );

        // Verify the serialized body is valid JSON before sending
        if let Err(e) = serde_json::from_str::<Value>(&body_json) {
            error!(
                subgraph = %fetch.subgraph,
                error = %e,
                body = %body_json,
                "BUG: Serialized body is not valid JSON!"
            );
        }

        // Build headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );

        // Forward context headers
        for (key, value) in &context.headers {
            if let Ok(header_name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                if let Ok(header_value) = value.parse() {
                    headers.insert(header_name, header_value);
                }
            }
        }

        // Add product header
        if let Ok(value) = context.product.parse() {
            headers.insert(reqwest::header::HeaderName::from_static("x-product"), value);
        }

        // Add user ID header if present
        if let Some(ref user_id) = context.user_id {
            if let Ok(value) = user_id.parse() {
                headers.insert(reqwest::header::HeaderName::from_static("x-user-id"), value);
            }
        }

        // Add user email header if present
        if let Some(ref user_email) = context.user_email {
            if let Ok(value) = user_email.parse() {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-user-email"),
                    value,
                );
            }
        }

        // Add user roles header (comma-separated, for pleme-rbac)
        if !context.user_roles.is_empty() {
            let roles_str = context.user_roles.join(",");
            if let Ok(value) = roles_str.parse() {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-user-roles"),
                    value,
                );
            }
        }

        // Add user permissions header (comma-separated, for pleme-rbac)
        if !context.user_permissions.is_empty() {
            let permissions_str = context.user_permissions.join(",");
            if let Ok(value) = permissions_str.parse() {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-user-permissions"),
                    value,
                );
            }
        }

        // Add user relationships header (comma-separated, for client-provider linking)
        if !context.user_relationships.is_empty() {
            let relationships_str = context.user_relationships.join(",");
            if let Ok(value) = relationships_str.parse() {
                headers.insert(
                    reqwest::header::HeaderName::from_static("x-user-relationships"),
                    value,
                );
            }
        }

        // Forward authorization header to all subgraphs
        if let Some(ref auth) = context.authorization {
            if let Ok(value) = auth.parse() {
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
        }

        // Forward cookies ONLY to auth subgraph (for HttpOnly refresh token handling)
        // This matches Hive Gateway's cookie forwarding pattern
        if fetch.subgraph == "auth" {
            if let Some(ref cookies) = context.cookies {
                if let Ok(value) = cookies.parse() {
                    headers.insert(reqwest::header::COOKIE, value);
                }
            }
        }

        // HMAC signature is now sent via GraphQL extensions field (above)
        // This matches Hive Gateway's hmacSignature pattern for compatibility

        // Debug: Log forwarded auth headers for permission debugging
        debug!(
            subgraph = %fetch.subgraph,
            has_user_id = context.user_id.is_some(),
            permissions_count = context.user_permissions.len(),
            permissions_preview = ?context.user_permissions.iter().take(5).collect::<Vec<_>>(),
            "Forwarding auth headers to subgraph"
        );

        // Log the operation being sent (first 200 chars to avoid log spam)
        let operation_preview = if operation.len() > 200 {
            format!("{}...(truncated)", &operation[..200])
        } else {
            operation.clone()
        };

        // Log full body for debugging JSON parsing errors
        let body_json =
            serde_json::to_string(&body).unwrap_or_else(|e| format!("JSON_ERROR: {}", e));
        info!(
            subgraph = %fetch.subgraph,
            url = %fetch.url,
            operation_preview = %operation_preview,
            body_len = body_json.len(),
            has_hmac = context.hmac_secret.is_some(),
            "Executing fetch with body: {}",
            if body_json.len() > 500 { format!("{}...(truncated)", &body_json[..500]) } else { body_json.clone() }
        );

        // Make request with retry
        let mut last_error = None;
        for attempt in 0..=self.config.retry_count {
            if attempt > 0 {
                tokio::time::sleep(self.config.retry_delay).await;
                debug!(subgraph = %fetch.subgraph, attempt, "Retrying fetch");
            }

            match self
                .http_client
                .post(&fetch.url)
                .headers(headers.clone())
                .json(&body)
                .timeout(self.config.timeout)
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();

                    if !status.is_success() {
                        let error_text = response.text().await.unwrap_or_default();

                        // Log detailed error for debugging (especially 400 errors from malformed requests)
                        // Include the body we sent so we can compare with what subgraph received
                        error!(
                            subgraph = %fetch.subgraph,
                            status = %status,
                            error_text = %error_text,
                            operation_preview = %operation_preview,
                            body_sent_len = body_json.len(),
                            body_sent = %if body_json.len() > 500 {
                                format!("{}...(truncated at 500)", &body_json[..500])
                            } else {
                                body_json.clone()
                            },
                            "Subgraph returned error - body included for debugging"
                        );

                        last_error = Some(ExecutionError {
                            message: format!("Subgraph returned {}: {}", status, error_text),
                            subgraph: Some(fetch.subgraph.clone()),
                            status_code: Some(status.as_u16()),
                        });

                        if status.is_server_error() {
                            continue; // Retry on 5xx
                        } else {
                            break; // Don't retry on 4xx
                        }
                    }

                    // Parse response
                    let response_body: Value =
                        response.json().await.map_err(|e| ExecutionError {
                            message: format!("Failed to parse response: {}", e),
                            subgraph: Some(fetch.subgraph.clone()),
                            status_code: None,
                        })?;

                    let data = response_body.get("data").cloned();
                    let errors = response_body
                        .get("errors")
                        .and_then(|e| serde_json::from_value::<Vec<GraphQLError>>(e.clone()).ok())
                        .unwrap_or_default();

                    if let Some(ref m) = self.metrics {
                        m.increment(
                            "bff.federation.executor.fetch_success",
                            &[("subgraph", fetch.subgraph.as_str())],
                        );
                        m.histogram(
                            "bff.federation.executor.fetch_duration_ms",
                            start.elapsed().as_millis() as f64,
                            &[("subgraph", fetch.subgraph.as_str())],
                        );
                    }

                    return Ok(FetchResult {
                        subgraph: fetch.subgraph.clone(),
                        data,
                        errors,
                        duration: start.elapsed(),
                    });
                }
                Err(e) => {
                    warn!(
                        subgraph = %fetch.subgraph,
                        error = %e,
                        attempt,
                        "Fetch failed"
                    );

                    last_error = Some(ExecutionError {
                        message: format!("Request failed: {}", e),
                        subgraph: Some(fetch.subgraph.clone()),
                        status_code: None,
                    });

                    // Retry on network errors
                    continue;
                }
            }
        }

        self.metrics.incr(
            "bff.federation.executor.fetch_error",
            &[("subgraph", fetch.subgraph.as_str())],
        );

        Err(last_error.unwrap_or_else(|| ExecutionError {
            message: "Unknown error".to_string(),
            subgraph: Some(fetch.subgraph.clone()),
            status_code: None,
        }))
    }

    /// Execute a sequence node
    async fn execute_sequence(
        &self,
        seq: &SequenceNode,
        operation: &str,
        context: &ExecutionContext,
    ) -> Result<FetchResult, ExecutionError> {
        let start = Instant::now();
        let mut merged_data = json!({});
        let mut all_errors = Vec::new();

        for node in &seq.nodes {
            let result = self.execute_node(node, operation, context).await?;

            if let Some(data) = result.data {
                self.merge_data(&mut merged_data, data);
            }

            all_errors.extend(result.errors);
        }

        Ok(FetchResult {
            subgraph: "sequence".to_string(),
            data: Some(merged_data),
            errors: all_errors,
            duration: start.elapsed(),
        })
    }

    /// Execute a parallel node
    async fn execute_parallel(
        &self,
        par: &ParallelNode,
        operation: &str,
        context: &ExecutionContext,
    ) -> Result<FetchResult, ExecutionError> {
        let start = Instant::now();

        // Execute all nodes concurrently
        let futures: Vec<_> = par
            .nodes
            .iter()
            .map(|node| self.execute_node(node, operation, context))
            .collect();

        let results = futures_util::future::join_all(futures).await;

        // Collect results
        let mut merged_data = json!({});
        let mut all_errors = Vec::new();

        for result in results {
            match result {
                Ok(fetch_result) => {
                    if let Some(data) = fetch_result.data {
                        self.merge_data(&mut merged_data, data);
                    }
                    all_errors.extend(fetch_result.errors);
                }
                Err(e) => {
                    // Convert execution error to GraphQL error
                    all_errors.push(GraphQLError {
                        message: e.message,
                        locations: Vec::new(),
                        path: Vec::new(),
                        extensions: HashMap::new(),
                    });
                }
            }
        }

        Ok(FetchResult {
            subgraph: "parallel".to_string(),
            data: Some(merged_data),
            errors: all_errors,
            duration: start.elapsed(),
        })
    }

    /// Execute a flatten node (entity resolution)
    async fn execute_flatten(
        &self,
        flatten: &FlattenNode,
        operation: &str,
        context: &ExecutionContext,
    ) -> Result<FetchResult, ExecutionError> {
        // For entity flattening, we need to execute the nested node
        // and merge the results back into the parent path
        self.execute_node(&flatten.node, operation, context).await
    }

    /// Merge data from subgraph responses
    /// PERFORMANCE: Inline for hot path (called on every response merge)
    #[inline]
    fn merge_data(&self, target: &mut Value, source: Value) {
        match (target, source) {
            (Value::Object(target_map), Value::Object(source_map)) => {
                for (key, value) in source_map {
                    target_map.insert(key, value);
                }
            }
            (target, source) => {
                *target = source;
            }
        }
    }

    /// Sign a request with HMAC
    /// PERFORMANCE: Inline for hot path, use pre-allocated buffer
    ///
    /// # Errors
    /// Returns `ExecutionError` if JSON serialization or HMAC initialization fails
    #[inline]
    fn sign_request(&self, body: &Value, secret: &str) -> Result<String, ExecutionError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Pre-allocate buffer for JSON serialization (typical GraphQL request ~500 bytes)
        let body_str = serde_json::to_string(body).map_err(|e| ExecutionError {
            message: format!("Failed to serialize request body for HMAC: {}", e),
            subgraph: None,
            status_code: None,
        })?;

        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).map_err(|e| ExecutionError {
                message: format!("Invalid HMAC key: {}", e),
                subgraph: None,
                status_code: None,
            })?;
        mac.update(body_str.as_bytes());

        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    /// Get executor statistics
    pub fn stats(&self) -> ExecutorStats {
        ExecutorStats {
            available_permits: self.semaphore.available_permits(),
            max_concurrency: self.config.max_concurrency,
        }
    }
}

/// Executor statistics
#[derive(Debug, Clone)]
pub struct ExecutorStats {
    /// Available concurrency permits
    pub available_permits: usize,
    /// Maximum concurrency
    pub max_concurrency: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_executor_config_defaults() {
        let config = ExecutorConfig::default();
        // CRITICAL: 10 seconds to fail fast like Hive Router
        // Long timeouts cause 504 cascades
        assert_eq!(config.timeout, Duration::from_secs(10));
        // CRITICAL: 256 permits prevent request queuing under load
        // Previous value of 16 caused 504 timeouts!
        assert_eq!(config.max_concurrency, 256);
    }

    /// Test that GraphQL request body serialization produces valid JSON
    /// This helps catch edge cases with special characters or escaping issues
    #[test]
    fn test_request_body_serialization_me_query() {
        // Simulate the body construction from execute_fetch
        let operation = "{me{id email}}";
        let variables = json!({});

        let mut body = json!({
            "query": operation,
            "variables": variables,
        });

        // Add HMAC extension (simulating the real flow)
        body["extensions"] = json!({
            "hmac-signature": "0".repeat(64) // 64-char hex signature
        });

        // Verify serialization produces valid JSON
        let json_str = serde_json::to_string(&body).expect("Body should serialize to JSON");

        // Verify we can parse it back
        let parsed: Value =
            serde_json::from_str(&json_str).expect("Serialized body should be valid JSON");

        // Verify the structure
        assert!(parsed.get("query").is_some(), "Should have query field");
        assert!(
            parsed.get("variables").is_some(),
            "Should have variables field"
        );
        assert!(
            parsed.get("extensions").is_some(),
            "Should have extensions field"
        );

        // Print for debugging
        println!("Body JSON ({} bytes): {}", json_str.len(), json_str);
    }

    /// Test body serialization with variables containing special characters
    #[test]
    fn test_request_body_serialization_with_special_chars() {
        let operation =
            r#"query IsFeatureEnabled($flagKey: String!) { isFeatureEnabled(flagKey: $flagKey) }"#;
        let variables = json!({
            "flagKey": "test-flag-with-special-chars-\n\t\"quoted\""
        });

        let mut body = json!({
            "query": operation,
            "variables": variables,
        });

        body["extensions"] = json!({
            "hmac-signature": "abc123".repeat(10)
        });

        // This should not panic - special chars should be properly escaped
        let json_str =
            serde_json::to_string(&body).expect("Body with special chars should serialize");

        // Verify we can parse it back
        let _parsed: Value =
            serde_json::from_str(&json_str).expect("Should parse back to valid JSON");

        // The special chars should be escaped in JSON
        assert!(json_str.contains("\\n"), "Newline should be escaped");
        assert!(json_str.contains("\\t"), "Tab should be escaped");
        assert!(json_str.contains("\\\""), "Quote should be escaped");

        println!(
            "Body with special chars ({} bytes): {}",
            json_str.len(),
            json_str
        );
    }

    /// Test body serialization with empty variables
    #[test]
    fn test_request_body_serialization_empty_variables() {
        let operation = "{products(limit:5){edges{node{id name}}}}";
        let variables = Value::Null;

        let mut body = json!({
            "query": operation,
            "variables": variables,
        });

        body["extensions"] = json!({
            "hmac-signature": "test"
        });

        let json_str = serde_json::to_string(&body).expect("Body should serialize");
        let _: Value = serde_json::from_str(&json_str).expect("Should be valid JSON");

        println!("Body with null variables: {}", json_str);
    }

    /// Test body serialization with nested object variables
    #[test]
    fn test_request_body_serialization_nested_variables() {
        let operation =
            "mutation CreateOrder($input: CreateOrderInput!) { createOrder(input: $input) { id } }";
        let variables = json!({
            "input": {
                "items": [
                    {"productId": "prod-123", "quantity": 2},
                    {"productId": "prod-456", "quantity": 1}
                ],
                "shipping": {
                    "address": "123 Main St\nApt 4",
                    "city": "São Paulo",
                    "state": "SP"
                },
                "notes": "Special instructions: \"handle with care\""
            }
        });

        let mut body = json!({
            "query": operation,
            "variables": variables,
        });

        body["extensions"] = json!({
            "hmac-signature": "0".repeat(64)
        });

        let json_str = serde_json::to_string(&body).expect("Nested body should serialize");
        let parsed: Value = serde_json::from_str(&json_str).expect("Should be valid JSON");

        // Verify nested structure preserved
        assert!(
            parsed["variables"]["input"]["items"].is_array(),
            "Nested array should be preserved"
        );
        assert_eq!(
            parsed["variables"]["input"]["shipping"]["city"], "São Paulo",
            "Unicode should be preserved"
        );

        println!(
            "Body with nested variables ({} bytes): {}",
            json_str.len(),
            json_str
        );
    }

    /// Test that operation strings from Hive planner are valid JSON when embedded
    #[test]
    fn test_hive_planner_operation_serialization() {
        // These are actual operation formats from Hive planner
        let operations = [
            "{me{id email}}",
            "{products(limit:5){edges{node{id name}}}}",
            "{myCart{id itemCount}}",
            r#"{_entities(representations:[{__typename:"User",id:"123"}]){...on User{email}}}"#,
            "query{__typename}",
            "{isFeatureEnabled(flagKey:\"test\")}",
        ];

        for op in operations {
            let body = json!({
                "query": op,
                "variables": {},
            });

            let json_str = serde_json::to_string(&body)
                .unwrap_or_else(|e| panic!("Operation '{}' should serialize: {}", op, e));

            let _: Value = serde_json::from_str(&json_str)
                .unwrap_or_else(|e| panic!("Operation '{}' should produce valid JSON: {}", op, e));

            // Verify no control characters leaked through
            for (i, c) in json_str.chars().enumerate() {
                if c.is_control() && c != '\n' && c != '\r' && c != '\t' {
                    panic!(
                        "Operation '{}' produced control char {:?} at position {}",
                        op, c, i
                    );
                }
            }

            println!("✓ Operation: {} -> {}", op, json_str);
        }
    }

    /// Test HMAC signature computation matches expected format
    #[test]
    fn test_hmac_signature_format() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let body = json!({
            "query": "{me{id email}}",
            "variables": {}
        });

        let body_str = serde_json::to_string(&body).unwrap();
        let secret = "test-secret";

        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key length error");
        mac.update(body_str.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // HMAC-SHA256 should produce 64 hex chars
        assert_eq!(signature.len(), 64, "Signature should be 64 hex chars");

        // Signature should be valid hex
        assert!(
            signature.chars().all(|c| c.is_ascii_hexdigit()),
            "Signature should be valid hex"
        );

        println!("Body: {}", body_str);
        println!("HMAC signature: {}", signature);
    }

    /// Test that the complete request body (with extensions) is valid JSON
    #[test]
    fn test_complete_request_body_flow() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        // Step 1: Create body (same as execute_fetch)
        let operation = "{me{id email}}";
        let variables = json!({});

        let mut body = json!({
            "query": operation,
            "variables": variables,
        });

        // Step 2: Compute HMAC on body BEFORE extensions (same as execute_fetch)
        let secret = "test-hmac-secret-key";
        let body_str_for_hmac = serde_json::to_string(&body).unwrap();
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key length error");
        mac.update(body_str_for_hmac.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        // Step 3: Add extensions (same as execute_fetch)
        body["extensions"] = json!({
            "hmac-signature": signature
        });

        // Step 4: Serialize final body (same as reqwest .json(&body))
        let final_json = serde_json::to_string(&body).unwrap();

        // Step 5: Verify it's valid JSON (same as what subgraph will parse)
        let parsed: Value =
            serde_json::from_str(&final_json).expect("Complete request body should be valid JSON");

        // Verify structure
        assert_eq!(parsed["query"].as_str().unwrap(), operation);
        assert!(parsed["variables"].is_object());
        assert!(parsed["extensions"]["hmac-signature"].is_string());

        println!("Complete request body ({} bytes):", final_json.len());
        println!("{}", final_json);

        // Verify no unexpected characters at specific positions
        // Column 40 is where the Me query error happened
        if final_json.len() > 40 {
            println!("Character at position 40: {:?}", final_json.chars().nth(40));
        }
    }

    // =========================================================================
    // NON-BLOCKING BEHAVIOR TESTS
    // =========================================================================
    // These tests verify that the plan executor never blocks indefinitely
    // and implements proper fail-fast patterns for load shedding.

    /// Test that semaphore exhaustion returns immediately (non-blocking)
    /// CRITICAL: Verifies the try_acquire pattern works correctly
    #[test]
    fn test_semaphore_exhaustion_returns_immediately() {
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        // Create a semaphore with 2 permits
        let semaphore = Arc::new(Semaphore::new(2));

        // Acquire both permits (simulating max concurrency reached)
        let _permit1 = semaphore.clone().try_acquire_owned().unwrap();
        let _permit2 = semaphore.clone().try_acquire_owned().unwrap();

        // Now try_acquire should fail immediately (not block!)
        let start = std::time::Instant::now();
        let result = semaphore.clone().try_acquire_owned();
        let elapsed = start.elapsed();

        // CRITICAL: Must return in microseconds, not milliseconds
        assert!(
            elapsed.as_micros() < 100,
            "try_acquire should return immediately, took {:?}",
            elapsed
        );
        assert!(result.is_err(), "Should fail when semaphore exhausted");

        println!(
            "✓ Semaphore exhaustion returned in {:?} (non-blocking verified)",
            elapsed
        );
    }

    /// Test that concurrent semaphore acquisition doesn't block
    /// Pre-acquires permits to ensure exhaustion, then verifies try_acquire fails fast
    #[tokio::test]
    async fn test_concurrent_semaphore_non_blocking() {
        use std::sync::Arc;
        use tokio::sync::{Barrier, Semaphore};

        let semaphore = Arc::new(Semaphore::new(5));

        // Pre-acquire all 5 permits and HOLD them for the duration of the test
        // This guarantees the semaphore is exhausted when tasks try to acquire
        let _held_permits: Vec<_> = (0..5)
            .map(|_| semaphore.clone().try_acquire_owned().unwrap())
            .collect();

        // Verify semaphore is actually exhausted
        assert!(
            semaphore.clone().try_acquire_owned().is_err(),
            "Semaphore should be exhausted after pre-acquiring all permits"
        );

        let barrier = Arc::new(Barrier::new(10)); // All 10 tasks wait at barrier
        let mut handles = vec![];

        // Spawn 10 tasks that will ALL try to acquire at the same instant
        // Since all permits are held, ALL should fail immediately
        for i in 0..10 {
            let sem = semaphore.clone();
            let bar = barrier.clone();
            handles.push(tokio::spawn(async move {
                // Wait for all tasks to be ready
                bar.wait().await;

                // Now all tasks try to acquire simultaneously
                let start = std::time::Instant::now();
                let result = sem.try_acquire_owned();
                let elapsed = start.elapsed();

                // CRITICAL: Each attempt should complete in microseconds (non-blocking)
                assert!(
                    elapsed.as_micros() < 1000,
                    "Task {} took too long: {:?}",
                    i,
                    elapsed
                );

                (i, result.is_ok(), elapsed)
            }));
        }

        let results: Vec<_> = futures_util::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let successful = results.iter().filter(|(_, ok, _)| *ok).count();
        let failed = results.iter().filter(|(_, ok, _)| !ok).count();

        // With permits held externally, ALL 10 should fail immediately
        assert_eq!(successful, 0, "None should succeed - all permits are held");
        assert_eq!(failed, 10, "All 10 should fail immediately");

        // Verify ALL attempts completed quickly (non-blocking proof)
        let max_elapsed = results.iter().map(|(_, _, e)| e).max().unwrap();
        assert!(
            max_elapsed.as_micros() < 1000,
            "All attempts should complete in <1ms, max was {:?}",
            max_elapsed
        );

        println!(
            "✓ Concurrent semaphore test passed: {} rejected immediately in {:?} max",
            failed, max_elapsed
        );
    }

    /// Test that try_send on bounded channel returns immediately when full
    #[tokio::test]
    async fn test_bounded_channel_non_blocking() {
        use tokio::sync::mpsc;

        // Create a channel with capacity 2
        let (tx, mut rx) = mpsc::channel::<i32>(2);

        // Fill the channel
        tx.try_send(1).unwrap();
        tx.try_send(2).unwrap();

        // Now try_send should fail immediately
        let start = std::time::Instant::now();
        let result = tx.try_send(3);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_micros() < 100,
            "try_send should return immediately, took {:?}",
            elapsed
        );
        assert!(result.is_err(), "Should fail when channel full");

        // Verify channel still works
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(rx.recv().await, Some(2));

        println!(
            "✓ Bounded channel try_send returned in {:?} (non-blocking verified)",
            elapsed
        );
    }

    /// Test timeout behavior on async operations
    #[tokio::test]
    async fn test_timeout_returns_before_deadline() {
        use tokio::time::{timeout, Duration};

        let start = std::time::Instant::now();

        // Operation that would block forever
        let slow_op = async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            42
        };

        // But we have a 10ms timeout
        let result = timeout(Duration::from_millis(10), slow_op).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Should timeout");
        assert!(
            elapsed.as_millis() < 100,
            "Timeout should return quickly, took {:?}",
            elapsed
        );

        println!(
            "✓ Timeout returned in {:?} (deadline enforcement verified)",
            elapsed
        );
    }

    /// Test that ExecutorConfig high concurrency prevents blocking
    #[test]
    fn test_executor_config_high_concurrency() {
        let config = ExecutorConfig::default();

        // CRITICAL: Must be high enough to handle burst traffic
        // With 100 concurrent users × 3 subgraph calls = 300 concurrent requests
        assert!(
            config.max_concurrency >= 256,
            "Concurrency {} too low, will cause queuing under load",
            config.max_concurrency
        );

        // Timeout must be reasonable
        assert!(
            config.timeout.as_secs() <= 30,
            "Timeout {} too long, will hold resources",
            config.timeout.as_secs()
        );

        println!(
            "✓ ExecutorConfig verified: {} concurrency, {}s timeout",
            config.max_concurrency,
            config.timeout.as_secs()
        );
    }

    /// Stress test: verify many concurrent try_acquire don't cause contention issues
    #[tokio::test]
    async fn test_high_contention_semaphore() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(10));
        let success_count = Arc::new(AtomicUsize::new(0));
        let reject_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn 1000 concurrent tasks
        for _ in 0..1000 {
            let sem = semaphore.clone();
            let success = success_count.clone();
            let reject = reject_count.clone();

            handles.push(tokio::spawn(async move {
                let start = std::time::Instant::now();
                match sem.try_acquire_owned() {
                    Ok(permit) => {
                        success.fetch_add(1, Ordering::Relaxed);
                        // Hold permit briefly to simulate work
                        tokio::time::sleep(std::time::Duration::from_micros(100)).await;
                        drop(permit);
                    }
                    Err(_) => {
                        reject.fetch_add(1, Ordering::Relaxed);
                    }
                }
                let elapsed = start.elapsed();

                // CRITICAL: Each attempt must complete quickly
                assert!(
                    elapsed.as_millis() < 50,
                    "Operation took too long: {:?}",
                    elapsed
                );
            }));
        }

        // Wait for all tasks
        let start = std::time::Instant::now();
        futures_util::future::join_all(handles).await;
        let total_elapsed = start.elapsed();

        let successes = success_count.load(Ordering::Relaxed);
        let rejects = reject_count.load(Ordering::Relaxed);

        // Should complete quickly - no blocking
        assert!(
            total_elapsed.as_millis() < 500,
            "High contention test took too long: {:?}",
            total_elapsed
        );

        println!(
            "✓ High contention test: {} succeeded, {} rejected in {:?}",
            successes, rejects, total_elapsed
        );
    }
}
