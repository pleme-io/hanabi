//! Backend-for-Frontend (BFF) configuration (proxy, cache, aggregate)

use serde::{Deserialize, Serialize};

pub mod cache;
pub mod federation;
pub mod http;
pub mod oauth;
pub mod optimization;
pub mod session;
pub mod webhooks;
pub mod websocket;

pub use self::cache::*;
pub use self::federation::*;
pub use self::http::*;
pub use self::oauth::*;
pub use self::optimization::*;
pub use self::session::*;
pub use self::webhooks::*;
pub use self::websocket::*;

/// Backend-for-Frontend (BFF) Configuration
/// Acts as proxy/aggregation layer between frontend and Hive Router
///
/// Supports separate configuration for HTTP and WebSocket use cases:
/// - HTTP: Queries/mutations with short timeouts and strict rate limits
/// - WebSocket: Subscriptions with long timeouts and connection limits
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct BffConfig {
    /// BFF mode: "disabled", "proxy", "cache", "aggregate"
    pub mode: String,

    /// Product identifier for multi-tenant isolation
    /// This BFF serves a specific product (e.g., "novaskyn", "myapp")
    /// Sets the x-product header on all requests to Hive Router
    pub product: String,

    /// Hive Router URL to proxy GraphQL requests to
    pub hive_router_url: String,

    /// Hive Router WebSocket URL for subscription proxying
    /// If not set, derived from hive_router_url (http→ws, https→wss)
    /// Set explicitly when backend expects WebSocket at different path (e.g., /graphql/ws)
    #[serde(default)]
    pub hive_router_ws_url: Option<String>,

    /// Auth Service URL for login/logout/refresh operations
    pub auth_service_url: String,

    /// Backend REST URL for proxying non-GraphQL API requests (e.g., file uploads)
    /// If not set, derived from hive_router_url by removing /graphql suffix
    /// Used for routes like /api/upload/* that need to bypass GraphQL
    #[serde(default)]
    pub backend_rest_url: Option<String>,

    /// HTTP-specific configuration (queries/mutations)
    #[serde(default)]
    pub http: BffHttpConfig,

    /// WebSocket-specific configuration (subscriptions)
    #[serde(default)]
    pub websocket: BffWebSocketConfig,

    /// Redis cache configuration for GraphQL responses
    #[serde(default)]
    pub cache: BffCacheConfig,

    /// Session configuration for BFF authentication
    #[serde(default)]
    pub session: BffSessionConfig,

    /// Auto-optimization configuration (runtime resource detection and optimization)
    #[serde(default)]
    pub optimization: BffOptimizationConfig,

    /// OAuth configuration (BFF handles OAuth token exchange)
    #[serde(default)]
    pub oauth: BffOAuthConfig,

    /// Webhook gateway configuration (BFF handles external webhook signature verification)
    #[serde(default)]
    pub webhooks: BffWebhooksConfig,

    /// Federation configuration (BFF acts as GraphQL federation router)
    /// When enabled, BFF handles federation directly instead of proxying to Hive Router
    #[serde(default)]
    pub federation: BffFederationConfig,

    /// NATS URL for subscribing to rate limit config changes from backend
    /// When set, BFF subscribes to `{product}.config.ratelimits` for dynamic rate limit updates
    /// Example: "nats://nats.nats-system:4222"
    #[serde(default)]
    pub nats_url: Option<String>,

    /// Backend GraphQL URL for querying platform settings after NATS notification
    /// Used to fetch fresh rate limit config when admin updates settings
    /// Example: "http://lilitu-backend:8080/graphql"
    #[serde(default)]
    pub backend_graphql_url: Option<String>,
}

impl Default for BffConfig {
    fn default() -> Self {
        Self {
            mode: "federation".to_string(),
            product: "default".to_string(),
            hive_router_url: "http://hive-router:4000/graphql".to_string(),
            hive_router_ws_url: None,
            auth_service_url: "http://auth:8080/graphql".to_string(),
            backend_rest_url: None,
            http: BffHttpConfig::default(),
            websocket: BffWebSocketConfig::default(),
            cache: BffCacheConfig::default(),
            session: BffSessionConfig::default(),
            optimization: BffOptimizationConfig::default(),
            oauth: BffOAuthConfig::default(),
            webhooks: BffWebhooksConfig::default(),
            federation: BffFederationConfig::default(),
            nats_url: None,
            backend_graphql_url: None,
        }
    }
}

impl BffConfig {
    /// Get the backend REST URL, deriving from hive_router_url if not explicitly set
    /// Removes /graphql suffix from hive_router_url to get the base URL
    pub fn get_backend_rest_url(&self) -> String {
        self.backend_rest_url.clone().unwrap_or_else(|| {
            // Derive from hive_router_url by removing /graphql suffix
            self.hive_router_url
                .trim_end_matches("/graphql")
                .trim_end_matches("/")
                .to_string()
        })
    }

    /// Get the Hive Router WebSocket URL
    ///
    /// If `hive_router_ws_url` is explicitly set, returns it.
    /// Otherwise, derives from `hive_router_url` by converting http→ws, https→wss.
    ///
    /// # Example
    /// - Explicit: `hive_router_ws_url: "ws://backend:8080/graphql/ws"` → returns as-is
    /// - Derived: `hive_router_url: "http://backend:8080/graphql"` → `ws://backend:8080/graphql`
    pub fn get_hive_router_ws_url(&self) -> String {
        if let Some(ref ws_url) = self.hive_router_ws_url {
            return ws_url.clone();
        }

        // Derive from hive_router_url
        if self.hive_router_url.starts_with("https://") {
            self.hive_router_url.replacen("https://", "wss://", 1)
        } else if self.hive_router_url.starts_with("http://") {
            self.hive_router_url.replacen("http://", "ws://", 1)
        } else {
            format!("ws://{}", self.hive_router_url)
        }
    }
}
