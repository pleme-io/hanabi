//! Server builder for composable BFF assembly
//!
//! Products compose their BFF by registering providers, webhook handlers,
//! and route extensions with [`ServerBuilder`], then calling [`Server::run`].
//!
//! # Example
//!
//! ```rust,no_run
//! use hanabi::builder::ServerBuilder;
//! use hanabi::config::AppConfig;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AppConfig::load()?;
//! let server = ServerBuilder::new(config)
//!     // .with_oauth(MyOAuthProvider::new())
//!     // .with_webhook(MyWebhookHandler::new())
//!     .build()
//!     .await;
//! server.run().await
//! # }
//! ```

use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use tracing::info;

use crate::config::AppConfig;
use crate::router::{self, CoreMiddleware, CoreRoute, MiddlewareCustomization, MiddlewareSlot};
use crate::server;
use crate::state::{AppState, Extensions};
use crate::traits::{OAuthProvider, RouteExtension, WebhookHandler};

use pleme_notifications::{
    DependencyStatus, NotificationClient, PodIdentity, StartupPhase, StartupReport, PhaseStatus,
};

/// Builder for composing a Hanabi BFF server.
///
/// Start with [`ServerBuilder::new`] or [`ServerBuilder::from_config`],
/// register providers/handlers/extensions, then call [`ServerBuilder::build`].
#[allow(dead_code)]
pub struct ServerBuilder {
    config: Arc<AppConfig>,
    oauth_providers: Vec<Box<dyn OAuthProvider>>,
    webhook_handlers: Vec<Box<dyn WebhookHandler>>,
    route_extensions: Vec<Box<dyn RouteExtension>>,
    custom_routes: Vec<Router<Arc<AppState>>>,
    state_extensions: Extensions,
    middleware_customization: MiddlewareCustomization,
}

#[allow(dead_code)]
impl ServerBuilder {
    /// Create a new builder from an owned config.
    pub fn new(config: AppConfig) -> Self {
        Self::from_config(Arc::new(config))
    }

    /// Create a new builder from a shared config.
    pub fn from_config(config: Arc<AppConfig>) -> Self {
        Self {
            config,
            oauth_providers: Vec::new(),
            webhook_handlers: Vec::new(),
            route_extensions: Vec::new(),
            custom_routes: Vec::new(),
            state_extensions: Extensions::new(),
            middleware_customization: MiddlewareCustomization::default(),
        }
    }

    /// Access the configuration for conditional provider registration.
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    /// Register an OAuth provider.
    pub fn with_oauth(mut self, provider: impl OAuthProvider) -> Self {
        self.oauth_providers.push(Box::new(provider));
        self
    }

    /// Register a webhook handler.
    pub fn with_webhook(mut self, handler: impl WebhookHandler) -> Self {
        self.webhook_handlers.push(Box::new(handler));
        self
    }

    /// Register a generic route extension.
    pub fn with_extension(mut self, ext: impl RouteExtension) -> Self {
        self.route_extensions.push(Box::new(ext));
        self
    }

    /// Attach product-specific state accessible via `state.extensions.get::<T>()`.
    pub fn with_state_extension<T: Send + Sync + 'static>(mut self, val: T) -> Self {
        self.state_extensions.insert(val);
        self
    }

    /// Register a raw Axum router to merge into the application.
    pub fn with_routes(mut self, routes: Router<Arc<AppState>>) -> Self {
        self.custom_routes.push(routes);
        self
    }

    /// Disable a core middleware layer.
    pub fn without_middleware(mut self, middleware: CoreMiddleware) -> Self {
        self.middleware_customization.disable(middleware);
        self
    }

    /// Exclude a core route from the application.
    pub fn without_route(mut self, route: CoreRoute) -> Self {
        self.middleware_customization.exclude_route(route);
        self
    }

    /// Add custom middleware at a specific position in the stack.
    ///
    /// The closure receives the current router and shared state, and returns
    /// a modified router with the custom layer applied. Called once at startup.
    pub fn with_middleware<F>(mut self, slot: MiddlewareSlot, f: F) -> Self
    where
        F: Fn(Router, &Arc<AppState>) -> Router + Send + Sync + 'static,
    {
        self.middleware_customization.add_custom(slot, f);
        self
    }

    /// Build the server, initializing application state and composing routes.
    pub async fn build(self) -> Server {
        let state = Arc::new(
            AppState::with_extensions(self.config.clone(), self.state_extensions).await,
        );

        Server {
            config: self.config,
            state,
            oauth_providers: self.oauth_providers,
            webhook_handlers: self.webhook_handlers,
            route_extensions: self.route_extensions,
            custom_routes: self.custom_routes,
            middleware_customization: self.middleware_customization,
        }
    }
}

/// A fully assembled Hanabi BFF server ready to run.
#[allow(dead_code)]
pub struct Server {
    config: Arc<AppConfig>,
    state: Arc<AppState>,
    oauth_providers: Vec<Box<dyn OAuthProvider>>,
    webhook_handlers: Vec<Box<dyn WebhookHandler>>,
    route_extensions: Vec<Box<dyn RouteExtension>>,
    custom_routes: Vec<Router<Arc<AppState>>>,
    middleware_customization: MiddlewareCustomization,
}

#[allow(dead_code)]
impl Server {
    /// Access the shared application state.
    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// Build the composed application router from core routes + registered providers.
    pub fn build_app_router(&self) -> Router {
        let mut app =
            router::build_core_app_router(self.state.clone(), &self.config, &self.middleware_customization);

        // Merge OAuth provider routes
        if !self.oauth_providers.is_empty() {
            info!("   OAuth: Enabled (BFF handles token exchange)");
            for provider in &self.oauth_providers {
                provider.log_config();
                app = app.merge(provider.routes(self.state.clone()));
            }
        }

        // Merge webhook handler routes
        if !self.webhook_handlers.is_empty() {
            info!("   Webhooks Gateway: ENABLED");
            for handler in &self.webhook_handlers {
                handler.log_config();
                app = app.merge(handler.routes(self.state.clone()));
            }
        }

        // Merge route extensions
        for ext in &self.route_extensions {
            ext.log_config();
            app = app.merge(ext.routes(self.state.clone()));
        }

        // Merge custom raw routes
        for routes in &self.custom_routes {
            app = app.merge(routes.clone());
        }

        router::apply_global_middleware(app, self.state.clone(), &self.config, &self.middleware_customization)
    }

    /// Run the server with dual-port serving and graceful shutdown.
    pub async fn run(self) -> Result<(), Box<dyn std::error::Error>> {
        let startup_start = Instant::now();
        server::log_startup_info(&self.state, &self.config);

        // Log registered providers
        if !self.oauth_providers.is_empty()
            || !self.webhook_handlers.is_empty()
            || !self.route_extensions.is_empty()
        {
            info!("   Registered extensions:");
            for p in &self.oauth_providers {
                info!("     - OAuth: {}", p.name());
            }
            for h in &self.webhook_handlers {
                info!("     - Webhook: {}", h.name());
            }
            for e in &self.route_extensions {
                info!("     - Extension: {}", e.name());
            }
        }

        let app_router = self.build_app_router();
        let health_router = router::build_health_router(self.state.clone());

        // Startup notification (fire-and-forget)
        let pod_identity = PodIdentity::from_env();
        let notifier = NotificationClient::from_env(&self.config.server.service_name);

        let total_duration = startup_start.elapsed();
        let report = StartupReport {
            service_name: self.config.server.service_name.clone(),
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
            total_duration,
            phases: vec![
                StartupPhase {
                    name: "init".into(),
                    duration: total_duration,
                    status: PhaseStatus::Success,
                    detail: None,
                },
            ],
            dependency_status: DependencyStatus::default(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: std::env::var("GIT_SHA").unwrap_or_else(|_| "unknown".to_string()),
            run_mode: "bff".to_string(),
        };

        notifier.notify_startup_success(&report);

        server::run_server(&self.config, app_router, health_router).await
    }
}
