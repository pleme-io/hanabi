//! Image proxy route extension implementation

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

use crate::state::AppState;
use crate::traits::RouteExtension;

/// Two-tier cached image proxy extension (moka L1 + Redis L2 + S3 backend).
#[derive(Default)]
pub struct ImageProxyExtension;

impl ImageProxyExtension {
    /// Always available — the image proxy has no config gate beyond S3 credentials.
    pub fn new() -> Self {
        Self
    }
}

impl RouteExtension for ImageProxyExtension {
    fn name(&self) -> &str {
        "ImageProxy"
    }

    fn routes(&self, state: Arc<AppState>) -> Router<Arc<AppState>> {
        Router::new()
            .route(
                "/api/images/:product/:user_id/:filename",
                get(crate::images::image_proxy),
            )
            .with_state(state)
    }
}
