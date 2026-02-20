//! Image Proxy with Two-Tier Caching
//!
//! Provides CDN-like image serving with:
//! - L1: moka in-memory cache (1000 images, 24h TTL)
//! - L2: Redis distributed cache (24h TTL)
//! - Origin: MinIO/S3 bucket (via HTTP client)
//!
//! # Architecture
//!
//! ```text
//! GET /api/images/{product}/{user_id}/{image_id}_{size}.webp
//!       │
//!       ▼
//! ┌─────────────────┐
//! │  L1 Moka Cache  │ ──► HIT ──► Return image
//! └─────────────────┘
//!       │ MISS
//!       ▼
//! ┌─────────────────┐
//! │  L2 Redis Cache │ ──► HIT ──► Populate L1 ──► Return image
//! └─────────────────┘
//!       │ MISS
//!       ▼
//! ┌─────────────────┐
//! │ Fetch from MinIO│ ──► Populate L1 + L2 ──► Return image
//! └─────────────────┘
//! ```
//!
//! # Cache Keys
//!
//! - L1: `{product}:{user_id}:{image_id}:{size}`
//! - L2 (Redis): `img:{product}:{user_id}:{image_id}:{size}`
//!
//! # Image Sizes
//!
//! - `thumb`: 150px thumbnail
//! - `medium`: 600px medium
//! - `full`: 1200px full size

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use moka::future::Cache;
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::Region;
use tracing::{debug, error, info, warn};

use crate::config::AppConfig;
use crate::redis::LazyRedisPool;
use crate::state::AppState;

/// Valid image sizes
const VALID_SIZES: [&str; 3] = ["thumb", "medium", "full"];

/// L1 cache TTL (24 hours)
const L1_TTL_SECS: u64 = 86400;

/// L2 cache TTL (24 hours)
const L2_TTL_SECS: u64 = 86400;

/// Max L1 cache entries
const L1_MAX_ENTRIES: u64 = 1000;

/// Max image size to cache (5MB)
const MAX_CACHE_SIZE_BYTES: usize = 5 * 1024 * 1024;

/// Image cache for L1 (moka in-memory)
pub struct ImageCache {
    /// In-memory cache (L1)
    moka: Cache<String, Bytes>,
}

impl ImageCache {
    /// Create a new image cache
    pub fn new() -> Self {
        let moka = Cache::builder()
            .max_capacity(L1_MAX_ENTRIES)
            .time_to_live(Duration::from_secs(L1_TTL_SECS))
            .build();

        info!(
            max_entries = L1_MAX_ENTRIES,
            ttl_secs = L1_TTL_SECS,
            "Image L1 cache initialized"
        );

        Self { moka }
    }

    /// Get from L1 cache
    pub async fn get_l1(&self, key: &str) -> Option<Bytes> {
        self.moka.get(key).await
    }

    /// Store in L1 cache
    pub async fn set_l1(&self, key: &str, data: Bytes) {
        self.moka.insert(key.to_string(), data).await;
    }

    /// Get from L2 cache (Redis)
    pub async fn get_l2(&self, redis: &LazyRedisPool, key: &str) -> Option<Bytes> {
        let redis_key = format!("img:{}", key);

        let mut conn = redis.get().await?;

        let result: Result<Option<Vec<u8>>, _> =
            redis::AsyncCommands::get(&mut conn, &redis_key).await;

        match result {
            Ok(Some(data)) => {
                debug!(key = %redis_key, "L2 cache HIT");
                Some(Bytes::from(data))
            }
            Ok(None) => {
                debug!(key = %redis_key, "L2 cache MISS");
                None
            }
            Err(e) => {
                warn!(key = %redis_key, error = %e, "L2 cache get failed");
                None
            }
        }
    }

    /// Store in L2 cache (Redis)
    pub async fn set_l2(&self, redis: &LazyRedisPool, key: &str, data: &Bytes) {
        let redis_key = format!("img:{}", key);

        let Some(mut conn) = redis.get().await else {
            warn!("Failed to get Redis connection for L2 cache");
            return;
        };

        let result: Result<(), _> =
            redis::AsyncCommands::set_ex(&mut conn, &redis_key, data.as_ref(), L2_TTL_SECS).await;

        if let Err(e) = result {
            warn!(key = %redis_key, error = %e, "L2 cache set failed");
        }
    }
}

impl Default for ImageCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Path parameters for image proxy
#[derive(Debug, serde::Deserialize)]
pub struct ImagePath {
    /// Product scope (e.g., "myapp", "storefront")
    pub product: String,
    /// User/Ad ID
    pub user_id: String,
    /// Image file (e.g., "abc123_thumb.webp")
    pub filename: String,
}

/// Image proxy handler
///
/// Serves images with two-tier caching (moka L1 + Redis L2)
///
/// # Path
/// `GET /api/images/{product}/{user_id}/{filename}`
///
/// # Example
/// `GET /api/images/myapp/550e8400-e29b-41d4-a716-446655440000/abc123_thumb.webp`
pub async fn image_proxy(
    State(state): State<Arc<AppState>>,
    Path(params): Path<ImagePath>,
) -> Response {
    // Parse filename to extract image_id and size
    let (image_id, size) = match parse_filename(&params.filename) {
        Some((id, sz)) => (id, sz),
        None => {
            return (StatusCode::BAD_REQUEST, "Invalid filename format").into_response();
        }
    };

    // Validate size
    if !VALID_SIZES.contains(&size.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            format!("Invalid size. Valid sizes: {:?}", VALID_SIZES),
        )
            .into_response();
    }

    // Build cache key
    let cache_key = format!(
        "{}:{}:{}:{}",
        params.product, params.user_id, image_id, size
    );

    // Get shared image cache from state
    let image_cache = match state.image_cache() {
        Some(cache) => cache,
        None => {
            error!("Image cache not initialized");
            return (StatusCode::SERVICE_UNAVAILABLE, "Image caching unavailable").into_response();
        }
    };

    // Check L1 cache
    if let Some(data) = image_cache.get_l1(&cache_key).await {
        debug!(cache_key = %cache_key, "L1 cache HIT");
        state.incr(
            "bff.image_proxy.cache.l1_hit",
            &[("product", &params.product)],
        );
        return image_response(data);
    }

    // Check L2 cache (Redis)
    if let Some(redis) = state.session_redis() {
        if let Some(data) = image_cache.get_l2(redis, &cache_key).await {
            // Populate L1 cache
            let data_clone: Bytes = data.clone();
            image_cache.set_l1(&cache_key, data_clone).await;

            state.incr(
                "bff.image_proxy.cache.l2_hit",
                &[("product", &params.product)],
            );
            return image_response(data);
        }
    }

    // Cache miss - fetch from origin (MinIO/S3)
    state.incr(
        "bff.image_proxy.cache.miss",
        &[("product", &params.product)],
    );

    // Build S3 object key
    let object_key = format!(
        "{}/{}/{}_{}.webp",
        params.product, params.user_id, image_id, size
    );

    // Fetch from S3 with authentication
    let data = match fetch_from_s3(&state.config, &object_key).await {
        Ok(bytes) => Bytes::from(bytes),
        Err(e) => {
            if e.contains("NoSuchKey") || e.contains("not found") {
                return (StatusCode::NOT_FOUND, "Image not found").into_response();
            }
            error!(object_key = %object_key, error = %e, "Failed to fetch from S3");
            return (StatusCode::BAD_GATEWAY, "Failed to fetch image").into_response();
        }
    };

    // Check size limit before caching
    if data.len() <= MAX_CACHE_SIZE_BYTES {
        // Populate L1 cache
        image_cache.set_l1(&cache_key, data.clone()).await;

        // Populate L2 cache (Redis)
        if let Some(redis) = state.session_redis() {
            image_cache.set_l2(redis, &cache_key, &data).await;
        }
    } else {
        warn!(
            size = data.len(),
            max = MAX_CACHE_SIZE_BYTES,
            "Image too large to cache"
        );
    }

    image_response(data)
}

/// Parse filename into (image_id, size)
///
/// Expected format: `{image_id}_{size}.webp`
/// Example: `abc123_thumb.webp` -> Some(("abc123", "thumb"))
fn parse_filename(filename: &str) -> Option<(String, String)> {
    // Remove .webp extension
    let base = filename.strip_suffix(".webp")?;

    // Split by last underscore
    let underscore_pos = base.rfind('_')?;
    if underscore_pos == 0 || underscore_pos == base.len() - 1 {
        return None;
    }

    let image_id = &base[..underscore_pos];
    let size = &base[underscore_pos + 1..];

    Some((image_id.to_string(), size.to_string()))
}

/// Fetch image from S3 with authentication
async fn fetch_from_s3(config: &AppConfig, object_key: &str) -> Result<Vec<u8>, String> {
    let s3_config = &config.s3;

    info!(
        enabled = s3_config.enabled,
        endpoint = %s3_config.endpoint,
        bucket = %s3_config.bucket,
        region = %s3_config.region,
        object_key = %object_key,
        "S3 image fetch starting"
    );

    // Check if S3 is enabled
    if !s3_config.enabled {
        return Err("S3 image proxy not enabled in config".to_string());
    }

    // Get credentials
    let access_key = s3_config
        .get_access_key()
        .ok_or_else(|| "S3 access key not configured (check S3_ACCESS_KEY env var)".to_string())?;
    let secret_key = s3_config
        .get_secret_key()
        .ok_or_else(|| "S3 secret key not configured (check S3_SECRET_KEY env var)".to_string())?;

    debug!(
        has_access_key = !access_key.is_empty(),
        has_secret_key = !secret_key.is_empty(),
        "S3 credentials loaded"
    );

    // Create credentials
    let credentials = Credentials::new(Some(&access_key), Some(&secret_key), None, None, None)
        .map_err(|e| format!("Failed to create S3 credentials: {}", e))?;

    // Create region with custom endpoint
    let region = Region::Custom {
        region: s3_config.region.clone(),
        endpoint: s3_config.endpoint.clone(),
    };

    info!(
        endpoint = %s3_config.endpoint,
        bucket = %s3_config.bucket,
        object_key = %object_key,
        "Creating S3 bucket client"
    );

    // Create bucket client with path-style for MinIO/RustFS
    let bucket = Bucket::new(&s3_config.bucket, region, credentials)
        .map_err(|e| format!("Failed to create S3 bucket client: {}", e))?
        .with_path_style();

    info!(
        object_key = %object_key,
        "Fetching object from S3"
    );

    // Fetch the object
    let response = bucket.get_object(object_key).await.map_err(|e| {
        error!(
            object_key = %object_key,
            endpoint = %s3_config.endpoint,
            bucket = %s3_config.bucket,
            error = %e,
            "S3 get_object failed"
        );
        format!("S3 get_object failed: {}", e)
    })?;

    let status = response.status_code();
    let bytes_len = response.bytes().len();

    if status != 200 {
        let body = String::from_utf8_lossy(response.bytes());
        error!(
            object_key = %object_key,
            status = status,
            body = %body,
            "S3 returned non-200 status"
        );
        return Err(format!("S3 returned status {}: {}", status, body));
    }

    info!(
        object_key = %object_key,
        status = status,
        bytes = bytes_len,
        "S3 fetch successful"
    );

    Ok(response.bytes().to_vec())
}

/// Create image response with proper headers
fn image_response(data: Bytes) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/webp")
        .header(header::CONTENT_LENGTH, data.len())
        .header(
            header::CACHE_CONTROL,
            "public, max-age=86400, immutable", // 24 hours
        )
        .body(Body::from(data))
        .unwrap_or_else(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Response build failed").into_response()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_filename_valid() {
        let result = parse_filename("abc123_thumb.webp");
        assert_eq!(result, Some(("abc123".to_string(), "thumb".to_string())));

        let result = parse_filename("image-id_medium.webp");
        assert_eq!(result, Some(("image-id".to_string(), "medium".to_string())));

        let result = parse_filename("550e8400-e29b-41d4-a716-446655440000_full.webp");
        assert_eq!(
            result,
            Some((
                "550e8400-e29b-41d4-a716-446655440000".to_string(),
                "full".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_filename_invalid() {
        // Missing extension
        assert_eq!(parse_filename("abc123_thumb"), None);

        // Wrong extension
        assert_eq!(parse_filename("abc123_thumb.png"), None);

        // Missing size
        assert_eq!(parse_filename("abc123.webp"), None);

        // Empty parts
        assert_eq!(parse_filename("_thumb.webp"), None);
        assert_eq!(parse_filename("abc123_.webp"), None);
    }

    #[test]
    fn test_valid_sizes() {
        assert!(VALID_SIZES.contains(&"thumb"));
        assert!(VALID_SIZES.contains(&"medium"));
        assert!(VALID_SIZES.contains(&"full"));
        assert!(!VALID_SIZES.contains(&"large"));
    }
}
