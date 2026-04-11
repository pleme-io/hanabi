//! HTTP response cache for the proxy layer.
//!
//! Caches upstream responses based on Cache-Control headers, ETags,
//! and Vary headers. Uses moka for in-memory LRU eviction.

use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use tracing::debug;

/// A cached HTTP response.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub max_age: Duration,
}

/// HTTP response cache backed by moka.
pub struct ResponseCache {
    cache: Cache<String, CachedResponse>,
}

impl ResponseCache {
    /// Create a new cache with the given maximum entry count.
    pub fn new(max_entries: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_entries)
            .time_to_live(Duration::from_secs(3600)) // default 1h TTL
            .build();
        Self { cache }
    }

    /// Build a cache key from method, URL, and Vary headers.
    pub fn cache_key(method: &str, url: &str, vary_headers: &HashMap<String, String>) -> String {
        let mut key = format!("{method}:{url}");
        if !vary_headers.is_empty() {
            let mut sorted: Vec<_> = vary_headers.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            for (k, v) in sorted {
                key.push_str(&format!(":{k}={v}"));
            }
        }
        key
    }

    /// Get a cached response if it exists and hasn't expired.
    pub async fn get(&self, key: &str) -> Option<CachedResponse> {
        self.cache.get(key).await
    }

    /// Store a response in the cache.
    pub async fn put(&self, key: String, response: CachedResponse) {
        debug!(key = %key, max_age = ?response.max_age, "caching response");
        self.cache.insert(key, response).await;
    }

    /// Parse Cache-Control header to determine if response is cacheable.
    pub fn is_cacheable(status: u16, cache_control: Option<&str>) -> bool {
        // Only cache successful responses
        if status < 200 || status >= 300 {
            return false;
        }

        if let Some(cc) = cache_control {
            let cc_lower = cc.to_lowercase();
            if cc_lower.contains("no-store") || cc_lower.contains("private") {
                return false;
            }
            return true;
        }

        // No Cache-Control header — don't cache by default
        false
    }

    /// Extract max-age from Cache-Control header.
    pub fn parse_max_age(cache_control: Option<&str>) -> Option<Duration> {
        let cc = cache_control?;
        for part in cc.split(',') {
            let part = part.trim();
            if let Some(age_str) = part.strip_prefix("max-age=") {
                if let Ok(secs) = age_str.trim().parse::<u64>() {
                    return Some(Duration::from_secs(secs));
                }
            }
        }
        None
    }

    /// Invalidate a cached entry.
    pub async fn invalidate(&self, key: &str) {
        self.cache.invalidate(key).await;
    }

    /// Get cache statistics.
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key() {
        let vary = HashMap::from([
            ("accept".to_string(), "application/json".to_string()),
            ("accept-encoding".to_string(), "gzip".to_string()),
        ]);
        let key = ResponseCache::cache_key("GET", "https://api.example.com/data", &vary);
        assert!(key.contains("GET:https://api.example.com/data"));
        assert!(key.contains("accept=application/json"));
    }

    #[test]
    fn test_is_cacheable() {
        assert!(ResponseCache::is_cacheable(200, Some("public, max-age=300")));
        assert!(!ResponseCache::is_cacheable(200, Some("no-store")));
        assert!(!ResponseCache::is_cacheable(200, Some("private")));
        assert!(!ResponseCache::is_cacheable(500, Some("public")));
        assert!(!ResponseCache::is_cacheable(200, None));
    }

    #[test]
    fn test_parse_max_age() {
        assert_eq!(
            ResponseCache::parse_max_age(Some("public, max-age=300")),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            ResponseCache::parse_max_age(Some("max-age=60, must-revalidate")),
            Some(Duration::from_secs(60))
        );
        assert_eq!(ResponseCache::parse_max_age(Some("no-cache")), None);
        assert_eq!(ResponseCache::parse_max_age(None), None);
    }
}
