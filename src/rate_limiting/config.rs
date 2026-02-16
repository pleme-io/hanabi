//! QuotaParams helper with correct `governor::Quota::per_second()` usage
//!
//! # Why this exists
//!
//! The `governor` crate has two ways to build quotas:
//!
//! - `governor::Quota::per_second(NonZeroU32::new(N))` — **Correct**: N = requests/second
//! - `GovernorConfigBuilder::per_second(N)` — **Confusing**: N = replenish interval in seconds
//!   (i.e., `per_second(1000)` means 1 token every 1000 seconds, NOT 1000 RPS!)
//!
//! This module provides a single helper that always uses the correct API.

use std::num::NonZeroU32;

use governor::Quota;
use tracing::warn;

/// Rate limit parameters that can be correctly converted to a `governor::Quota`.
#[derive(Debug, Clone, Copy)]
pub struct QuotaParams {
    /// Requests per second (the intuitive meaning)
    pub requests_per_second: u32,
    /// Maximum burst capacity
    pub burst_size: u32,
}

impl QuotaParams {
    /// Convert to a `governor::Quota` using the **correct** API.
    ///
    /// Uses `Quota::per_second(N)` where N = requests/second.
    pub fn to_quota(&self) -> Quota {
        let rps = to_non_zero(self.requests_per_second, "requests_per_second");
        let burst = to_non_zero(self.burst_size, "burst_size");
        Quota::per_second(rps).allow_burst(burst)
    }
}

/// Convert a u32 to NonZeroU32, falling back to 1 if zero.
/// Logs a warning if the value was zero to aid debugging config issues.
pub fn to_non_zero(value: u32, field_name: &str) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap_or_else(|| {
        warn!(
            field = field_name,
            "Rate limit config value was 0, using minimum (1)"
        );
        NonZeroU32::MIN
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quota_params_basic() {
        let params = QuotaParams {
            requests_per_second: 100,
            burst_size: 200,
        };
        // Should not panic
        let _quota = params.to_quota();
    }

    #[test]
    fn test_zero_values_use_minimum() {
        let nz = to_non_zero(0, "test_field");
        assert_eq!(nz.get(), 1);
    }

    #[test]
    fn test_non_zero_passthrough() {
        let nz = to_non_zero(42, "test_field");
        assert_eq!(nz.get(), 42);
    }
}
