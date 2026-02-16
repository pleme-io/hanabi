//! Re-exports Redis infrastructure from crate::redis
//!
//! This module exists for backwards compatibility. New code should import
//! directly from `crate::redis`.

#[allow(unused_imports)]
pub use crate::redis::{LazyRedisConfig, LazyRedisPool};
