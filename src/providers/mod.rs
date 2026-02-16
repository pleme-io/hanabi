//! Built-in provider implementations (feature-gated)
//!
//! Each provider wraps existing handler code and implements the
//! corresponding trait from [`crate::traits`]. Products using Hanabi
//! as a library can register these providers via [`ServerBuilder`](crate::builder::ServerBuilder)
//! or implement their own.

#[cfg(feature = "google-oauth")]
pub mod google_oauth;

#[cfg(feature = "instagram-oauth")]
pub mod instagram_oauth;

#[cfg(feature = "stripe-webhooks")]
pub mod stripe_webhooks;

#[cfg(feature = "meta-webhooks")]
pub mod meta_webhooks;

#[cfg(feature = "geolocation")]
pub mod geolocation;

#[cfg(feature = "image-proxy")]
pub mod image_proxy;
