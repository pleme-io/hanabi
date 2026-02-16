//! BFF Authentication Module
//!
//! Implements the Backend-for-Frontend (BFF) authentication pattern:
//! - Sessions stored in Redis (tokens never reach browser)
//! - Browser only has httpOnly session cookie
//! - BFF handles OAuth token exchange (confidential client)
//! - BFF adds Authorization header to upstream requests from session
//!
//! # Architecture
//!
//! ## Email/Password Auth (GraphQL Response Interception)
//! ```text
//! Browser ──POST /graphql (login mutation)──► BFF ──► Hive Router
//!                                              │
//!                                              └─► On login response:
//!                                                  1. Extract tokens from response
//!                                                  2. Create session in Redis
//!                                                  3. Set httpOnly cookie
//!                                                  4. Strip tokens from response
//! ```
//!
//! ## OAuth Auth (Full BFF Flow - IETF Recommended)
//! ```text
//! Browser ──GET /api/auth/google──► BFF ──302──► Google OAuth
//!                                                     │
//! Browser ◄──────────────────────────────────────────┘
//!    │
//!    └──GET /api/auth/google/callback──► BFF
//!                                          │
//!                                          ├─► Google: Exchange code for tokens
//!                                          ├─► Google: Get user info
//!                                          ├─► Auth Service: loginWithOAuthProvider
//!                                          ├─► Redis: Create session
//!                                          └─► Browser: Set cookie, redirect to frontend
//! ```
//!
//! # Why BFF Handles OAuth
//! - BFF is confidential client (has client_secret)
//! - BFF is edge service with external network access
//! - Auth Service stays internal-only (no external API calls)
//! - Follows IETF draft-ietf-oauth-browser-based-apps recommendations
//!
//! # Modules
//! - `session`: Session struct and Redis operations
//! - `middleware`: Session validation middleware for /graphql
//! - `interceptor`: GraphQL response interception for login/logout
//! - `oauth`: OAuth flow handlers (Google, Facebook)

pub mod compiled;
pub mod interceptor;
pub mod middleware;
#[allow(dead_code)]
pub mod oauth;
pub mod query_rewriter;
pub mod redis_pool;
pub mod session;
pub mod session_events;
#[allow(dead_code)]
pub mod social_oauth;
pub mod traits;

// Re-export commonly used types
#[allow(unused_imports)]
pub use compiled::CompiledAuthInterception;
pub use interceptor::{intercept_auth_response, AuthInterceptResult, ClientInfo};
pub use middleware::session_auth_middleware;
#[cfg(feature = "google-oauth")]
pub use oauth::{
    google_oauth_callback, google_oauth_init, link_oauth_account, restore_oauth_account,
};
pub use query_rewriter::{rewrite_login_query, rewrite_verify_mfa_login_query};
#[cfg(feature = "instagram-oauth")]
pub use social_oauth::{instagram_oauth_callback, instagram_oauth_init};

// Infrastructure traits for future session store integration
#[allow(unused_imports)]
pub use traits::{AuthError, AuthResult, SessionInfo, SessionStore, SharedSessionStore};
