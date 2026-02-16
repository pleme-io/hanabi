//! Pre-compiled auth interception rules for efficient runtime matching.
//!
//! Built once at startup from [`AuthInterceptionConfig`], stored in [`BffInfra`].
//! All string comparisons use pre-lowercased prefixes to avoid per-request allocations.

use crate::config::{AuthInterceptionConfig, MutationMatcher, TokenFieldConfig};

/// Pre-compiled auth interception rules (built once at startup).
#[derive(Debug, Clone)]
pub struct CompiledAuthInterception {
    pub login: CompiledMatcher,
    pub logout: CompiledMatcher,
    pub mfa_verify: CompiledMatcher,
    pub magic_link: CompiledMatcher,
    pub start_profile: CompiledMatcher,
    pub token_fields: TokenFieldConfig,
    pub login_response_fields: Vec<String>,
    pub strip_fields: Vec<String>,
    /// BFF-required fields to inject into login queries
    pub bff_required_fields: Vec<String>,
    /// Login query patterns for query rewriter (e.g., "login(input:", "loginWithGoogle(")
    pub login_query_patterns: Vec<String>,
}

/// Pre-compiled matcher for a single mutation type.
#[derive(Debug, Clone)]
pub struct CompiledMatcher {
    /// Pre-lowercased operation name prefixes
    pub op_prefixes: Vec<String>,
    /// Query string patterns (matched with `.contains()`)
    pub query_patterns: Vec<String>,
    /// Combined patterns: both strings must appear in the query
    pub query_combined_patterns: Vec<(String, String)>,
    /// Exact operation names (pre-lowercased) for `eq` matching
    pub op_exact: Vec<String>,
}

impl CompiledMatcher {
    /// Check if an operation name + query string matches this mutation type.
    #[inline]
    pub fn matches(&self, operation_name: &str, query: &str) -> bool {
        let op_lower = operation_name.to_lowercase();

        // Check operation name prefixes
        if self
            .op_prefixes
            .iter()
            .any(|p| op_lower.starts_with(p.as_str()))
        {
            return true;
        }

        // Check exact operation names
        if self.op_exact.contains(&op_lower) {
            return true;
        }

        // Check query patterns
        if self
            .query_patterns
            .iter()
            .any(|p| query.contains(p.as_str()))
        {
            return true;
        }

        // Check combined patterns (both must match)
        if self
            .query_combined_patterns
            .iter()
            .any(|(a, b)| query.contains(a.as_str()) && query.contains(b.as_str()))
        {
            return true;
        }

        false
    }
}

impl CompiledAuthInterception {
    /// Build compiled rules from configuration.
    pub fn from_config(config: &AuthInterceptionConfig) -> Self {
        Self {
            login: Self::compile_matcher(&config.login),
            logout: Self::compile_logout(&config.logout),
            mfa_verify: Self::compile_mfa_verify(&config.mfa_verify),
            magic_link: Self::compile_magic_link(&config.magic_link),
            start_profile: Self::compile_start_profile(&config.start_profile),
            token_fields: config.token_fields.clone(),
            login_response_fields: config.login_response_fields.clone(),
            strip_fields: config.strip_fields.clone(),
            bff_required_fields: vec![
                config.token_fields.access_token.clone(),
                config.token_fields.refresh_token.clone(),
                config.token_fields.expires_in.clone(),
            ],
            login_query_patterns: config.login_query_patterns.clone(),
        }
    }

    fn compile_matcher(
        matcher: &MutationMatcher,
    ) -> CompiledMatcher {
        CompiledMatcher {
            op_prefixes: matcher
                .operation_prefixes
                .iter()
                .map(|p| p.to_lowercase())
                .collect(),
            query_patterns: matcher.query_patterns.clone(),
            query_combined_patterns: matcher.query_combined_patterns.clone(),
            op_exact: Vec::new(),
        }
    }

    fn compile_logout(
        matcher: &MutationMatcher,
    ) -> CompiledMatcher {
        let mut compiled = Self::compile_matcher(matcher);
        // Default behavior: exact match on "logout" and "logoutmutation"
        if compiled.op_exact.is_empty()
            && compiled.op_prefixes.is_empty()
            && matcher.operation_prefixes.is_empty()
        {
            compiled.op_exact = vec!["logout".to_string(), "logoutmutation".to_string()];
        }
        compiled
    }

    fn compile_mfa_verify(
        matcher: &MutationMatcher,
    ) -> CompiledMatcher {
        let mut compiled = Self::compile_matcher(matcher);
        if compiled.op_exact.is_empty()
            && compiled.op_prefixes.is_empty()
            && matcher.operation_prefixes.is_empty()
        {
            compiled.op_exact = vec![
                "verifymfalogin".to_string(),
                "verifymfaloginmutation".to_string(),
            ];
        }
        compiled
    }

    fn compile_magic_link(
        matcher: &MutationMatcher,
    ) -> CompiledMatcher {
        let mut compiled = Self::compile_matcher(matcher);
        if compiled.op_exact.is_empty()
            && compiled.op_prefixes.is_empty()
            && matcher.operation_prefixes.is_empty()
        {
            compiled.op_exact = vec![
                "verifymagiclink".to_string(),
                "verifyprovidermagiclink".to_string(),
            ];
        }
        compiled
    }

    fn compile_start_profile(
        matcher: &MutationMatcher,
    ) -> CompiledMatcher {
        let mut compiled = Self::compile_matcher(matcher);
        if compiled.op_exact.is_empty()
            && compiled.op_prefixes.is_empty()
            && matcher.operation_prefixes.is_empty()
        {
            compiled.op_exact = vec!["startprofile".to_string()];
        }
        compiled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_compiled() -> CompiledAuthInterception {
        CompiledAuthInterception::from_config(&AuthInterceptionConfig::default())
    }

    // ── Login matching (reproduces original hardcoded behavior) ──

    #[test]
    fn login_by_operation_name_prefix() {
        let c = default_compiled();
        assert!(c.login.matches("Login", ""));
        assert!(c.login.matches("LoginUser", ""));
        assert!(c.login.matches("LoginMutation", ""));
        assert!(c.login.matches("LoginWithGoogle", ""));
        assert!(c.login.matches("login", ""));
    }

    #[test]
    fn login_by_query_pattern() {
        let c = default_compiled();
        assert!(c.login.matches("", "mutation Login($input: LoginInput!)"));
        assert!(c.login.matches("", "mutation login($input: LoginInput!)"));
    }

    #[test]
    fn login_by_combined_pattern() {
        let c = default_compiled();
        assert!(c
            .login
            .matches("", "query { login(input: $input) { accessToken } }"));
    }

    #[test]
    fn login_no_false_positive() {
        let c = default_compiled();
        assert!(!c.login.matches("GetUser", "query GetUser { user { id } }"));
        assert!(!c
            .login
            .matches("CreateUser", "mutation CreateUser { createUser { id } }"));
    }

    // ── Logout matching ──

    #[test]
    fn logout_by_operation_name() {
        let c = default_compiled();
        assert!(c.logout.matches("Logout", ""));
        assert!(c.logout.matches("LogoutMutation", ""));
        assert!(c.logout.matches("logout", ""));
    }

    #[test]
    fn logout_by_query_pattern() {
        let c = default_compiled();
        assert!(c.logout.matches("", "mutation Logout { logout }"));
        assert!(c.logout.matches("", "mutation logout { logout }"));
    }

    // ── MFA verify matching ──

    #[test]
    fn mfa_verify_by_operation_name() {
        let c = default_compiled();
        assert!(c.mfa_verify.matches("VerifyMfaLogin", ""));
        assert!(c.mfa_verify.matches("VerifyMfaLoginMutation", ""));
    }

    #[test]
    fn mfa_verify_by_query_pattern() {
        let c = default_compiled();
        assert!(c
            .mfa_verify
            .matches("", "mutation VerifyMfaLogin($input: MfaInput!)"));
        assert!(c
            .mfa_verify
            .matches("", "mutation verifyMfaLogin($input: MfaInput!)"));
        assert!(c
            .mfa_verify
            .matches("", "{ verifyMfaLogin(input: $input) { user } }"));
    }

    // ── Magic link matching ──

    #[test]
    fn magic_link_by_operation_name() {
        let c = default_compiled();
        assert!(c.magic_link.matches("VerifyMagicLink", ""));
        assert!(c.magic_link.matches("VerifyProviderMagicLink", ""));
    }

    #[test]
    fn magic_link_by_query_pattern() {
        let c = default_compiled();
        assert!(c
            .magic_link
            .matches("", "mutation VerifyMagicLink { verifyMagicLink(token: $t) }"));
        assert!(c
            .magic_link
            .matches("", "mutation VerifyProviderMagicLink { ... }"));
        assert!(c
            .magic_link
            .matches("", "{ verifyMagicLink(token: $t) { user } }"));
    }

    // ── Start profile matching ──

    #[test]
    fn start_profile_by_operation_name() {
        let c = default_compiled();
        assert!(c.start_profile.matches("StartProfile", ""));
    }

    #[test]
    fn start_profile_by_query_pattern() {
        let c = default_compiled();
        assert!(c
            .start_profile
            .matches("", "mutation StartProfile { startProfile(input: $i) }"));
        assert!(c
            .start_profile
            .matches("", "{ startProfile(input: $i) { user } }"));
    }

    // ── Token fields match defaults ──

    #[test]
    fn default_token_fields() {
        let c = default_compiled();
        assert_eq!(c.token_fields.access_token, "accessToken");
        assert_eq!(c.token_fields.refresh_token, "refreshToken");
        assert_eq!(c.token_fields.expires_in, "expiresIn");
        assert_eq!(c.token_fields.user_id_path, "user.id");
    }

    #[test]
    fn default_bff_required_fields() {
        let c = default_compiled();
        assert_eq!(
            c.bff_required_fields,
            vec!["accessToken", "refreshToken", "expiresIn"]
        );
    }

    #[test]
    fn default_strip_fields() {
        let c = default_compiled();
        assert_eq!(
            c.strip_fields,
            vec!["accessToken", "refreshToken", "expiresIn"]
        );
    }

    #[test]
    fn default_login_query_patterns() {
        let c = default_compiled();
        assert!(c.login_query_patterns.contains(&"login(input:".to_string()));
        assert!(c
            .login_query_patterns
            .contains(&"loginWithGoogle(".to_string()));
        assert!(c
            .login_query_patterns
            .contains(&"loginWithOAuthProvider(".to_string()));
    }
}
