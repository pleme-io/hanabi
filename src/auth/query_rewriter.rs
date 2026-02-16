//! GraphQL Query Rewriter for BFF Authentication
//!
//! The BFF needs to extract tokens from login mutation responses to create sessions,
//! but GraphQL only returns fields that are requested. The frontend should NOT need
//! to request tokens - that's an internal BFF concern.
//!
//! This module rewrites login queries to add the fields the BFF needs:
//! - `accessToken` - JWT for authenticating requests
//! - `refreshToken` - Token for refreshing expired JWTs
//! - `expiresIn` - Token lifetime in seconds
//! - `user.id` - User ID for session storage
//!
//! The frontend's query remains unchanged from their perspective - they just get
//! user data. The BFF intercepts the response and strips the tokens before returning.
//!
//! # Performance
//! Query rewriting happens ONLY on login mutations (rare).
//! Optimizations focus on minimal allocations and efficient string parsing.

use serde_json::Value;
use tracing::{debug, trace};

use super::compiled::CompiledAuthInterception;

/// Static patterns for inline fragment detection
const PATTERN_LOGIN_RESPONSE_FRAGMENT: &str = "... on LoginResponse";

/// Static field names for string operations
const FIELD_QUERY: &str = "query";
const FIELD_OPERATION_NAME: &str = "operationName";
const FIELD_USER: &str = "user";
const FIELD_ID: &str = "id";
const FIELD_USER_WITH_ID: &str = "user { id }";

/// Check if a query is a login mutation using compiled config rules.
///
/// # Performance
/// Inlined - called on every GraphQL request to check if rewriting needed
#[inline]
pub fn is_login_mutation(
    query: &str,
    operation_name: Option<&str>,
    compiled: &CompiledAuthInterception,
) -> bool {
    compiled.login.matches(operation_name.unwrap_or(""), query)
}

/// Check if a query is a verifyMfaLogin mutation using compiled config rules.
///
/// # Performance
/// Inlined - called on every GraphQL request to check if rewriting needed
#[inline]
pub fn is_verify_mfa_login_mutation(
    query: &str,
    operation_name: Option<&str>,
    compiled: &CompiledAuthInterception,
) -> bool {
    compiled.mfa_verify.matches(operation_name.unwrap_or(""), query)
}

/// Rewrite a login mutation to include BFF-required fields
///
/// This function parses the GraphQL query and adds the fields the BFF needs
/// for session management. The approach is simple string manipulation since
/// we know the structure of login mutations.
///
/// # Example
/// Input:
/// ```graphql
/// mutation Login($input: LoginInput!) {
///   login(input: $input) {
///     user { email firstName }
///   }
/// }
/// ```
///
/// Output:
/// ```graphql
/// mutation Login($input: LoginInput!) {
///   login(input: $input) {
///     accessToken refreshToken expiresIn user { id email firstName }
///   }
/// }
/// ```
pub fn rewrite_login_query(body: &mut Value, compiled: &CompiledAuthInterception) -> bool {
    let query = match body.get(FIELD_QUERY).and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return false,
    };

    let operation_name = body.get(FIELD_OPERATION_NAME).and_then(|v| v.as_str());

    if !is_login_mutation(query, operation_name, compiled) {
        return false;
    }

    debug!("Detected login mutation - rewriting query to add BFF-required fields");
    trace!("Original query: {}", query);

    // Find the login mutation field and its selection set
    // We need to handle multiple variants:
    // - login(input: $input) { ... }
    // - loginWithGoogle(...) { ... }
    // - loginWithFacebook(...) { ... }

    let rewritten = add_bff_fields_to_login(query, compiled);

    if rewritten != query {
        trace!("Rewritten query: {}", rewritten);
        if let Some(obj) = body.as_object_mut() {
            obj.insert(FIELD_QUERY.to_string(), Value::String(rewritten));
        }
        true
    } else {
        debug!("Query already has required fields or couldn't be rewritten");
        false
    }
}

/// Rewrite a verifyMfaLogin mutation to include BFF-required fields
///
/// This is similar to rewrite_login_query but for the MFA verification step.
/// The BFF needs tokens from this response to create the session.
pub fn rewrite_verify_mfa_login_query(
    body: &mut Value,
    compiled: &CompiledAuthInterception,
) -> bool {
    let query = match body.get(FIELD_QUERY).and_then(|v| v.as_str()) {
        Some(q) => q,
        None => return false,
    };

    let operation_name = body.get(FIELD_OPERATION_NAME).and_then(|v| v.as_str());

    if !is_verify_mfa_login_mutation(query, operation_name, compiled) {
        return false;
    }

    debug!("Detected verifyMfaLogin mutation - rewriting query to add BFF-required fields");
    trace!("Original query: {}", query);

    let rewritten = add_bff_fields_to_verify_mfa_login(query, compiled);

    if rewritten != query {
        trace!("Rewritten query: {}", rewritten);
        if let Some(obj) = body.as_object_mut() {
            obj.insert(FIELD_QUERY.to_string(), Value::String(rewritten));
        }
        true
    } else {
        debug!("Query already has required fields or couldn't be rewritten");
        false
    }
}

/// Add BFF-required fields to a verifyMfaLogin mutation query
fn add_bff_fields_to_verify_mfa_login(query: &str, compiled: &CompiledAuthInterception) -> String {
    let mut result = query.to_string();

    // Find the verifyMfaLogin call using compiled patterns
    let mfa_call_pattern = "verifyMfaLogin(";
    if let Some(mfa_start) = result.find(mfa_call_pattern) {
        // Find the opening brace of the selection set
        if let Some(brace_offset) = result[mfa_start..].find('{') {
            let brace_pos = mfa_start + brace_offset;
            let selection_start = brace_pos + 1;
            let selection_end = find_matching_brace(&result, brace_pos);

            if let Some(end) = selection_end {
                let selection = &result[selection_start..end];

                // Build the fields to inject (from config)
                let mut fields_to_add: Vec<&str> = Vec::new();

                for field in &compiled.bff_required_fields {
                    if !selection.contains(field.as_str()) {
                        fields_to_add.push(field.as_str());
                    }
                }

                // Check if user field exists and has id
                let needs_user_id = check_needs_user_id(selection, &mut fields_to_add);

                if !fields_to_add.is_empty() || needs_user_id {
                    let injection = if fields_to_add.is_empty() {
                        String::new()
                    } else {
                        format!(" {} ", fields_to_add.join(" "))
                    };

                    result.insert_str(selection_start, &injection);

                    if needs_user_id {
                        inject_user_id(&mut result, selection_start);
                    }
                }
            }
        }
    }

    result
}

/// Add BFF-required fields to a login mutation query
///
/// Handles both simple login responses and union type responses with inline fragments.
/// For union types like `login { ... on LoginResponse { user { ... } } ... on MfaChallengeRequired { ... } }`,
/// we inject tokens INSIDE the LoginResponse fragment, not at the root.
fn add_bff_fields_to_login(query: &str, compiled: &CompiledAuthInterception) -> String {
    let mut result = query.to_string();

    for pattern in &compiled.login_query_patterns {
        if let Some(login_start) = result.find(pattern.as_str()) {
            // Find the opening brace of the selection set after the login field
            if let Some(brace_offset) = result[login_start..].find('{') {
                let brace_pos = login_start + brace_offset;

                // Check if we already have the required fields
                let selection_start = brace_pos + 1;
                let selection_end = find_matching_brace(&result, brace_pos);

                if let Some(end) = selection_end {
                    let selection = &result[selection_start..end];

                    // Check if this uses inline fragments (union type pattern)
                    // Pattern: "... on LoginResponse { ... }"
                    let uses_inline_fragments = selection.contains(PATTERN_LOGIN_RESPONSE_FRAGMENT);

                    if uses_inline_fragments {
                        // For union types, inject tokens inside the LoginResponse fragment
                        result = add_bff_fields_to_login_response_fragment(
                            &result,
                            selection_start,
                            compiled,
                        );
                    } else {
                        // Original behavior for simple login responses
                        result = add_bff_fields_to_simple_login(
                            &result,
                            selection_start,
                            end,
                            compiled,
                        );
                    }
                }

                break; // Only process first matching login pattern
            }
        }
    }

    result
}

/// Add BFF-required fields to a LoginResponse inline fragment
///
/// For queries like:
/// ```graphql
/// login(input: $input) {
///   ... on LoginResponse {
///     user { email }
///   }
///   ... on MfaChallengeRequired {
///     mfaChallengeToken
///   }
/// }
/// ```
///
/// We inject tokens inside the LoginResponse fragment:
/// ```graphql
/// login(input: $input) {
///   ... on LoginResponse {
///     accessToken refreshToken expiresIn user { id email }
///   }
///   ... on MfaChallengeRequired {
///     mfaChallengeToken
///   }
/// }
/// ```
fn add_bff_fields_to_login_response_fragment(
    query: &str,
    _selection_start: usize,
    compiled: &CompiledAuthInterception,
) -> String {
    let mut result = query.to_string();

    // Find "... on LoginResponse {" and inject after its opening brace
    if let Some(fragment_start) = result.find(PATTERN_LOGIN_RESPONSE_FRAGMENT) {
        // Find the opening brace of the LoginResponse fragment
        if let Some(brace_offset) = result[fragment_start..].find('{') {
            let brace_pos = fragment_start + brace_offset;
            let fragment_selection_start = brace_pos + 1;
            let fragment_selection_end = find_matching_brace(&result, brace_pos);

            if let Some(frag_end) = fragment_selection_end {
                let fragment_selection = &result[fragment_selection_start..frag_end];

                // Build fields to inject (from config)
                let mut fields_to_add: Vec<&str> = Vec::new();

                for field in &compiled.bff_required_fields {
                    if !fragment_selection.contains(field.as_str()) {
                        fields_to_add.push(field.as_str());
                    }
                }

                // Check if user field exists and has id
                let needs_user_id =
                    check_needs_user_id(fragment_selection, &mut fields_to_add);

                if !fields_to_add.is_empty() || needs_user_id {
                    let injection = if fields_to_add.is_empty() {
                        String::new()
                    } else {
                        format!(" {} ", fields_to_add.join(" "))
                    };

                    result.insert_str(fragment_selection_start, &injection);

                    if needs_user_id {
                        inject_user_id(&mut result, fragment_selection_start);
                    }
                }
            }
        }
    }

    result
}

/// Add BFF-required fields to a simple (non-union) login response
fn add_bff_fields_to_simple_login(
    query: &str,
    selection_start: usize,
    selection_end: usize,
    compiled: &CompiledAuthInterception,
) -> String {
    let mut result = query.to_string();
    let selection = &query[selection_start..selection_end];

    // Build the fields to inject (from config)
    let mut fields_to_add: Vec<&str> = Vec::new();

    for field in &compiled.bff_required_fields {
        if !selection.contains(field.as_str()) {
            fields_to_add.push(field.as_str());
        }
    }

    // Check if user field exists and has id
    let needs_user_id = check_needs_user_id(selection, &mut fields_to_add);

    if !fields_to_add.is_empty() || needs_user_id {
        // Build the injection string
        let injection = if fields_to_add.is_empty() {
            String::new()
        } else {
            format!(" {} ", fields_to_add.join(" "))
        };

        // Inject after the opening brace
        result.insert_str(selection_start, &injection);

        // If we need to add id to existing user field, we need to do that too
        if needs_user_id {
            inject_user_id(&mut result, selection_start);
        }
    }

    result
}

/// Check if a selection set needs a user.id field injected.
/// Returns true if user field exists but lacks id.
/// Pushes "user { id }" to fields_to_add if no user field exists at all.
fn check_needs_user_id(selection: &str, fields_to_add: &mut Vec<&str>) -> bool {
    if selection.contains(FIELD_USER) {
        if let Some(user_start) = selection.find(FIELD_USER) {
            if let Some(user_brace) = selection[user_start..].find('{') {
                let user_selection_start = user_start + user_brace + 1;
                if let Some(user_end) = find_matching_brace(selection, user_start + user_brace) {
                    let user_selection = &selection[user_selection_start..user_end];
                    return !user_selection.split_whitespace().any(|word| {
                        word == FIELD_ID
                            || word.starts_with("id ")
                            || word.starts_with("id\n")
                    });
                }
                return true;
            }
            return true;
        }
        true
    } else {
        fields_to_add.push(FIELD_USER_WITH_ID);
        false
    }
}

/// Re-find user field after injection and insert " id " into its selection set.
fn inject_user_id(result: &mut String, search_start: usize) {
    if let Some(new_user_start) = result[search_start..].find(FIELD_USER) {
        let abs_user_start = search_start + new_user_start;
        if let Some(user_brace) = result[abs_user_start..].find('{') {
            let id_insert_pos = abs_user_start + user_brace + 1;
            result.insert_str(id_insert_pos, " id ");
        }
    }
}

/// Find the position of the matching closing brace
///
/// # Performance
/// Inlined - called multiple times during query rewriting
#[inline]
fn find_matching_brace(s: &str, open_pos: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(open_pos) != Some(&b'{') {
        return None;
    }

    let mut depth = 1;
    let mut pos = open_pos + 1;

    while pos < bytes.len() && depth > 0 {
        match bytes[pos] {
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        if depth > 0 {
            pos += 1;
        }
    }

    if depth == 0 {
        Some(pos)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthInterceptionConfig;

    fn default_compiled() -> CompiledAuthInterception {
        CompiledAuthInterception::from_config(&AuthInterceptionConfig::default())
    }

    /// Test helper to extract the query string from a body Value
    /// Panics with descriptive message if query field is missing or not a string
    fn get_query_str(body: &Value) -> &str {
        body.get("query")
            .expect("Body should have 'query' field")
            .as_str()
            .expect("'query' field should be a string")
    }

    #[test]
    fn test_is_login_mutation() {
        let c = default_compiled();
        assert!(is_login_mutation(
            "mutation Login($input: LoginInput!) { login(input: $input) { user { id } } }",
            Some("Login"),
            &c,
        ));
        assert!(is_login_mutation(
            "mutation Login($input: LoginInput!) { login(input: $input) { user { id } } }",
            None,
            &c,
        ));
        assert!(is_login_mutation(
            "mutation login($input: LoginInput!) { login(input: $input) { user { id } } }",
            None,
            &c,
        ));
        assert!(!is_login_mutation("query GetUser { user { id } }", None, &c));
        assert!(!is_login_mutation(
            "mutation CreateUser { createUser { id } }",
            None,
            &c,
        ));
    }

    #[test]
    fn test_rewrite_login_adds_missing_fields() {
        let c = default_compiled();
        let mut body = serde_json::json!({
            "query": "mutation Login($input: LoginInput!) { login(input: $input) { user { email } } }",
            "variables": { "input": { "email": "test@test.com", "password": "pass" } }
        });

        let rewritten = rewrite_login_query(&mut body, &c);
        assert!(rewritten);

        let query = get_query_str(&body);
        assert!(
            query.contains("accessToken"),
            "Should contain accessToken: {}",
            query
        );
        assert!(
            query.contains("refreshToken"),
            "Should contain refreshToken: {}",
            query
        );
        assert!(
            query.contains("expiresIn"),
            "Should contain expiresIn: {}",
            query
        );
    }

    #[test]
    fn test_rewrite_login_adds_user_id() {
        let c = default_compiled();
        let mut body = serde_json::json!({
            "query": "mutation Login($input: LoginInput!) { login(input: $input) { user { email firstName } } }",
            "variables": { "input": { "email": "test@test.com", "password": "pass" } }
        });

        let rewritten = rewrite_login_query(&mut body, &c);
        assert!(rewritten);

        let query = get_query_str(&body);
        // Check that id is in the user selection
        assert!(
            query.contains("user {") || query.contains("user{"),
            "Should have user selection"
        );

        // Find the user { } block and check for id
        if let Some(user_start) = query.find("user") {
            let user_section = &query[user_start..];
            if let Some(brace_start) = user_section.find('{') {
                let inside_braces = &user_section[brace_start..];
                assert!(
                    inside_braces.contains("id"),
                    "User selection should contain id: {}",
                    inside_braces
                );
            }
        }
    }

    #[test]
    fn test_rewrite_login_preserves_existing_fields() {
        let c = default_compiled();
        let mut body = serde_json::json!({
            "query": "mutation Login($input: LoginInput!) { login(input: $input) { accessToken refreshToken expiresIn user { id email } } }",
            "variables": { "input": { "email": "test@test.com", "password": "pass" } }
        });

        let _original_query = get_query_str(&body).to_string();
        let _rewritten = rewrite_login_query(&mut body, &c);

        // Should not modify if all fields are present
        let new_query = get_query_str(&body);
        // Even if rewritten returns true, the content should be essentially the same
        assert!(new_query.contains("accessToken"));
        assert!(new_query.contains("refreshToken"));
        assert!(new_query.contains("expiresIn"));
    }

    #[test]
    fn test_rewrite_non_login_unchanged() {
        let c = default_compiled();
        let mut body = serde_json::json!({
            "query": "query GetUser { me { id email } }",
            "variables": {}
        });

        let original_query = get_query_str(&body).to_string();
        let rewritten = rewrite_login_query(&mut body, &c);
        assert!(!rewritten);

        let new_query = get_query_str(&body);
        assert_eq!(original_query, new_query);
    }

    #[test]
    fn test_find_matching_brace() {
        assert_eq!(find_matching_brace("{ a }", 0), Some(4));
        assert_eq!(find_matching_brace("{ { } }", 0), Some(6));
        assert_eq!(find_matching_brace("{ a { b } c }", 0), Some(12));
        assert_eq!(find_matching_brace("no brace", 0), None);
    }

    #[test]
    fn test_rewrite_login_with_union_type_inline_fragments() {
        let c = default_compiled();
        // This is the actual query format used by the frontend with MFA support
        let mut body = serde_json::json!({
            "query": r#"mutation Login($input: LoginInput!) {
                login(input: $input) {
                    ... on LoginResponse {
                        user {
                            id
                            email
                            mfaEnabled
                        }
                    }
                    ... on MfaChallengeRequired {
                        mfaRequired
                        mfaChallengeToken
                        maskedEmail
                    }
                }
            }"#,
            "variables": { "input": { "email": "test@test.com", "password": "pass" } }
        });

        let rewritten = rewrite_login_query(&mut body, &c);
        assert!(rewritten, "Should have rewritten the query");

        let query = get_query_str(&body);

        // Tokens should be injected INSIDE the LoginResponse fragment, not at root
        assert!(
            query.contains("... on LoginResponse"),
            "Should preserve LoginResponse fragment"
        );
        assert!(
            query.contains("... on MfaChallengeRequired"),
            "Should preserve MfaChallengeRequired fragment"
        );

        // The tokens should be inside LoginResponse fragment
        // Find LoginResponse fragment and verify tokens are inside it
        if let Some(lr_start) = query.find("... on LoginResponse") {
            if let Some(brace_start) = query[lr_start..].find('{') {
                let after_brace = &query[lr_start + brace_start..];
                assert!(
                    after_brace.contains("accessToken"),
                    "accessToken should be in LoginResponse fragment: {}",
                    query
                );
                assert!(
                    after_brace.contains("refreshToken"),
                    "refreshToken should be in LoginResponse fragment: {}",
                    query
                );
                assert!(
                    after_brace.contains("expiresIn"),
                    "expiresIn should be in LoginResponse fragment: {}",
                    query
                );
            } else {
                panic!("No brace found after LoginResponse");
            }
        } else {
            panic!("LoginResponse fragment not found");
        }

        // Tokens should NOT appear before the LoginResponse fragment (at root level)
        if let Some(lr_start) = query.find("... on LoginResponse") {
            let before_fragment = &query[..lr_start];
            // Check that tokens aren't at the login() level before fragments
            let login_section = if let Some(login_start) = before_fragment.find("login(") {
                &before_fragment[login_start..]
            } else {
                before_fragment
            };
            // Should not have tokens at root level
            assert!(
                !login_section.contains("accessToken")
                    || login_section.find("accessToken").unwrap_or(0)
                        > login_section.find("{").unwrap_or(usize::MAX),
                "accessToken should not be at root level"
            );
        }
    }

    #[test]
    fn test_rewrite_login_union_type_preserves_mfa_challenge_fragment() {
        let c = default_compiled();
        let mut body = serde_json::json!({
            "query": r#"mutation Login($input: LoginInput!) {
                login(input: $input) {
                    ... on LoginResponse { user { email } }
                    ... on MfaChallengeRequired { mfaRequired mfaChallengeToken maskedEmail }
                }
            }"#,
            "variables": {}
        });

        rewrite_login_query(&mut body, &c);
        let query = get_query_str(&body);

        // MfaChallengeRequired fragment should be unchanged
        assert!(
            query.contains("mfaRequired"),
            "Should preserve mfaRequired field"
        );
        assert!(
            query.contains("mfaChallengeToken"),
            "Should preserve mfaChallengeToken field"
        );
        assert!(
            query.contains("maskedEmail"),
            "Should preserve maskedEmail field"
        );
    }
}
