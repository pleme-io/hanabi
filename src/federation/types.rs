#![allow(dead_code)]
//! Shared types for federation module

use serde::{Deserialize, Serialize};

/// Execution context passed to subgraph requests
/// Contains authenticated user information extracted from JWT/session
#[derive(Debug, Clone, Default)]
pub struct ExecutionContext {
    /// User ID from JWT 'sub' claim
    pub user_id: Option<String>,

    /// User email from JWT 'email' claim
    pub user_email: Option<String>,

    /// Comma-separated roles from JWT 'roles' claim
    pub user_roles: Option<String>,

    /// Comma-separated permissions from JWT 'permissions' claim
    pub user_permissions: Option<String>,

    /// JSON-encoded relationships from JWT 'relationships' claim
    pub user_relationships: Option<String>,

    /// Product identifier (e.g., "myapp", "storefront")
    pub product: String,

    /// Cookie header value (for forwarding to auth subgraph)
    pub cookies: Option<String>,

    /// Raw JWT token (for WebSocket authentication)
    pub token: Option<String>,
}

/// GraphQL request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLRequest {
    pub query: String,

    #[serde(default)]
    pub variables: serde_json::Value,

    #[serde(rename = "operationName")]
    pub operation_name: Option<String>,

    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// GraphQL response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLResponse {
    #[serde(default)]
    pub data: serde_json::Value,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl GraphQLResponse {
    pub fn error(message: &str) -> Self {
        Self {
            data: serde_json::Value::Null,
            errors: Some(vec![serde_json::json!({
                "message": message,
            })]),
            extensions: None,
        }
    }
}

/// graphql-ws protocol message types (static strings for zero allocation)
pub mod protocol {
    pub const CONNECTION_INIT: &str = "connection_init";
    pub const CONNECTION_ACK: &str = "connection_ack";
    pub const PING: &str = "ping";
    pub const PONG: &str = "pong";
    pub const SUBSCRIBE: &str = "subscribe";
    pub const NEXT: &str = "next";
    pub const ERROR: &str = "error";
    pub const COMPLETE: &str = "complete";
}

/// Message from client to server (graphql-ws protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientMessage {
    #[serde(rename = "type")]
    pub msg_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

/// Message from server to client (graphql-ws protocol)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMessage {
    #[serde(rename = "type")]
    pub msg_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

impl ServerMessage {
    /// PERFORMANCE: Inlined - called once per connection
    #[inline]
    pub fn connection_ack() -> Self {
        Self {
            msg_type: protocol::CONNECTION_ACK.to_string(),
            id: None,
            payload: None,
        }
    }

    /// PERFORMANCE: Inlined for hot path - called on every subscription event
    /// This is the most frequently called constructor (100s-1000s per second per active subscription)
    #[inline]
    pub fn next(id: &str, data: serde_json::Value) -> Self {
        Self {
            msg_type: protocol::NEXT.to_string(),
            id: Some(id.to_string()),
            payload: Some(serde_json::json!({ "data": data })),
        }
    }

    /// PERFORMANCE: Inlined for hot path - called on subscription errors
    #[inline]
    pub fn error(id: &str, errors: Vec<serde_json::Value>) -> Self {
        Self {
            msg_type: protocol::ERROR.to_string(),
            id: Some(id.to_string()),
            payload: Some(serde_json::json!(errors)),
        }
    }

    /// PERFORMANCE: Inlined for hot path - called when subscriptions complete
    #[inline]
    pub fn complete(id: &str) -> Self {
        Self {
            msg_type: protocol::COMPLETE.to_string(),
            id: Some(id.to_string()),
            payload: None,
        }
    }

    /// PERFORMANCE: Inlined - called on ping/pong cycles
    #[inline]
    pub fn pong() -> Self {
        Self {
            msg_type: protocol::PONG.to_string(),
            id: None,
            payload: None,
        }
    }
}

/// Subscribe payload from client
#[derive(Debug, Clone, Deserialize)]
pub struct SubscribePayload {
    pub query: String,

    #[serde(default)]
    pub variables: serde_json::Value,

    #[serde(rename = "operationName")]
    pub operation_name: Option<String>,

    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// Connection parameters from connection_init
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConnectionParams {
    pub authorization: Option<String>,

    #[serde(rename = "x-user-id")]
    pub user_id: Option<String>,

    #[serde(rename = "x-product")]
    pub product: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_request_deserializes_minimal() {
        let json = r#"{"query": "{ users { id } }"}"#;
        let req: GraphQLRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.query, "{ users { id } }");
        assert!(req.operation_name.is_none());
        assert_eq!(req.variables, serde_json::Value::Null);
        assert_eq!(req.extensions, serde_json::Value::Null);
    }

    #[test]
    fn graphql_request_deserializes_full() {
        let json = r#"{
            "query": "query GetUser($id: ID!) { user(id: $id) { name } }",
            "operationName": "GetUser",
            "variables": {"id": "123"},
            "extensions": {"persistedQuery": {"sha256Hash": "abc"}}
        }"#;
        let req: GraphQLRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.operation_name, Some("GetUser".to_string()));
        assert_eq!(req.variables["id"], "123");
        assert!(req.extensions["persistedQuery"].is_object());
    }

    #[test]
    fn graphql_request_roundtrip() {
        let req = GraphQLRequest {
            query: "{ me { name } }".to_string(),
            variables: serde_json::json!({"x": 1}),
            operation_name: Some("Me".to_string()),
            extensions: serde_json::Value::Null,
        };
        let json = serde_json::to_string(&req).unwrap();
        let req2: GraphQLRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.query, req2.query);
        assert_eq!(req.operation_name, req2.operation_name);
    }

    #[test]
    fn graphql_response_error_shape() {
        let resp = GraphQLResponse::error("Something went wrong");
        assert_eq!(resp.data, serde_json::Value::Null);
        let errors = resp.errors.as_ref().unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0]["message"], "Something went wrong");
    }

    #[test]
    fn graphql_response_skips_none_fields() {
        let resp = GraphQLResponse {
            data: serde_json::json!({"user": null}),
            errors: None,
            extensions: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(!json.as_object().unwrap().contains_key("errors"));
        assert!(!json.as_object().unwrap().contains_key("extensions"));
    }

    #[test]
    fn graphql_response_includes_present_fields() {
        let resp = GraphQLResponse {
            data: serde_json::json!(null),
            errors: Some(vec![serde_json::json!({"message": "err"})]),
            extensions: Some(serde_json::json!({"tracing": {}})),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json.as_object().unwrap().contains_key("errors"));
        assert!(json.as_object().unwrap().contains_key("extensions"));
    }

    #[test]
    fn server_message_connection_ack_serializes_correctly() {
        let msg = ServerMessage::connection_ack();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "connection_ack");
        assert!(!json.as_object().unwrap().contains_key("id"));
        assert!(!json.as_object().unwrap().contains_key("payload"));
    }

    #[test]
    fn server_message_next_wraps_data() {
        let msg = ServerMessage::next("sub-1", serde_json::json!({"count": 42}));
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "next");
        assert_eq!(json["id"], "sub-1");
        assert_eq!(json["payload"]["data"]["count"], 42);
    }

    #[test]
    fn server_message_error_wraps_errors_array() {
        let errors = vec![serde_json::json!({"message": "field error"})];
        let msg = ServerMessage::error("sub-2", errors);
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "error");
        assert_eq!(json["id"], "sub-2");
        assert!(json["payload"].is_array());
        assert_eq!(json["payload"][0]["message"], "field error");
    }

    #[test]
    fn server_message_complete_has_no_payload() {
        let msg = ServerMessage::complete("sub-3");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "complete");
        assert_eq!(json["id"], "sub-3");
        assert!(!json.as_object().unwrap().contains_key("payload"));
    }

    #[test]
    fn server_message_pong_has_no_id_or_payload() {
        let msg = ServerMessage::pong();
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "pong");
        assert!(!json.as_object().unwrap().contains_key("id"));
        assert!(!json.as_object().unwrap().contains_key("payload"));
    }

    #[test]
    fn client_message_deserializes_subscribe() {
        let json = r#"{
            "type": "subscribe",
            "id": "1",
            "payload": {"query": "subscription { onMessage { text } }"}
        }"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.msg_type, "subscribe");
        assert_eq!(msg.id, Some("1".to_string()));
        assert!(msg.payload.is_some());
    }

    #[test]
    fn client_message_deserializes_connection_init_without_payload() {
        let json = r#"{"type": "connection_init"}"#;
        let msg: ClientMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.msg_type, "connection_init");
        assert!(msg.id.is_none());
        assert!(msg.payload.is_none());
    }

    #[test]
    fn connection_params_renames_fields() {
        let json = r#"{
            "authorization": "Bearer tok",
            "x-user-id": "user-123",
            "x-product": "myapp"
        }"#;
        let params: ConnectionParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.authorization, Some("Bearer tok".to_string()));
        assert_eq!(params.user_id, Some("user-123".to_string()));
        assert_eq!(params.product, Some("myapp".to_string()));
    }

    #[test]
    fn connection_params_default_is_all_none() {
        let params = ConnectionParams::default();
        assert!(params.authorization.is_none());
        assert!(params.user_id.is_none());
        assert!(params.product.is_none());
    }

    #[test]
    fn subscribe_payload_defaults_work() {
        let json = r#"{"query": "subscription { tick }"}"#;
        let payload: SubscribePayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.query, "subscription { tick }");
        assert!(payload.operation_name.is_none());
        assert_eq!(payload.variables, serde_json::Value::Null);
        assert_eq!(payload.extensions, serde_json::Value::Null);
    }

    #[test]
    fn execution_context_default_has_empty_product() {
        let ctx = ExecutionContext::default();
        assert!(ctx.user_id.is_none());
        assert!(ctx.user_email.is_none());
        assert_eq!(ctx.product, "");
    }

    #[test]
    fn protocol_constants_match_graphql_ws_spec() {
        assert_eq!(protocol::CONNECTION_INIT, "connection_init");
        assert_eq!(protocol::CONNECTION_ACK, "connection_ack");
        assert_eq!(protocol::PING, "ping");
        assert_eq!(protocol::PONG, "pong");
        assert_eq!(protocol::SUBSCRIBE, "subscribe");
        assert_eq!(protocol::NEXT, "next");
        assert_eq!(protocol::ERROR, "error");
        assert_eq!(protocol::COMPLETE, "complete");
    }
}
