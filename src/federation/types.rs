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

    /// Product identifier (e.g., "novaskyn", "myapp")
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
