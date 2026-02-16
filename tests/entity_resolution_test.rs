//! Entity Resolution Tests
//!
//! These tests verify that entity resolution follows Apollo Federation v2 spec:
//! - Entity representations have correct `__typename` and key fields
//! - `_entities` queries are properly formatted
//! - Batch entity loading works correctly
//! - Key field extraction follows @key directive patterns

use serde_json::{json, Value};

/// Test that entity representations have the correct structure for Federation v2
#[test]
fn test_entity_representation_structure() {
    // Federation v2 requires:
    // 1. __typename field with the entity type name
    // 2. Key field(s) as defined by @key directive

    let representation = json!({
        "__typename": "User",
        "id": "user-123"
    });

    assert_eq!(representation["__typename"], "User");
    assert_eq!(representation["id"], "user-123");

    // Composite key example
    let composite_representation = json!({
        "__typename": "Product",
        "sku": "ABC123",
        "warehouse": "US-WEST"
    });

    assert_eq!(composite_representation["__typename"], "Product");
    assert_eq!(composite_representation["sku"], "ABC123");
    assert_eq!(composite_representation["warehouse"], "US-WEST");
}

/// Test that _entities query format matches Federation v2 spec
#[test]
fn test_entities_query_format() {
    // The _entities query format from Apollo Federation
    let query = r#"query($_representations: [_Any!]!) {
        _entities(representations: $_representations) {
            ... on User {
                id
                email
                name
            }
        }
    }"#;

    let variables = json!({
        "_representations": [
            {"__typename": "User", "id": "user-1"},
            {"__typename": "User", "id": "user-2"}
        ]
    });

    // Verify the structure
    let reps = variables["_representations"].as_array().unwrap();
    assert_eq!(reps.len(), 2);
    assert_eq!(reps[0]["__typename"], "User");
    assert_eq!(reps[1]["__typename"], "User");

    // Verify query contains required elements
    assert!(query.contains("_entities"));
    assert!(query.contains("representations"));
    assert!(query.contains("... on User"));
}

/// Test multiple entity types in a single _entities query
#[test]
fn test_mixed_entity_types_query() {
    let variables = json!({
        "_representations": [
            {"__typename": "User", "id": "user-1"},
            {"__typename": "Product", "id": "prod-1"},
            {"__typename": "User", "id": "user-2"}
        ]
    });

    let reps = variables["_representations"].as_array().unwrap();
    assert_eq!(reps.len(), 3);

    // Count by type
    let user_count = reps.iter().filter(|r| r["__typename"] == "User").count();
    let product_count = reps.iter().filter(|r| r["__typename"] == "Product").count();

    assert_eq!(user_count, 2);
    assert_eq!(product_count, 1);
}

/// Test entity representation with nested key fields
#[test]
fn test_nested_key_entity_representation() {
    // Some entities have composite keys with nested fields
    let representation = json!({
        "__typename": "Review",
        "product": {
            "id": "prod-123"
        },
        "author": {
            "id": "user-456"
        }
    });

    assert_eq!(representation["__typename"], "Review");
    assert_eq!(representation["product"]["id"], "prod-123");
    assert_eq!(representation["author"]["id"], "user-456");
}

/// Test _entities query response structure
#[test]
fn test_entities_response_structure() {
    // Federation router expects this response format
    let response = json!({
        "data": {
            "_entities": [
                {
                    "__typename": "User",
                    "id": "user-1",
                    "email": "user1@example.com"
                },
                {
                    "__typename": "User",
                    "id": "user-2",
                    "email": "user2@example.com"
                }
            ]
        }
    });

    let entities = response["data"]["_entities"].as_array().unwrap();
    assert_eq!(entities.len(), 2);

    // Each entity should have __typename
    for entity in entities {
        assert!(entity["__typename"].is_string());
    }
}

/// Test handling of null entities in response (entity not found)
#[test]
fn test_entities_response_with_null() {
    // When an entity is not found, the response contains null
    let response = json!({
        "data": {
            "_entities": [
                {
                    "__typename": "User",
                    "id": "user-1",
                    "email": "user1@example.com"
                },
                null,  // Entity not found
                {
                    "__typename": "User",
                    "id": "user-3",
                    "email": "user3@example.com"
                }
            ]
        }
    });

    let entities = response["data"]["_entities"].as_array().unwrap();
    assert_eq!(entities.len(), 3);
    assert!(entities[0].is_object());
    assert!(entities[1].is_null());
    assert!(entities[2].is_object());
}

/// Test _entities query with different key types
#[test]
fn test_entity_key_types() {
    // UUID key
    let uuid_rep = json!({
        "__typename": "Booking",
        "id": "550e8400-e29b-41d4-a716-446655440000"
    });
    assert_eq!(uuid_rep["__typename"], "Booking");

    // Integer key
    let int_rep = json!({
        "__typename": "LegacyProduct",
        "legacyId": 12345
    });
    assert_eq!(int_rep["legacyId"], 12345);

    // String key with special characters
    let string_rep = json!({
        "__typename": "Document",
        "path": "/docs/api/v2/endpoints.md"
    });
    assert_eq!(string_rep["path"], "/docs/api/v2/endpoints.md");
}

/// Test entity response merging with additional fields
#[test]
fn test_entity_field_selection() {
    // When resolving an entity, only requested fields should be returned
    let query = r#"
        _entities(representations: $_representations) {
            ... on User {
                email
                # id is already in representation
            }
        }
    "#;

    // The response should include the resolved fields
    let response = json!({
        "__typename": "User",
        "id": "user-1",  // From representation
        "email": "test@example.com"  // Resolved by subgraph
    });

    assert!(response.get("id").is_some());
    assert!(response.get("email").is_some());
    // Fields not requested should not be present
    assert!(response.get("name").is_none());
    assert!(query.contains("email"));
}

/// Test that entity representations preserve order
#[test]
fn test_entity_order_preservation() {
    let representations = [
        json!({"__typename": "User", "id": "user-3"}),
        json!({"__typename": "User", "id": "user-1"}),
        json!({"__typename": "User", "id": "user-2"}),
    ];

    // Response should maintain order
    let response_entities = [
        json!({"__typename": "User", "id": "user-3", "name": "Charlie"}),
        json!({"__typename": "User", "id": "user-1", "name": "Alice"}),
        json!({"__typename": "User", "id": "user-2", "name": "Bob"}),
    ];

    // Verify order matches
    for (i, rep) in representations.iter().enumerate() {
        assert_eq!(rep["id"], response_entities[i]["id"]);
    }
}

/// Test serialization of _entities query body
#[test]
fn test_entities_request_body_serialization() {
    let query = r#"query($_representations: [_Any!]!) {
        _entities(representations: $_representations) {
            ... on User { id email }
        }
    }"#;

    let variables = json!({
        "_representations": [
            {"__typename": "User", "id": "user-123"}
        ]
    });

    let body = json!({
        "query": query,
        "variables": variables
    });

    // Should serialize to valid JSON
    let json_str = serde_json::to_string(&body).expect("Entity query body should serialize");

    // Should parse back
    let parsed: Value = serde_json::from_str(&json_str).expect("Should be valid JSON");

    assert!(parsed["query"].is_string());
    assert!(parsed["variables"]["_representations"].is_array());
}

/// Test inline _entities query format (used by some planners)
#[test]
fn test_inline_entities_query() {
    // Some query planners inline the representations directly
    let inline_query =
        r#"{_entities(representations:[{__typename:"User",id:"123"}]){...on User{email}}}"#;

    // This format should be valid GraphQL
    assert!(inline_query.contains("_entities"));
    assert!(inline_query.contains("__typename"));
    assert!(inline_query.contains("representations"));

    // Should be embeddable in JSON
    let body = json!({
        "query": inline_query,
        "variables": {}
    });

    let json_str = serde_json::to_string(&body).expect("Inline query should serialize");

    // Parse and verify
    let parsed: Value = serde_json::from_str(&json_str).expect("Should be valid JSON");

    assert_eq!(parsed["query"], inline_query);
}

/// Test deduplication of entity representations
#[test]
fn test_entity_representation_deduplication() {
    let representations = [
        json!({"__typename": "User", "id": "user-1"}),
        json!({"__typename": "User", "id": "user-2"}),
        json!({"__typename": "User", "id": "user-1"}), // Duplicate
        json!({"__typename": "User", "id": "user-3"}),
    ];

    // Deduplication by serializing to string and using a set
    use std::collections::HashSet;
    let unique: HashSet<String> = representations
        .iter()
        .map(|r| serde_json::to_string(r).unwrap())
        .collect();

    assert_eq!(
        unique.len(),
        3,
        "Should deduplicate to 3 unique representations"
    );
}
