//! Federation Edge Case Tests
//!
//! These tests verify that the supergraph parser handles ALL valid Federation v2
//! constructs, not just the patterns present in the current production supergraph.
//!
//! Edge cases covered:
//! - Unusual whitespace and formatting
//! - Multiple directives on fields
//! - Complex argument types (@requires, @provides)
//! - Type extensions spread across schema
//! - Special characters in names
//! - Large schemas with many types
//! - Interface and union types
//! - Nested input types in arguments

use hanabi::federation::Supergraph;

// =============================================================================
// Subgraph Parsing Edge Cases
// =============================================================================

/// Test @join__graph with reversed argument order (url before name)
#[test]
fn test_subgraph_reversed_argument_order() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(url: "http://auth:8080/graphql", name: "auth")
}

type Query {
  me: User @join__field(graph: AUTH)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse with reversed argument order");

    assert!(
        supergraph.subgraph("auth").is_some(),
        "Should find auth subgraph with reversed args"
    );
}

/// Test @join__graph with extra whitespace
#[test]
fn test_subgraph_extra_whitespace() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(
    name:   "auth"  ,
    url:    "http://auth:8080/graphql"
  )
}

type Query {
  me: User @join__field(graph: AUTH)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse with extra whitespace");

    let auth = supergraph.subgraph("auth");
    assert!(
        auth.is_some(),
        "Should find auth subgraph with extra whitespace"
    );
}

/// Test subgraph with special characters in URL
#[test]
fn test_subgraph_complex_url() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "https://api.example.com:443/v2/graphql?token=abc123&env=prod")
}

type Query {
  me: User @join__field(graph: AUTH)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse complex URL");

    let auth = supergraph.subgraph("auth").unwrap();
    assert!(
        auth.url.contains("token=abc123"),
        "URL should preserve query params"
    );
    assert_eq!(
        auth.ws_url,
        "wss://api.example.com:443/v2/graphql?token=abc123&env=prod"
    );
}

/// Test subgraph name with numbers and special patterns
#[test]
fn test_subgraph_name_with_numbers() {
    let schema = r#"
enum join__Graph {
  SERVICE_V2 @join__graph(name: "service-v2", url: "http://service-v2:8080/graphql")
  API_2024 @join__graph(name: "api-2024", url: "http://api-2024:8080/graphql")
}

type Query {
  data: Data @join__field(graph: SERVICE_V2)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse subgraph names with numbers");

    assert!(supergraph.subgraph("service-v2").is_some());
    assert!(supergraph.subgraph("api-2024").is_some());
}

/// Test many subgraphs (stress test)
#[test]
fn test_many_subgraphs() {
    let mut schema = String::from("enum join__Graph {\n");

    for i in 0..50 {
        schema.push_str(&format!(
            "  SERVICE_{} @join__graph(name: \"service-{}\", url: \"http://service-{}:8080/graphql\")\n",
            i, i, i
        ));
    }

    schema.push_str("}\n\ntype Query {\n  health: Boolean @join__field(graph: SERVICE_0)\n}");

    let supergraph = Supergraph::parse(&schema).expect("Should parse 50 subgraphs");

    assert!(supergraph.subgraphs().len() >= 50);

    for i in 0..50 {
        assert!(
            supergraph.subgraph(&format!("service-{}", i)).is_some(),
            "Should find service-{}",
            i
        );
    }
}

// =============================================================================
// Subscription Routing Edge Cases
// =============================================================================

/// Test subscription with multiple directives
#[test]
fn test_subscription_multiple_directives() {
    let schema = r#"
enum join__Graph {
  EVENTS @join__graph(name: "events", url: "http://events:8080/graphql")
}

type Subscription {
  onEvent(id: ID!): Event! @deprecated(reason: "Use onEventV2") @join__field(graph: EVENTS)
  onEventV2(id: ID!): EventV2! @join__field(graph: EVENTS)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse subscriptions with multiple directives");

    assert_eq!(
        supergraph.subscription_routes.get("onEvent"),
        Some(&"events".to_string()),
        "Deprecated subscription should still route"
    );
    assert_eq!(
        supergraph.subscription_routes.get("onEventV2"),
        Some(&"events".to_string())
    );
}

/// Test subscription with complex argument types
#[test]
fn test_subscription_complex_arguments() {
    let schema = r#"
enum join__Graph {
  REALTIME @join__graph(name: "realtime", url: "http://realtime:8080/graphql")
}

input FilterInput {
  status: [String!]
  createdAfter: DateTime
  tags: [TagInput!]
}

input TagInput {
  key: String!
  value: String!
}

type Subscription {
  onFiltered(filter: FilterInput!, limit: Int = 10): [Item!]! @join__field(graph: REALTIME)
  onBatch(ids: [ID!]!, options: BatchOptions): BatchResult @join__field(graph: REALTIME)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse subscriptions with complex arguments");

    assert_eq!(
        supergraph.subscription_routes.get("onFiltered"),
        Some(&"realtime".to_string())
    );
    assert_eq!(
        supergraph.subscription_routes.get("onBatch"),
        Some(&"realtime".to_string())
    );
}

/// Test subscription with @requires and @provides alongside @join__field
#[test]
fn test_subscription_with_requires_provides() {
    let schema = r#"
enum join__Graph {
  CHAT @join__graph(name: "chat", url: "http://chat:8080/graphql")
  USER @join__graph(name: "user", url: "http://user:8080/graphql")
}

type Subscription {
  onMessage(roomId: ID!): Message! @join__field(graph: CHAT, requires: "user { id }")
}

type Message @join__type(graph: CHAT, key: "id") {
  id: ID!
  text: String!
  user: User! @join__field(graph: CHAT, provides: "name")
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse subscriptions with @requires");

    assert_eq!(
        supergraph.subscription_routes.get("onMessage"),
        Some(&"chat".to_string()),
        "@join__field with requires should still route correctly"
    );
}

/// Test subscription spread across base type and extension
#[test]
fn test_subscription_with_extension() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
  CHAT @join__graph(name: "chat", url: "http://chat:8080/graphql")
  BOOKING @join__graph(name: "booking", url: "http://booking:8080/graphql")
}

type Subscription {
  onAuth: AuthEvent! @join__field(graph: AUTH)
}

extend type Subscription {
  onChat: ChatEvent! @join__field(graph: CHAT)
}

extend type Subscription {
  onBooking: BookingEvent! @join__field(graph: BOOKING)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse subscription with multiple extensions");

    assert_eq!(supergraph.subscription_routes.len(), 3);
    assert_eq!(
        supergraph.subscription_routes.get("onAuth"),
        Some(&"auth".to_string())
    );
    assert_eq!(
        supergraph.subscription_routes.get("onChat"),
        Some(&"chat".to_string())
    );
    assert_eq!(
        supergraph.subscription_routes.get("onBooking"),
        Some(&"booking".to_string())
    );
}

/// Test subscription field with nullable return type
#[test]
fn test_subscription_nullable_return() {
    let schema = r#"
enum join__Graph {
  EVENTS @join__graph(name: "events", url: "http://events:8080/graphql")
}

type Subscription {
  onOptionalEvent(id: ID!): Event @join__field(graph: EVENTS)
  onListEvent: [Event] @join__field(graph: EVENTS)
  onNestedList: [[Event!]!] @join__field(graph: EVENTS)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse subscriptions with various return types");

    assert_eq!(supergraph.subscription_routes.len(), 3);
}

// =============================================================================
// Field Ownership Edge Cases
// =============================================================================

/// Test field with @join__field on interface type
#[test]
fn test_field_ownership_interface() {
    let schema = r#"
enum join__Graph {
  CONTENT @join__graph(name: "content", url: "http://content:8080/graphql")
}

interface Node {
  id: ID! @join__field(graph: CONTENT)
}

type Query {
  node(id: ID!): Node @join__field(graph: CONTENT)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse interface field ownership");

    assert!(
        supergraph.provides_field("Query", "node", "content"),
        "Query.node should be owned by content"
    );
}

/// Test field owned by multiple subgraphs (federation sharing)
#[test]
fn test_field_multiple_owners() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
  PROFILE @join__graph(name: "profile", url: "http://profile:8080/graphql")
}

type User @join__type(graph: AUTH, key: "id") @join__type(graph: PROFILE, key: "id") {
  id: ID! @join__field(graph: AUTH)
  email: String! @join__field(graph: AUTH)
  bio: String @join__field(graph: PROFILE)
  avatar: String @join__field(graph: PROFILE)
}

type Query {
  me: User @join__field(graph: AUTH)
  profile(id: ID!): User @join__field(graph: PROFILE)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse entity with multiple owners");

    // Each field has ONE owner in the field_ownership map
    assert!(supergraph.provides_field("User", "email", "auth"));
    assert!(supergraph.provides_field("User", "bio", "profile"));
    assert!(supergraph.provides_field("Query", "me", "auth"));
    assert!(supergraph.provides_field("Query", "profile", "profile"));
}

/// Test deeply nested type definitions
#[test]
fn test_deeply_nested_types() {
    let schema = r#"
enum join__Graph {
  API @join__graph(name: "api", url: "http://api:8080/graphql")
}

type Query {
  data: Level1! @join__field(graph: API)
}

type Level1 {
  nested: Level2! @join__field(graph: API)
}

type Level2 {
  nested: Level3! @join__field(graph: API)
}

type Level3 {
  nested: Level4! @join__field(graph: API)
}

type Level4 {
  value: String! @join__field(graph: API)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse deeply nested types");

    assert!(supergraph.provides_field("Query", "data", "api"));
    assert!(supergraph.provides_field("Level4", "value", "api"));
}

/// Test type with many fields (stress test)
#[test]
fn test_type_with_many_fields() {
    let mut schema = String::from(
        r#"
enum join__Graph {
  DATA @join__graph(name: "data", url: "http://data:8080/graphql")
}

type Query {
  getData: LargeType! @join__field(graph: DATA)
}

type LargeType {
"#,
    );

    // Add 100 fields
    for i in 0..100 {
        schema.push_str(&format!("  field{}: String @join__field(graph: DATA)\n", i));
    }

    schema.push_str("}\n");

    let supergraph = Supergraph::parse(&schema).expect("Should parse type with 100 fields");

    assert!(supergraph.provides_field("Query", "getData", "data"));
    assert!(supergraph.provides_field("LargeType", "field0", "data"));
    assert!(supergraph.provides_field("LargeType", "field99", "data"));
}

// =============================================================================
// Error Handling Edge Cases
// =============================================================================

/// Test schema with parse errors still extracts what it can (error-resilient)
#[test]
fn test_partial_parse_on_errors() {
    // Schema with a syntax error in the middle
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
}

type Query {
  me: User @join__field(graph: AUTH)
  broken: Invalid @@@@ SYNTAX ERROR HERE
  stillWorks: Data @join__field(graph: AUTH)
}
"#;

    // Apollo-parser is error-resilient, so it should still extract valid parts
    let result = Supergraph::parse(schema);

    // Should not panic, may or may not succeed depending on error severity
    if let Ok(supergraph) = result {
        // If it succeeds, check that it extracted what it could
        assert!(supergraph.subgraph("auth").is_some());
    }
    // Either way, no panic is success for this test
}

/// Test completely empty Subscription type
#[test]
fn test_empty_subscription_type() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
}

type Query {
  me: User @join__field(graph: AUTH)
}

type Subscription {
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse empty Subscription type");

    assert!(supergraph.subscription_routes.is_empty());
}

/// Test subscription field without @join__field (should not be routed)
#[test]
fn test_subscription_without_join_field() {
    let schema = r#"
enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
}

type Subscription {
  onEvent: Event
  onRoutedEvent: Event @join__field(graph: AUTH)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse subscription without @join__field");

    // Only the field with @join__field should be routed
    assert_eq!(supergraph.subscription_routes.len(), 1);
    assert!(!supergraph.subscription_routes.contains_key("onEvent"));
    assert!(supergraph.subscription_routes.contains_key("onRoutedEvent"));
}

// =============================================================================
// GraphQL Spec Compliance Edge Cases
// =============================================================================

/// Test field with description (doc comment)
#[test]
fn test_field_with_description() {
    let schema = r#"
enum join__Graph {
  API @join__graph(name: "api", url: "http://api:8080/graphql")
}

type Query {
  """
  Get the currently authenticated user.
  Returns null if not authenticated.
  """
  me: User @join__field(graph: API)

  "Short description for simple field"
  health: Boolean! @join__field(graph: API)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse fields with descriptions");

    assert!(supergraph.provides_field("Query", "me", "api"));
    assert!(supergraph.provides_field("Query", "health", "api"));
}

/// Test enum type definition (should not break parsing)
#[test]
fn test_enum_type_in_schema() {
    let schema = r#"
enum join__Graph {
  API @join__graph(name: "api", url: "http://api:8080/graphql")
}

enum Status {
  PENDING
  ACTIVE
  COMPLETED
}

type Query {
  status: Status! @join__field(graph: API)
}

type Subscription {
  onStatusChange: Status! @join__field(graph: API)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse schema with enum types");

    assert!(supergraph.provides_field("Query", "status", "api"));
    assert_eq!(
        supergraph.subscription_routes.get("onStatusChange"),
        Some(&"api".to_string())
    );
}

/// Test union type definition
#[test]
fn test_union_type_in_schema() {
    let schema = r#"
enum join__Graph {
  SEARCH @join__graph(name: "search", url: "http://search:8080/graphql")
}

union SearchResult = User | Product | Article

type Query {
  search(query: String!): [SearchResult!]! @join__field(graph: SEARCH)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse schema with union types");

    assert!(supergraph.provides_field("Query", "search", "search"));
}

/// Test scalar type definitions
#[test]
fn test_custom_scalars() {
    let schema = r#"
enum join__Graph {
  API @join__graph(name: "api", url: "http://api:8080/graphql")
}

scalar DateTime
scalar JSON
scalar UUID

type Query {
  createdAt: DateTime! @join__field(graph: API)
  metadata: JSON @join__field(graph: API)
  id: UUID! @join__field(graph: API)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse schema with custom scalars");

    assert!(supergraph.provides_field("Query", "createdAt", "api"));
    assert!(supergraph.provides_field("Query", "metadata", "api"));
}

/// Test input types with complex nested structure
#[test]
fn test_complex_input_types() {
    let schema = r#"
enum join__Graph {
  API @join__graph(name: "api", url: "http://api:8080/graphql")
}

input CreateUserInput {
  name: String!
  email: String!
  address: AddressInput
  preferences: PreferencesInput!
}

input AddressInput {
  street: String!
  city: String!
  country: String!
  coordinates: CoordinatesInput
}

input CoordinatesInput {
  lat: Float!
  lng: Float!
}

input PreferencesInput {
  notifications: Boolean! = true
  theme: ThemeInput
}

input ThemeInput {
  mode: String!
  colors: [String!]
}

type Query {
  user(id: ID!): User @join__field(graph: API)
}

type Mutation {
  createUser(input: CreateUserInput!): User! @join__field(graph: API)
}
"#;

    let supergraph =
        Supergraph::parse(schema).expect("Should parse schema with complex input types");

    assert!(supergraph.provides_field("Query", "user", "api"));
    assert!(supergraph.provides_field("Mutation", "createUser", "api"));
}

// =============================================================================
// Real-World Federation Patterns
// =============================================================================

/// Test @key directive on entities (Federation v2)
#[test]
fn test_entity_with_key_directive() {
    let schema = r#"
enum join__Graph {
  USERS @join__graph(name: "users", url: "http://users:8080/graphql")
  ORDERS @join__graph(name: "orders", url: "http://orders:8080/graphql")
}

type User @join__type(graph: USERS, key: "id") @join__type(graph: ORDERS, key: "id") {
  id: ID! @join__field(graph: USERS)
  name: String! @join__field(graph: USERS)
  orders: [Order!]! @join__field(graph: ORDERS)
}

type Order @join__type(graph: ORDERS, key: "id") {
  id: ID! @join__field(graph: ORDERS)
  user: User! @join__field(graph: ORDERS)
  total: Float! @join__field(graph: ORDERS)
}

type Query {
  me: User @join__field(graph: USERS)
  order(id: ID!): Order @join__field(graph: ORDERS)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse federated entities with @key");

    assert!(supergraph.provides_field("User", "name", "users"));
    assert!(supergraph.provides_field("User", "orders", "orders"));
    assert!(supergraph.provides_field("Order", "user", "orders"));
}

/// Test @external directive pattern
#[test]
fn test_external_field_pattern() {
    let schema = r#"
enum join__Graph {
  PRODUCTS @join__graph(name: "products", url: "http://products:8080/graphql")
  REVIEWS @join__graph(name: "reviews", url: "http://reviews:8080/graphql")
}

type Product @join__type(graph: PRODUCTS, key: "id") @join__type(graph: REVIEWS, key: "id") {
  id: ID! @join__field(graph: PRODUCTS)
  name: String! @join__field(graph: PRODUCTS)
  reviews: [Review!]! @join__field(graph: REVIEWS)
  averageRating: Float @join__field(graph: REVIEWS, requires: "id")
}

type Review @join__type(graph: REVIEWS, key: "id") {
  id: ID!
  rating: Int!
  comment: String
  product: Product! @join__field(graph: REVIEWS)
}

type Query {
  product(id: ID!): Product @join__field(graph: PRODUCTS)
  reviews(productId: ID!): [Review!]! @join__field(graph: REVIEWS)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse @external pattern");

    assert!(supergraph.provides_field("Product", "name", "products"));
    assert!(supergraph.provides_field("Product", "reviews", "reviews"));
    assert!(supergraph.provides_field("Query", "product", "products"));
    assert!(supergraph.provides_field("Query", "reviews", "reviews"));
}

/// Test Federation v2 @shareable pattern
#[test]
fn test_shareable_field_pattern() {
    let schema = r#"
enum join__Graph {
  INVENTORY @join__graph(name: "inventory", url: "http://inventory:8080/graphql")
  PRODUCTS @join__graph(name: "products", url: "http://products:8080/graphql")
}

type Product @join__type(graph: PRODUCTS, key: "sku") @join__type(graph: INVENTORY, key: "sku") {
  sku: String! @join__field(graph: PRODUCTS) @join__field(graph: INVENTORY)
  name: String! @join__field(graph: PRODUCTS)
  stock: Int! @join__field(graph: INVENTORY)
}

type Query {
  product(sku: String!): Product @join__field(graph: PRODUCTS)
  inventory(sku: String!): Product @join__field(graph: INVENTORY)
}
"#;

    let supergraph = Supergraph::parse(schema).expect("Should parse @shareable pattern");

    // In shareable pattern, the field may appear in multiple subgraphs
    // Our parser takes the last one (HashMap behavior)
    assert!(supergraph.subgraph("products").is_some());
    assert!(supergraph.subgraph("inventory").is_some());
}
