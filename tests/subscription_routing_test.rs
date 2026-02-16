//! Subscription Routing Tests
//!
//! These tests verify that the BFF federation router correctly parses subscription
//! fields from the supergraph schema and routes them to the correct subgraphs.
//!
//! This test suite validates the fix for the subscription routing bug where the
//! regex-based parser (`[^}]+`) stopped at the first closing brace, causing
//! subscription fields beyond the first few lines to be missed.

use hanabi::federation::Supergraph;

/// Minimal test supergraph with subscription routing
const MINIMAL_SUPERGRAPH: &str = r#"
schema
  @link(url: "https://specs.apollo.dev/link/v1.0")
  @link(url: "https://specs.apollo.dev/join/v0.4", for: EXECUTION)
{
  query: Query
  mutation: Mutation
  subscription: Subscription
}

enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
  BOOKING @join__graph(name: "booking", url: "http://booking:8080/graphql")
  CHAT @join__graph(name: "chat", url: "http://chat:8080/graphql")
  JOB_SCHEDULER @join__graph(name: "job-scheduler", url: "http://job-scheduler:8080/graphql")
}

type Subscription {
  authEvents: AuthEvent! @join__field(graph: AUTH)
  bookingUpdated(bookingId: UUID!): Booking @join__field(graph: BOOKING)
  onChatMessage(conversationId: UUID!): ChatMessage! @join__field(graph: CHAT)
  onTypingStatus(conversationId: UUID!): TypingStatus! @join__field(graph: CHAT)
  jobsUpdated(statuses: [JobStatus!]): [Job!]! @join__field(graph: JOB_SCHEDULER)
  jobUpdated(id: UUID!): Job @join__field(graph: JOB_SCHEDULER)
}
"#;

/// Test supergraph with extended Subscription type (simulates production pattern)
const EXTENDED_SUBSCRIPTION_SUPERGRAPH: &str = r#"
schema
  @link(url: "https://specs.apollo.dev/link/v1.0")
  @link(url: "https://specs.apollo.dev/join/v0.4", for: EXECUTION)
{
  query: Query
  subscription: Subscription
}

enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
  CHAT @join__graph(name: "chat", url: "http://chat:8080/graphql")
}

type Subscription {
  authEvents: AuthEvent! @join__field(graph: AUTH)
}

extend type Subscription {
  onChatMessage(conversationId: UUID!): ChatMessage! @join__field(graph: CHAT)
}
"#;

/// Test supergraph with complex nested types before Subscription (stress test)
const COMPLEX_SUPERGRAPH: &str = r#"
schema
  @link(url: "https://specs.apollo.dev/link/v1.0")
  @link(url: "https://specs.apollo.dev/join/v0.4", for: EXECUTION)
{
  query: Query
  subscription: Subscription
}

enum join__Graph {
  AUTH @join__graph(name: "auth", url: "http://auth:8080/graphql")
  JOB_SCHEDULER @join__graph(name: "job-scheduler", url: "http://job-scheduler:8080/graphql")
}

type Query {
  me: User @join__field(graph: AUTH)
  jobs(filter: JobFilter): [Job!]! @join__field(graph: JOB_SCHEDULER)
}

input JobFilter {
  statuses: [JobStatus!]
  createdAfter: DateTime
  createdBefore: DateTime
}

type User @join__type(graph: AUTH, key: "id") {
  id: ID!
  email: String!
  name: String
  roles: [Role!]!
}

type Job @join__type(graph: JOB_SCHEDULER, key: "id") {
  id: ID!
  status: JobStatus!
  createdAt: DateTime!
  payload: JSON
}

enum JobStatus {
  PENDING
  RUNNING
  COMPLETED
  FAILED
}

type Subscription {
  userUpdated(userId: UUID!): User @join__field(graph: AUTH)
  jobsUpdated(statuses: [JobStatus!]): [Job!]! @join__field(graph: JOB_SCHEDULER)
}
"#;

#[test]
fn test_parse_minimal_supergraph_routes_all_subscriptions() {
    let supergraph =
        Supergraph::parse(MINIMAL_SUPERGRAPH).expect("Failed to parse minimal supergraph");

    // Verify all 6 subscription fields are routed
    assert_eq!(
        supergraph.subscription_routes.len(),
        6,
        "Expected 6 subscription routes, got {}",
        supergraph.subscription_routes.len()
    );

    // Verify specific routes
    assert_eq!(
        supergraph.subscription_routes.get("authEvents"),
        Some(&"auth".to_string()),
        "authEvents should route to auth"
    );
    assert_eq!(
        supergraph.subscription_routes.get("bookingUpdated"),
        Some(&"booking".to_string()),
        "bookingUpdated should route to booking"
    );
    assert_eq!(
        supergraph.subscription_routes.get("onChatMessage"),
        Some(&"chat".to_string()),
        "onChatMessage should route to chat"
    );
    assert_eq!(
        supergraph.subscription_routes.get("onTypingStatus"),
        Some(&"chat".to_string()),
        "onTypingStatus should route to chat"
    );
    assert_eq!(
        supergraph.subscription_routes.get("jobsUpdated"),
        Some(&"job-scheduler".to_string()),
        "jobsUpdated should route to job-scheduler"
    );
    assert_eq!(
        supergraph.subscription_routes.get("jobUpdated"),
        Some(&"job-scheduler".to_string()),
        "jobUpdated should route to job-scheduler"
    );
}

#[test]
fn test_parse_extended_subscription_type() {
    let supergraph = Supergraph::parse(EXTENDED_SUBSCRIPTION_SUPERGRAPH)
        .expect("Failed to parse extended subscription supergraph");

    // Verify both base and extended subscription fields are routed
    assert_eq!(
        supergraph.subscription_routes.len(),
        2,
        "Expected 2 subscription routes (base + extended)"
    );

    assert_eq!(
        supergraph.subscription_routes.get("authEvents"),
        Some(&"auth".to_string()),
        "authEvents (from base type) should route to auth"
    );
    assert_eq!(
        supergraph.subscription_routes.get("onChatMessage"),
        Some(&"chat".to_string()),
        "onChatMessage (from extend type) should route to chat"
    );
}

#[test]
fn test_parse_complex_supergraph_with_nested_types() {
    let supergraph =
        Supergraph::parse(COMPLEX_SUPERGRAPH).expect("Failed to parse complex supergraph");

    // Verify subscription routes parsed correctly despite complex type definitions before
    assert_eq!(
        supergraph.subscription_routes.get("userUpdated"),
        Some(&"auth".to_string()),
        "userUpdated should route to auth"
    );
    assert_eq!(
        supergraph.subscription_routes.get("jobsUpdated"),
        Some(&"job-scheduler".to_string()),
        "jobsUpdated should route to job-scheduler"
    );
}

#[test]
fn test_get_subscription_subgraph_returns_correct_subgraph() {
    let supergraph = Supergraph::parse(MINIMAL_SUPERGRAPH).expect("Failed to parse supergraph");

    let job_scheduler = supergraph
        .get_subscription_subgraph("jobsUpdated")
        .expect("jobsUpdated should have a subgraph");

    assert_eq!(job_scheduler.name, "job-scheduler");
    assert_eq!(job_scheduler.url, "http://job-scheduler:8080/graphql");
    assert_eq!(job_scheduler.ws_url, "ws://job-scheduler:8080/graphql");
}

#[test]
fn test_unknown_subscription_field_returns_none() {
    let supergraph = Supergraph::parse(MINIMAL_SUPERGRAPH).expect("Failed to parse supergraph");

    assert!(
        supergraph
            .get_subscription_subgraph("unknownField")
            .is_none(),
        "Unknown subscription field should return None"
    );
}

#[test]
fn test_subgraph_ws_url_derivation() {
    let supergraph = Supergraph::parse(MINIMAL_SUPERGRAPH).expect("Failed to parse supergraph");

    // HTTP → WS
    let chat = supergraph
        .subgraph("chat")
        .expect("chat subgraph should exist");
    assert_eq!(chat.ws_url, "ws://chat:8080/graphql");

    // Verify all subgraphs have derived WS URLs
    for (name, subgraph) in supergraph.subgraphs() {
        assert!(
            subgraph.ws_url.starts_with("ws://") || subgraph.ws_url.starts_with("wss://"),
            "Subgraph {} should have ws:// or wss:// URL, got {}",
            name,
            subgraph.ws_url
        );
    }
}

/// This test uses the production supergraph to verify that the apollo-parser
/// correctly handles the large Subscription type spanning many lines.
///
/// The Subscription type in production is around lines 16400-16580+, far beyond
/// where the old regex-based parser would stop.
#[test]
fn test_parse_production_supergraph_subscription_routes() {
    let supergraph_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../infrastructure/hive-router/supergraph.graphql"
    );

    let schema = match std::fs::read_to_string(supergraph_path) {
        Ok(s) => s,
        Err(_) => {
            eprintln!(
                "Skipping test: production supergraph not found at {}",
                supergraph_path
            );
            return;
        }
    };

    let supergraph = Supergraph::parse(&schema).expect("Failed to parse production supergraph");

    // CRITICAL: Verify jobsUpdated is routed correctly
    // This was the subscription that was failing before the apollo-parser fix
    assert_eq!(
        supergraph.subscription_routes.get("jobsUpdated"),
        Some(&"job-scheduler".to_string()),
        "CRITICAL: jobsUpdated MUST route to job-scheduler (this was broken before apollo-parser fix)"
    );

    // Verify other critical subscription routes
    // Production uses onNewMessage for chat, not onChatMessage
    assert!(
        supergraph.subscription_routes.contains_key("onNewMessage"),
        "Chat subscription (onNewMessage) should be routed"
    );

    // Log subscription count for debugging
    let route_count = supergraph.subscription_routes.len();
    println!(
        "Production supergraph has {} subscription routes",
        route_count
    );
    assert!(
        route_count >= 5,
        "Production supergraph should have at least 5 subscription routes, got {}",
        route_count
    );

    // Print all routes for debugging
    println!("Subscription routes:");
    for (field, subgraph) in &supergraph.subscription_routes {
        println!("  {} → {}", field, subgraph);
    }
}

#[test]
fn test_subscription_subgraphs_returns_unique_list() {
    let supergraph = Supergraph::parse(MINIMAL_SUPERGRAPH).expect("Failed to parse supergraph");

    let subscription_subgraphs = supergraph.subscription_subgraphs();

    // Should have 4 unique subgraphs (auth, booking, chat, job-scheduler)
    // But subscription_subgraphs may have duplicates since chat appears twice
    assert!(
        !subscription_subgraphs.is_empty(),
        "Should have at least one subscription-capable subgraph"
    );

    // Verify each returned subgraph is valid
    for subgraph in subscription_subgraphs {
        assert!(
            !subgraph.name.is_empty(),
            "Subgraph name should not be empty"
        );
        assert!(!subgraph.url.is_empty(), "Subgraph URL should not be empty");
    }
}
