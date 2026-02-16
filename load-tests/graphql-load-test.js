/**
 * Hanabi BFF Load Test Suite
 *
 * Uses k6 (https://k6.io) to stress test the GraphQL federation endpoint.
 *
 * Installation:
 *   brew install k6  # macOS
 *   # or download from https://k6.io/docs/getting-started/installation/
 *
 * Usage:
 *   k6 run load-tests/graphql-load-test.js
 *   k6 run --vus 50 --duration 60s load-tests/graphql-load-test.js
 *   k6 run --env TARGET_URL=https://staging.example.com load-tests/graphql-load-test.js
 *
 * Environment Variables:
 *   TARGET_URL  - Base URL of Hanabi BFF (default: http://localhost:8080)
 *   VUS         - Number of virtual users (default: 10)
 *   DURATION    - Test duration (default: 30s)
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";

// Custom metrics
const graphqlErrors = new Rate("graphql_errors");
const responseTime = new Trend("response_time");
const requestsPerSecond = new Counter("requests_per_second");
const circuitBreakerRejections = new Counter("circuit_breaker_rejections");
const loadSheddingRejections = new Counter("load_shedding_rejections");

// Test configuration
export const options = {
  stages: [
    { duration: "10s", target: 10 }, // Ramp up to 10 users
    { duration: "30s", target: 50 }, // Ramp up to 50 users
    { duration: "30s", target: 50 }, // Stay at 50 users
    { duration: "10s", target: 100 }, // Spike to 100 users
    { duration: "20s", target: 100 }, // Stay at 100 users
    { duration: "10s", target: 0 }, // Ramp down
  ],

  thresholds: {
    // Response time thresholds
    http_req_duration: ["p(95)<500", "p(99)<1000"], // 95th < 500ms, 99th < 1s
    response_time: ["p(95)<500"],

    // Error rate thresholds
    graphql_errors: ["rate<0.01"], // Less than 1% GraphQL errors
    http_req_failed: ["rate<0.05"], // Less than 5% HTTP failures

    // Load shedding is expected under extreme load
    // These are informational, not failing thresholds
  },
};

// Configuration from environment
const TARGET_URL = __ENV.TARGET_URL || "http://localhost:8080";
const GRAPHQL_ENDPOINT = `${TARGET_URL}/graphql`;

// Sample GraphQL queries
const QUERIES = {
  // Simple query - minimal load
  introspection: {
    query: `{ __typename }`,
    operationName: "Introspection",
  },

  // Product catalog query - common read operation
  products: {
    query: `
      query GetProducts($first: Int) {
        products(first: $first) {
          edges {
            node {
              id
              name
              price
              category {
                id
                name
              }
            }
          }
          pageInfo {
            hasNextPage
          }
        }
      }
    `,
    variables: { first: 10 },
    operationName: "GetProducts",
  },

  // User profile query - auth-dependent
  userProfile: {
    query: `
      query GetUserProfile {
        me {
          id
          email
          name
          preferences {
            theme
            notifications
          }
        }
      }
    `,
    operationName: "GetUserProfile",
  },

  // Complex query - tests federation
  productWithReviews: {
    query: `
      query GetProductWithReviews($id: ID!) {
        product(id: $id) {
          id
          name
          description
          price
          reviews {
            id
            rating
            comment
            author {
              id
              name
            }
          }
          relatedProducts {
            id
            name
            price
          }
        }
      }
    `,
    variables: { id: "product-1" },
    operationName: "GetProductWithReviews",
  },
};

// Request headers
function getHeaders(product = "novaskyn") {
  return {
    "Content-Type": "application/json",
    "X-Product": product,
    "X-Request-ID": `load-test-${Date.now()}-${Math.random()
      .toString(36)
      .substr(2, 9)}`,
  };
}

// Make GraphQL request
function graphqlRequest(queryConfig, product = "novaskyn") {
  const payload = JSON.stringify({
    query: queryConfig.query,
    variables: queryConfig.variables || {},
    operationName: queryConfig.operationName,
  });

  const start = Date.now();
  const response = http.post(GRAPHQL_ENDPOINT, payload, {
    headers: getHeaders(product),
    timeout: "30s",
  });
  const duration = Date.now() - start;

  // Track metrics
  responseTime.add(duration);
  requestsPerSecond.add(1);

  // Check for load shedding or circuit breaker
  if (response.status === 503) {
    loadSheddingRejections.add(1);
  } else if (response.status === 502 || response.status === 504) {
    circuitBreakerRejections.add(1);
  }

  // Parse response and check for GraphQL errors
  let hasGraphQLError = false;
  if (response.status === 200) {
    try {
      const body = JSON.parse(response.body);
      hasGraphQLError = body.errors && body.errors.length > 0;
    } catch (e) {
      hasGraphQLError = true;
    }
  }
  graphqlErrors.add(hasGraphQLError);

  return response;
}

// Main test scenario
export default function () {
  group("GraphQL Operations", function () {
    // Simple health check query (high frequency)
    group("Introspection", function () {
      const res = graphqlRequest(QUERIES.introspection);
      check(res, {
        "status is 200 or 503": (r) => r.status === 200 || r.status === 503,
        "response is valid JSON": (r) => {
          try {
            JSON.parse(r.body);
            return true;
          } catch {
            return false;
          }
        },
      });
    });

    // Product catalog (medium frequency)
    if (Math.random() < 0.7) {
      group("Products", function () {
        const res = graphqlRequest(QUERIES.products);
        check(res, {
          "status is 200 or 503": (r) => r.status === 200 || r.status === 503,
        });
      });
    }

    // Complex federated query (low frequency)
    if (Math.random() < 0.3) {
      group("ProductWithReviews", function () {
        const res = graphqlRequest(QUERIES.productWithReviews);
        check(res, {
          "status is 200 or 503": (r) => r.status === 200 || r.status === 503,
        });
      });
    }
  });

  // Multi-product isolation test
  group("Multi-Product Isolation", function () {
    const products = ["novaskyn", "lilitu", "thai"];
    const product = products[Math.floor(Math.random() * products.length)];
    const res = graphqlRequest(QUERIES.introspection, product);
    check(res, {
      "product header accepted": (r) => r.status === 200 || r.status === 503,
    });
  });

  // Small sleep to simulate realistic user behavior
  sleep(0.1 + Math.random() * 0.2);
}

// Setup function (runs once per VU)
export function setup() {
  console.log(`Starting load test against: ${TARGET_URL}`);
  console.log(`GraphQL endpoint: ${GRAPHQL_ENDPOINT}`);

  // Verify target is reachable
  const healthCheck = http.get(`${TARGET_URL}/health`);
  if (healthCheck.status !== 200) {
    console.error(`Health check failed: ${healthCheck.status}`);
  }

  return { startTime: Date.now() };
}

// Teardown function (runs once at end)
export function teardown(data) {
  const duration = (Date.now() - data.startTime) / 1000;
  console.log(`Load test completed in ${duration.toFixed(1)}s`);
}

// Summary handler for custom output
export function handleSummary(data) {
  const summary = {
    timestamp: new Date().toISOString(),
    duration_s: data.root_group.checks[0]
      ? data.metrics.iteration_duration.values.med / 1000
      : 0,
    http_reqs: data.metrics.http_reqs.values.count,
    http_req_failed_rate: data.metrics.http_req_failed.values.rate,
    http_req_duration_p95:
      data.metrics.http_req_duration.values["p(95)"] || "N/A",
    http_req_duration_p99:
      data.metrics.http_req_duration.values["p(99)"] || "N/A",
    graphql_error_rate: data.metrics.graphql_errors
      ? data.metrics.graphql_errors.values.rate
      : 0,
    load_shedding_rejections: data.metrics.load_shedding_rejections
      ? data.metrics.load_shedding_rejections.values.count
      : 0,
    circuit_breaker_rejections: data.metrics.circuit_breaker_rejections
      ? data.metrics.circuit_breaker_rejections.values.count
      : 0,
  };

  return {
    stdout: JSON.stringify(summary, null, 2) + "\n",
    "load-test-results.json": JSON.stringify(summary, null, 2),
  };
}
