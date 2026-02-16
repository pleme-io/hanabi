/**
 * Hanabi BFF Smoke Test
 *
 * Quick validation that Hanabi is responding correctly.
 * Run this before full load tests to verify the target is healthy.
 *
 * Usage:
 *   k6 run load-tests/smoke-test.js
 *   k6 run --env TARGET_URL=https://staging.example.com load-tests/smoke-test.js
 */

import http from "k6/http";
import { check, fail } from "k6";

export const options = {
  vus: 1,
  iterations: 1,
  thresholds: {
    checks: ["rate==1"], // All checks must pass
    http_req_failed: ["rate==0"], // No HTTP failures
    http_req_duration: ["p(95)<2000"], // Response under 2s
  },
};

const TARGET_URL = __ENV.TARGET_URL || "http://localhost:8080";

export default function () {
  // Test 1: Health endpoint
  const healthRes = http.get(`${TARGET_URL}/health`);
  const healthCheck = check(healthRes, {
    "health endpoint returns 200": (r) => r.status === 200,
    "health response is OK": (r) =>
      r.body && r.body.toLowerCase().includes("ok"),
  });
  if (!healthCheck) {
    fail("Health check failed - is Hanabi running?");
  }

  // Test 2: GraphQL introspection
  const graphqlRes = http.post(
    `${TARGET_URL}/graphql`,
    JSON.stringify({
      query: "{ __typename }",
      operationName: "Introspection",
    }),
    {
      headers: {
        "Content-Type": "application/json",
        "X-Product": "novaskyn",
      },
    }
  );
  check(graphqlRes, {
    "graphql endpoint returns 200": (r) => r.status === 200,
    "graphql response is valid": (r) => {
      try {
        const body = JSON.parse(r.body);
        return body.data && !body.errors;
      } catch {
        return false;
      }
    },
  });

  // Test 3: Multi-product support
  const products = ["novaskyn", "lilitu", "thai"];
  for (const product of products) {
    const res = http.post(
      `${TARGET_URL}/graphql`,
      JSON.stringify({
        query: "{ __typename }",
      }),
      {
        headers: {
          "Content-Type": "application/json",
          "X-Product": product,
        },
      }
    );
    check(res, {
      [`product ${product} accepted`]: (r) => r.status === 200,
    });
  }

  console.log("Smoke test passed - Hanabi is healthy!");
}
