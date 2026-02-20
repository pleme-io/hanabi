# Hanabi Load Tests

k6-based load testing suite for the Hanabi BFF server.

## Prerequisites

Install k6:
```bash
# macOS
brew install k6

# Linux
sudo gpg -k
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6
```

## Test Scripts

| Script | Purpose |
|--------|---------|
| `smoke-test.js` | Quick validation that Hanabi is healthy |
| `graphql-load-test.js` | Full load test with ramping users |

## Quick Start

```bash
# Start Hanabi locally
cargo run

# Run smoke test (in another terminal)
k6 run load-tests/smoke-test.js

# Run load test
k6 run load-tests/graphql-load-test.js
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `TARGET_URL` | `http://localhost:8080` | Base URL of Hanabi |
| `VUS` | varies by test | Virtual users |
| `DURATION` | varies by test | Test duration |

## Examples

```bash
# Test against staging
k6 run --env TARGET_URL=https://staging.example.com \
  load-tests/graphql-load-test.js

# Quick test with 10 users for 30s
k6 run --vus 10 --duration 30s load-tests/graphql-load-test.js

# Stress test with 200 users
k6 run --vus 200 --duration 60s load-tests/graphql-load-test.js
```

## Metrics

The load tests track:
- `http_req_duration`: HTTP request latency
- `response_time`: GraphQL response time
- `graphql_errors`: Rate of GraphQL errors
- `load_shedding_rejections`: 503 responses (load shedding active)
- `circuit_breaker_rejections`: 502/504 responses (circuit breaker open)

## Thresholds

Default pass criteria:
- p95 response time < 500ms
- p99 response time < 1000ms
- GraphQL error rate < 1%
- HTTP failure rate < 5%

## Output

Results are written to `load-test-results.json` after each run.

## CI Integration

Add to GitHub Actions:
```yaml
- name: Run load tests
  run: |
    k6 run --out json=results.json load-tests/smoke-test.js
    k6 run --vus 20 --duration 30s load-tests/graphql-load-test.js
```
