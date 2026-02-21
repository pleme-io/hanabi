# Hanabi (花火)

GraphQL Federation BFF (Backend-for-Frontend) platform service built in Rust with Axum.

Hanabi sits between your frontend and backend microservices, providing a unified GraphQL endpoint with built-in federation, authentication, rate limiting, and real-time subscriptions.

## Features

- **GraphQL Federation** - Built-in query planner (Hive Router compatible) with automatic subgraph discovery and query deduplication
- **BFF Pattern** - Proxies GraphQL traffic to backend services with response caching, request coalescing, and load shedding
- **Multi-Product Support** - Single deployment serves multiple products via `X-Product` header routing
- **OAuth Integration** - Google and Instagram OAuth flows with PKCE, token encryption (AES-256-GCM), and session management
- **WebSocket Proxy** - Transparent WebSocket forwarding for GraphQL subscriptions with automatic reconnection
- **Rate Limiting** - Per-product, per-operation rate limiting with JWT-based exemptions and adaptive load shedding
- **Webhook Processing** - Stripe and Meta webhook verification (HMAC signatures) and routing
- **Image Proxy** - Authenticated S3/MinIO image proxy with on-the-fly transformations
- **Federation Cache** - In-memory response cache (Moka) with NATS-based cross-pod invalidation
- **Security Headers** - Configurable CSP, CORS, HSTS, and permissions policies
- **Health Checks** - Liveness/readiness probes with dependency health aggregation
- **Observability** - Structured logging, Prometheus metrics, optional OpenTelemetry tracing, and Discord/Grafana startup notifications
- **Static File Serving** - Serves SPA frontend builds with Brotli/gzip compression and cache headers
- **Geolocation** - Request geolocation via configurable provider

## Quick Start

```bash
# Build
cargo build

# Run with default config
cargo run

# Run with custom config
CONFIG_PATH=config/example.yaml cargo run

# Run with jemalloc (recommended for production)
cargo build --release --features jemalloc
```

## Configuration

Hanabi is configured via YAML files. See [`config/README.md`](config/README.md) for the full reference.

```bash
cp config/example.yaml config/local.yaml
# Edit config/local.yaml with your values
```

Key environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_PATH` | Path to config YAML | `/etc/hanabi/config.yaml` |
| `RUST_LOG` | Log level filter | `info,hanabi=debug` |
| `LOG_FORMAT` | Log format (`json` or `pretty`) | `json` |
| `BFF_PRODUCT` | Product identifier | `default` |
| `REDIS_URL` | Redis connection URL | _(optional)_ |
| `NATS_URL` | NATS connection URL | _(optional)_ |

## Building with Nix

```bash
# Regenerate Cargo.nix after dependency changes
nix run .#regen

# Build the binary (Linux only - Docker images target Linux)
nix build .#hanabi

# Build the Docker image
nix build .#hanabi-image
```

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────┐
│   Browser    │────▶│              Hanabi BFF                  │
│  (Frontend)  │◀────│                                         │
└─────────────┘     │  ┌─────────┐  ┌──────────┐  ┌────────┐ │
                    │  │  Auth    │  │ Rate     │  │ Cache  │ │
                    │  │  (OAuth) │  │ Limiter  │  │ (Moka) │ │
                    │  └─────────┘  └──────────┘  └────────┘ │
                    │                                         │
                    │  ┌──────────────────────────────────┐   │
                    │  │    Federation Query Planner       │   │
                    │  │    (Hive Router compatible)       │   │
                    │  └──────────┬───────────┬───────────┘   │
                    └─────────────┼───────────┼───────────────┘
                                  │           │
                    ┌─────────────▼──┐  ┌─────▼──────────┐
                    │   Subgraph A   │  │   Subgraph B   │  ...
                    │  (e.g., users) │  │ (e.g., catalog)│
                    └────────────────┘  └────────────────┘
```

## Load Testing

k6-based load tests are in [`load-tests/`](load-tests/README.md):

```bash
k6 run load-tests/smoke-test.js
k6 run load-tests/graphql-load-test.js
```

## License

[MIT](LICENSE)
