# Hanabi (花火)

GraphQL Federation BFF (Backend-for-Frontend) platform service built in Rust with Axum. Hanabi sits between frontend applications and backend microservices, providing a unified GraphQL endpoint with built-in federation query planning, OAuth authentication, session management, rate limiting, WebSocket subscriptions, webhook processing, and static file serving. A single Hanabi deployment can serve multiple products via `X-Product` header routing.

## Architecture

```
                         ┌────────────────────────────────────────────────────────┐
                         │                     Hanabi BFF                         │
┌───────────┐            │                                                        │
│  Browser  │─── HTTP ──▶│  ┌──────────┐  ┌───────────┐  ┌──────────┐           │
│  (SPA)    │◀───────────│  │ Security │  │   Rate    │  │  Session │           │
└───────────┘            │  │ Headers  │  │  Limiter  │  │  Auth    │           │
                         │  │ CSP/CORS │  │ (Governor)│  │ (Redis)  │           │
      │                  │  └──────────┘  └───────────┘  └──────────┘           │
      │                  │                                                        │
      │  WebSocket       │  ┌────────────────────────────────────────────┐       │
      └──────────────────│  │        Federation Query Planner            │       │
                         │  │  (Hive Router compatible, APQ, dedup)      │       │
                         │  └──────────┬──────────┬──────────┬──────────┘       │
                         │             │          │          │                    │
                         │  ┌──────────▼──┐  ┌────▼────┐  ┌─▼──────────────┐   │
                         │  │  L1 Cache   │  │  L2     │  │  Plan Executor │   │
                         │  │  (Moka)     │  │ (Redis) │  │  (parallel)    │   │
                         │  └─────────────┘  └─────────┘  └────────────────┘   │
                         │                                                        │
                         │  ┌──────────┐  ┌────────────┐  ┌─────────────────┐   │
                         │  │ Webhooks │  │  Image     │  │  Static Files   │   │
                         │  │ Stripe   │  │  Proxy     │  │  (SPA + Brotli) │   │
                         │  │ Meta     │  │  (S3)      │  │                 │   │
                         │  └──────────┘  └────────────┘  └─────────────────┘   │
                         └──────────────┬──────────┬──────────┬─────────────────┘
                                        │          │          │
                         ┌──────────────▼──┐ ┌─────▼────┐ ┌──▼─────────────┐
                         │   Subgraph A    │ │ Subgraph │ │   Subgraph C   │
                         │   (e.g. users)  │ │    B     │ │   (e.g. chat)  │
                         └─────────────────┘ └──────────┘ └────────────────┘
```

### Federation Execution Pipeline

Every GraphQL request flows through a multi-stage pipeline:

1. **Rate Limiter** -- per-user, per-operation, per-subgraph limits (Governor + tower)
2. **Plugin Pre-Exec** -- tracing and metrics hooks
3. **APQ Lookup** -- resolve persisted query hash to full query text
4. **Security** -- depth/complexity validation
5. **Deduplication** -- coalesce concurrent identical queries
6. **Cache Check** -- L1 (Moka in-memory) then L2 (Redis) lookup
7. **Query Planner** -- create execution plan (Hive Router compatible, cached)
8. **Plan Executor** -- execute against subgraphs in parallel
9. **Response Merge** -- combine subgraph responses, entity resolution

### Dual-Port Server

Hanabi runs two TCP listeners:

- **Port 80** (configurable) -- HTTP application server (GraphQL, OAuth, static files, webhooks)
- **Port 8080** (configurable) -- Health probes (`/health/startup`, `/health/live`, `/health/ready`) and Prometheus metrics (`/metrics`)

## Features

- **GraphQL Federation** -- built-in query planner (Hive Router compatible) with automatic subgraph discovery, query deduplication, and automatic persisted queries (APQ)
- **BFF Pattern** -- proxies GraphQL traffic to backend services with response caching, request coalescing, and adaptive load shedding
- **Multi-Product Support** -- single deployment serves multiple products via `X-Product` header routing
- **Composable Builder API** -- `ServerBuilder` lets products register OAuth providers, webhook handlers, route extensions, and custom middleware without forking
- **OAuth Integration** -- Google and Instagram OAuth flows with PKCE, token encryption (AES-256-GCM), and Redis session management
- **WebSocket Proxy** -- transparent WebSocket forwarding for GraphQL subscriptions with connection pooling and automatic reconnection
- **Rate Limiting** -- per-product, per-operation rate limiting with JWT-based exemptions and adaptive load shedding
- **Webhook Processing** -- Stripe and Meta webhook verification (HMAC signatures) and routing
- **Image Proxy** -- authenticated S3/MinIO image proxy with per-product bucket routing
- **Federation Cache** -- two-tier cache (Moka L1 + Redis L2) with NATS-based cross-pod invalidation
- **Security Headers** -- configurable CSP, CORS, HSTS, X-Frame-Options, Referrer-Policy, and Permissions-Policy
- **Health Checks** -- liveness, readiness, and startup probes with dependency health aggregation (disk, memory, Redis, NATS)
- **Observability** -- structured JSON logging, Prometheus metrics, optional OpenTelemetry tracing (OTLP), and Discord/Grafana startup notifications
- **Static File Serving** -- serves SPA frontend builds from S3 (downloaded at startup) or local directory with Brotli/gzip compression
- **Geolocation** -- request geolocation via configurable provider
- **jemalloc** -- optional jemalloc allocator for improved multi-threaded allocation performance
- **Nix-native builds** -- reproducible Docker images via substrate's `buildRustService` pattern

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

# Run tests
cargo test
```

## Configuration

Hanabi is configured via YAML files. See [`config/README.md`](config/README.md) for the full reference.

```bash
cp config/example.yaml config/local.yaml
# Edit config/local.yaml with your values
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CONFIG_PATH` | Path to config YAML | `/etc/hanabi/config.yaml` |
| `RUST_LOG` | Log level filter | `info,hanabi=debug` |
| `LOG_FORMAT` | Log format (`json` or `pretty`) | `json` |
| `BFF_PRODUCT` | Product identifier | `default` |
| `REDIS_URL` | Redis connection URL | _(optional)_ |
| `NATS_URL` | NATS connection URL | _(optional)_ |
| `HMAC_SECRET` | HMAC secret for supergraph admin API | _(optional)_ |

### Configuration Sections

| Section | Purpose |
|---------|---------|
| `security` | CSP, CORS, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy |
| `api` | GraphQL and WebSocket endpoint paths |
| `bff` | BFF mode, federation settings, cache, rate limiting, session, webhooks, WebSocket tuning |
| `server` | Ports, bind address, timeouts, static directory, worker threads |
| `compression` | Brotli/gzip settings |
| `cache` | Static asset and HTML cache-control headers |
| `health` | Disk and memory warning/critical thresholds |
| `metrics` | StatsD/Vector host, port, prefix |
| `logging` | Format, level, module-level overrides |
| `features` | Feature flags (bug reports, metrics, health checks, BFF) |

### Kubernetes Deployment

Mount configuration via ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: hanabi-config
data:
  config.yaml: |
    environment: production
    bff:
      federation:
        enabled: true
        supergraph_url: file:///etc/supergraph.graphql
    server:
      http_port: 80
      health_port: 8080
```

## Building with Nix

```bash
# Regenerate Cargo.nix after dependency changes
nix run .#regen

# Build the binary
nix build .#hanabi

# Build Docker images (multi-arch: amd64 + arm64)
nix build .#hanabi-image

# Push to registry
nix run .#release
```

The flake uses substrate's `rust-service-flake.nix` pattern for reproducible multi-architecture Docker images published to `ghcr.io/pleme-io/hanabi`.

## Composable Server Builder

Products extend Hanabi without forking by using the `ServerBuilder` API:

```rust
use hanabi::builder::ServerBuilder;
use hanabi::config::AppConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load()?;
    let server = ServerBuilder::new(config)
        .with_oauth(MyOAuthProvider::new())
        .with_webhook(MyWebhookHandler::new())
        .with_routes(my_custom_routes())
        .disable_middleware(CoreMiddleware::SpaFallback)
        .build()
        .await;
    server.run().await
}
```

Extension points:

- **OAuthProvider** trait -- register custom OAuth flows (routes + callbacks)
- **WebhookHandler** trait -- register webhook verification and handling
- **RouteExtension** trait -- add arbitrary Axum routes
- **MiddlewareCustomization** -- disable core middleware, inject custom layers at Outermost/BeforeRouteHandling/Innermost slots

## Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `jemalloc` | Use jemalloc global allocator | off |
| `otel` | OpenTelemetry distributed tracing (OTLP) | off |
| `google-oauth` | Google OAuth provider routes | on |
| `instagram-oauth` | Instagram OAuth provider routes | on |
| `stripe-webhooks` | Stripe/PIX webhook routes | on |
| `meta-webhooks` | Meta webhook routes | on |
| `geolocation` | Geolocation endpoint | on |
| `image-proxy` | S3 image proxy endpoint | on |

## Development

```bash
# Build
cargo build

# Run tests (unit + integration)
cargo test

# Run federation-specific tests
cargo test --test query_planning_test
cargo test --test entity_resolution_test
cargo test --test federation_edge_cases_test
cargo test --test schema_validation_test
cargo test --test subscription_routing_test

# Lint
cargo clippy

# Load testing (requires k6)
k6 run load-tests/smoke-test.js
k6 run load-tests/graphql-load-test.js
```

## Project Structure

| Path | Purpose |
|------|---------|
| `src/main.rs` | Binary entry point, tokio runtime setup |
| `src/lib.rs` | Library root, public module re-exports |
| `src/builder.rs` | `ServerBuilder` for composable BFF assembly |
| `src/server.rs` | Server lifecycle (listener binding, dual-port, graceful shutdown) |
| `src/router.rs` | Router construction, middleware stack, route registration |
| `src/state.rs` | `AppState` shared across all handlers |
| `src/config/` | YAML config parsing and validation |
| `src/federation/` | GraphQL federation (query planner, executor, cache, dedup, APQ, subscriptions) |
| `src/auth/` | OAuth flows (Google, Instagram), session management, middleware |
| `src/bff.rs` | GraphQL proxy handler, supergraph admin endpoints |
| `src/rate_limiting/` | Per-operation rate limiting with JWT exemptions |
| `src/webhooks/` | Stripe and Meta webhook handlers |
| `src/health.rs` | Liveness, readiness, startup probes |
| `src/health_aggregator.rs` | Dependency health aggregation |
| `src/images.rs` | Authenticated S3 image proxy |
| `src/handlers.rs` | Bug reports, telemetry, upload proxy, SPA fallback |
| `src/middleware.rs` | CORS, security headers, cache-control, request metrics |
| `src/metrics.rs` | StatsD metrics emission |
| `src/prometheus.rs` | Prometheus metrics rendering |
| `src/redis.rs` | Redis connection management |
| `src/memory/` | Memory monitoring and resource optimization |
| `src/telemetry/` | OpenTelemetry setup |
| `src/providers/` | Pluggable provider implementations |
| `src/traits.rs` | Extension traits (OAuthProvider, WebhookHandler, RouteExtension) |
| `config/` | Example YAML config and config documentation |
| `tests/` | Integration tests (federation, entity resolution, schema validation) |
| `load-tests/` | k6 load test scripts |
| `module/` | Nix home-manager and NixOS modules |
| `nix/` | Nix build support files |

## Related Projects

- [substrate](https://github.com/pleme-io/substrate) -- Nix build patterns (`rust-service-flake.nix`, `buildRustService`)
- [forge](https://github.com/pleme-io/forge) -- CI/CD build platform (Attic cache, GHCR push)
- [k8s](https://github.com/pleme-io/k8s) -- GitOps manifests (FluxCD reconciles Hanabi deployments)
- [nexus](https://github.com/pleme-io/nexus) -- Product monorepo that consumes Hanabi as its BFF
- [libraries](https://github.com/pleme-io/libraries) -- Shared platform libraries (pleme-notifications)

## License

[MIT](LICENSE)
