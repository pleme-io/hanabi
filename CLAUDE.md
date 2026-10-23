# Hanabi

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.

GraphQL Federation BFF (Backend-for-Frontend) platform service built in Rust with Axum. Hanabi sits between frontend applications and backend microservices, providing a unified GraphQL endpoint with built-in federation query planning, OAuth authentication, session management, rate limiting, WebSocket subscriptions, webhook processing, and static file serving. A single Hanabi deployment can serve multiple products via `X-Product` header routing.

## Embedded blue (FRONTEND-PLAN F7)

hanabi runs blue through `blue-lang-host` (`src/blue.rs`). The package is
`blue/hanabi/hanabi.b` (Bluefile + `Bluefile.lock`, from `blue lock blue/hanabi`).
Each surface is a typed setting under `blue:` in the YAML, default off; the YAML
reader stays the default and is never removed.

| Setting | Default | Effect when on |
|---|---|---|
| `blue.config.enabled` + `blue.config.source` | off | `AppConfig` comes from the `.b` file's `declaration()`, settled by `hanabi::settle` (kousei entries, one per section; a bad entry is refused alone and logged, its siblings stand). The YAML still supplies `blue:` itself. |
| `blue.persisted_ops.enabled` + `blue.persisted_ops.source` | off | the `.b` file's `operations()` (`hanabi::persisted({hash => operation})`) is the APQ table: a known hash is served from it, an unknown hash is refused (`PERSISTED_QUERY_NOT_REGISTERED`), a hash that is not the sha256 of its text is refused at load. A table that fails to load refuses every hash. Only consulted when federation APQ is on; requests without a `persistedQuery` extension are not affected. |

`config/example.b` and `config/spa-popup-auth.b` are the blue spellings of the two
YAML fixtures; `tests/blue_config_test.rs` proves each pair yields the same
`AppConfig`. A `.b` file must be canonical (`blue fmt --write`). Six keys in
`example.yaml` were never read by serde (`bff.timeout_secs`, `bff.rate_limit`,
`bff.federation.{hmac_secret, subgraph_timeout_secs, websocket_enabled,
websocket_path}`); the blue schema refuses them. Not built yet: hot reload of
either surface (no config reload path exists), the remaining F7 surfaces.
