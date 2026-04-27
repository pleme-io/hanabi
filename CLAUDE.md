# Hanabi

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.

GraphQL Federation BFF (Backend-for-Frontend) platform service built in Rust with Axum. Hanabi sits between frontend applications and backend microservices, providing a unified GraphQL endpoint with built-in federation query planning, OAuth authentication, session management, rate limiting, WebSocket subscriptions, webhook processing, and static file serving. A single Hanabi deployment can serve multiple products via `X-Product` header routing.
