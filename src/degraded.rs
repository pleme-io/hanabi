//! Degraded-mode server — resilience by default.
//!
//! When startup fails (config load, S3 webapp fetch, preflight checks, or the
//! server build/run panicking), hanabi MUST NOT exit and CrashLoop invisibly.
//! Instead it binds its configured HTTP + health ports and serves an
//! **explicit** error — so the failure reason is visible in a browser, in a
//! `curl`, and in the readiness probe — rather than forcing an operator to go
//! dig through pod logs.
//!
//! Contract:
//! - HTTP port: every path → `503 Service Unavailable` + an on-brand HTML page
//!   stating the exact reason (service, version, the failure message).
//! - Health port:
//!     - `GET /health/live`    → `200` (the process IS alive — do not kill it).
//!     - `GET /health/ready`   → `503` + reason (stay NotReady; no traffic, but
//!       the pod stays `Running`, never CrashLoopBackOff).
//!     - `GET /health/startup` → `503` + reason.
//!     - `GET /metrics`        → `hanabi_degraded{...} 1` so the scrape's
//!       `up == 1` and a typed gauge flags the degraded state on the dashboards.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use tracing::error;

use crate::config::AppConfig;

#[derive(Clone)]
struct DegradedState {
    reason: Arc<str>,
    service: Arc<str>,
    version: Arc<str>,
}

/// Bind the configured ports and serve an explicit degraded-mode response
/// instead of exiting. Returns only when the process is shut down.
pub async fn run_degraded(
    config: &AppConfig,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    error!(
        "hanabi entering DEGRADED mode (binding ports to serve an explicit error \
         instead of crashing): {reason}"
    );

    let st = DegradedState {
        reason: Arc::from(reason.as_str()),
        service: Arc::from(config.server.service_name.as_str()),
        version: Arc::from(env!("CARGO_PKG_VERSION")),
    };

    // App port: every request (any method, any path) → the explicit 503 page.
    let app_router: Router = Router::new()
        .fallback(error_page)
        .with_state(st.clone());

    // Health port: live=200, ready/startup=503+reason, metrics flag the state.
    let health_router: Router = Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(not_ready))
        .route("/health/startup", get(not_ready))
        .route("/health", get(not_ready))
        .route("/metrics", get(metrics))
        .with_state(st);

    crate::server::run_server(config, app_router, health_router).await
}

async fn error_page(State(st): State<DegradedState>) -> Response {
    // `Html` sets `content-type: text/html; charset=utf-8`.
    (StatusCode::SERVICE_UNAVAILABLE, Html(render_page(&st))).into_response()
}

async fn live() -> StatusCode {
    StatusCode::OK
}

async fn not_ready(State(st): State<DegradedState>) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        format!("degraded: {}", st.reason),
    )
        .into_response()
}

async fn metrics(State(st): State<DegradedState>) -> Response {
    // Minimal Prometheus exposition so the scrape's `up == 1` AND a typed gauge
    // makes the degraded state queryable (hanabi_degraded == 1 ⇒ misconfigured).
    let body = format!(
        "# HELP hanabi_degraded Whether hanabi is running in degraded \
         (startup-failed) mode.\n\
         # TYPE hanabi_degraded gauge\n\
         hanabi_degraded{{service=\"{}\",version=\"{}\"}} 1\n",
        st.service, st.version
    );
    // `String` sets `content-type: text/plain; charset=utf-8` (Prometheus-parseable).
    (StatusCode::OK, body).into_response()
}

/// An explicit, on-brand (bold-black / metallic / dark-depth) degraded page.
/// Self-contained: no external requests. States the exact failure reason.
///
/// Built from a raw-string template (literal CSS braces, no `format!` escaping)
/// with sentinel substitution — robust against brace-escaping mistakes.
fn render_page(st: &DegradedState) -> String {
    // HTML-escape the operator-facing diagnostic text.
    let reason = st
        .reason
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    const TEMPLATE: &str = r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="color-scheme" content="dark"/>
<title>__SERVICE__ — service unavailable</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;display:flex;align-items:center;justify-content:center;
background:radial-gradient(120% 90% at 50% 32%,#16181F 0%,#101117 45%,#0A0A0B 100%);
color:#ECEFF4;font-family:'JetBrains Mono','SF Mono',Menlo,Consolas,monospace;padding:24px}
.card{width:100%;max-width:680px;background:linear-gradient(180deg,rgba(154,163,178,.06) 0%,#16181F 8%,#101117 100%);
border:1px solid #2E3440;border-radius:14px;
box-shadow:inset 0 1px 0 rgba(200,205,216,.10),0 16px 48px -8px rgba(0,0,0,.6);padding:40px}
.eyebrow{font-size:.72rem;letter-spacing:.32em;text-transform:uppercase;color:#81A1C1;margin-bottom:14px}
h1{font-size:1.6rem;font-weight:600;letter-spacing:-.01em;margin-bottom:8px;
background:linear-gradient(180deg,#F5F5F0,#9AA3B2);-webkit-background-clip:text;background-clip:text;color:transparent}
.sub{color:#D8DEE9;font-size:.95rem;line-height:1.5;margin-bottom:22px}
.label{font-size:.68rem;letter-spacing:.18em;text-transform:uppercase;color:#4C566A;margin:0 0 8px}
pre{background:#0A0A0B;border:1px solid #3B4252;border-radius:8px;padding:16px 18px;
color:#88C0D0;font-size:.86rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;overflow:auto}
.foot{margin-top:22px;font-size:.7rem;letter-spacing:.12em;color:#4C566A}
.dot{display:inline-block;width:7px;height:7px;border-radius:999px;background:#EBCB8B;
box-shadow:0 0 10px 1px rgba(235,203,139,.6);margin-right:8px;vertical-align:middle}
</style></head><body><main class="card">
<p class="eyebrow"><span class="dot"></span>__SERVICE__ · degraded</p>
<h1>Service temporarily unavailable</h1>
<p class="sub">hanabi started but could not enter service. It is holding its ports
open and reporting the reason explicitly instead of restarting. No data is being
served until this is resolved.</p>
<p class="label">Startup failure reason</p>
<pre>__REASON__</pre>
<p class="foot">hanabi __VERSION__ · pleme-io</p>
</main></body></html>"#;
    TEMPLATE
        .replace("__SERVICE__", &st.service)
        .replace("__VERSION__", &st.version)
        .replace("__REASON__", &reason)
}
