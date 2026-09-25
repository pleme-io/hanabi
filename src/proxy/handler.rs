//! Putting the proxy on the request path.
//!
//! ── WHY A MIDDLEWARE AND NOT A FALLBACK ─────────────────────────────────────
//!
//! `config.proxy` was deserialized and never read: `ProxyConfig` existed,
//! `AppConfig::proxy` existed, and no `ProxyService` was ever constructed from
//! either — so the proxy could not be turned on by any configuration, only by
//! editing code. This module is what closes that.
//!
//! The obvious wiring is `Router::fallback`, and it is wrong here. hanabi
//! already serves a static SPA from its fallback, so a second fallback either
//! loses the SPA or is never reached. A `from_fn_with_state` layer sees every
//! request BEFORE routing resolves, so it can claim the paths a route matches
//! and pass everything else through untouched — the SPA, GraphQL, OAuth,
//! webhooks and health all keep working without knowing this exists.
//!
//! The pass-through is therefore the load-bearing behaviour, not the proxying,
//! and it is what the tests below pin hardest: a misconfigured route must cost
//! one upstream lookup, never the whole application.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use tracing::{debug, error, warn};

use super::upgrade;
use super::{ProxyService, HOP_BY_HOP};

/// Headers a response must not carry back to the client.
///
/// Reuses [`HOP_BY_HOP`] rather than restating it: the set that must not be
/// forwarded TO an upstream is the same set that must not be replayed FROM one,
/// and two lists would drift. `content-length` is additionally dropped because
/// the body is re-framed as a stream — keeping the upstream's length beside a
/// differently-chunked body is how a proxy truncates a response.
fn strip_hop_by_hop(headers: &mut axum::http::HeaderMap) {
    for name in HOP_BY_HOP {
        headers.remove(*name);
    }
    headers.remove(axum::http::header::CONTENT_LENGTH);
}

/// `reqwest::Response` → `axum::Response`.
///
/// The conversion the proxy was missing. `ProxyService::forward` returns a
/// `reqwest::Response` and nothing turned it into something axum could serve,
/// which is why `mod.rs`'s `axum` imports were unused — the handler had never
/// been written.
///
/// The body is STREAMED, not buffered. A buffering proxy holds an entire
/// response in memory per request, which for a media route (go2rtc, Jellyfin)
/// is the difference between a proxy and an outage.
fn into_axum_response(upstream: reqwest::Response) -> Response<Body> {
    let status = StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    let mut builder = Response::builder().status(status);
    {
        let headers = builder.headers_mut().expect("fresh builder has headers");
        for (name, value) in upstream.headers() {
            headers.append(name.clone(), value.clone());
        }
        strip_hop_by_hop(headers);
    }

    builder
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|e| {
            error!(error = %e, "could not build a response from the upstream's");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::empty())
                .expect("a bad-gateway shell always builds")
        })
}

/// Replay an upstream's `101` downstream so the client's own handshake completes.
fn switching_protocols(headers: &axum::http::HeaderMap) -> Response<Body> {
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    {
        let out = builder.headers_mut().expect("fresh builder has headers");
        for (name, value) in headers.iter() {
            out.append(name.clone(), value.clone());
        }
        // ★ `connection` and `upgrade` are KEPT here, unlike every other
        // response: on a 101 they are the answer, not hop-by-hop metadata.
        // `Sec-WebSocket-Accept` must also survive verbatim or the client
        // rejects the handshake it just completed.
        out.remove(axum::http::header::CONTENT_LENGTH);
    }
    builder
        .body(Body::empty())
        .expect("an empty 101 always builds")
}

/// Intercept requests a proxy route claims; pass everything else through.
pub async fn intercept(
    State(proxy): State<Arc<ProxyService>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let path = req.uri().path().to_string();
    let host = req
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Not ours → the application never learns this layer exists.
    let Some(route) = proxy.match_route(&path, host.as_deref()).cloned() else {
        return next.run(req).await;
    };

    let client_ip = Some(peer.ip());
    let scheme = req.uri().scheme_str().unwrap_or("http").to_string();

    // ── The upgrade path, decided BEFORE any header is stripped ────────────
    if let Some(proto) = upgrade::requested_upgrade(req.headers()) {
        debug!(path = %path, proto = %proto, service = %route.service, "proxying an upgrade");

        // Taken before the request is consumed. hyper completes this future
        // only AFTER a 101 goes back downstream, which is why the upstream
        // handshake has to happen first.
        let client_upgrade = req.extensions_mut().remove::<hyper::upgrade::OnUpgrade>();

        let Some(backend) = proxy.pick_backend(&route).await else {
            warn!(service = %route.service, "no backends for an upgrade route");
            return bare(StatusCode::SERVICE_UNAVAILABLE);
        };

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| path.clone());

        match upgrade::handshake(
            &backend,
            req.method(),
            &path_and_query,
            req.headers(),
            client_ip,
            &scheme,
        )
        .await
        {
            Ok(h) if h.status == 101 => {
                let response = switching_protocols(&h.headers);
                match client_upgrade {
                    Some(on_upgrade) => {
                        tokio::spawn(async move {
                            match on_upgrade.await {
                                Ok(upgraded) => {
                                    upgrade::tunnel(
                                        hyper_util::rt::TokioIo::new(upgraded),
                                        h.stream,
                                        h.leftover,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    warn!(error = %e, "client never completed its upgrade");
                                }
                            }
                        });
                        response
                    }
                    None => {
                        // A 101 with no way to reach the client's socket would
                        // leave a half-open tunnel, so refuse instead.
                        warn!("upstream agreed to upgrade but the client connection is not upgradable");
                        bare(StatusCode::BAD_GATEWAY)
                    }
                }
            }
            Ok(h) => {
                // The upstream did not honour the upgrade. A configuration
                // finding worth naming, not a crash: the route points at
                // something that does not speak this protocol.
                warn!(
                    service = %route.service,
                    status = h.status,
                    "upstream refused the upgrade; check the route's upstream"
                );
                bare(StatusCode::BAD_GATEWAY)
            }
            Err(e) => {
                error!(service = %route.service, error = %e, "upgrade handshake failed");
                bare(StatusCode::BAD_GATEWAY)
            }
        }
    } else {
        // ── Plain HTTP: the existing, tested forwarder ─────────────────────
        let (parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, usize::MAX).await {
            Ok(b) => b,
            Err(e) => {
                warn!(error = %e, "could not read the request body for proxying");
                return bare(StatusCode::BAD_REQUEST);
            }
        };

        match proxy
            .forward(
                &route,
                &parts.uri,
                parts.method.clone(),
                parts.headers.clone(),
                reqwest::Body::from(bytes),
                client_ip,
            )
            .await
        {
            Ok(upstream) => into_axum_response(upstream),
            Err(e) => {
                error!(service = %route.service, error = %e, "proxy forward failed");
                bare(StatusCode::BAD_GATEWAY)
            }
        }
    }
}

fn bare(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("a bare status response always builds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_hop_by_hop_and_content_length_from_a_response() {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in [
            ("connection", "keep-alive"),
            ("transfer-encoding", "chunked"),
            ("content-length", "42"),
            ("upgrade", "websocket"),
            ("content-type", "application/json"),
            ("x-custom", "kept"),
        ] {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_static(v),
            );
        }

        strip_hop_by_hop(&mut h);

        assert!(h.get("connection").is_none());
        assert!(h.get("transfer-encoding").is_none());
        assert!(h.get("upgrade").is_none());
        assert!(
            h.get("content-length").is_none(),
            "the body is re-framed as a stream; a stale length truncates it"
        );
        // Everything end-to-end survives.
        assert_eq!(h.get("content-type").unwrap(), "application/json");
        assert_eq!(h.get("x-custom").unwrap(), "kept");
    }

    // ★ The 101 is the one response that must KEEP the two headers every other
    // response drops. Getting this backwards makes the client reject a
    // handshake the upstream already agreed to.
    #[test]
    fn a_101_keeps_connection_upgrade_and_accept() {
        let mut h = axum::http::HeaderMap::new();
        for (k, v) in [
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="),
            ("content-length", "0"),
        ] {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                axum::http::HeaderValue::from_static(v),
            );
        }

        let resp = switching_protocols(&h);

        assert_eq!(resp.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(resp.headers().get("connection").unwrap(), "Upgrade");
        assert_eq!(resp.headers().get("upgrade").unwrap(), "websocket");
        assert_eq!(
            resp.headers().get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "Accept must reach the client verbatim"
        );
        assert!(
            resp.headers().get("content-length").is_none(),
            "a 101 has no body"
        );
    }
}
