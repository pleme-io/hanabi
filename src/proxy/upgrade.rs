//! Carrying an HTTP `Upgrade` (WebSocket) through the proxy.
//!
//! ── WHY THIS IS NOT PART OF `forward()` ──────────────────────────────────────
//!
//! `ProxyService::forward` speaks `reqwest`, and reqwest is a *request/response*
//! client: it owns the connection, reads the body, and gives the body back as a
//! stream. There is no way to reach the raw socket afterwards, so a `101
//! Switching Protocols` handshake completes and the tunnel that should follow it
//! has nowhere to live. That is the whole reason a websocket route through this
//! proxy used to connect and then stall — the module header records it, and this
//! file is the answer.
//!
//! The answer is deliberately NOT "replace reqwest with hyper-util everywhere".
//! An upgrade is a byte tunnel after a one-shot handshake, which is precisely
//! what `l4::run_tcp_proxy` already does — so this carries the handshake by hand
//! over a `TcpStream` and then runs the same bidirectional copy. Plain HTTP
//! keeps its existing, tested path untouched.
//!
//! ── WHY IT MATTERS HERE ─────────────────────────────────────────────────────
//!
//! Every UI this fleet proxies is websocket-driven: Home Assistant, node-red,
//! esphome, music-assistant and go2rtc all open a socket immediately after the
//! first page load. A proxy that carries HTTP but not upgrades does not serve a
//! *degraded* version of those apps; it serves a page that loads and then hangs,
//! which is harder to diagnose than an outright failure.

use std::net::IpAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::Backend;

/// The largest response head we will read from an upstream before giving up.
///
/// A `101` head is a few hundred bytes. This bound exists so a misbehaving or
/// non-HTTP upstream cannot make us buffer without limit while looking for a
/// terminator that will never arrive.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Does this request ask to leave HTTP behind, and for what?
///
/// ★ Read the `Connection` header as a COMMA-SEPARATED TOKEN LIST, not as a
/// string. Browsers send `Connection: keep-alive, Upgrade`, and Firefox has
/// historically sent `Connection: Upgrade` with different casing than Chrome, so
/// an `eq_ignore_ascii_case("upgrade")` on the whole value misses real clients —
/// it would pass Chrome and silently fail Firefox, which is the worst possible
/// distribution of a bug.
///
/// Returns the `Upgrade` token (e.g. `websocket`) when both headers agree that
/// an upgrade is being requested.
pub fn requested_upgrade(headers: &http::HeaderMap) -> Option<String> {
    let connection = headers.get(http::header::CONNECTION)?.to_str().ok()?;
    let asks_upgrade = connection
        .split(',')
        .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"));
    if !asks_upgrade {
        return None;
    }
    let proto = headers.get(http::header::UPGRADE)?.to_str().ok()?;
    if proto.trim().is_empty() {
        return None;
    }
    Some(proto.trim().to_string())
}

/// An upstream's answer to the handshake, plus anything it had already sent.
pub struct UpstreamHandshake {
    /// The socket, positioned immediately after the response head.
    pub stream: TcpStream,
    /// The status line's code.
    pub status: u16,
    /// The response headers, to be replayed downstream verbatim.
    pub headers: http::HeaderMap,
    /// ★ Bytes that arrived in the SAME read as the head.
    ///
    /// This is the field it is easiest to forget, and forgetting it loses the
    /// first websocket frame roughly whenever the upstream is fast enough to
    /// coalesce its `101` and its first message into one TCP segment — i.e.
    /// intermittently, on a loopback upstream, under load. `tokio::io::copy`
    /// starts from the socket's CURRENT position and knows nothing about what
    /// we already pulled into userspace, so these bytes must be written to the
    /// client before the tunnel starts.
    pub leftover: Vec<u8>,
}

/// Errors carrying an upgrade. Kept separate from [`super::ProxyError`] so the
/// upgrade path's failure modes are nameable — "connect failed" and "upstream
/// refused the upgrade" are different operator actions.
#[derive(Debug)]
pub enum UpgradeError {
    Connect(String),
    Write(String),
    Read(String),
    Malformed(String),
    HeadTooLarge,
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connecting to upstream: {e}"),
            Self::Write(e) => write!(f, "writing handshake to upstream: {e}"),
            Self::Read(e) => write!(f, "reading upstream handshake: {e}"),
            Self::Malformed(e) => write!(f, "upstream sent a malformed response head: {e}"),
            Self::HeadTooLarge => write!(
                f,
                "upstream response head exceeded {MAX_HEAD_BYTES} bytes without a terminator"
            ),
        }
    }
}

impl std::error::Error for UpgradeError {}

/// The headers an upstream should see for an UPGRADE request.
///
/// ★ This is not `ProxyService::prepare_headers`, and the difference is the
/// point. That function strips every hop-by-hop header, including `Connection`
/// and `Upgrade` — which is correct for plain HTTP (RFC 9110 §7.6.1: they
/// describe the client's connection to US) and fatal here, because those two
/// headers ARE the request. Strip them and the upstream answers `200` with a
/// normal body, the client waits for a `101` that never comes, and the page
/// hangs.
///
/// So the upgrade path forwards them deliberately, along with the
/// `Sec-WebSocket-*` set, which is end-to-end: `Sec-WebSocket-Key` must reach
/// the upstream unchanged or its `Sec-WebSocket-Accept` will not validate at the
/// client, and `Sec-WebSocket-Protocol` is the subprotocol the two ends
/// negotiate past us.
///
/// Everything else matches the plain path: `Host` is rewritten to the backend's
/// authority, and the forwarded-for chain is EXTENDED rather than replaced.
fn upgrade_headers(
    inbound: &http::HeaderMap,
    backend: &Backend,
    client_ip: Option<IpAddr>,
    scheme: &str,
) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();

    // Hop-by-hop headers that stay hop-by-hop even on an upgrade. `connection`
    // and `upgrade` are deliberately ABSENT from this list.
    const DROP: &[&str] = &[
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "host",
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-real-ip",
    ];

    for (name, value) in inbound.iter() {
        if DROP.iter().any(|d| name.as_str().eq_ignore_ascii_case(d)) {
            continue;
        }
        out.append(name.clone(), value.clone());
    }

    if let Ok(v) = http::HeaderValue::from_str(&format!("{}:{}", backend.address, backend.port)) {
        out.insert(http::header::HOST, v);
    }

    if let Some(ip) = client_ip {
        let chain = match inbound
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            Some(existing) => format!("{existing}, {ip}"),
            None => ip.to_string(),
        };
        if let Ok(v) = http::HeaderValue::from_str(&chain) {
            out.insert(http::HeaderName::from_static("x-forwarded-for"), v);
        }
        if let Ok(v) = http::HeaderValue::from_str(&ip.to_string()) {
            out.insert(http::HeaderName::from_static("x-real-ip"), v);
        }
    }
    if let Ok(v) = http::HeaderValue::from_str(scheme) {
        out.insert(http::HeaderName::from_static("x-forwarded-proto"), v);
    }
    if let Some(h) = inbound.get(http::header::HOST).and_then(|v| v.to_str().ok()) {
        if let Ok(v) = http::HeaderValue::from_str(h) {
            out.insert(http::HeaderName::from_static("x-forwarded-host"), v);
        }
    }

    out
}

/// Serialize an HTTP/1.1 request head. Split out so a test can assert the exact
/// bytes on the wire — the `Sec-WebSocket-Key` surviving verbatim is the whole
/// contract, and asserting it through a socket would test tokio instead.
fn serialize_request_head(
    method: &http::Method,
    path_and_query: &str,
    headers: &http::HeaderMap,
) -> Vec<u8> {
    let mut head = format!("{method} {path_and_query} HTTP/1.1\r\n");
    for (name, value) in headers.iter() {
        // A header whose value is not valid UTF-8 is skipped rather than
        // lossily transcoded: a corrupted Sec-WebSocket-Key would fail the
        // client's Accept check with a confusing error, where an absent one
        // fails the handshake immediately and says so.
        if let Ok(v) = value.to_str() {
            head.push_str(name.as_str());
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Find the end of a response head, returning (head, leftover).
///
/// Returns `None` while no terminator has been seen yet, so the caller keeps
/// reading. Split out and pure so the leftover-bytes case — the one that loses
/// a websocket frame when it is wrong — is directly testable.
fn split_head(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| (&buf[..i + 4], &buf[i + 4..]))
}

/// Parse a serialized response head into a status code and headers.
fn parse_response_head(head: &[u8]) -> Result<(u16, http::HeaderMap), UpgradeError> {
    let text = std::str::from_utf8(head)
        .map_err(|e| UpgradeError::Malformed(format!("head is not utf-8: {e}")))?;
    let mut lines = text.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| UpgradeError::Malformed("empty head".into()))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| UpgradeError::Malformed(format!("no status code in {status_line:?}")))?;
    let status: u16 = code
        .parse()
        .map_err(|_| UpgradeError::Malformed(format!("status code {code:?} is not a number")))?;

    let mut headers = http::HeaderMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if let (Ok(n), Ok(v)) = (
            http::HeaderName::from_bytes(name.trim().as_bytes()),
            http::HeaderValue::from_str(value.trim()),
        ) {
            headers.append(n, v);
        }
    }

    Ok((status, headers))
}

/// Perform the upgrade handshake against a backend.
///
/// Returns the socket positioned after the response head, so the caller can
/// decide what to do with a non-101 answer instead of having it decided here —
/// an upstream that answers `200` to a websocket request is a *configuration*
/// finding worth surfacing, not an error to swallow.
pub async fn handshake(
    backend: &Backend,
    method: &http::Method,
    path_and_query: &str,
    inbound_headers: &http::HeaderMap,
    client_ip: Option<IpAddr>,
    scheme: &str,
) -> Result<UpstreamHandshake, UpgradeError> {
    let addr = format!("{}:{}", backend.address, backend.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| UpgradeError::Connect(format!("{addr}: {e}")))?;

    let headers = upgrade_headers(inbound_headers, backend, client_ip, scheme);
    let head = serialize_request_head(method, path_and_query, &headers);
    stream
        .write_all(&head)
        .await
        .map_err(|e| UpgradeError::Write(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| UpgradeError::Write(e.to_string()))?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| UpgradeError::Read(e.to_string()))?;
        if n == 0 {
            return Err(UpgradeError::Malformed(
                "upstream closed before sending a complete response head".into(),
            ));
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some((head, leftover)) = split_head(&buf) {
            let (status, headers) = parse_response_head(head)?;
            let leftover = leftover.to_vec();
            debug!(
                backend = %addr,
                status,
                leftover = leftover.len(),
                "upstream answered the upgrade handshake"
            );
            return Ok(UpstreamHandshake {
                stream,
                status,
                headers,
                leftover,
            });
        }

        if buf.len() > MAX_HEAD_BYTES {
            return Err(UpgradeError::HeadTooLarge);
        }
    }
}

/// Run the tunnel: client ⇄ upstream, until either side closes.
///
/// `leftover` is written to the client FIRST — see [`UpstreamHandshake::leftover`]
/// for why dropping it loses the upstream's first frame.
///
/// The copy shape is `l4::run_tcp_proxy`'s: two `tokio::io::copy` halves raced
/// with `select!`, so whichever direction closes first tears the pair down. A
/// websocket close is a normal end, so both arms log at debug rather than error.
pub async fn tunnel<C>(client: C, upstream: TcpStream, leftover: Vec<u8>)
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(upstream);

    if !leftover.is_empty() {
        if let Err(e) = cw.write_all(&leftover).await {
            warn!(error = %e, bytes = leftover.len(), "failed to replay upstream's buffered bytes to the client");
            return;
        }
    }

    let client_to_upstream = tokio::io::copy(&mut cr, &mut uw);
    let upstream_to_client = tokio::io::copy(&mut ur, &mut cw);

    tokio::select! {
        r = client_to_upstream => {
            if let Err(e) = r { debug!(error = %e, "client->upstream tunnel ended"); }
        }
        r = upstream_to_client => {
            if let Err(e) = r { debug!(error = %e, "upstream->client tunnel ended"); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> http::HeaderMap {
        let mut h = http::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    // The header the whole path turns on, in the forms real browsers send it.
    #[test]
    fn detects_upgrade_in_a_token_list() {
        assert_eq!(
            requested_upgrade(&hm(&[
                ("connection", "keep-alive, Upgrade"),
                ("upgrade", "websocket")
            ])),
            Some("websocket".to_string()),
            "Chrome's comma-separated form must be detected"
        );
        assert_eq!(
            requested_upgrade(&hm(&[("connection", "Upgrade"), ("upgrade", "websocket")])),
            Some("websocket".to_string())
        );
        assert_eq!(
            requested_upgrade(&hm(&[("connection", "upgrade"), ("upgrade", "WebSocket")])),
            Some("WebSocket".to_string()),
            "casing differs between clients and must not decide the outcome"
        );
    }

    #[test]
    fn plain_requests_are_not_upgrades() {
        assert_eq!(requested_upgrade(&hm(&[("connection", "keep-alive")])), None);
        // `Upgrade` without `Connection: Upgrade` is not a request to upgrade.
        assert_eq!(requested_upgrade(&hm(&[("upgrade", "websocket")])), None);
        assert_eq!(
            requested_upgrade(&hm(&[("connection", "keep-alive"), ("upgrade", "websocket")])),
            None
        );
        assert_eq!(requested_upgrade(&http::HeaderMap::new()), None);
    }

    // ★ The regression this module exists to prevent, asserted directly:
    // prepare_headers strips `connection`/`upgrade`, and doing that here makes
    // the upstream answer 200 instead of 101.
    #[test]
    fn upgrade_headers_keep_connection_upgrade_and_the_websocket_key() {
        let backend = Backend {
            address: "10.0.0.5".into(),
            port: 8123,
            healthy: true,
        };
        let inbound = hm(&[
            ("host", "ha.example.com"),
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "websocket"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ("sec-websocket-version", "13"),
            ("sec-websocket-protocol", "graphql-ws"),
            ("transfer-encoding", "chunked"),
        ]);

        let out = upgrade_headers(&inbound, &backend, Some("203.0.113.9".parse().unwrap()), "https");

        assert_eq!(out.get("connection").unwrap(), "keep-alive, Upgrade");
        assert_eq!(out.get("upgrade").unwrap(), "websocket");
        assert_eq!(
            out.get("sec-websocket-key").unwrap(),
            "dGhlIHNhbXBsZSBub25jZQ==",
            "the key is end-to-end: altering it breaks the client's Accept check"
        );
        assert_eq!(out.get("sec-websocket-protocol").unwrap(), "graphql-ws");

        // Still a proxy: authority rewritten, chain extended, framing dropped.
        assert_eq!(out.get("host").unwrap(), "10.0.0.5:8123");
        assert_eq!(out.get("x-forwarded-for").unwrap(), "203.0.113.9");
        assert_eq!(out.get("x-forwarded-host").unwrap(), "ha.example.com");
        assert_eq!(out.get("x-forwarded-proto").unwrap(), "https");
        assert!(
            out.get("transfer-encoding").is_none(),
            "transfer-encoding is hop-by-hop even on an upgrade"
        );
    }

    #[test]
    fn forwarded_for_appends_rather_than_replacing() {
        let backend = Backend {
            address: "127.0.0.1".into(),
            port: 9000,
            healthy: true,
        };
        let inbound = hm(&[
            ("connection", "Upgrade"),
            ("upgrade", "websocket"),
            ("x-forwarded-for", "198.51.100.1"),
        ]);
        let out = upgrade_headers(&inbound, &backend, Some("203.0.113.9".parse().unwrap()), "http");
        assert_eq!(
            out.get("x-forwarded-for").unwrap(),
            "198.51.100.1, 203.0.113.9",
            "a proxy that overwrites the chain erases the original client"
        );
    }

    // ★ The bug that loses the first websocket frame.
    #[test]
    fn split_head_returns_bytes_that_arrived_with_the_head() {
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello";
        let (head, leftover) = split_head(raw).expect("terminator is present");
        assert!(head.ends_with(b"\r\n\r\n"));
        assert_eq!(
            leftover, b"\x81\x05hello",
            "a frame coalesced into the head's TCP segment must be preserved"
        );
    }

    #[test]
    fn split_head_waits_for_the_terminator() {
        assert!(split_head(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: web").is_none());
    }

    #[test]
    fn parses_a_101_head() {
        let (status, headers) = parse_response_head(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .unwrap();
        assert_eq!(status, 101);
        assert_eq!(headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(
            headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            "Accept must be replayed downstream verbatim or the client rejects it"
        );
    }

    // An upstream that does not honour the upgrade is a finding, not a crash.
    #[test]
    fn parses_a_non_101_answer() {
        let (status, _) =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
        assert_eq!(status, 200);
    }

    #[test]
    fn rejects_a_malformed_head() {
        assert!(parse_response_head(b"NOT-HTTP\r\n\r\n").is_err());
        assert!(parse_response_head(b"HTTP/1.1 abc Weird\r\n\r\n").is_err());
    }

    #[test]
    fn serializes_a_request_head_on_the_wire() {
        let headers = hm(&[("upgrade", "websocket")]);
        let bytes = serialize_request_head(&http::Method::GET, "/api/websocket?x=1", &headers);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("GET /api/websocket?x=1 HTTP/1.1\r\n"));
        assert!(text.contains("upgrade: websocket\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "head must be terminated");
    }
}
