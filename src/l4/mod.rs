//! L4 TCP load balancer for non-HTTP services.
//!
//! ── ★ TIER: WIRED as of 2026-09-24. IN THE SHIPPED BINARY. ───────────────
//! `main.rs` has `mod l4;`, `AppConfig.l4` deserializes, and
//! `server::run_server` calls [`spawn_all`] behind `l4.enabled` — sharing the
//! ONE shutdown broadcast the HTTP servers use. This header said "LIBRARY-ONLY,
//! NOT IN THE SHIPPED BINARY" until that landed, and the gate
//! (`tests/dark_modules_test.rs`) is what forced it to be corrected in the same
//! change rather than aging into a lie.
//!
//! **Why it exists**: not everything a front door must carry is HTTP. The
//! motivating case is Google Cast, whose control channel is a protobuf protocol
//! over TLS on **:8009** — no L7 proxy can carry that — while the media fetch
//! beside it is plain HTTP that `crate::proxy` already handles. One device, two
//! layers. Databases, NATS and Redis are the same shape.
//!
//! **Default OFF.** `L4Config::enabled` is `false` and the field is
//! `#[serde(default)]`, so every existing config loads byte-identically and no
//! node gains a listener it did not ask for.
//!
//! ── L4 IS STATEFUL, AND THAT CHANGES THE LIFECYCLE ──────────────────────
//! An L7 request is independent and retryable; a TCP tunnel is a live session
//! whose peer notices when it dies. So [`run_tcp_proxy`] takes a shutdown
//! receiver and stops ACCEPTING on the signal, while in-flight tunnels finish on
//! their own tasks — a Cast control channel cut at process exit is a speaker
//! unresponsive until it reconnects, not a request the client retries.
//!
//! **UDP still has no implementation**, and the refusal is deliberately at
//! SPAWN rather than at parse. `L4Proxy.protocol` stays a `String` with
//! [`L4Transport`] as a derived view; [`spawn_all`] skips an unsupported
//! transport per-proxy, names it, and keeps every TCP proxy in the same document
//! listening.
//!
//! **The reason is blast radius, not backward compatibility.** An earlier draft
//! of this comment justified the open scalar as "nothing that parsed before stops
//! parsing", which is the wrong test — it would license a narrowed enum on any
//! field no operator had used yet. The actual rule
//! (`theory/UNREPRESENTABILITY.md` §II.2.1) is that a refusal must be scoped to
//! the bad state it names: `proxies` is a list of INDEPENDENT entries, so the
//! document is not the unit of use, and a parse-time rejection would take every
//! valid proxy beside the bad one down with it — hanabi failing to boot over one
//! line it was already ignoring.
//!
//! Tier-honest: rejecting `udp` at parse WOULD be a higher tier for that one
//! value than refusing it at spawn. We decline to buy that tier with the whole
//! config. The bad state is `only-mitigated` at the value; every good state
//! beside it is preserved unconditionally.
//!
//! Backends come from each proxy's static `upstreams`; catalog discovery can
//! still drive [`L4BackendPool::update`] where a catalog exists, and a house has
//! none to poll.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// L4 load balancer configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct L4Config {
    /// Whether L4 load balancing is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// L4 proxy definitions.
    #[serde(default)]
    pub proxies: Vec<L4Proxy>,
}

/// What a declared `protocol` string means to the code — a DERIVED view.
///
/// ── ★ THE WIRE FORMAT IS UNCHANGED, DELIBERATELY ──────────────────────────
/// `L4Proxy.protocol` stays a `String`, exactly as it has always been, and this
/// enum is a projection of it. Two drafts of this change were more type-strict
/// and both were wrong:
///
///   1. a closed enum `{ Tcp }` — then `protocol: udp` fails to parse, and serde
///      rejects the WHOLE document on one unknown variant, so a single line that
///      was previously ignored now stops hanabi loading its config at all.
///   2. `{ Tcp, Udp }` — better, but still narrows the surface: `protocol: sctp`
///      used to parse and be inert, and would now be a boot failure.
///
/// Both converted a silently-ignored value into a service that will not start.
/// That is a regression dressed as rigour — the same shape as the omoya trap
/// where one unrecognised field rejected an entire file. **Behaviour is
/// additive: nothing that parsed before may stop parsing.**
///
/// So the parse boundary accepts everything it always did, and the TYPING moves
/// one layer in: the code matches on this, and [`spawn_all`] refuses an
/// unsupported transport *per proxy*, by name, while every TCP proxy in the same
/// document keeps running. What was added is the diagnosis; what was removed is
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4Transport {
    /// The one transport implemented.
    Tcp,
    /// Anything else — parsed, carried, and refused at spawn with its own name
    /// so the message can say which proxy and which word. UDP is the expected
    /// member (DNS and MQTT want it); it is connectionless, so implementing it
    /// means a NAT-style flow table rather than an accepted socket.
    Unsupported(String),
}

/// A single L4 proxy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4Proxy {
    /// Human-readable name.
    pub name: String,

    /// Protocol (tcp or udp), as written. A `String` on purpose — see
    /// [`L4Transport`] for why narrowing this type would be a regression. Read
    /// it through [`Self::transport`], never by comparing strings at call sites.
    #[serde(default = "default_protocol")]
    pub protocol: String,

    /// Local listen address and port.
    pub listen: String,

    /// Pool key. With `upstreams` empty this is also the tatara catalog service
    /// name to discover; with `upstreams` set it is just the name.
    pub service: String,

    /// Static upstreams as `host:port`, for a node with no service catalog.
    ///
    /// The same arm `ProxyRoute::upstreams` carries, and for the same reason:
    /// catalog discovery is the right shape for a cluster and the WRONG shape
    /// for a house, where every upstream is a fixed address on a LAN and there
    /// is no catalog to ask. Without this there is no code path at all for the
    /// machines this proxy would actually front.
    #[serde(default)]
    pub upstreams: Vec<String>,
}

fn default_protocol() -> String {
    "tcp".to_string()
}

impl L4Proxy {
    /// The declared protocol as a typed view. Case-insensitive, because a config
    /// is hand-written and `TCP` meaning something different from `tcp` would be
    /// a trap rather than a feature.
    pub fn transport(&self) -> L4Transport {
        if self.protocol.trim().eq_ignore_ascii_case("tcp") {
            L4Transport::Tcp
        } else {
            L4Transport::Unsupported(self.protocol.clone())
        }
    }
}

/// Backend address for L4 proxying.
#[derive(Debug, Clone)]
pub struct L4Backend {
    pub address: String,
    pub port: u16,
}

impl L4Backend {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }
}

/// L4 backend pool with round-robin selection.
pub struct L4BackendPool {
    backends: RwLock<Vec<L4Backend>>,
    counter: AtomicUsize,
}

impl L4BackendPool {
    pub fn new() -> Self {
        Self {
            backends: RwLock::new(Vec::new()),
            counter: AtomicUsize::new(0),
        }
    }

    pub async fn update(&self, backends: Vec<L4Backend>) {
        *self.backends.write().await = backends;
    }

    pub async fn next(&self) -> Option<L4Backend> {
        let backends = self.backends.read().await;
        if backends.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % backends.len();
        Some(backends[idx].clone())
    }
}

/// `host:port` → an [`L4Backend`]. Returns None rather than guessing a port.
///
/// Mirrors `proxy::parse_upstream` deliberately, including the refusal to
/// default a port: on a home node every upstream is a distinct loopback or LAN
/// port, so a silently-defaulted 80 would proxy to the wrong service.
pub fn parse_upstream(s: &str) -> Option<L4Backend> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some(L4Backend {
        address: host.to_string(),
        port,
    })
}

/// Run a TCP proxy listener, forwarding connections to backends.
///
/// ── ★ WHY THE SHUTDOWN RECEIVER IS NOT OPTIONAL ───────────────────────────
/// The accept loop used to be `loop { listener.accept().await? }`, which never
/// returns — so this could not participate in graceful drain, and a task
/// spawned with it would be killed mid-connection at process exit.
///
/// That matters more at L4 than at L7 because **L4 is stateful**. An HTTP
/// request is independent and retryable; a TCP tunnel is a live session whose
/// peer notices when it dies. A Cast control channel dropped without warning is
/// a speaker that goes unresponsive until it re-connects, not a request the
/// client retries. So the listener stops ACCEPTING on the shutdown signal, and
/// in-flight tunnels are left to finish on their own tasks.
pub async fn run_tcp_proxy(
    listen_addr: &str,
    pool: Arc<L4BackendPool>,
    name: &str,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(listen_addr).await?;
    info!(name, listen = %listen_addr, "L4 TCP proxy listening");

    loop {
        let (inbound, peer_addr) = tokio::select! {
            accepted = listener.accept() => accepted?,
            _ = shutdown.recv() => {
                info!(name, listen = %listen_addr, "L4 TCP proxy draining — no longer accepting");
                return Ok(());
            }
        };
        let pool = pool.clone();
        let name = name.to_string();

        tokio::spawn(async move {
            let backend = match pool.next().await {
                Some(b) => b,
                None => {
                    warn!(name = %name, "no backends available");
                    return;
                }
            };

            debug!(
                name = %name,
                peer = %peer_addr,
                backend = %backend.addr(),
                "proxying TCP connection"
            );

            match TcpStream::connect(backend.addr()).await {
                Ok(outbound) => {
                    let (mut ri, mut wi) = tokio::io::split(inbound);
                    let (mut ro, mut wo) = tokio::io::split(outbound);

                    let client_to_server = tokio::io::copy(&mut ri, &mut wo);
                    let server_to_client = tokio::io::copy(&mut ro, &mut wi);

                    tokio::select! {
                        r = client_to_server => {
                            if let Err(e) = r { debug!(error = %e, "client->server copy ended"); }
                        }
                        r = server_to_client => {
                            if let Err(e) = r { debug!(error = %e, "server->client copy ended"); }
                        }
                    }
                }
                Err(e) => {
                    error!(
                        name = %name,
                        backend = %backend.addr(),
                        error = %e,
                        "failed to connect to backend"
                    );
                }
            }
        });
    }
}

/// Spawn every configured L4 proxy, returning their join handles.
///
/// The entry point that makes this module part of the binary rather than a
/// library nobody calls. Called from `server::run_server`, which already owns
/// the shutdown broadcast — so the listeners share the one drain signal the HTTP
/// servers use instead of inventing a second lifecycle.
///
/// Pools are seeded from each proxy's STATIC `upstreams`. Catalog discovery is
/// deliberately not wired here: a node with a tatara catalog can have its pool
/// updated through [`L4BackendPool::update`] by whatever polls the catalog, and
/// a house has no catalog to poll. Seeding statically is what makes the module
/// useful on the machines it would actually front.
///
/// A proxy with no resolvable upstreams is SKIPPED with a warning rather than
/// bound: a listener whose pool is empty accepts connections and drops every one
/// of them at `next()` returning `None`, which looks like a network fault from
/// the client and like success from the process.
pub fn spawn_all(
    config: &L4Config,
    shutdown: &tokio::sync::broadcast::Sender<()>,
) -> Vec<tokio::task::JoinHandle<()>> {
    if !config.enabled {
        return Vec::new();
    }

    let mut handles = Vec::new();
    for proxy in &config.proxies {
        // ── The UDP refusal, located and per-proxy ─────────────────────────
        // Skipping THIS entry rather than failing the whole config is the
        // difference between "your MQTT-over-UDP proxy is not running, here is
        // its name" and "hanabi did not start". Every TCP proxy in the same
        // document keeps working, which is what makes the diagnosis safe to
        // ship: no feature that worked before stops working now.
        if let L4Transport::Unsupported(p) = proxy.transport() {
            warn!(
                name = %proxy.name,
                listen = %proxy.listen,
                protocol = %p,
                "L4 proxy declares a protocol that is NOT IMPLEMENTED — skipping this \
                 entry and continuing. It was silently inert before this message \
                 existed and it is still inert, but now it names itself. UDP is the \
                 expected case: connectionless, so it needs a flow table rather than \
                 an accepted socket."
            );
            continue;
        }

        let backends: Vec<L4Backend> = proxy.upstreams.iter().filter_map(|u| parse_upstream(u)).collect();

        if backends.len() != proxy.upstreams.len() {
            warn!(
                name = %proxy.name,
                declared = proxy.upstreams.len(),
                parsed = backends.len(),
                "some L4 upstreams are not `host:port` and were dropped"
            );
        }

        if backends.is_empty() {
            warn!(
                name = %proxy.name,
                listen = %proxy.listen,
                "L4 proxy has no usable upstreams — NOT binding a listener, because \
                 one with an empty pool accepts and then drops every connection"
            );
            continue;
        }

        let pool = Arc::new(L4BackendPool::new());
        let listen = proxy.listen.clone();
        let name = proxy.name.clone();
        let rx = shutdown.subscribe();
        let seed = backends;

        handles.push(tokio::spawn(async move {
            pool.update(seed).await;
            if let Err(e) = run_tcp_proxy(&listen, pool, &name, rx).await {
                error!(name = %name, listen = %listen, error = %e, "L4 proxy exited with an error");
            }
        }));
    }

    handles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_backend_pool_round_robin() {
        let pool = L4BackendPool::new();
        pool.update(vec![
            L4Backend {
                address: "10.0.0.1".to_string(),
                port: 5432,
            },
            L4Backend {
                address: "10.0.0.2".to_string(),
                port: 5432,
            },
        ])
        .await;

        let b1 = pool.next().await.unwrap();
        let b2 = pool.next().await.unwrap();
        let b3 = pool.next().await.unwrap();

        assert_eq!(b1.address, "10.0.0.1");
        assert_eq!(b2.address, "10.0.0.2");
        assert_eq!(b3.address, "10.0.0.1");
    }

    fn proxy(protocol: &str, upstreams: &[&str]) -> L4Proxy {
        L4Proxy {
            name: "cast".into(),
            protocol: protocol.into(),
            listen: "127.0.0.1:0".into(),
            service: "cast".into(),
            upstreams: upstreams.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    // ★ THE ADDITIVE GUARANTEE. Every protocol string that parsed before this
    // change must still parse — a narrowed enum would have made one ignored
    // line stop the whole service from loading its config.
    #[test]
    fn any_protocol_string_still_deserializes() {
        for p in ["tcp", "udp", "TCP", "sctp", "nonsense", ""] {
            let yaml = format!(
                "name: x\nprotocol: {p}\nlisten: 127.0.0.1:1\nservice: s\n"
            );
            let parsed: Result<L4Proxy, _> = serde_yaml::from_str(&yaml);
            assert!(
                parsed.is_ok(),
                "protocol {p:?} must still parse -- narrowing the wire format turns \
                 a previously-ignored line into a service that will not boot"
            );
        }
    }

    #[test]
    fn the_protocol_is_typed_where_the_code_reads_it() {
        assert_eq!(proxy("tcp", &[]).transport(), L4Transport::Tcp);
        // Case-insensitive: a hand-written config saying TCP means tcp.
        assert_eq!(proxy("TCP", &[]).transport(), L4Transport::Tcp);
        assert_eq!(proxy(" tcp ", &[]).transport(), L4Transport::Tcp);
        // Everything else is carried, named, and refused at spawn.
        assert_eq!(
            proxy("udp", &[]).transport(),
            L4Transport::Unsupported("udp".into())
        );
        assert_eq!(
            proxy("sctp", &[]).transport(),
            L4Transport::Unsupported("sctp".into())
        );
    }

    #[test]
    fn a_missing_protocol_defaults_to_tcp() {
        let parsed: L4Proxy =
            serde_yaml::from_str("name: x\nlisten: 127.0.0.1:1\nservice: s\n").unwrap();
        assert_eq!(parsed.protocol, "tcp");
        assert_eq!(parsed.transport(), L4Transport::Tcp);
        assert!(parsed.upstreams.is_empty(), "upstreams defaults to empty");
    }

    // Disabled config must spawn NOTHING. This is the guarantee that makes the
    // whole change safe to ship: an existing node gains no listener.
    #[test]
    fn disabled_l4_spawns_no_listeners() {
        let (tx, _rx) = tokio::sync::broadcast::channel::<()>(1);
        let cfg = L4Config {
            enabled: false,
            proxies: vec![proxy("tcp", &["127.0.0.1:9"])],
        };
        assert!(
            spawn_all(&cfg, &tx).is_empty(),
            "enabled: false must bind nothing, whatever the proxies say"
        );
    }

    // An unsupported transport skips ONE entry and leaves the rest alone --
    // "your udp proxy is not running" rather than "hanabi did not start".
    #[tokio::test]
    async fn an_unsupported_protocol_skips_only_its_own_entry() {
        let (tx, _rx) = tokio::sync::broadcast::channel::<()>(1);
        let cfg = L4Config {
            enabled: true,
            proxies: vec![
                proxy("udp", &["127.0.0.1:9"]),
                L4Proxy {
                    name: "tcp-one".into(),
                    ..proxy("tcp", &["127.0.0.1:9"])
                },
            ],
        };
        let handles = spawn_all(&cfg, &tx);
        assert_eq!(
            handles.len(),
            1,
            "the udp entry is skipped; the tcp entry beside it still runs"
        );
        let _ = tx.send(());
        for h in handles {
            let _ = h.await;
        }
    }

    // A listener with an empty pool would accept and then drop every
    // connection, which looks like a network fault to the client and like
    // success to the process. Refuse to bind instead.
    #[test]
    fn a_proxy_with_no_usable_upstreams_is_not_bound() {
        let (tx, _rx) = tokio::sync::broadcast::channel::<()>(1);
        let cfg = L4Config {
            enabled: true,
            // Neither is `host:port`, so both are dropped and the pool is empty.
            proxies: vec![proxy("tcp", &["no-port", ":8009"])],
        };
        assert!(spawn_all(&cfg, &tx).is_empty());
    }

    #[test]
    fn upstreams_parse_like_the_l7_ones() {
        assert_eq!(parse_upstream("10.0.0.5:8009").unwrap().addr(), "10.0.0.5:8009");
        // No guessed port, no empty host -- a defaulted 80 would proxy to the
        // wrong service on a node where every upstream is a distinct port.
        assert!(parse_upstream("10.0.0.5").is_none());
        assert!(parse_upstream(":8009").is_none());
        assert!(parse_upstream("10.0.0.5:not-a-port").is_none());
    }
}
