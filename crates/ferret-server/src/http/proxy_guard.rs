//! Which proxies to believe.
//!
//! `X-Forwarded-*`, `Forwarded` and `X-Real-IP` are believed only from the
//! addresses in `FERRET_TRUSTED_PROXIES`; every other peer's are removed before
//! anything else runs. Anyone who reaches the ports directly could otherwise
//! claim any address and any scheme.
//!
//! The Docker bridge gateway is never a trusted proxy. With published ports,
//! every direct client on the LAN reaches the container as the gateway, so
//! trusting it would make every LAN client a proxy that can claim any address
//! and any scheme. [`ProxyList::parse`] refuses such a list, and a list that
//! matches every address, so the server does not start with it. List the
//! address of the proxy itself.
//!
//! `FERRET_LOG_PEERS=1` makes the guard write one log line for each peer
//! address it sees for the first time (and nothing else), to find out which
//! address a proxy connects from.
//!
//! Spec: Fase 1 § 7.6.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::{IpNet, Ipv4Net};

use crate::error::ConfigError;

/// How many different peer addresses the peer log remembers. A scan from many
/// addresses cannot grow the set (or the log) without bound.
const PEER_LOG_LIMIT: usize = 1024;

/// The headers that carry a client's claim about the address or the scheme
/// besides the `X-Forwarded-*` family.
const FORWARDING_HEADERS: [&str; 2] = ["forwarded", "x-real-ip"];

/// The trusted proxy addresses and networks.
#[derive(Debug, Clone, Default)]
pub struct ProxyList {
    nets: Vec<IpNet>,
    peer_log: Option<Arc<PeerLog>>,
}

/// The peer addresses seen so far, for `FERRET_LOG_PEERS`.
#[derive(Debug, Default)]
struct PeerLog {
    seen: Mutex<HashSet<IpAddr>>,
}

impl PeerLog {
    /// Logs `peer` the first time it is seen.
    fn note(&self, peer: IpAddr, trusted: bool) {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.len() >= PEER_LOG_LIMIT {
            return;
        }
        if seen.insert(peer) {
            tracing::info!(%peer, trusted, "new peer address");
        }
    }
}

impl ProxyList {
    /// The list from the configured items: single addresses (`10.0.3.26`,
    /// `fd00::1`) or CIDR networks (`10.0.3.0/24`). Empty items are skipped.
    ///
    /// `FERRET_LOG_PEERS` (`1`, `true`, `yes` or `on`) switches the peer log on;
    /// [`with_peer_log`](Self::with_peer_log) does it by hand.
    ///
    /// # Errors
    ///
    /// An item that is not an address or a network, a network that matches every
    /// address (`/0`), and any address or network that contains the gateway of
    /// a Docker bridge network (a `.1` address in `172.16.0.0/12`, Docker's
    /// default pool).
    pub fn parse(items: &[String]) -> Result<Self, ConfigError> {
        let mut nets = Vec::new();
        for item in items {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            let net = parse_entry(item)?;
            if let Some(why) = refusal(&net) {
                return Err(ConfigError(format!(
                    "FERRET_TRUSTED_PROXIES: {item} {why}; list the address of the proxy itself"
                )));
            }
            nets.push(net);
        }
        let list = Self {
            nets,
            peer_log: None,
        };
        let log_peers = std::env::var("FERRET_LOG_PEERS")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        Ok(list.with_peer_log(log_peers))
    }

    /// The same list with the peer log on or off.
    #[must_use]
    pub fn with_peer_log(mut self, on: bool) -> Self {
        self.peer_log = on.then(|| Arc::new(PeerLog::default()));
        self
    }

    /// Whether `ip` is a trusted proxy. An IPv4 address that arrives as an
    /// IPv4-mapped IPv6 address (a dual-stack listener) counts as the IPv4
    /// address.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|net| net.contains(&ip))
    }

    /// Whether the list has no entry: no proxy is believed.
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    fn note_peer(&self, peer: IpAddr, trusted: bool) {
        if let Some(log) = &self.peer_log {
            log.note(peer.to_canonical(), trusted);
        }
    }
}

/// One item of the list: an address (a network of one) or a network.
fn parse_entry(item: &str) -> Result<IpNet, ConfigError> {
    let bad = |what: &str| {
        ConfigError(format!(
            "FERRET_TRUSTED_PROXIES: {item:?} is not {what}; use an address like 10.0.3.26 or a network like 10.0.3.0/24"
        ))
    };
    if item.contains('/') {
        let net: IpNet = item.parse().map_err(|_| bad("a network"))?;
        Ok(net.trunc())
    } else {
        let ip: IpAddr = item.parse().map_err(|_| bad("an address"))?;
        Ok(IpNet::from(ip.to_canonical()))
    }
}

/// Why an entry may not be trusted, if it may not.
fn refusal(net: &IpNet) -> Option<&'static str> {
    if net.prefix_len() == 0 {
        return Some("matches every address");
    }
    if covers_docker_gateway(net) {
        return Some("contains the gateway of a Docker bridge network");
    }
    None
}

/// Whether the network contains an address `172.16.0.0/12` ends in `.1` of: the
/// gateway of a Docker bridge network under Docker's default address pool.
fn covers_docker_gateway(net: &IpNet) -> bool {
    let IpNet::V4(net) = net else {
        return false;
    };
    let Ok(pool) = Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12) else {
        return false;
    };
    if net.prefix_len() < 12 {
        // Wider than the pool: the pool is inside it if it holds its start.
        return net.contains(&pool.network());
    }
    if !pool.contains(&net.network()) {
        return false;
    }
    if net.prefix_len() <= 24 {
        return true;
    }
    // Inside one /24: does the range hold ".1"?
    (net.network().octets()[3]..=net.broadcast().octets()[3]).contains(&1)
}

/// Removes the claims about the client's address and scheme.
fn strip_forwarding(headers: &mut HeaderMap) {
    let names: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            name.as_str().starts_with("x-forwarded-") || FORWARDING_HEADERS.contains(&name.as_str())
        })
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

/// Removes `X-Forwarded-*`, `Forwarded` and `X-Real-IP` from the request of
/// every peer that is not a trusted proxy. Run it first.
pub async fn proxy_guard(
    State(proxies): State<Arc<ProxyList>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let trusted = proxies.contains(peer.ip());
    proxies.note_peer(peer.ip(), trusted);
    if !trusted {
        strip_forwarding(request.headers_mut());
    }
    next.run(request).await
}

/// Whether the request reached the proxy over HTTPS, as far as it can be
/// believed: the deployment is configured with an `https` public URL, the peer
/// is a trusted proxy, and the right-most `X-Forwarded-Proto` entry (the one the
/// last proxy wrote) is `https`.
///
/// It is `false` for a peer that is not listed whatever the header says, and
/// `false` when the public URL is not `https`: the server itself speaks plain
/// HTTP, so only a proxy in front of it can have served HTTPS. A caller that
/// has an `https` public URL and gets `false` here refuses the sign-in and the
/// set-up (`insecure_transport`) instead of sending a cookie the browser would
/// silently drop.
pub fn request_is_https(
    headers: &HeaderMap,
    peer: IpAddr,
    proxies: &ProxyList,
    configured_public_https: bool,
) -> bool {
    if !configured_public_https || !proxies.contains(peer) {
        return false;
    }
    headers
        .get_all("x-forwarded-proto")
        .iter()
        .next_back()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .is_some_and(|proto| proto.trim().eq_ignore_ascii_case("https"))
}
