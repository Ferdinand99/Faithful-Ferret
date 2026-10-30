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
//! and any scheme. [`ProxyList::parse`] refuses such a list, a network wider
//! than /24 (IPv4) or /64 (IPv6) and a list that matches every address, so the
//! server does not start with it. List the address of the proxy itself (in a
//! compose file, pin it with a fixed `ipv4_address`).
//!
//! `FERRET_LOG_PEERS=1` makes the guard write one log line for each peer
//! address it sees for the first time (and nothing else), to find out which
//! address a proxy connects from.
//!
//! Spec: Fase 1 § 7.6.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::Response;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use crate::error::ConfigError;

/// How many different peer addresses the peer log remembers. A scan from many
/// addresses cannot grow the set (or the log) without bound.
const PEER_LOG_LIMIT: usize = 1024;

/// The widest IPv4 network that may be listed, as a prefix length.
const MIN_V4_PREFIX: u8 = 24;
/// The widest IPv6 network that may be listed, as a prefix length.
const MIN_V6_PREFIX: u8 = 64;

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
    /// An item that is not an address or a network; a network that matches every
    /// address (`/0`); a network wider than /24 (IPv4) or /64 (IPv6); an IPv4
    /// network written as IPv6; and any address or network that contains the
    /// gateway of a Docker bridge network (a `.1` address in `172.16.0.0/12` or
    /// in a /20 of `192.168.0.0/16`, a `::1` host inside a /64).
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
        if let IpNet::V6(v6) = net
            && v6.network().to_ipv4_mapped().is_some()
        {
            return Err(ConfigError(format!(
                "FERRET_TRUSTED_PROXIES: {item:?} is an IPv4 address written as IPv6, which would never match; write it as an IPv4 network"
            )));
        }
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
    if covers_bridge_gateway(net) {
        return Some("contains the gateway of a Docker bridge network");
    }
    let too_wide = match net {
        IpNet::V4(v4) => v4.prefix_len() < MIN_V4_PREFIX,
        IpNet::V6(v6) => v6.prefix_len() < MIN_V6_PREFIX,
    };
    if too_wide {
        return Some("is a wider network than /24 (IPv4) or /64 (IPv6)");
    }
    None
}

/// Whether the network contains the gateway of a bridge network, going by where
/// Docker puts them:
///
/// * IPv4: `x.y.z.1` in `172.16.0.0/12` (the default pool of bridge networks),
///   and `192.168.(16 * n).1` (the /20 networks it takes from `192.168.0.0/16`
///   once that pool is used up);
/// * IPv6: a `::1` host inside a /64 (a network narrower than the /64 that holds
///   it; the loopback address `::1` is not one).
///
/// Custom address pools and gateways cannot be known: list the proxy's own
/// address.
fn covers_bridge_gateway(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4_covers_gateway(v4),
        IpNet::V6(v6) => v6_covers_gateway(v6),
    }
}

fn v4_covers_gateway(net: &Ipv4Net) -> bool {
    let (Ok(docker), Ok(lan)) = (
        Ipv4Net::new(Ipv4Addr::new(172, 16, 0, 0), 12),
        Ipv4Net::new(Ipv4Addr::new(192, 168, 0, 0), 16),
    ) else {
        return false;
    };
    // Wider than a pool: it holds the start of the pool, and so its first
    // gateway.
    if net.prefix_len() < 12 && net.contains(&docker.network()) {
        return true;
    }
    if net.prefix_len() < 16 && net.contains(&lan.network()) {
        return true;
    }
    if docker.contains(&net.network()) && net.prefix_len() >= 12 {
        return holds_dot_one(net, |_third| true);
    }
    if lan.contains(&net.network()) && net.prefix_len() >= 16 {
        return holds_dot_one(net, |third| third % 16 == 0);
    }
    false
}

/// Whether `net` holds a `.1` address in a /24 whose third octet `gateway_row`
/// accepts.
fn holds_dot_one(net: &Ipv4Net, gateway_row: impl Fn(u8) -> bool) -> bool {
    let first = net.network().octets();
    let last = net.broadcast().octets();
    if net.prefix_len() <= 24 {
        // Whole /24 networks: every row from the first to the last.
        return (first[2]..=last[2]).any(gateway_row);
    }
    gateway_row(first[2]) && (first[3]..=last[3]).contains(&1)
}

fn v6_covers_gateway(net: &Ipv6Net) -> bool {
    if net.prefix_len() <= 64 || net.network() == Ipv6Addr::LOCALHOST {
        return false;
    }
    let host = |addr: Ipv6Addr| u128::from(addr) & u128::from(u64::MAX);
    (host(net.network())..=host(net.broadcast())).contains(&1)
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
