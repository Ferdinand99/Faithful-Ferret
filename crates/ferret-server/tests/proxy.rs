//! Proxy trust: which peers' forwarding headers are believed.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use clap::Parser as _;
use ferret_server::config::Config;
use ferret_server::http::proxy_guard::{ProxyList, proxy_guard, request_is_https};
use ferret_server_auth::{Clock, SystemClock};
use tower::ServiceExt as _;
use tracing_subscriber::fmt::MakeWriter;

const FORWARDING: [&str; 6] = [
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-forwarded-port",
    "forwarded",
    "x-real-ip",
];

fn list(items: &[&str]) -> ProxyList {
    let items: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
    ProxyList::parse(&items).expect("a valid list")
}

fn refused(items: &[&str]) -> String {
    let items: Vec<String> = items.iter().map(|s| (*s).to_string()).collect();
    ProxyList::parse(&items)
        .expect_err(&format!("{items:?} must be refused"))
        .to_string()
}

/// A router that answers with the forwarding headers that reached it.
fn echo(proxies: ProxyList) -> Router {
    async fn headers(request: Request<Body>) -> String {
        let mut seen: Vec<String> = FORWARDING
            .iter()
            .filter_map(|name| {
                request
                    .headers()
                    .get(*name)
                    .map(|v| format!("{name}={}", v.to_str().unwrap_or("?")))
            })
            .collect();
        if let Some(keep) = request.headers().get("x-keep") {
            seen.push(format!("x-keep={}", keep.to_str().unwrap_or("?")));
        }
        seen.join(";")
    }
    Router::new()
        .route("/", get(headers))
        .layer(from_fn_with_state(Arc::new(proxies), proxy_guard))
}

async fn send(router: &Router, peer: &str) -> String {
    let peer: SocketAddr = peer.parse().expect("a peer");
    let mut request = Request::builder().uri("/");
    for name in FORWARDING {
        request = request.header(name, "9.9.9.9");
    }
    let mut request = request
        .header("x-forwarded-proto", "https")
        .header("x-keep", "yes")
        .body(Body::empty())
        .expect("a request");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router.clone().oneshot(request).await.expect("a response");
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("a body");
    String::from_utf8(bytes.to_vec()).expect("text")
}

#[tokio::test]
async fn forwarded_headers_from_an_unlisted_peer_are_removed() {
    let router = echo(list(&["10.0.3.26"]));
    for peer in ["198.51.100.10:4000", "10.0.3.27:4000", "[2001:db8::1]:4000"] {
        // Everything but the unrelated header is gone.
        assert_eq!(send(&router, peer).await, "x-keep=yes", "{peer}");
    }
    // With no list at all, nobody is believed.
    let none = echo(list(&[]));
    assert_eq!(send(&none, "10.0.3.26:4000").await, "x-keep=yes");
}

#[tokio::test]
async fn forwarded_headers_from_a_listed_proxy_are_kept() {
    let router = echo(list(&["10.0.3.26", "192.168.7.0/24"]));
    for peer in ["10.0.3.26:4000", "192.168.7.200:4000"] {
        let seen = send(&router, peer).await;
        for name in FORWARDING {
            assert!(seen.contains(name), "{peer}: {name} missing from {seen}");
        }
        assert!(seen.contains("x-keep=yes"));
    }
}

#[test]
fn docker_bridge_gateway_in_the_trusted_list_is_rejected_at_startup() {
    // The list itself.
    for entry in [
        "172.17.0.1",
        "172.18.0.1",
        "172.31.0.1",
        "172.17.0.0/16",
        "172.20.5.0/24",
        "172.18.0.0/30",
        "172.16.0.0/12",
        "172.0.0.0/8",
        "172.17.0.1/32",
    ] {
        let message = refused(&[entry]);
        assert!(message.contains("FERRET_TRUSTED_PROXIES"), "{message}");
        assert!(message.contains("Docker bridge"), "{entry}: {message}");
    }
    // A list that trusts everyone is refused too, and one bad item spoils a
    // list of good ones.
    assert!(refused(&["0.0.0.0/0"]).contains("every address"));
    assert!(refused(&["::/0"]).contains("every address"));
    refused(&["10.0.3.26", "172.17.0.1"]);

    // Addresses next to the gateways are fine: a proxy container, hosts outside
    // the pool, a /30 that starts after ".1".
    for entry in [
        "172.17.0.2",
        "172.17.0.0/32",
        "172.18.0.4/30",
        "172.32.0.1",
        "172.15.255.1",
        "10.0.3.26",
        "10.0.3.0/24",
        "192.168.1.1",
    ] {
        list(&[entry]);
    }
}

#[tokio::test]
async fn the_server_does_not_start_with_the_gateway_in_the_trusted_list() {
    let dir = std::env::temp_dir().join(format!("ferret-test-proxy-{}", std::process::id()));
    let data_dir = dir.to_string_lossy().into_owned();
    let config = Config::try_parse_from([
        "ferret",
        "--data-dir",
        &data_dir,
        "--vault-url",
        "https://vault.ferret.test",
        "--admin-url",
        "https://admin.ferret.test",
        "--trusted-proxies",
        "10.0.3.26,172.17.0.1",
    ])
    .expect("a configuration");
    let outcome = ferret_server::start(&config, Arc::new(SystemClock) as Arc<dyn Clock>).await;
    let _ = std::fs::remove_dir_all(&dir);
    let error = outcome.err().expect("the start must fail").to_string();
    assert!(error.contains("FERRET_TRUSTED_PROXIES"), "{error}");
    assert!(error.contains("Docker bridge"), "{error}");
}

#[test]
fn cidr_and_single_ip_entries_parse() {
    let proxies = list(&[
        "10.0.3.26",
        " 192.168.7.0/24 ",
        "",
        "fd00::1",
        "2001:db8::/32",
    ]);
    let ip = |s: &str| -> IpAddr { s.parse().expect("an address") };
    assert!(proxies.contains(ip("10.0.3.26")));
    assert!(!proxies.contains(ip("10.0.3.27")));
    assert!(proxies.contains(ip("192.168.7.0")));
    assert!(proxies.contains(ip("192.168.7.255")));
    assert!(!proxies.contains(ip("192.168.8.1")));
    assert!(proxies.contains(ip("fd00::1")));
    assert!(!proxies.contains(ip("fd00::2")));
    // Host bits in a network are ignored.
    assert!(list(&["10.1.2.3/24"]).contains(ip("10.1.2.99")));
    assert!(list(&[]).is_empty());
    assert!(!proxies.is_empty());
    for bad in [
        "banana",
        "10.0.0.0/33",
        "10.0.0.1/24/1",
        "10.0.0",
        "10.0.0.1 10.0.0.2",
    ] {
        let message = refused(&[bad]);
        assert!(message.contains("FERRET_TRUSTED_PROXIES"), "{message}");
    }
}

#[test]
fn ipv6_peer_in_a_listed_cidr() {
    let proxies = list(&["2001:db8:aa::/48", "10.0.3.0/24"]);
    let ip = |s: &str| -> IpAddr { s.parse().expect("an address") };
    assert!(proxies.contains(ip("2001:db8:aa::1")));
    assert!(proxies.contains(ip("2001:db8:aa:ffff::9")));
    assert!(!proxies.contains(ip("2001:db8:ab::1")));
    // A dual-stack listener reports an IPv4 peer as an IPv4-mapped address.
    assert!(proxies.contains(ip("::ffff:10.0.3.9")));
    assert!(!proxies.contains(ip("::ffff:10.0.4.9")));
}

#[tokio::test]
async fn an_ipv6_peer_in_a_listed_cidr_keeps_its_headers() {
    let router = echo(list(&["2001:db8:aa::/48"]));
    assert!(
        send(&router, "[2001:db8:aa::7]:4000")
            .await
            .contains("x-forwarded-for")
    );
    assert_eq!(send(&router, "[2001:db8:ab::7]:4000").await, "x-keep=yes");
}

#[test]
fn https_is_false_without_a_trusted_proxy_even_when_the_header_says_https() {
    let proxies = list(&["10.0.3.26"]);
    let proxy: IpAddr = "10.0.3.26".parse().unwrap();
    let stranger: IpAddr = "198.51.100.10".parse().unwrap();
    let with = |value: &'static str| {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static(value));
        headers
    };

    // The header says https, but the peer is nobody we believe.
    assert!(!request_is_https(&with("https"), stranger, &proxies, true));
    assert!(!request_is_https(&with("https"), proxy, &list(&[]), true));
    // From the proxy, it counts.
    assert!(request_is_https(&with("https"), proxy, &proxies, true));
    assert!(request_is_https(&with("HTTPS"), proxy, &proxies, true));
    // The right-most entry is the one the last proxy wrote.
    assert!(request_is_https(
        &with("http, https"),
        proxy,
        &proxies,
        true
    ));
    assert!(!request_is_https(
        &with("https, http"),
        proxy,
        &proxies,
        true
    ));
    // Plain http, no header, junk.
    assert!(!request_is_https(&with("http"), proxy, &proxies, true));
    assert!(!request_is_https(&HeaderMap::new(), proxy, &proxies, true));
    assert!(!request_is_https(&with("httpsx"), proxy, &proxies, true));
    // A deployment whose public URL is not https is never https.
    assert!(!request_is_https(&with("https"), proxy, &proxies, false));
}

/// A log sink the test can read.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

#[tokio::test]
async fn peer_log_prints_each_new_peer_once_and_nothing_else() {
    let sink = Sink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let router = echo(list(&["10.0.3.26"]).with_peer_log(true));
    for peer in [
        "198.51.100.10:4000",
        "198.51.100.10:4001",
        "10.0.3.26:5000",
        "198.51.100.10:4002",
        "10.0.3.26:5001",
        "[2001:db8::1]:4000",
    ] {
        send(&router, peer).await;
    }
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    for (line, peer) in lines
        .iter()
        .zip(["198.51.100.10", "10.0.3.26", "2001:db8::1"])
    {
        assert!(line.contains(peer), "{line}");
        assert!(line.contains("new peer address"), "{line}");
        // No ports, no header values.
        assert!(!line.contains("9.9.9.9"), "{line}");
        assert!(!line.contains("4000"), "{line}");
    }
    assert!(lines[1].contains("trusted=true"), "{}", lines[1]);
    assert!(lines[0].contains("trusted=false"), "{}", lines[0]);

    // Switched off, it prints nothing.
    let quiet = echo(list(&["10.0.3.26"]).with_peer_log(false));
    let before = sink.0.lock().unwrap().len();
    send(&quiet, "203.0.113.5:4000").await;
    assert_eq!(sink.0.lock().unwrap().len(), before);
}
