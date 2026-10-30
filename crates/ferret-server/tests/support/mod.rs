//! The test harness: the whole server in one process, driven without a socket.
//!
//! [`TestApp`] builds the same two routers that `server::run` serves (the vault
//! listener and the admin listener) from one shared state, with a clock that
//! only moves when a test says so and with no throttle. A request is sent to
//! one listener with [`TestApp::call`]; the cookies of each listener are kept
//! apart in a [`Jar`], as a browser keeps them apart for two host names.
//!
//! `accounts` (test accounts straight into the database) and `session`
//! (sessions and their cookies) are the helpers of the tasks that own them.

#![allow(dead_code)]

pub mod accounts;
pub mod handoff;
pub mod session;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use ferret_server::config::Config;
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::server;
use ferret_server::state::FerretState;
use ferret_server_auth::{Clock, ManualClock, NoThrottle, Throttle};
use serde_json::Value;
use tower::ServiceExt as _;

/// The public address of the vault listener in tests.
pub const VAULT_URL: &str = "https://vault.ferret.test";
/// The public address of the admin listener in tests.
pub const ADMIN_URL: &str = "https://admin.ferret.test";
/// The address requests come from unless a test says otherwise.
pub const PEER: &str = "198.51.100.10:40000";
/// Where the clock starts: 2026-11-01 00:00:00 UTC.
pub const START: u64 = 1_793_491_200;

/// The two listeners.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Which {
    Vault,
    Admin,
}

impl Which {
    /// The public address of the listener.
    pub fn url(self) -> &'static str {
        match self {
            Which::Vault => VAULT_URL,
            Which::Admin => ADMIN_URL,
        }
    }

    /// The host name of the public address (the `Host` header of a browser).
    pub fn host(self) -> &'static str {
        match self {
            Which::Vault => "vault.ferret.test",
            Which::Admin => "admin.ferret.test",
        }
    }
}

/// The cookies a browser holds for one host name.
#[derive(Clone, Debug, Default)]
pub struct Jar(BTreeMap<String, String>);

impl Jar {
    /// Takes in the `Set-Cookie` headers of a response: a cookie that is set is
    /// stored, one that is emptied or expired is dropped.
    pub fn absorb(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(header::SET_COOKIE) {
            let Ok(text) = value.to_str() else { continue };
            let mut parts = text.split(';');
            let Some((name, val)) = parts.next().and_then(|p| p.split_once('=')) else {
                continue;
            };
            let gone = val.is_empty()
                || parts.any(|attr| {
                    let attr = attr.trim().to_ascii_lowercase();
                    attr == "max-age=0" || attr.starts_with("max-age=-")
                });
            if gone {
                self.0.remove(name.trim());
            } else {
                self.0.insert(name.trim().to_string(), val.to_string());
            }
        }
    }

    /// The value of a cookie.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// Sets a cookie by hand (a copied or doctored one).
    pub fn set(&mut self, name: &str, value: &str) {
        self.0.insert(name.to_string(), value.to_string());
    }

    /// Drops a cookie.
    pub fn remove(&mut self, name: &str) {
        self.0.remove(name);
    }

    /// The names of the cookies held.
    pub fn names(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }

    /// The `Cookie` header value, if there is any cookie.
    pub fn header(&self) -> Option<String> {
        if self.0.is_empty() {
            return None;
        }
        Some(
            self.0
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

/// A request to build: the usual headers of a browser's `fetch` are one call
/// away.
pub struct Req {
    builder: axum::http::request::Builder,
    body: Body,
}

impl Req {
    pub fn get(uri: &str) -> Self {
        Self::new(Method::GET, uri)
    }

    pub fn post(uri: &str) -> Self {
        Self::new(Method::POST, uri)
    }

    pub fn put(uri: &str) -> Self {
        Self::new(Method::PUT, uri)
    }

    pub fn new(method: Method, uri: &str) -> Self {
        Self {
            builder: Request::builder().method(method).uri(uri),
            body: Body::empty(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    /// A JSON body.
    pub fn json(mut self, value: &Value) -> Self {
        self.builder = self
            .builder
            .header(header::CONTENT_TYPE, "application/json");
        self.body = Body::from(value.to_string());
        self
    }

    /// What a page of listener `which` sends with a `fetch`: its `Origin` and
    /// the protocol header.
    pub fn page_fetch(self, which: Which) -> Self {
        self.header("origin", which.url())
            .header("ferret-protocol", "1")
    }

    pub fn build(self) -> Request<Body> {
        self.builder.body(self.body).expect("a valid request")
    }
}

/// An answer, read to the end.
#[derive(Debug)]
pub struct Res {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Res {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.text()))
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    /// Every `Set-Cookie` header.
    pub fn set_cookies(&self) -> Vec<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect()
    }
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Settings of a [`TestApp`] that a test may change before it starts.
pub struct Builder {
    start: u64,
    throttle: Arc<dyn Throttle>,
    proxies: ProxyList,
}

impl Builder {
    /// Where the manual clock starts (Unix seconds).
    pub fn start(mut self, start: u64) -> Self {
        self.start = start;
        self
    }

    /// Another throttle than `NoThrottle`.
    pub fn throttle(mut self, throttle: Arc<dyn Throttle>) -> Self {
        self.throttle = throttle;
        self
    }

    /// The proxies whose forwarding headers are believed.
    pub fn proxies(mut self, proxies: ProxyList) -> Self {
        self.proxies = proxies;
        self
    }

    pub async fn build(self) -> TestApp {
        TestApp::start(self).await
    }
}

/// The server in a temporary directory, with both routers.
pub struct TestApp {
    /// The state both routers share.
    pub state: FerretState,
    /// The clock of the state; `advance` and `set` move it.
    pub clock: Arc<ManualClock>,
    /// The data directory (removed when the app is dropped).
    pub dir: PathBuf,
    vault: Router,
    admin: Router,
    jars: Mutex<BTreeMap<Which, Jar>>,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TestApp {
    /// A server with the manual clock at [`START`], no throttle and no trusted
    /// proxy.
    pub async fn new() -> TestApp {
        Self::builder().build().await
    }

    /// A server whose clock starts at the real time of the machine. For tests
    /// that go through the kit's pages: the kit checks its own cookies against
    /// the system clock, so a session made at [`START`] is not one to it.
    pub async fn new_at_real_time() -> TestApp {
        let now = u64::try_from(vole_kit::auth::session::now_unix()).expect("a time");
        Self::builder().start(now).build().await
    }

    pub fn builder() -> Builder {
        Builder {
            start: START,
            throttle: Arc::new(NoThrottle),
            proxies: ProxyList::parse(&[]).expect("an empty proxy list"),
        }
    }

    async fn start(settings: Builder) -> TestApp {
        let dir = std::env::temp_dir().join(format!(
            "ferret-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create the data directory");
        let clock = Arc::new(ManualClock::new(settings.start));
        let config = Config {
            data_dir: dir.clone(),
            host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            vault_port: 3041,
            admin_port: 3040,
            vault_url: VAULT_URL.to_string(),
            admin_url: ADMIN_URL.to_string(),
            trusted_proxies: Vec::new(),
        };
        // The same start-up as the binary: migrations, the secret files and the
        // check of them against the database, the login state store. Only the
        // clock, the throttle and the proxy list are the test's own.
        let mut state = ferret_server::start(&config, clock.clone() as Arc<dyn Clock>)
            .await
            .expect("start the server");
        state.throttle = settings.throttle;
        state.proxies = Arc::new(settings.proxies);
        TestApp {
            vault: server::vault_router(state.clone()),
            admin: server::admin_router(state.clone()),
            state,
            clock,
            dir,
            jars: Mutex::new(BTreeMap::new()),
        }
    }

    /// Sends a request to a listener, with the cookies that listener's jar
    /// holds (unless the request has a `Cookie` header already), and keeps the
    /// cookies of the answer. A request without a `Host` header gets the host
    /// of the listener, and one without a peer address comes from [`PEER`].
    pub async fn call(&self, which: Which, request: Request<Body>) -> Res {
        let (mut parts, body) = request.into_parts();
        if !parts.headers.contains_key(header::COOKIE) {
            let jars = self.jars.lock().expect("jars");
            if let Some(cookie) = jars.get(&which).and_then(Jar::header) {
                parts.headers.insert(
                    header::COOKIE,
                    HeaderValue::from_str(&cookie).expect("a cookie header"),
                );
            }
        }
        let res = self.call_raw(which, Request::from_parts(parts, body)).await;
        self.jars
            .lock()
            .expect("jars")
            .entry(which)
            .or_default()
            .absorb(&res.headers);
        res
    }

    /// Sends a request exactly as it is: no jar in, no jar out.
    pub async fn call_raw(&self, which: Which, mut request: Request<Body>) -> Res {
        if !request.headers().contains_key(header::HOST) {
            request
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static(which.host()));
        }
        if request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .is_none()
        {
            let peer: SocketAddr = PEER.parse().expect("a peer address");
            request.extensions_mut().insert(ConnectInfo(peer));
        }
        let router = match which {
            Which::Vault => self.vault.clone(),
            Which::Admin => self.admin.clone(),
        };
        let response = router.oneshot(request).await.expect("a response");
        let (parts, body) = response.into_parts();
        let body = to_bytes(body, 16 * 1024 * 1024).await.expect("a body");
        Res {
            status: parts.status,
            headers: parts.headers,
            body: body.to_vec(),
        }
    }

    /// A copy of the cookies of a listener's jar.
    pub fn jar(&self, which: Which) -> Jar {
        self.jars
            .lock()
            .expect("jars")
            .get(&which)
            .cloned()
            .unwrap_or_default()
    }

    /// Replaces the jar of a listener (a browser that was given cookies).
    pub fn set_jar(&self, which: Which, jar: Jar) {
        self.jars.lock().expect("jars").insert(which, jar);
    }

    /// Forgets every cookie of a listener (a closed browser).
    pub fn clear_jar(&self, which: Which) {
        self.jars.lock().expect("jars").remove(&which);
    }
}
