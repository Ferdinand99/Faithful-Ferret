//! The matrix of device tokens: the real routes, the real stores and the real
//! OPAQUE client, with devices that sign in, use their access token, renew,
//! sign out, are revoked one by one or all at once, and are ended by every
//! change of trust, while the clock moves and the server restarts.
//!
//! Each run is one account with several devices and a stream of steps. A model
//! of what the server must answer decides every step before it is sent: which
//! status and which code, what a revoked device may still do (nothing), whether
//! a renewal is the same successor again (inside the grace period, with the
//! same key, while the server still holds it) or a reuse (which revokes the
//! device), and what the purge removes. Every step is also checked against the
//! database: the revocation times, at most one unused refresh token per device,
//! the quota, and no token in clear text.
//!
//! The invariants, each checked on every step it concerns:
//!
//! * at most one live successor per device;
//! * a revoked device never gets a `200` or a token, with any token it ever
//!   held (access or refresh), and every revocation is announced;
//! * a reuse after the grace period always revokes the device;
//! * the same `(jkt, jti)` is never accepted twice while the server holds it
//!   (a restart empties the cache, which the model knows);
//! * no token, access or refresh, is in the database in clear text;
//! * the quota holds: at most 20 live devices, and the 21st is refused.
//!
//! The matrix fails when a row of its list is never reached (`ROWS`). Time is
//! the manual clock of the app. A second account, with a device that renews
//! all along, is the bystander: nothing a run does may touch it.
//!
//! `FERRET_TOKENS_MATRIX_RUNS` sets the number of runs (5 000 by default) and
//! `FERRET_TOKENS_MATRIX_SEED` the base seed; a failure names the seed of its
//! run, and `FERRET_TOKENS_MATRIX_ONLY=<seed>` runs that one alone.
//!
//! Spec: Fase 1 § 4.6, § 7.6, § 8.2 and § 11; RFC 9449 § 4 and § 11.1.

mod support;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::ConnectInfo;
use axum::http::{HeaderValue, Method, StatusCode, header};
use ferret_core::OsRng;
use ferret_server::auth::devices::REVOKED_KEEP_SECS;
use ferret_server::auth::refresh::{
    ABSOLUTE_SECS, GRACE_SECS, IDLE_SECS, USED_KEEP_SECS, purge_once,
};
use ferret_server::auth::session::end_everything_after_restore;
use ferret_server::auth::tokens::DeviceAuth;
use ferret_server::ids::{DeviceId, TokenSecret};
use ferret_server::vault::notify::Revoked;
use ferret_server::wire::{ACCESS_TOKEN_SECS, MAX_DEVICES, b64url, hex16};
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::{Value, json};
use support::accounts::{
    CLIENT_PASSWORD, Client, client_account, client_session, password_change, post_recover,
    put_password, recovered,
};
use support::device::{
    DeviceClient, LOGIN_FINISH, device_app_builder, device_body, finish_req, login_start,
};
use support::dpop::DeviceKey;
use support::m3::{Ledger, Rng, env_number, run_in_parallel, seed_of, took_recovered};
use support::{Jar, PEER, Req, Res, TestApp, VAULT_URL, Which};
use tower::ServiceExt as _;

/// The base seed of the runs.
const BASE_SEED: u64 = 0x544F_4B45_4E53_4D58;
/// How many runs there are by default.
const RUNS: u64 = 5_000;
/// How many accounts one server holds (one per run of its share of the seeds).
const ACCOUNTS_PER_APP: u64 = 100;
/// The number of the account that no step touches.
const BYSTANDER: u8 = 250;
/// The threads the runs are spread over.
const THREADS: u64 = 4;
/// From this many runs on (with the base seed of the file), every row must
/// have been reached.
const RUNS_FOR_ALL_ROWS: u64 = 400;
/// Seconds of a day.
const DAY: i64 = 86_400;
/// The longest the clock moves in one piece: the bystander renews after each
/// piece, as a device that is in use does.
const CHUNK: i64 = 20 * DAY;
/// Seconds a proof may be off the server's clock.
const PROOF_WINDOW: i64 = 60;

const REFRESH: &str = "/api/auth/token/refresh";
const REVOKE: &str = "/api/auth/token/revoke";
const SYNC: &str = "/api/sync/changes";
const DEVICES: &str = "/api/auth/devices";
const REVOKE_ALL: &str = "/api/auth/devices/revoke-all";
const NEW_PASSWORD: &str = "matrix new horse battery staple";

/// Every row of the matrix: what must have been exercised at least once.
const ROWS: &[&str] = &[
    "access.expired",
    "access.gone_after_purge",
    "access.ok",
    "access.other_key",
    "access.revoked",
    "bystander.untouched",
    "bystander.ended_by_a_restore",
    "clock.boundary",
    "clock.moved",
    "db.no_clear_text_token",
    "quota.full_refuses_the_next",
    "quota.holds",
    "purge.access_rows",
    "purge.device_deleted_after_30_days",
    "purge.idle_device_revoked",
    "purge.used_rows",
    "refresh.abs_end_revokes",
    "refresh.dead_device_refused",
    "refresh.double_with_two_proofs_one_successor",
    "refresh.fresh",
    "refresh.grace_after_restart_is_not_a_reuse",
    "refresh.grace_same_successor",
    "refresh.idle_end_revokes",
    "refresh.other_key_revokes",
    "refresh.purged_token_is_unknown",
    "refresh.reuse_after_grace_revokes",
    "refresh.reuse_of_an_older_token_revokes",
    "refresh.same_proof_twice_one_answer",
    "replay.after_restart_follows_the_model",
    "replay.refused_while_held",
    "replay.stale_proof",
    "restart.caches_emptied",
    "revoke.all",
    "revoke.announced",
    "revoke.one",
    "revoke.one_unknown",
    "signin.bad_password",
    "signin.key_in_use",
    "signin.ok",
    "signin.quota",
    "signout.ok",
    "signout.other_key_revokes",
    "signout.unknown_token",
    "trust.kit_sign_out_everywhere",
    "trust.password_change",
    "trust.recover",
    "trust.redeem",
    "trust.restore",
];

// ------------------------------------------------------------------ helpers

/// A router of our own over the app's database and clock, with an empty `jti`
/// cache and an empty grace store: the server after a start.
fn started(app: &TestApp) -> Router {
    let mut state = app.state.clone();
    state.device_auth = DeviceAuth::new(VAULT_URL);
    ferret_server::server::vault_router(state)
}

/// Sends a request to a router of our own, as the harness sends it to its
/// own.
async fn call_router(router: Router, req: Req) -> Res {
    let mut request = req.build();
    request
        .headers_mut()
        .insert(header::HOST, HeaderValue::from_static(Which::Vault.host()));
    let peer: std::net::SocketAddr = PEER.parse().expect("a peer");
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = router.oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.expect("a body");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

fn now_of(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// A copy of a token (the model holds several handles of one).
fn copy(token: &TokenSecret) -> TokenSecret {
    TokenSecret::from_wire(&token.to_wire()).expect("a token")
}

/// A token the server never made.
fn unknown_token() -> TokenSecret {
    TokenSecret::random(&mut OsRng)
}

static KEYS: AtomicU64 = AtomicU64::new(1);

/// A key no other call returns in this process.
fn new_key() -> DeviceKey {
    DeviceKey::from_counter(KEYS.fetch_add(1, Ordering::Relaxed))
}

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

/// What the model says an answer is: the status and the code (empty for an
/// answer without one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Exp {
    status: u16,
    code: &'static str,
}

const fn done(status: u16) -> Exp {
    Exp { status, code: "" }
}

const fn refused(code: &'static str) -> Exp {
    Exp { status: 401, code }
}

/// The status and the code of an answer.
fn read(res: &Res) -> Exp {
    let code = serde_json::from_slice::<Value>(&res.body)
        .ok()
        .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default();
    // Codes are static strings in the model; the few the server uses are
    // matched here so the comparison is on text.
    let code = match code.as_str() {
        "" => "",
        "dpop_invalid" => "dpop_invalid",
        "token_expired" => "token_expired",
        "token_reused" => "token_reused",
        "device_revoked" => "device_revoked",
        "quota_exceeded" => "quota_exceeded",
        "bad_request" => "bad_request",
        "denied" => "denied",
        "not_found" => "not_found",
        _ => "other",
    };
    Exp {
        status: res.status.as_u16(),
        code,
    }
}

/// A request of the web vault: its cookies, `Origin` and the protocol header,
/// over `https`.
fn page(method: Method, path: &str, jar: &Jar) -> Req {
    let mut req = Req::new(method, path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    req
}

/// A request with an access token and a proof, as a device client sends it.
fn access_req(path: &str, access: &TokenSecret, proof: &str) -> Req {
    Req::new(Method::GET, path)
        .header("authorization", &format!("DPoP {}", access.to_wire()))
        .header("dpop", proof)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
}

/// A request to a token route with the refresh token in the body.
fn token_body_req(path: &str, token: &TokenSecret, proof: &str) -> Req {
    Req::post(path)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
        .header("dpop", proof)
        .json(&json!({ "refresh_token": token.to_wire() }))
}

/// A proof of `key` for `method` and `path` on the vault origin at `iat`.
fn proof_of(
    key: &DeviceKey,
    method: &str,
    path: &str,
    iat: i64,
    token: Option<&TokenSecret>,
) -> String {
    key.proof(method, &format!("{VAULT_URL}{path}"), iat, token)
}

/// The access token and the refresh token of a `200` (the refresh token is
/// absent from an answer that has none).
fn tokens_of(res: &Res) -> (TokenSecret, TokenSecret) {
    let body = res.json();
    assert_eq!(body["token_type"], "DPoP", "{}", res.text());
    assert_eq!(body["expires_in"], 900, "{}", res.text());
    let token = |name: &str| {
        TokenSecret::from_wire(body[name].as_str().expect("a token")).expect("a token")
    };
    (token("access_token"), token("refresh_token"))
}

// ----------------------------------------------------------------- the model

/// An access token the model knows.
struct Acc {
    token: TokenSecret,
    expires: i64,
    /// The purge deleted its row.
    gone: bool,
}

/// A refresh token that was used.
struct Used {
    token: TokenSecret,
    used_at: i64,
    gone: bool,
}

/// A device, as the model knows it.
struct Dev {
    client: DeviceClient,
    id: [u8; 16],
    created: i64,
    /// The refresh token that is not used yet (the end of the chain).
    current: TokenSecret,
    /// When it was issued.
    current_issued: i64,
    accesses: Vec<Acc>,
    /// The chain of used refresh tokens, oldest first; the successor of
    /// `used[i]` is `used[i + 1]`, and of the last one `current`.
    used: Vec<Used>,
    /// The index in `used` whose successor the server still holds for a
    /// retry (the last renewal, until a restart).
    grace_for: Option<usize>,
    /// `revoked_at`.
    rev: Option<i64>,
    /// The kit moved the user's `session_version` (its own "sign out
    /// everywhere"): no token of the device is good, and `revoked_at` is
    /// still empty.
    ver_dead: bool,
    /// Every token row of the device was deleted (a restore, or the purge
    /// 30 days after the revocation).
    tokens_gone: bool,
    /// The device row was deleted.
    row_gone: bool,
}

/// Which refresh token of a device a request carries.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Current,
    Used(usize),
}

/// What the server does to the device besides answering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Effect {
    Nothing,
    Revoke,
    Rotate,
    Grace,
}

impl Dev {
    /// Whether the quota counts the device.
    fn counts(&self, now: i64) -> bool {
        self.rev.is_none() && !self.ver_dead && now < self.created + ABSOLUTE_SECS
    }

    /// Whether the model expects the device to work (as far as it can tell
    /// without looking at a token).
    fn working(&self, now: i64) -> bool {
        self.counts(now)
    }

    fn dead(&self) -> bool {
        self.rev.is_some() || self.ver_dead || self.tokens_gone
    }

    /// What a request with the access token `acc` answers.
    fn access_expect(&self, acc: usize, own: bool, replayed: bool, now: i64) -> Exp {
        let acc = &self.accesses[acc];
        if self.tokens_gone || acc.gone {
            return refused("token_expired");
        }
        if self.rev.is_some() {
            return refused("device_revoked");
        }
        if now >= acc.expires {
            return refused("token_expired");
        }
        if !own {
            return refused("dpop_invalid");
        }
        if self.ver_dead || now >= self.created + ABSOLUTE_SECS {
            return refused("device_revoked");
        }
        if replayed {
            return refused("dpop_invalid");
        }
        done(200)
    }

    /// What a renewal with `tok` answers, and what it does. The order is the
    /// route's: the row, the device, the key, the `jti`, the ends of the
    /// token, and then the rotation, the grace period or the reuse.
    fn refresh_expect(&self, tok: Tok, own: bool, replayed: bool, now: i64) -> (Exp, Effect) {
        let exists = !self.tokens_gone
            && match tok {
                Tok::Current => true,
                Tok::Used(i) => !self.used[i].gone,
            };
        if !exists {
            return (refused("token_expired"), Effect::Nothing);
        }
        if self.rev.is_some() || self.ver_dead {
            return (refused("device_revoked"), Effect::Nothing);
        }
        if !own {
            return (refused("token_reused"), Effect::Revoke);
        }
        if replayed {
            return (refused("dpop_invalid"), Effect::Nothing);
        }
        let abs_end = now >= self.created + ABSOLUTE_SECS;
        let idle_end = tok == Tok::Current && now >= self.current_issued + IDLE_SECS;
        if abs_end || idle_end {
            return (refused("token_expired"), Effect::Revoke);
        }
        match tok {
            Tok::Current => (done(200), Effect::Rotate),
            Tok::Used(i) => {
                let newest = i + 1 == self.used.len();
                if newest && now - self.used[i].used_at <= GRACE_SECS {
                    if self.grace_for == Some(i) {
                        (done(200), Effect::Grace)
                    } else {
                        (refused("token_expired"), Effect::Nothing)
                    }
                } else {
                    (refused("token_reused"), Effect::Revoke)
                }
            }
        }
    }

    /// What a sign-out with `tok` answers, and what it does.
    fn signout_expect(&self, tok: Tok, own: bool, replayed: bool, now: i64) -> (Exp, Effect) {
        let exists = !self.tokens_gone
            && match tok {
                Tok::Current => true,
                Tok::Used(i) => !self.used[i].gone,
            };
        if !exists || self.rev.is_some() {
            return (done(204), Effect::Nothing);
        }
        if !own {
            return (done(204), Effect::Revoke);
        }
        if self.ver_dead || now >= self.created + ABSOLUTE_SECS {
            return (done(204), Effect::Revoke);
        }
        if replayed {
            return (refused("dpop_invalid"), Effect::Nothing);
        }
        (done(204), Effect::Revoke)
    }

    fn locate(&self, token: &TokenSecret) -> Option<Tok> {
        let wire = token.to_wire();
        if self.current.to_wire() == wire {
            return Some(Tok::Current);
        }
        self.used
            .iter()
            .position(|u| u.token.to_wire() == wire)
            .map(Tok::Used)
    }

    fn acc_index(&self, token: &TokenSecret) -> Option<usize> {
        let wire = token.to_wire();
        self.accesses.iter().position(|a| a.token.to_wire() == wire)
    }
}

/// One request of a device that is made and answered: the proof it carries,
/// when the proof was made, whether it is the device's own key, whether the
/// server still holds its `jti`, and what to call it in a failure.
struct Attempt<'a> {
    proof: String,
    iat: i64,
    own: bool,
    replayed: bool,
    label: &'a str,
}

/// A request that was answered `2xx`, with the proof it carried: kept to be
/// sent again.
struct Sent {
    dev: usize,
    token: TokenSecret,
    is_refresh: bool,
    proof: String,
    iat: i64,
    /// How often the server had started when the proof was taken.
    epoch: u32,
}

// ------------------------------------------------------------- the bystander

/// An account that no step touches, with a device that renews all along.
struct Bystander {
    device: DeviceClient,
    created: i64,
}

impl Bystander {
    async fn new(app: &TestApp) -> Bystander {
        client_account(app, BYSTANDER).await;
        let (device, created) = Self::sign_in(app).await;
        Bystander { device, created }
    }

    async fn sign_in(app: &TestApp) -> (DeviceClient, i64) {
        let mut device = DeviceClient {
            key: new_key(),
            device_id: None,
            access: None,
            refresh: None,
        };
        let res = device
            .sign_in(app, &email(BYSTANDER), CLIENT_PASSWORD)
            .await;
        assert_eq!(res.status, StatusCode::OK, "the bystander: {}", res.text());
        (device, now_of(app))
    }

    async fn sync(&self, app: &TestApp) -> Res {
        self.device
            .send(app, self.device.token_req(app, Method::GET, SYNC))
            .await
    }

    /// The bystander's device renews and syncs: nothing a run did may have
    /// touched it. A device that is old is replaced as a client does (a new
    /// key, the old one signed out). Says whether the device it started with
    /// is the one that renewed (not a replacement), which is what "untouched"
    /// is about.
    async fn touch(&mut self, app: &TestApp) -> bool {
        let mut kept = true;
        if now_of(app) - self.created > 60 * DAY {
            kept = false;
            let old = copy(self.device.refresh.as_ref().expect("signed in"));
            let proof = self.device.proof(app, "POST", REVOKE, None);
            let res = app
                .call_raw(Which::Vault, token_body_req(REVOKE, &old, &proof).build())
                .await;
            assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());
            (self.device, self.created) = Self::sign_in(app).await;
        }
        let token = copy(self.device.refresh.as_ref().expect("signed in"));
        let proof = self.device.proof(app, "POST", REFRESH, None);
        let res = app
            .call_raw(
                Which::Vault,
                token_body_req(REFRESH, &token, &proof).build(),
            )
            .await;
        assert_eq!(
            res.status,
            StatusCode::OK,
            "the bystander's device was touched by a run: {}",
            res.text()
        );
        let (access, refresh) = tokens_of(&res);
        self.device.access = Some(access);
        self.device.refresh = Some(refresh);
        let res = self.sync(app).await;
        assert_eq!(
            res.status,
            StatusCode::OK,
            "the bystander cannot sync: {}",
            res.text()
        );
        kept
    }

    /// After a restore: every token of the device is gone, and a new device
    /// signs in.
    async fn after_a_restore(&mut self, app: &TestApp) {
        let res = self.sync(app).await;
        let ended = read(&res) == refused("token_expired");
        assert!(
            ended,
            "the bystander still syncs after a restore: {}",
            res.text()
        );
        (self.device, self.created) = Self::sign_in(app).await;
    }
}

// -------------------------------------------------------------------- a run

struct Run<'a> {
    app: &'a TestApp,
    ledger: &'a Ledger,
    bystander: &'a mut Bystander,
    seed: u64,
    rng: Rng,
    n: u8,
    client: Client,
    router: Router,
    revocations: tokio::sync::broadcast::Receiver<Revoked>,
    devs: Vec<Dev>,
    sent: Vec<Sent>,
    /// How often the server started in this run.
    epoch: u32,
    /// Every token of the run, as text, for the "never twice" check.
    issued: HashSet<String>,
    /// Every token of the run, in both forms, for the clear text check.
    patterns: Vec<Vec<u8>>,
    trace: Vec<String>,
}

impl<'a> Run<'a> {
    async fn new(
        app: &'a TestApp,
        ledger: &'a Ledger,
        bystander: &'a mut Bystander,
        n: u8,
        seed: u64,
    ) -> Run<'a> {
        let client = client_account(app, n).await;
        let router = started(app);
        let revocations = app.sync_events().subscribe_revocations();
        Run {
            app,
            ledger,
            bystander,
            seed,
            rng: Rng::new(seed),
            n,
            client,
            router,
            revocations,
            devs: Vec::new(),
            sent: Vec::new(),
            epoch: 0,
            issued: HashSet::new(),
            patterns: Vec::new(),
            trace: Vec::new(),
        }
    }

    fn now(&self) -> i64 {
        now_of(self.app)
    }

    fn note(&mut self, text: String) {
        let start = i64::try_from(support::START).expect("a time");
        self.trace
            .push(format!("[t+{}] {text}", self.now() - start));
    }

    /// A number below `n`, as seconds.
    fn below_i64(&mut self, n: usize) -> i64 {
        i64::try_from(self.rng.below(n)).expect("a small number")
    }

    fn fail(&self, what: &str) -> ! {
        panic!(
            "run with seed {} (account {}): {what}\nsteps so far:\n  {}\nreplay with FERRET_TOKENS_MATRIX_ONLY={}",
            self.seed,
            self.n,
            self.trace.join("\n  "),
            self.seed
        )
    }

    fn ensure(&self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.fail(&what());
        }
    }

    fn hit(&self, row: &str) {
        self.ledger.hit(row);
    }

    async fn send(&self, req: Req) -> Res {
        call_router(self.router.clone(), req).await
    }

    /// Checks an answer against the model: the status and the code, and no
    /// token in a refusal.
    fn check(&self, what: &str, res: &Res, exp: Exp) {
        let got = read(res);
        self.ensure(got == exp, || {
            format!("{what}: expected {exp:?}, got {got:?}: {}", res.text())
        });
        if !res.status.is_success() {
            let text = res.text();
            self.ensure(
                !text.contains("access_token") && !text.contains("refresh_token"),
                || format!("{what}: a refusal carries a token"),
            );
        }
    }

    /// Notes a token the server made: it must be new, and it is searched for
    /// in the database at the end.
    fn take_token(&mut self, token: &TokenSecret, what: &str) {
        let wire = token.to_wire();
        let fresh = self.issued.insert(wire.clone());
        self.ensure(fresh, || {
            format!("{what}: the server made a token it made before")
        });
        self.patterns.push(wire.into_bytes());
        self.patterns
            .push(b64url::decode(&token.to_wire()).expect("a token"));
    }

    /// The revocations that were announced since the last look.
    fn announced(&mut self) -> Vec<Revoked> {
        use tokio::sync::broadcast::error::TryRecvError;
        let mut seen = Vec::new();
        loop {
            match self.revocations.try_recv() {
                Ok(revoked) => seen.push(revoked),
                Err(TryRecvError::Lagged(_)) => {}
                Err(_) => break,
            }
        }
        seen
    }

    /// Every revocation that is `ids` was announced (after its commit).
    fn expect_announced(&mut self, ids: &[[u8; 16]], what: &str) {
        let seen = self.announced();
        for id in ids {
            self.ensure(seen.contains(&Revoked::Device(DeviceId(*id))), || {
                format!("{what}: the revocation of a device was not announced")
            });
            self.hit("revoke.announced");
        }
    }

    // ------------------------------------------------------- picking things

    /// A device of the run: mostly one the model counts as working.
    fn pick(&mut self) -> Option<usize> {
        if self.devs.is_empty() {
            return None;
        }
        let now = self.now();
        let working: Vec<usize> = (0..self.devs.len())
            .filter(|&i| self.devs[i].working(now))
            .collect();
        if !working.is_empty() && self.rng.chance(3, 4) {
            return Some(*self.rng.pick(&working));
        }
        Some(self.rng.below(self.devs.len()))
    }

    /// A proof of a key that is not the device's: another device's, or one no
    /// device has.
    fn foreign_proof(
        &mut self,
        of: usize,
        method: &str,
        path: &str,
        token: Option<&TokenSecret>,
    ) -> String {
        let now = self.now();
        let others: Vec<usize> = (0..self.devs.len()).filter(|&i| i != of).collect();
        if !others.is_empty() && self.rng.chance(1, 2) {
            let other = *self.rng.pick(&others);
            return proof_of(&self.devs[other].client.key, method, path, now, token);
        }
        proof_of(&new_key(), method, path, now, token)
    }

    // ------------------------------------------------------------- sign-in

    /// A sign-in with `key`, after a `login/start` for `password`.
    async fn sign_in_with(&mut self, key: &DeviceKey, password: &str) -> Res {
        let half = login_start(self.app, &email(self.n), password).await;
        let proof = proof_of(key, "POST", LOGIN_FINISH, self.now(), None);
        self.send(finish_req(&device_body(&half), Some(&proof)))
            .await
    }

    async fn sign_in(&mut self) {
        let now = self.now();
        let counted = self.devs.iter().filter(|d| d.counts(now)).count();
        let key = new_key();
        let res = self.sign_in_with(&key, &self.client.password.clone()).await;
        if counted >= MAX_DEVICES {
            self.note("sign in over the quota".to_string());
            self.check(
                "a sign-in over the quota",
                &res,
                Exp {
                    status: 413,
                    code: "quota_exceeded",
                },
            );
            self.hit("signin.quota");
            return;
        }
        self.note("sign in".to_string());
        self.check("a sign-in", &res, done(200));
        let mut client = DeviceClient {
            key,
            device_id: None,
            access: None,
            refresh: None,
        };
        client.keep(&res);
        let (access, refresh) = tokens_of(&res);
        self.take_token(&access, "sign-in");
        self.take_token(&refresh, "sign-in");
        let id = client.device_id.expect("an id");
        self.ensure(self.devs.iter().all(|d| d.id != id), || {
            "the server gave a device id twice".to_string()
        });
        self.devs.push(Dev {
            client,
            id,
            created: now,
            current: refresh,
            current_issued: now,
            accesses: vec![Acc {
                token: access,
                expires: now + i64::from(ACCESS_TOKEN_SECS),
                gone: false,
            }],
            used: Vec::new(),
            grace_for: None,
            rev: None,
            ver_dead: false,
            tokens_gone: false,
            row_gone: false,
        });
        self.hit("signin.ok");
    }

    async fn bad_password(&mut self) {
        self.note("sign in with a wrong password".to_string());
        let key = new_key();
        let res = self
            .sign_in_with(&key, "not the master password of anyone")
            .await;
        self.check("a wrong password", &res, refused("denied"));
        self.hit("signin.bad_password");
    }

    /// A sign-in with the key of a device that is known (live, revoked or
    /// ended): one key is one device.
    async fn reuse_key(&mut self) {
        let candidates: Vec<usize> = (0..self.devs.len())
            .filter(|&i| !self.devs[i].row_gone)
            .collect();
        if candidates.is_empty() {
            return self.sign_in().await;
        }
        let d = *self.rng.pick(&candidates);
        self.note(format!("sign in again with the key of device {d}"));
        let half = login_start(self.app, &email(self.n), &self.client.password.clone()).await;
        let proof = proof_of(
            &self.devs[d].client.key,
            "POST",
            LOGIN_FINISH,
            self.now(),
            None,
        );
        let res = self
            .send(finish_req(&device_body(&half), Some(&proof)))
            .await;
        self.check(
            "a known key",
            &res,
            Exp {
                status: 400,
                code: "bad_request",
            },
        );
        self.hit("signin.key_in_use");
    }

    /// Signs devices in until the account has 20 that count, then one more.
    async fn fill_quota(&mut self) {
        loop {
            let now = self.now();
            let counted = self.devs.iter().filter(|d| d.counts(now)).count();
            if counted >= MAX_DEVICES {
                break;
            }
            self.sign_in().await;
        }
        self.sign_in().await;
        self.hit("quota.full_refuses_the_next");
    }

    // ---------------------------------------------------------- the access

    async fn access_core(&mut self, d: usize, token: TokenSecret, attempt: Attempt<'_>) {
        let Attempt {
            proof,
            iat,
            own,
            replayed,
            label,
        } = attempt;
        let now = self.now();
        let stale = (now - iat).abs() > PROOF_WINDOW;
        let Some(a) = self.devs[d].acc_index(&token) else {
            self.fail("an access token the model does not know");
        };
        let exp = if stale {
            refused("dpop_invalid")
        } else {
            self.devs[d].access_expect(a, own, replayed, now)
        };
        self.note(format!("{label}: device {d}, access {a}, expect {exp:?}"));
        let res = self.send(access_req(SYNC, &token, &proof)).await;
        self.check(label, &res, exp);
        if exp.status == 200 {
            self.ensure(res.json().get("latest_seq").is_some(), || {
                "a sync answer without a sequence".to_string()
            });
            self.sent.push(Sent {
                dev: d,
                token,
                is_refresh: false,
                proof,
                iat,
                epoch: self.epoch,
            });
            self.cap_sent();
            self.hit("access.ok");
        } else if exp.code == "device_revoked" {
            self.hit("access.revoked");
        } else if exp.code == "token_expired" {
            if self.devs[d].accesses[a].gone || self.devs[d].tokens_gone {
                self.hit("access.gone_after_purge");
            } else {
                self.hit("access.expired");
            }
        } else if !own {
            self.hit("access.other_key");
        }
    }

    fn cap_sent(&mut self) {
        if self.sent.len() > 40 {
            self.sent.remove(0);
        }
    }

    async fn access(&mut self) {
        let Some(d) = self.pick() else {
            return self.sign_in().await;
        };
        let len = self.devs[d].accesses.len();
        // Mostly the newest tokens, sometimes any.
        let a = if self.rng.chance(2, 3) {
            len - 1 - self.rng.below(len.min(2))
        } else {
            self.rng.below(len)
        };
        let token = copy(&self.devs[d].accesses[a].token);
        let own = self.rng.chance(6, 7);
        let now = self.now();
        let proof = if own {
            proof_of(&self.devs[d].client.key, "GET", SYNC, now, Some(&token))
        } else {
            self.foreign_proof(d, "GET", SYNC, Some(&token))
        };
        self.access_core(
            d,
            token,
            Attempt {
                proof,
                iat: now,
                own,
                replayed: false,
                label: "access",
            },
        )
        .await;
    }

    // --------------------------------------------------------- the renewal

    /// Applies what a renewal did to the model: the tokens of a `200`, or a
    /// revocation.
    fn apply_refresh(&mut self, d: usize, tok: Tok, effect: Effect, res: &Res) {
        let now = self.now();
        match effect {
            Effect::Nothing => {}
            Effect::Revoke => {
                self.devs[d].rev = Some(now);
            }
            Effect::Rotate => {
                let (access, refresh) = tokens_of(res);
                self.take_token(&access, "renewal");
                self.take_token(&refresh, "renewal");
                let dev = &mut self.devs[d];
                let old = std::mem::replace(&mut dev.current, refresh);
                dev.used.push(Used {
                    token: old,
                    used_at: now,
                    gone: false,
                });
                dev.current_issued = now;
                dev.grace_for = Some(dev.used.len() - 1);
                dev.accesses.push(Acc {
                    token: access,
                    expires: now + i64::from(ACCESS_TOKEN_SECS),
                    gone: false,
                });
            }
            Effect::Grace => {
                let (access, refresh) = tokens_of(res);
                self.take_token(&access, "grace");
                let same = self.devs[d].current.to_wire() == refresh.to_wire();
                self.ensure(same, || {
                    format!("a retry inside the grace period got another successor (token {tok:?})")
                });
                self.devs[d].accesses.push(Acc {
                    token: access,
                    expires: now + i64::from(ACCESS_TOKEN_SECS),
                    gone: false,
                });
            }
        }
    }

    async fn refresh_core(&mut self, d: usize, token: TokenSecret, attempt: Attempt<'_>) {
        let Attempt {
            proof,
            iat,
            own,
            replayed,
            label,
        } = attempt;
        let now = self.now();
        let stale = (now - iat).abs() > PROOF_WINDOW;
        let Some(tok) = self.devs[d].locate(&token) else {
            self.fail("a refresh token the model does not know");
        };
        let (exp, effect) = if stale {
            (refused("dpop_invalid"), Effect::Nothing)
        } else {
            self.devs[d].refresh_expect(tok, own, replayed, now)
        };
        self.note(format!(
            "{label}: device {d}, {tok:?}, expect {exp:?} {effect:?}"
        ));
        let id = self.devs[d].id;
        let res = self.send(token_body_req(REFRESH, &token, &proof)).await;
        self.check(label, &res, exp);
        self.apply_refresh(d, tok, effect, &res);
        if exp.status == 200 {
            self.sent.push(Sent {
                dev: d,
                token,
                is_refresh: true,
                proof,
                iat,
                epoch: self.epoch,
            });
            self.cap_sent();
        }
        match effect {
            Effect::Revoke => self.expect_announced(&[id], label),
            _ => {
                let seen = self.announced();
                self.ensure(!seen.contains(&Revoked::Device(DeviceId(id))), || {
                    format!("{label}: a revocation was announced that did not happen")
                });
            }
        }
        // Rows that tell what the answer was.
        match (tok, exp.code, effect) {
            (Tok::Current, "", Effect::Rotate) => self.hit("refresh.fresh"),
            (_, "", Effect::Grace) => self.hit("refresh.grace_same_successor"),
            (Tok::Used(_), "token_reused", Effect::Revoke) if own => {
                let newest = matches!(tok, Tok::Used(i) if i + 1 == self.devs[d].used.len());
                if newest {
                    self.hit("refresh.reuse_after_grace_revokes");
                } else {
                    self.hit("refresh.reuse_of_an_older_token_revokes");
                }
            }
            (_, "token_reused", Effect::Revoke) => self.hit("refresh.other_key_revokes"),
            (Tok::Used(_), "token_expired", Effect::Nothing) => {
                if self.devs[d].tokens_gone
                    || matches!(tok, Tok::Used(i) if self.devs[d].used[i].gone)
                {
                    self.hit("refresh.purged_token_is_unknown");
                } else if !stale {
                    self.hit("refresh.grace_after_restart_is_not_a_reuse");
                }
            }
            (_, "token_expired", Effect::Revoke) => {
                if now >= self.devs[d].created + ABSOLUTE_SECS {
                    self.hit("refresh.abs_end_revokes");
                } else {
                    self.hit("refresh.idle_end_revokes");
                }
            }
            (_, "token_expired", Effect::Nothing) if self.devs[d].tokens_gone => {
                self.hit("refresh.purged_token_is_unknown");
            }
            (_, "device_revoked", _) => self.hit("refresh.dead_device_refused"),
            _ => {}
        }
    }

    async fn refresh(&mut self, tok: Tok, own: bool) {
        let Some(d) = self.pick() else {
            return self.sign_in().await;
        };
        let tok = match tok {
            Tok::Current => Tok::Current,
            Tok::Used(_) => {
                if self.devs[d].used.is_empty() {
                    Tok::Current
                } else if self.rng.chance(2, 3) {
                    Tok::Used(self.devs[d].used.len() - 1)
                } else {
                    Tok::Used(self.rng.below(self.devs[d].used.len()))
                }
            }
        };
        let token = match tok {
            Tok::Current => copy(&self.devs[d].current),
            Tok::Used(i) => copy(&self.devs[d].used[i].token),
        };
        let now = self.now();
        let proof = if own {
            proof_of(&self.devs[d].client.key, "POST", REFRESH, now, None)
        } else {
            self.foreign_proof(d, "POST", REFRESH, None)
        };
        self.refresh_core(
            d,
            token,
            Attempt {
                proof,
                iat: now,
                own,
                replayed: false,
                label: "renewal",
            },
        )
        .await;
    }

    /// Two renewals of the same token at once.
    async fn double_refresh(&mut self) {
        let now = self.now();
        let working: Vec<usize> = (0..self.devs.len())
            .filter(|&i| {
                self.devs[i]
                    .refresh_expect(Tok::Current, true, false, now)
                    .0
                    == done(200)
            })
            .collect();
        if working.is_empty() {
            return self.refresh(Tok::Current, true).await;
        }
        let d = *self.rng.pick(&working);
        let token = copy(&self.devs[d].current);
        let same_proof = self.rng.chance(1, 2);
        let first = proof_of(&self.devs[d].client.key, "POST", REFRESH, now, None);
        let second = if same_proof {
            first.clone()
        } else {
            proof_of(&self.devs[d].client.key, "POST", REFRESH, now, None)
        };
        self.note(format!(
            "two renewals at once on device {d} (one proof: {same_proof})"
        ));
        let a = self.send(token_body_req(REFRESH, &token, &first));
        let b = self.send(token_body_req(REFRESH, &token, &second));
        let (a, b) = tokio::join!(a, b);
        let id = self.devs[d].id;
        if same_proof {
            let mut answers = [a, b];
            answers.sort_by_key(|r| r.status.as_u16());
            let [ok, replay] = answers;
            self.check("the proof that won", &ok, done(200));
            self.check("the same proof again", &replay, refused("dpop_invalid"));
            self.apply_refresh(d, Tok::Current, Effect::Rotate, &ok);
            self.sent.push(Sent {
                dev: d,
                token,
                is_refresh: true,
                proof: first,
                iat: now,
                epoch: self.epoch,
            });
            self.cap_sent();
            self.hit("refresh.same_proof_twice_one_answer");
        } else {
            self.check("the first of two renewals", &a, done(200));
            self.check("the second of two renewals", &b, done(200));
            let (access_a, refresh_a) = tokens_of(&a);
            let (access_b, refresh_b) = tokens_of(&b);
            self.ensure(refresh_a.to_wire() == refresh_b.to_wire(), || {
                "two renewals of one token made two successors".to_string()
            });
            self.ensure(access_a.to_wire() != access_b.to_wire(), || {
                "two renewals shared an access token".to_string()
            });
            // One of them rotated and the other got the same successor in
            // the grace period; the model takes both in turn.
            self.apply_refresh(d, Tok::Current, Effect::Rotate, &a);
            let last = self.devs[d].used.len() - 1;
            self.apply_refresh(d, Tok::Used(last), Effect::Grace, &b);
            self.hit("refresh.double_with_two_proofs_one_successor");
        }
        let seen = self.announced();
        self.ensure(!seen.contains(&Revoked::Device(DeviceId(id))), || {
            "two renewals at once revoked the device".to_string()
        });
    }

    // ------------------------------------------------------------ sign-out

    async fn sign_out(&mut self) {
        let Some(d) = self.pick() else {
            return self.sign_in().await;
        };
        let now = self.now();
        let roll = self.rng.below(10);
        let (token, tok, own, label) = if roll == 0 {
            (
                unknown_token(),
                None,
                true,
                "sign-out with an unknown token",
            )
        } else if roll < 3 && !self.devs[d].used.is_empty() {
            let i = self.rng.below(self.devs[d].used.len());
            (
                copy(&self.devs[d].used[i].token),
                Some(Tok::Used(i)),
                true,
                "sign-out with a used token",
            )
        } else if roll < 5 {
            (
                copy(&self.devs[d].current),
                Some(Tok::Current),
                false,
                "sign-out with another key",
            )
        } else {
            (
                copy(&self.devs[d].current),
                Some(Tok::Current),
                true,
                "sign-out",
            )
        };
        let proof = if own {
            proof_of(&self.devs[d].client.key, "POST", REVOKE, now, None)
        } else {
            self.foreign_proof(d, "POST", REVOKE, None)
        };
        let (exp, effect) = match tok {
            Some(tok) => self.devs[d].signout_expect(tok, own, false, now),
            None => (done(204), Effect::Nothing),
        };
        self.note(format!("{label}: device {d}, expect {exp:?} {effect:?}"));
        let res = self.send(token_body_req(REVOKE, &token, &proof)).await;
        self.check(label, &res, exp);
        let id = self.devs[d].id;
        match effect {
            Effect::Revoke => {
                self.devs[d].rev = Some(now);
                self.expect_announced(&[id], label);
                if own {
                    self.hit("signout.ok");
                } else {
                    self.hit("signout.other_key_revokes");
                }
            }
            _ => {
                let seen = self.announced();
                self.ensure(!seen.contains(&Revoked::Device(DeviceId(id))), || {
                    format!("{label}: a revocation was announced that did not happen")
                });
                if tok.is_none() {
                    self.hit("signout.unknown_token");
                }
            }
        }
    }

    // ------------------------------------------------ the web vault's side

    /// A fresh browser session of the account, as the page "Devices" has.
    async fn browser(&mut self) -> support::session::Issued {
        client_session(self.app, &self.client, SessionScope::Full, 7).await
    }

    async fn revoke_one(&mut self) {
        let Some(d) = self.pick() else {
            return self.sign_in().await;
        };
        let now = self.now();
        let browser = self.browser().await;
        let dev = &self.devs[d];
        let live = dev.rev.is_none() && !dev.row_gone;
        let id = dev.id;
        let res = self
            .app
            .call_raw(
                Which::Vault,
                page(
                    Method::DELETE,
                    &format!("{DEVICES}/{}", hex16::encode(&id)),
                    &browser.jar,
                )
                .build(),
            )
            .await;
        let exp = if live {
            done(204)
        } else {
            Exp {
                status: 404,
                code: "not_found",
            }
        };
        self.note(format!("revoke device {d} from the page: expect {exp:?}"));
        self.check("revoking one device", &res, exp);
        if live {
            self.devs[d].rev = Some(now);
            self.expect_announced(&[id], "revoking one device");
            self.hit("revoke.one");
        } else {
            self.hit("revoke.one_unknown");
        }
    }

    async fn revoke_all(&mut self) {
        let now = self.now();
        let browser = self.browser().await;
        let res = self
            .app
            .call_raw(
                Which::Vault,
                page(Method::POST, REVOKE_ALL, &browser.jar).build(),
            )
            .await;
        self.note("revoke all devices".to_string());
        self.check("revoking all devices", &res, done(200));
        let ids = self.end_all_devices(now);
        let revoked = res.json()["revoked"].as_u64().unwrap_or(0);
        self.ensure(
            revoked >= u64::try_from(ids.len()).expect("a count"),
            || {
                format!(
                    "revoke all said {revoked}, and {} devices were live",
                    ids.len()
                )
            },
        );
        self.expect_announced(&ids, "revoking all devices");
        self.hit("revoke.all");
    }

    /// Every device that was not revoked is, at `now`; their ids.
    fn end_all_devices(&mut self, now: i64) -> Vec<[u8; 16]> {
        let mut ids = Vec::new();
        for dev in &mut self.devs {
            if dev.rev.is_none() && !dev.row_gone {
                dev.rev = Some(now);
                ids.push(dev.id);
            }
        }
        ids
    }

    async fn password_change(&mut self) {
        let now = self.now();
        let browser = self.browser().await;
        let password = format!("{NEW_PASSWORD} {}", self.rng.below(1_000_000));
        let change = password_change(self.app, &browser.jar, &mut self.client, &password).await;
        let res = put_password(self.app, &browser.jar, &self.client, &change).await;
        self.note("change the master password".to_string());
        self.check("a change of the password", &res, done(200));
        self.client.took_password(&change, &password);
        let ids = self.end_all_devices(now);
        self.expect_announced(&ids, "a change of the password");
        self.hit("trust.password_change");
    }

    async fn recover(&mut self) {
        let now = self.now();
        let reset = client_session(self.app, &self.client, SessionScope::AccountReset, 8).await;
        let password = format!("{NEW_PASSWORD} {}", self.rng.below(1_000_000));
        let recovery = recovered(self.app, &reset.jar, &mut self.client, &password, false).await;
        let res = post_recover(self.app, &reset.jar, &recovery).await;
        self.note("recover the account".to_string());
        self.check("a recovery", &res, done(200));
        took_recovered(&mut self.client, recovery, &password);
        let ids = self.end_all_devices(now);
        self.expect_announced(&ids, "a recovery");
        self.hit("trust.recover");
    }

    async fn redeem(&mut self) {
        static ADDRESS: AtomicU64 = AtomicU64::new(0);
        let now = self.now();
        let user = self.client.ids.user_id;
        let code = vole_kit::auth::sign_in_codes::generate();
        let hash = vole_kit::auth::sign_in_codes::hash(&code);
        self.app
            .state
            .vault_db
            .with_conn(move |conn| {
                vole_kit::db::sign_in_codes::insert(conn, user, &hash, user)?;
                Ok(())
            })
            .await
            .expect("a code");
        let n = ADDRESS.fetch_add(1, Ordering::Relaxed);
        let address = format!("198.19.{}.{}", (n / 254) % 254 + 1, n % 254 + 1);
        let res = self
            .app
            .call_raw(
                Which::Vault,
                Req::post("/api/auth/redeem")
                    .page_fetch(Which::Vault)
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-for", &address)
                    .json(&json!({ "email": email(self.n), "code": code }))
                    .build(),
            )
            .await;
        self.note("redeem a sign-in code".to_string());
        self.check("a redeemed code", &res, done(200));
        let ids = self.end_all_devices(now);
        self.expect_announced(&ids, "a redeemed code");
        self.hit("trust.redeem");
    }

    /// The sweep after a restore from a backup: every token of every account
    /// is deleted and every device revoked, the bystander's too.
    async fn restore(&mut self) {
        let now = self.now();
        self.app
            .state
            .vault_db
            .with_conn(move |conn| {
                let tx = conn.transaction()?;
                end_everything_after_restore(&tx, now)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .expect("a sweep");
        self.note("restore from a backup (the sweep)".to_string());
        for dev in &mut self.devs {
            if dev.rev.is_none() {
                dev.rev = Some(now);
            }
            dev.tokens_gone = true;
        }
        self.bystander.after_a_restore(self.app).await;
        self.hit("bystander.ended_by_a_restore");
        self.hit("trust.restore");
    }

    /// The kit's own "sign out everywhere": it raises the user's
    /// `session_version` and nothing else.
    async fn kit_sign_out(&mut self) {
        let user = self.client.ids.user_id;
        self.app
            .state
            .vault_db
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
                    [user],
                )?;
                Ok(())
            })
            .await
            .expect("a new version");
        self.note("the kit signs the user out everywhere".to_string());
        for dev in &mut self.devs {
            if dev.rev.is_none() {
                dev.ver_dead = true;
            }
        }
        self.hit("trust.kit_sign_out_everywhere");
    }

    // ----------------------------------------------- the clock and the server

    async fn advance_to(&mut self, secs: i64) {
        let mut left = secs.max(1);
        while left > 0 {
            let piece = left.min(CHUNK);
            self.app
                .clock
                .advance(u64::try_from(piece).expect("a duration"));
            left -= piece;
            let kept = self.bystander.touch(self.app).await;
            self.bystander_untouched(kept);
        }
    }

    /// The row "the bystander was not touched" counts only when the claim has a
    /// content: the bystander's own device renewed and synced, and this run had
    /// ended a device of its own account by then, so something could have
    /// reached it by mistake.
    fn bystander_untouched(&self, kept: bool) {
        if kept && self.devs.iter().any(Dev::dead) {
            self.hit("bystander.untouched");
        }
    }

    async fn advance(&mut self) {
        let now = self.now();
        let roll = self.rng.below(100);
        let jitter = self.below_i64(2);
        let mut target: Option<i64> = None;
        let mut boundary = false;
        if roll < 30 {
            target = Some(now + 1 + self.below_i64(40));
        } else if roll < 42 {
            // The end of the grace period of a renewal.
            let candidates: Vec<i64> = self
                .devs
                .iter()
                .filter_map(|d| d.used.last())
                .map(|u| u.used_at + GRACE_SECS + jitter)
                .filter(|&t| t > now)
                .collect();
            if !candidates.is_empty() {
                target = Some(*self.rng.pick(&candidates));
                boundary = true;
            }
        } else if roll < 52 {
            // The end of an access token.
            let candidates: Vec<i64> = self
                .devs
                .iter()
                .filter_map(|d| d.accesses.last())
                .map(|a| a.expires - 1 + jitter)
                .filter(|&t| t > now)
                .collect();
            if !candidates.is_empty() {
                target = Some(*self.rng.pick(&candidates));
                boundary = true;
            }
        } else if roll < 62 {
            target = Some(now + 120 + self.below_i64(720));
        } else if roll < 70 {
            target = Some(now + 900 + self.below_i64(21_000));
        } else if roll < 80 {
            // The idle end or the absolute end of a device.
            let candidates: Vec<i64> = self
                .devs
                .iter()
                .filter(|d| d.rev.is_none())
                .flat_map(|d| {
                    [
                        d.current_issued + IDLE_SECS - 1,
                        d.current_issued + IDLE_SECS,
                        d.created + ABSOLUTE_SECS - 1,
                        d.created + ABSOLUTE_SECS,
                    ]
                })
                .filter(|&t| t > now)
                .collect();
            if !candidates.is_empty() {
                target = Some(*self.rng.pick(&candidates));
                boundary = true;
            }
        } else if roll < 88 {
            target = Some(now + DAY * (1 + self.below_i64(40)));
        } else if roll < 94 {
            // 30 days after a revocation: the purge deletes the device.
            let candidates: Vec<i64> = self
                .devs
                .iter()
                .filter_map(|d| d.rev)
                .map(|r| r + REVOKED_KEEP_SECS + jitter)
                .filter(|&t| t > now)
                .collect();
            if !candidates.is_empty() {
                target = Some(*self.rng.pick(&candidates));
                boundary = true;
            }
        } else {
            target = Some(now + DAY * (91 + self.below_i64(30)));
        }
        let t = target.unwrap_or(now + 1 + self.below_i64(30));
        self.note(format!("the clock moves {} s", t - now));
        self.advance_to(t - now).await;
        self.hit("clock.moved");
        if boundary {
            self.hit("clock.boundary");
        }
    }

    /// The server restarts: the `jti` cache and the grace store are empty.
    fn restart(&mut self) {
        self.note("the server restarts".to_string());
        self.router = started(self.app);
        self.epoch += 1;
        for dev in &mut self.devs {
            dev.grace_for = None;
        }
        self.hit("restart.caches_emptied");
    }

    async fn purge(&mut self) {
        let now = self.now();
        self.note("the purge runs".to_string());
        let purged = purge_once(&self.app.state.vault_db, &*self.app.clock)
            .await
            .expect("a purge");
        // 1. expired access rows; 2. old used rows; 3. devices without a
        // live refresh token; 4. devices revoked long ago, with their rows.
        for dev in &mut self.devs {
            for acc in &mut dev.accesses {
                if acc.expires <= now && !acc.gone {
                    acc.gone = true;
                    self.ledger.hit("purge.access_rows");
                }
            }
            for used in &mut dev.used {
                if used.used_at < now - USED_KEEP_SECS && !used.gone {
                    used.gone = true;
                    self.ledger.hit("purge.used_rows");
                }
            }
            if dev.rev.is_none()
                && !dev.tokens_gone
                && !(dev.current_issued + IDLE_SECS > now && dev.created + ABSOLUTE_SECS > now)
            {
                dev.rev = Some(now);
                self.ledger.hit("purge.idle_device_revoked");
            }
            if let Some(rev) = dev.rev
                && rev < now - REVOKED_KEEP_SECS
                && !dev.row_gone
            {
                dev.tokens_gone = true;
                dev.row_gone = true;
                self.ledger.hit("purge.device_deleted_after_30_days");
            }
        }
        let _ = purged;
    }

    // ------------------------------------------------------------- replays

    /// A request that was answered `2xx` is sent again with the same proof.
    async fn replay(&mut self) {
        if self.sent.is_empty() {
            return self.access().await;
        }
        let i = self.rng.below(self.sent.len());
        let now = self.now();
        let entry = self.sent.remove(i);
        if (now - entry.iat).abs() == PROOF_WINDOW {
            // The edge of the window is the server's to draw.
            self.sent.push(entry);
            return;
        }
        let held = entry.epoch == self.epoch;
        let stale = (now - entry.iat).abs() > PROOF_WINDOW;
        let (d, token, proof, iat) = (
            entry.dev,
            copy(&entry.token),
            entry.proof.clone(),
            entry.iat,
        );
        if entry.is_refresh {
            self.refresh_core(
                d,
                token,
                Attempt {
                    proof,
                    iat,
                    own: true,
                    replayed: held,
                    label: "a renewal sent again",
                },
            )
            .await;
        } else {
            self.access_core(
                d,
                token,
                Attempt {
                    proof,
                    iat,
                    own: true,
                    replayed: held,
                    label: "a request sent again",
                },
            )
            .await;
        }
        if stale {
            self.hit("replay.stale_proof");
        } else if held {
            self.hit("replay.refused_while_held");
            // Still held: it can be sent again.
            self.sent.push(entry);
        } else {
            // The cache was empty (a restart): the model followed the
            // server. An accepted replay took a new place in the cache and
            // was kept by the core; any other outcome may or may not have
            // recorded the `jti`, so the proof is not used again.
            self.hit("replay.after_restart_follows_the_model");
        }
    }

    // ---------------------------------------------------------- the checks

    /// What the database must hold, for every device of the run.
    async fn check_db(&mut self) {
        let user = self.client.ids.user_id;
        let now = self.now();
        type Row = ([u8; 16], Option<i64>, i64);
        let rows: Vec<Row> = self
            .app
            .state
            .vault_db
            .with_conn(move |conn| {
                let mut statement = conn.prepare(
                    "SELECT d.device_id, d.revoked_at,
                            (SELECT COUNT(*) FROM ferret_refresh r
                             WHERE r.device_id = d.device_id AND r.used_at IS NULL)
                     FROM ferret_devices d WHERE d.user_id = ?1",
                )?;
                let rows = statement.query_map([user], |r| {
                    let id: Vec<u8> = r.get(0)?;
                    Ok((
                        <[u8; 16]>::try_from(id).expect("a device id"),
                        r.get::<_, Option<i64>>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .await
            .expect("the device rows");
        let kept = self.devs.iter().filter(|d| !d.row_gone).count();
        self.ensure(rows.len() == kept, || {
            format!(
                "the database holds {} devices, the model {kept}",
                rows.len()
            )
        });
        for dev in &self.devs {
            let found = rows.iter().find(|r| r.0 == dev.id);
            if dev.row_gone {
                self.ensure(found.is_none(), || {
                    "a deleted device is still there".to_string()
                });
                continue;
            }
            let Some((_, revoked_at, unused)) = found else {
                self.fail("a device has no row");
            };
            self.ensure(*revoked_at == dev.rev, || {
                format!(
                    "a device's revoked_at is {revoked_at:?}, the model has {:?}",
                    dev.rev
                )
            });
            let expected_unused = i64::from(!dev.tokens_gone);
            // At most one live successor, always: an unused row per device.
            self.ensure(*unused == expected_unused, || {
                format!("a device has {unused} unused refresh rows, expected {expected_unused}")
            });
        }
        // The quota: what the database counts as live (the predicate of the
        // sign-in) agrees with the model, and is never over 20.
        let since = now - ABSOLUTE_SECS;
        let live: i64 = self
            .app
            .state
            .vault_db
            .with_conn(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM ferret_devices d JOIN users u ON u.id = d.user_id
                     WHERE d.user_id = ?1 AND d.revoked_at IS NULL
                       AND d.session_version = u.session_version AND d.created_at > ?2",
                    rusqlite::params![user, since],
                    |r| r.get(0),
                )?)
            })
            .await
            .expect("a count");
        let counted = self.devs.iter().filter(|d| d.counts(now)).count();
        let counted = i64::try_from(counted).expect("a count");
        self.ensure(live == counted, || {
            format!("the database counts {live} live devices, the model {counted}")
        });
        self.ensure(
            live <= i64::try_from(MAX_DEVICES).expect("a number"),
            || format!("{live} devices are live, over the quota"),
        );
        // The row counts when there is a quota to hold: a device is live.
        if live > 0 {
            self.hit("quota.holds");
        }
    }

    /// Every token the run holds is looked at once more, for the devices the
    /// model has dead: none of them gets a `200` or a token.
    async fn probe_the_dead(&mut self) {
        for d in 0..self.devs.len() {
            if !self.devs[d].dead() {
                continue;
            }
            let now = self.now();
            for a in 0..self.devs[d].accesses.len() {
                let token = copy(&self.devs[d].accesses[a].token);
                let proof = proof_of(&self.devs[d].client.key, "GET", SYNC, now, Some(&token));
                let exp = self.devs[d].access_expect(a, true, false, now);
                self.ensure(exp.status != 200, || {
                    "the model lets a dead device in".to_string()
                });
                let res = self.send(access_req(SYNC, &token, &proof)).await;
                self.check("a dead device's access token", &res, exp);
            }
            let mut toks = vec![Tok::Current];
            toks.extend((0..self.devs[d].used.len()).map(Tok::Used));
            for tok in toks {
                let token = match tok {
                    Tok::Current => copy(&self.devs[d].current),
                    Tok::Used(i) => copy(&self.devs[d].used[i].token),
                };
                let proof = proof_of(&self.devs[d].client.key, "POST", REFRESH, now, None);
                let (exp, effect) = self.devs[d].refresh_expect(tok, true, false, now);
                self.ensure(exp.status != 200 && effect == Effect::Nothing, || {
                    "the model lets a dead device renew".to_string()
                });
                let res = self.send(token_body_req(REFRESH, &token, &proof)).await;
                self.check("a dead device's refresh token", &res, exp);
            }
        }
    }

    /// No token of the run is in the rows of its devices, in either form.
    async fn no_clear_text(&mut self) {
        let user = self.client.ids.user_id;
        let patterns: HashSet<Vec<u8>> = self.patterns.iter().cloned().collect();
        let issued_any = !patterns.is_empty();
        let (hits, token_rows) = self
            .app
            .state
            .vault_db
            .with_conn(move |conn| {
                let mut hits = Vec::new();
                let mut token_rows = 0usize;
                for (table, sql) in [
                    (
                        "ferret_access",
                        "SELECT * FROM ferret_access WHERE device_id IN
                         (SELECT device_id FROM ferret_devices WHERE user_id = ?1)",
                    ),
                    (
                        "ferret_refresh",
                        "SELECT * FROM ferret_refresh WHERE device_id IN
                         (SELECT device_id FROM ferret_devices WHERE user_id = ?1)",
                    ),
                    (
                        "ferret_devices",
                        "SELECT * FROM ferret_devices WHERE user_id = ?1",
                    ),
                ] {
                    let mut statement = conn.prepare(sql)?;
                    let columns = statement.column_count();
                    let mut rows = statement.query([user])?;
                    while let Some(row) = rows.next()? {
                        if table != "ferret_devices" {
                            token_rows += 1;
                        }
                        for column in 0..columns {
                            if cell_holds(row.get_ref(column)?, &patterns) {
                                hits.push(table);
                            }
                        }
                    }
                }
                Ok((hits, token_rows))
            })
            .await
            .expect("a scan");
        self.ensure(hits.is_empty(), || {
            format!("a token is in clear text in {hits:?}")
        });
        // The row counts when the scan had something to find and somewhere to
        // find it: tokens were issued, and rows of tokens were looked at.
        if token_rows > 0 && issued_any {
            self.hit("db.no_clear_text_token");
        }
    }

    async fn step(&mut self) {
        let roll = self.rng.below(100);
        match roll {
            0..=8 => self.sign_in().await,
            9..=22 => self.access().await,
            23..=34 => self.refresh(Tok::Current, true).await,
            35..=42 => self.refresh(Tok::Used(0), true).await,
            43..=46 => {
                let tok = if self.rng.chance(1, 2) {
                    Tok::Current
                } else {
                    Tok::Used(0)
                };
                self.refresh(tok, false).await;
            }
            47..=49 => self.double_refresh().await,
            50..=52 => self.sign_out().await,
            53..=55 => self.revoke_one().await,
            56 => self.revoke_all().await,
            57..=58 => self.password_change().await,
            59 => self.recover().await,
            60 => self.redeem().await,
            61 => {
                if self.rng.chance(1, 2) {
                    self.restore().await;
                } else {
                    self.sign_in().await;
                }
            }
            62 => self.kit_sign_out().await,
            63..=76 => self.advance().await,
            77..=79 => self.restart(),
            80..=83 => self.purge().await,
            84..=90 => self.replay().await,
            91 => self.bad_password().await,
            92 => self.reuse_key().await,
            93 => {
                if self.rng.chance(1, 4) {
                    self.fill_quota().await;
                } else {
                    self.sign_in().await;
                }
            }
            _ => self.access().await,
        }
        self.check_db().await;
    }

    async fn finish(&mut self) {
        self.probe_the_dead().await;
        self.check_db().await;
        self.no_clear_text().await;
        // The bystander: nothing a run did touched it.
        let kept = self.bystander.touch(self.app).await;
        self.bystander_untouched(kept);
    }
}

/// Whether a cell of a row holds one of the patterns (a token in either form)
/// as a value or inside one.
fn cell_holds(cell: rusqlite::types::ValueRef<'_>, patterns: &HashSet<Vec<u8>>) -> bool {
    let bytes: &[u8] = match cell {
        rusqlite::types::ValueRef::Text(text) | rusqlite::types::ValueRef::Blob(text) => text,
        _ => return false,
    };
    [32usize, 43]
        .into_iter()
        .any(|len| bytes.len() >= len && bytes.windows(len).any(|window| patterns.contains(window)))
}

/// Scans every table of the database for the tokens.
async fn no_token_anywhere(app: &TestApp, patterns: &HashSet<Vec<u8>>) {
    let patterns = patterns.clone();
    let hits = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let tables: Vec<String> = {
                let mut statement = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                )?;
                let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
                rows.collect::<Result<_, _>>()?
            };
            let mut hits = Vec::new();
            for table in tables {
                let mut statement = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
                let columns = statement.column_count();
                let mut rows = statement.query([])?;
                while let Some(row) = rows.next()? {
                    for column in 0..columns {
                        if cell_holds(row.get_ref(column)?, &patterns) {
                            hits.push(table.clone());
                        }
                    }
                }
            }
            Ok(hits)
        })
        .await
        .expect("a scan");
    assert!(
        hits.is_empty(),
        "a token of the matrix is in clear text in the database: {hits:?}"
    );
}

// ------------------------------------------------------------------ the runs

/// The app of a share of the runs, with the proxy list that makes `https`
/// count, and the bystander.
async fn app_with_bystander() -> (TestApp, Bystander) {
    let app = device_app_builder().build().await;
    let bystander = Bystander::new(&app).await;
    (app, bystander)
}

/// One run: a seed on an account of the app. Returns the tokens it made.
async fn one_run(
    app: &TestApp,
    bystander: &mut Bystander,
    ledger: &Ledger,
    n: u8,
    seed: u64,
) -> Vec<Vec<u8>> {
    let mut run = Run::new(app, ledger, bystander, n, seed).await;
    run.sign_in().await;
    if run.rng.chance(2, 3) {
        run.sign_in().await;
    }
    let steps = 14 + run.rng.below(12);
    for _ in 0..steps {
        run.step().await;
    }
    run.finish().await;
    let Run { patterns, .. } = run;
    patterns
}

#[test]
fn tokens_matrix_holds_for_5000_runs() {
    let runs = env_number("FERRET_TOKENS_MATRIX_RUNS", RUNS);
    let base = env_number("FERRET_TOKENS_MATRIX_SEED", BASE_SEED);
    let only = std::env::var("FERRET_TOKENS_MATRIX_ONLY")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let ledger = Ledger::new();
    let started = std::time::Instant::now();
    if let Some(seed) = only {
        let ledger = ledger.clone();
        run_in_parallel(1, 1, |_| {
            let ledger = ledger.clone();
            async move {
                let (app, mut bystander) = app_with_bystander().await;
                one_run(&app, &mut bystander, &ledger, 1, seed).await;
            }
        });
        return;
    }
    run_in_parallel(runs, THREADS, |range| {
        let ledger = ledger.clone();
        async move {
            let mut shared: Option<(TestApp, Bystander, HashSet<Vec<u8>>)> = None;
            let count = range.end - range.start;
            for (position, index) in range.enumerate() {
                let slot = u64::try_from(position).expect("a position") % ACCOUNTS_PER_APP;
                if slot == 0 {
                    if let Some((app, _, patterns)) = shared.take() {
                        no_token_anywhere(&app, &patterns).await;
                    }
                    let (app, bystander) = app_with_bystander().await;
                    shared = Some((app, bystander, HashSet::new()));
                }
                let (app, bystander, patterns) = shared.as_mut().expect("an app");
                let n = u8::try_from(slot + 1).expect("an account number");
                let made = one_run(app, bystander, &ledger, n, seed_of(base, index)).await;
                patterns.extend(made);
            }
            let _ = count;
            if let Some((app, _, patterns)) = shared.take() {
                no_token_anywhere(&app, &patterns).await;
            }
        }
    });
    println!("{runs} runs in {:?}", started.elapsed());
    if runs >= RUNS_FOR_ALL_ROWS && base == BASE_SEED {
        ledger.assert_covers(ROWS);
    }
}
