//! Registration of the first administrator: `register/start` and
//! `register/finish` on the vault listener, driven by the real client of
//! `ferret-core` (with the small test key stretching function) against the
//! whole server in process.

mod support;

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum_extra::extract::cookie::SignedCookieJar;
use ferret_core::testing::opaque::{TestKsf, register_finish_with};
use ferret_core::{
    AccountId, KsfProfile, MasterPassword, MethodId, MpPolicy, NewAccountIds, NewPassword,
    OpaqueInput, RegistrationState, SecureRng, TestRng, VaultId, create_account,
    opaque_register_start,
};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::wire::{b64url, hex16};
use ferret_server_auth::testing::SMALL;
use ferret_server_auth::{
    Clock as _, RecordingThrottle, RetryAfter, Stage, Throttle, ThrottleCall,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::session::{self, get_with};
use support::{Builder, Req, Res, TestApp, Which};
use vole_kit::auth::reauth;
use vole_kit::auth::session::{required_setup_token, set_setup_open_for_tests};

/// A change to a finish body, boxed with the type of its argument spelled out.
macro_rules! change {
    (|$b:ident| $body:expr) => {
        Box::new(|$b: &mut Value| {
            $body;
        }) as Box<dyn Fn(&mut Value)>
    };
}

const START: &str = "/api/auth/opaque/register/start";
const FINISH: &str = "/api/auth/opaque/register/finish";
const PASSWORD: &str = "correct horse battery staple";
const TABLES: [&str; 7] = [
    "users",
    "ferret_accounts",
    "ferret_vaults",
    "ferret_unlock_methods",
    "ferret_items",
    "ferret_checkpoints",
    "ferret_sessions",
];

// ----------------------------------------------------------------- helpers

/// An app whose proxy list holds the test peer, so a request that carries
/// `X-Forwarded-Proto: https` counts as HTTPS.
fn proxied() -> Builder {
    TestApp::builder().proxies(ProxyList::parse(&["198.51.100.10".to_string()]).expect("proxies"))
}

async fn server() -> TestApp {
    proxied().build().await
}

/// A request the way the web vault sends it through the proxy.
fn post(uri: &str, body: &Value) -> Req {
    Req::post(uri)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("sec-fetch-site", "same-origin")
        .json(body)
}

async fn call(app: &TestApp, uri: &str, body: &Value) -> Res {
    app.call_raw(Which::Vault, post(uri, body).build()).await
}

async fn count(app: &TestApp, table: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
        })
        .await
        .expect("a count")
}

async fn counts(app: &TestApp) -> Vec<i64> {
    let mut all = Vec::new();
    for table in TABLES {
        all.push(count(app, table).await);
    }
    all
}

async fn pending_rows(app: &TestApp) -> i64 {
    count_registrations(app).await
}

async fn count_registrations(app: &TestApp) -> i64 {
    count(app, "ferret_registrations").await
}

async fn nothing_was_created(app: &TestApp) {
    assert_eq!(counts(app).await, vec![0; TABLES.len()], "{TABLES:?}");
}

fn error_of(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

fn decode_id(value: &Value) -> [u8; 16] {
    hex16::decode(value.as_str().expect("an id")).expect("hex")
}

/// The client side of one registration: its OPAQUE input, the first message
/// and the state that the finish needs.
struct Client {
    input: OpaqueInput,
    state: RegistrationState,
    request: Vec<u8>,
    rng: TestRng,
}

fn client(seed: &str) -> Client {
    let mut rng = TestRng::new(format!("register client {seed}").as_bytes());
    let input = MasterPassword::new(PASSWORD.as_bytes(), MpPolicy::WithoutSecretKey)
        .expect("a password")
        .opaque_input(None);
    let (request, state) = opaque_register_start(&mut rng, &input).expect("a first message");
    Client {
        input,
        state,
        request,
        rng,
    }
}

impl Client {
    fn start_body(&self, email: &str, token: Option<&str>) -> Value {
        let mut body = json!({ "email": email, "request": b64url::encode(&self.request) });
        if let Some(token) = token {
            body["setup_token"] = json!(token);
        }
        body
    }

    /// Everything the client sends in `finish`, made from the server's answer
    /// to `start`.
    fn finish_body(mut self, started: &Value, device_name: Option<&str>) -> Value {
        let response =
            b64url::decode(started["response"].as_str().expect("a response")).expect("base64url");
        let registration = register_finish_with(
            &mut self.rng,
            self.state,
            &self.input,
            &response,
            &TestKsf::new(SMALL),
        )
        .expect("the client finishes");
        let mut method_ids = [0u8; 32];
        self.rng.fill(&mut method_ids);
        let (password_id, recovery_id) = method_ids.split_at(16);
        let ids = NewAccountIds {
            account_id: AccountId::from_bytes(decode_id(&started["account_id"])),
            vault_id: VaultId::from_bytes(decode_id(&started["vault_id"])),
            password_method_id: MethodId::from_bytes(password_id.try_into().expect("16")),
            recovery_method_id: MethodId::from_bytes(recovery_id.try_into().expect("16")),
        };
        let new = create_account(
            &mut self.rng,
            &ids,
            NewPassword {
                input: &self.input,
                registration,
                profile: KsfProfile::P1,
            },
            None,
        )
        .expect("the client makes the account");
        let wraps: Vec<Value> = new
            .wraps
            .iter()
            .map(|w| {
                json!({
                    "method_id": hex16::encode(w.method_id.as_bytes()),
                    "method_type": w.method.type_code(),
                    "kek_generation": w.kek_generation,
                    "wrap": b64url::encode(&w.wrap),
                })
            })
            .collect();
        let mut body = json!({
            "registration_id": started["registration_id"],
            "device_id": hex16::encode(&[0x5d; 16]),
            "record": b64url::encode(&new.registration_record),
            "ksf_profile": new.ksf_profile.number(),
            "sk_bit": false,
            "wraps": wraps,
            "manifest": {
                "rev": new.manifest.rev,
                "envelope": b64url::encode(&new.manifest.envelope),
                "tag": b64url::encode(&new.manifest.tag),
            },
            "checkpoint": {
                "seq": new.checkpoint.seq,
                "digest": b64url::encode(&new.checkpoint.digest),
                "mac": b64url::encode(&new.checkpoint.mac),
                "entries": b64url::encode(&new.checkpoint.entries),
            },
            "pk_a": b64url::encode(&new.pk_a),
            "pk_r": b64url::encode(&new.pk_r),
        });
        if let Some(name) = device_name {
            body["device_name"] = json!(name);
        }
        body
    }
}

/// `start` for `email`, and the finish body the client makes from the answer.
async fn prepared(app: &TestApp, email: &str) -> (Value, Value) {
    let client = client(email);
    let started = call(app, START, &client.start_body(email, None)).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let started = started.json();
    let finish = client.finish_body(&started, Some("Test browser"));
    (started, finish)
}

/// A complete registration; returns the answer to `finish`.
async fn register(app: &TestApp, email: &str) -> Res {
    let (_, finish) = prepared(app, email).await;
    call(app, FINISH, &finish).await
}

/// The text of a canary must not be found in what the server logs.
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Starts collecting everything the process logs (once) and returns the
/// buffer.
fn log_buffer() -> Arc<Mutex<Vec<u8>>> {
    static LOG: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOG.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || Sink(sink.clone()))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        buffer
    })
    .clone()
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn setup_roundtrip_with_real_client() {
    let app = server().await;
    let client = client("ada@example.test");
    let started = call(&app, START, &client.start_body("Ada@Example.test", None)).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    // The answer holds the key to `finish`, like every other answer here.
    assert_eq!(started.header("cache-control"), "no-store");
    let started = started.json();
    assert_eq!(started["ksf_profile"], 1);
    assert_eq!(
        b64url::decode(started["response"].as_str().unwrap())
            .unwrap()
            .len(),
        64
    );
    assert_eq!(count(&app, "ferret_registrations").await, 1);

    let finish = client.finish_body(&started, Some("Firefox on a laptop"));
    let done = app.call(Which::Vault, post(FINISH, &finish).build()).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    assert_eq!(done.header("cache-control"), "no-store");
    assert_eq!(
        done.json(),
        json!({ "account_id": started["account_id"], "vault_id": started["vault_id"] })
    );

    // The rows of the account, the user and the session.
    assert_eq!(counts(&app).await, vec![1, 1, 1, 2, 1, 1, 1]);
    assert_eq!(count(&app, "ferret_registrations").await, 0);
    let account_id = decode_id(&started["account_id"]);
    let vault_id = decode_id(&started["vault_id"]);
    let (user, role, record, profile, sk_hint, pk_a, pk_r, vault, created_at) = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT u.username, u.role, a.opaque_record, a.ksf_profile, a.sk_hint,
                        a.pk_a, a.pk_r, a.vault_id, a.created_at
                 FROM ferret_accounts a JOIN users u ON u.id = a.user_id
                 WHERE a.account_id = ?1",
                [account_id.as_slice()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                        r.get::<_, i64>(3)?,
                        r.get::<_, i64>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                        r.get::<_, Vec<u8>>(6)?,
                        r.get::<_, Vec<u8>>(7)?,
                        r.get::<_, i64>(8)?,
                    ))
                },
            )?)
        })
        .await
        .expect("the account");
    assert_eq!(
        user, "ada@example.test",
        "the login name is stored normalized"
    );
    assert_eq!(role, "admin");
    assert_eq!(
        record,
        b64url::decode(finish["record"].as_str().unwrap()).unwrap()
    );
    assert_eq!((profile, sk_hint), (1, 0));
    assert_eq!(
        pk_a,
        b64url::decode(finish["pk_a"].as_str().unwrap()).unwrap()
    );
    assert_eq!(
        pk_r,
        b64url::decode(finish["pk_r"].as_str().unwrap()).unwrap()
    );
    assert_eq!(vault, vault_id);
    assert_eq!(created_at, i64::try_from(app.clock.now_unix()).unwrap());
    let (site, zone, seq, items, session_scope, session_origin, device_name) = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok((
                conn.query_row(
                    "SELECT value FROM settings WHERE key = 'site_name'",
                    [],
                    |r| r.get::<_, String>(0),
                )?,
                conn.query_row(
                    "SELECT value FROM settings WHERE key = 'timezone'",
                    [],
                    |r| r.get::<_, String>(0),
                )?,
                conn.query_row("SELECT seq FROM ferret_vaults", [], |r| r.get::<_, i64>(0))?,
                conn.query_row(
                    "SELECT rev FROM ferret_items WHERE item_id = zeroblob(16)",
                    [],
                    |r| r.get::<_, i64>(0),
                )?,
                conn.query_row("SELECT scope FROM ferret_sessions", [], |r| {
                    r.get::<_, String>(0)
                })?,
                conn.query_row("SELECT origin FROM ferret_sessions", [], |r| {
                    r.get::<_, String>(0)
                })?,
                conn.query_row("SELECT device_name FROM ferret_sessions", [], |r| {
                    r.get::<_, String>(0)
                })?,
            ))
        })
        .await
        .expect("the rest");
    assert_eq!((site.as_str(), zone.as_str()), ("Faithful Ferret", "UTC"));
    assert_eq!((seq, items), (1, 1));
    assert_eq!(
        (
            session_scope.as_str(),
            session_origin.as_str(),
            device_name.as_str()
        ),
        ("full", "vault", "Firefox on a laptop")
    );

    // Both cookies, and the re-auth grant of the kit, were set; the session is
    // valid on the vault listener and nowhere else.
    let cookies = done.set_cookies();
    for name in [
        ferret_server::product::SESSION_COOKIE,
        ferret_server::product::SID_COOKIE,
        reauth::cookie_name(),
    ] {
        assert!(
            cookies.iter().any(|c| c.starts_with(&format!("{name}="))),
            "{name} in {cookies:?}"
        );
    }
    let sid = cookies
        .iter()
        .find(|c| c.starts_with("__Host-ferret_sid="))
        .expect("the sid cookie");
    for attribute in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
        assert!(sid.contains(attribute), "{attribute} in {sid}");
    }
    let router = session::router(&app);
    let jar = app.jar(Which::Vault);
    let who = get_with(&router, &jar, "/vault").await;
    assert_eq!(who.status, StatusCode::OK, "{}", who.text());
    assert_eq!(who.json()["account"], started["account_id"]);
    assert_eq!(who.json()["vault"], started["vault_id"]);
    assert_eq!(
        get_with(&router, &jar, "/admin").await.status,
        StatusCode::UNAUTHORIZED
    );
    // The grant is fresh for the new session.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        jar.header().expect("cookies").parse().unwrap(),
    );
    let signed = SignedCookieJar::from_headers(&headers, app.state.core.session_key.clone());
    assert!(reauth::is_fresh(&signed, &app.state.core.session_key));
}

#[tokio::test]
async fn wrong_or_missing_setup_token_is_403_and_throttled_after_repeated_guesses() {
    set_setup_open_for_tests(Some(false));
    let token = required_setup_token().expect("a setup token is required");
    let app = server().await;
    let c = client("token@example.test");

    let missing = call(&app, START, &c.start_body("token@example.test", None)).await;
    assert_eq!(
        (missing.status, error_of(&missing).as_str()),
        (StatusCode::FORBIDDEN, "forbidden")
    );
    let wrong = call(
        &app,
        START,
        &c.start_body("token@example.test", Some("not-the-token")),
    )
    .await;
    assert_eq!(
        (wrong.status, error_of(&wrong).as_str()),
        (StatusCode::FORBIDDEN, "forbidden")
    );
    let blank = call(
        &app,
        START,
        &c.start_body("token@example.test", Some("   ")),
    )
    .await;
    assert_eq!(blank.status, StatusCode::FORBIDDEN);
    assert_eq!(
        count_registrations(&app).await,
        0,
        "a refused guess leaves nothing"
    );

    let good = call(
        &app,
        START,
        &c.start_body("token@example.test", Some(&token)),
    )
    .await;
    assert_eq!(good.status, StatusCode::OK, "{}", good.text());

    // Guesses that come too fast are throttled, and then even the right token
    // waits.
    let mut throttled = None;
    for guess in 0..200 {
        let res = call(
            &app,
            START,
            &c.start_body("token@example.test", Some(&format!("guess-{guess}"))),
        )
        .await;
        if res.status == StatusCode::TOO_MANY_REQUESTS {
            throttled = Some(res);
            break;
        }
        assert_eq!(res.status, StatusCode::FORBIDDEN, "guess {guess}");
    }
    let throttled = throttled.expect("repeated guesses are throttled");
    assert_eq!(error_of(&throttled), "throttled");
    assert!(throttled.header("retry-after").parse::<u32>().unwrap() >= 1);
    let blocked = call(
        &app,
        START,
        &c.start_body("token@example.test", Some(&token)),
    )
    .await;
    assert_eq!(blocked.status, StatusCode::TOO_MANY_REQUESTS);

    // A token that is far too long is refused before it is compared.
    let long = "x".repeat(300);
    let res = call(
        &app,
        START,
        &c.start_body("token@example.test", Some(&long)),
    )
    .await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
}

#[tokio::test]
async fn starts_without_a_token_are_refused_before_the_kit_and_the_throttle() {
    let log = log_buffer();
    set_setup_open_for_tests(Some(false));
    let token = required_setup_token().expect("a setup token is required");
    let throttle = Arc::new(RecordingThrottle::new());
    let app = proxied()
        .throttle(throttle.clone() as Arc<dyn Throttle>)
        .build()
        .await;
    let c = client("tokenless@example.test");
    for n in 0..200 {
        let given = if n % 2 == 0 { None } else { Some("  ") };
        let res = call(&app, START, &c.start_body("tokenless@example.test", given)).await;
        assert_eq!(
            (res.status, error_of(&res).as_str()),
            (StatusCode::FORBIDDEN, "forbidden"),
            "request {n}"
        );
    }
    assert!(
        throttle.calls().is_empty(),
        "the library throttle was not asked"
    );
    assert_eq!(count_registrations(&app).await, 0);
    let logged = String::from_utf8_lossy(
        &log.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    assert!(
        !logged.contains("setup page opened without the setup token"),
        "a start without a token wrote a warning line"
    );

    // Nothing was counted against the address: the right token still works.
    let ok = call(
        &app,
        START,
        &c.start_body("tokenless@example.test", Some(&token)),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
}

#[tokio::test]
async fn transport_is_checked_before_the_body_is_read() {
    let app = server().await;
    for uri in [START, FINISH] {
        // Plain HTTP (no `X-Forwarded-Proto`), with a body that is not JSON, one
        // that is far too large, and a type that is not JSON.
        for (content_type, body) in [
            ("application/json", b"not json".to_vec()),
            ("application/json", vec![b' '; 300 * 1024]),
            ("text/plain", b"{}".to_vec()),
        ] {
            let req = Request::builder()
                .method("POST")
                .uri(uri)
                .header("origin", support::VAULT_URL)
                .header("ferret-protocol", "1")
                .header("content-type", content_type)
                .body(Body::from(body))
                .unwrap();
            let res = app.call_raw(Which::Vault, req).await;
            assert_eq!(
                (res.status, error_of(&res).as_str()),
                (StatusCode::BAD_REQUEST, "insecure_transport"),
                "{uri} {content_type}"
            );
        }
    }
    assert_eq!(count_registrations(&app).await, 0);
}

#[tokio::test]
async fn pending_rows_are_capped_at_64_and_the_oldest_go_first() {
    // Every start is admitted, so the cap is what limits the table.
    let throttle = Arc::new(RecordingThrottle::new());
    let app = proxied()
        .throttle(throttle as Arc<dyn Throttle>)
        .build()
        .await;
    let (_, first) = prepared(&app, "name0@example.test").await;
    for n in 1..=64 {
        // The rows must differ in age, or "oldest" has no meaning.
        app.clock.advance(1);
        let name = format!("name{n}@example.test");
        let started = call(&app, START, &client(&name).start_body(&name, None)).await;
        assert_eq!(started.status, StatusCode::OK, "{n}: {}", started.text());
        let expected = i64::from(n + 1).min(64);
        assert_eq!(count_registrations(&app).await, expected, "after {n}");
    }
    assert_eq!(count_registrations(&app).await, 64);
    let res = call(&app, FINISH, &first).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::UNAUTHORIZED, "denied"),
        "the oldest row was dropped"
    );
    nothing_was_created(&app).await;
}

#[tokio::test]
async fn a_start_sweeps_the_rows_that_expired() {
    let app = server().await;
    let (_, early) = prepared(&app, "early@example.test").await;
    app.clock.advance(300);
    let (_, middle) = prepared(&app, "middle@example.test").await;
    assert_eq!(count_registrations(&app).await, 2);
    // The first row expires at 600; the second still has 300 seconds.
    app.clock.advance(300);
    prepared(&app, "last@example.test").await;
    assert_eq!(
        count_registrations(&app).await,
        2,
        "the expired row was removed by the start, not by a finish"
    );
    let res = call(&app, FINISH, &early).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    let res = call(&app, FINISH, &middle).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
}

#[tokio::test]
async fn finishing_removes_every_waiting_registration() {
    let app = server().await;
    let (_, first) = prepared(&app, "first@example.test").await;
    let (_, other) = prepared(&app, "other@example.test").await;
    let (_, third) = prepared(&app, "third@example.test").await;
    assert_eq!(count_registrations(&app).await, 3);
    let res = call(&app, FINISH, &first).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    assert_eq!(
        count_registrations(&app).await,
        0,
        "the rows of the names that did not finish are gone"
    );
    for body in [other, third] {
        let res = call(&app, FINISH, &body).await;
        assert_eq!(
            (res.status, error_of(&res).as_str()),
            (StatusCode::UNAUTHORIZED, "denied")
        );
    }
    assert_eq!(count(&app, "users").await, 1);
}

#[tokio::test]
async fn the_secret_key_bit_is_stored_as_the_hint() {
    for (sk_bit, expected) in [(true, 1_i64), (false, 0)] {
        let app = server().await;
        let (_, mut finish) = prepared(&app, "hint@example.test").await;
        finish["sk_bit"] = json!(sk_bit);
        let res = call(&app, FINISH, &finish).await;
        assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
        let hint: i64 = app
            .state
            .vault_db
            .with_conn(|conn| {
                Ok(conn.query_row("SELECT sk_hint FROM ferret_accounts", [], |r| r.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(hint, expected, "sk_bit {sk_bit}");
    }
}

#[tokio::test]
async fn a_method_id_may_not_be_the_account_id_or_the_vault_id() {
    let app = server().await;
    for (n, which) in ["account_id", "vault_id"].into_iter().enumerate() {
        for slot in 0..2 {
            let (started, mut finish) = prepared(&app, &format!("ids{n}{slot}@example.test")).await;
            finish["wraps"][slot]["method_id"] = started[which].clone();
            let res = call(&app, FINISH, &finish).await;
            assert_eq!(
                (res.status, error_of(&res).as_str()),
                (StatusCode::BAD_REQUEST, "bad_request"),
                "{which} in wrap {slot}"
            );
            nothing_was_created(&app).await;
        }
    }
}

#[tokio::test]
async fn second_registration_after_the_first_user_is_409_registration_closed() {
    let app = server().await;
    assert_eq!(
        register(&app, "first@example.test").await.status,
        StatusCode::CREATED
    );

    let second = client("second@example.test");
    let res = call(&app, START, &second.start_body("second@example.test", None)).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::CONFLICT, "registration_closed")
    );
    assert_eq!(count_registrations(&app).await, 0);
    assert_eq!(count(&app, "users").await, 1);
}

#[tokio::test]
async fn two_finishes_at_once_let_exactly_one_through() {
    for round in 0..3 {
        let app = server().await;
        let (_, first) = prepared(&app, &format!("one{round}@example.test")).await;
        let (_, second) = prepared(&app, &format!("two{round}@example.test")).await;
        assert_eq!(count_registrations(&app).await, 2);
        let (a, b) = tokio::join!(call(&app, FINISH, &first), call(&app, FINISH, &second));
        // The loser either took its waiting row before the winner committed
        // (and finds the server closed, 409), or finds the row already removed
        // by the winner's transaction (and is denied, 401).
        let (winner, loser) = if a.status == StatusCode::CREATED {
            (&a, &b)
        } else {
            (&b, &a)
        };
        assert_eq!(winner.status, StatusCode::CREATED, "round {round}");
        let loser_answer = (loser.status, error_of(loser));
        assert!(
            loser_answer == (StatusCode::CONFLICT, "registration_closed".to_string())
                || loser_answer == (StatusCode::UNAUTHORIZED, "denied".to_string()),
            "round {round}: {loser_answer:?}"
        );
        assert_eq!(
            counts(&app).await,
            vec![1, 1, 1, 2, 1, 1, 1],
            "round {round}"
        );
    }
}

#[tokio::test]
async fn registration_is_atomic_when_the_manifest_is_invalid() {
    let app = server().await;
    let cases: Vec<Case> = vec![
        (
            "an item envelope for a manifest",
            change!(|body| {
                let mut envelope =
                    b64url::decode(body["manifest"]["envelope"].as_str().unwrap()).unwrap();
                envelope[2] = 1;
                body["manifest"]["envelope"] = json!(b64url::encode(&envelope));
            }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_envelope",
        ),
        (
            "revision 2",
            change!(|body| body["manifest"]["rev"] = json!(2)),
            StatusCode::BAD_REQUEST,
            "bad_request",
        ),
        (
            "garbage",
            change!(|body| body["manifest"]["envelope"] = json!(b64url::encode(&[7u8; 100]))),
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_envelope",
        ),
        (
            "over 65536 bytes",
            change!(|body| body["manifest"]["envelope"] = json!(b64url::encode(&vec![0u8; 65_537]))),
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
        ),
    ];
    for (n, (what, change, status, code)) in cases.into_iter().enumerate() {
        let (_, mut finish) = prepared(&app, &format!("atomic{n}@example.test")).await;
        change(&mut finish);
        let res = call(&app, FINISH, &finish).await;
        assert_eq!(
            (res.status, error_of(&res).as_str()),
            (status, code),
            "{what}"
        );
        nothing_was_created(&app).await;
        assert_eq!(pending_rows(&app).await, 0, "the try took its own row");
        // The pending row is burnt by the failed try.
        let again = call(&app, FINISH, &finish).await;
        assert_eq!(
            (again.status, error_of(&again).as_str()),
            (StatusCode::UNAUTHORIZED, "denied")
        );
    }
}

#[tokio::test]
async fn a_failure_inside_the_transaction_leaves_no_row_behind() {
    let app = server().await;
    let site_before: Option<String> = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM settings WHERE key = 'site_name'",
                    [],
                    |r| r.get(0),
                )
                .ok())
        })
        .await
        .unwrap();
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER fail_session BEFORE INSERT ON ferret_sessions
                 BEGIN SELECT RAISE(ABORT, 'no sessions today'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let (_, finish) = prepared(&app, "trigger@example.test").await;
    let res = call(&app, FINISH, &finish).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::INTERNAL_SERVER_ERROR, "internal")
    );
    assert!(res.set_cookies().is_empty());
    nothing_was_created(&app).await;
    let site_after: Option<String> = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn
                .query_row(
                    "SELECT value FROM settings WHERE key = 'site_name'",
                    [],
                    |r| r.get(0),
                )
                .ok())
        })
        .await
        .unwrap();
    assert_eq!(
        site_before, site_after,
        "the site settings were rolled back too"
    );

    // With the fault gone the same server registers.
    app.state
        .vault_db
        .with_conn(|conn| Ok(conn.execute_batch("DROP TRIGGER fail_session")?))
        .await
        .unwrap();
    assert_eq!(
        register(&app, "trigger@example.test").await.status,
        StatusCode::CREATED
    );
}

/// Changes to the finish body that the server must refuse, and how.
type Case = (
    &'static str,
    Box<dyn Fn(&mut Value)>,
    StatusCode,
    &'static str,
);

fn refusals() -> Vec<Case> {
    let bad = (StatusCode::BAD_REQUEST, "bad_request");
    let (s, c) = bad;
    let mut cases: Vec<Case> = vec![
        ("no wraps", change!(|b| b["wraps"] = json!([])), s, c),
        (
            "one wrap",
            change!(|b| {
                let first = b["wraps"][0].clone();
                b["wraps"] = json!([first]);
            }),
            s,
            c,
        ),
        (
            "three wraps",
            change!(|b| {
                let first = b["wraps"][0].clone();
                b["wraps"].as_array_mut().unwrap().push(first);
            }),
            s,
            c,
        ),
        (
            "two password wraps",
            change!(|b| b["wraps"][1]["method_type"] = json!(1)),
            s,
            c,
        ),
        (
            "two recovery wraps",
            change!(|b| b["wraps"][0]["method_type"] = json!(2)),
            s,
            c,
        ),
        (
            "a passkey wrap",
            change!(|b| b["wraps"][1]["method_type"] = json!(3)),
            s,
            c,
        ),
        (
            "a short password wrap",
            change!(|b| b["wraps"][0]["wrap"] = json!(b64url::encode(&[1u8; 103]))),
            s,
            c,
        ),
        (
            "a password wrap without the commitment",
            change!(|b| b["wraps"][0]["wrap"] = json!(b64url::encode(&[1u8; 72]))),
            s,
            c,
        ),
        (
            "a long recovery wrap",
            change!(|b| b["wraps"][1]["wrap"] = json!(b64url::encode(&[1u8; 73]))),
            s,
            c,
        ),
        (
            "an empty wrap",
            change!(|b| b["wraps"][1]["wrap"] = json!("")),
            s,
            c,
        ),
        (
            "generation 0",
            change!(|b| b["wraps"][0]["kek_generation"] = json!(0)),
            s,
            c,
        ),
        (
            "generation 2",
            change!(|b| b["wraps"][1]["kek_generation"] = json!(2)),
            s,
            c,
        ),
        (
            "a generation above u32",
            change!(|b| b["wraps"][0]["kek_generation"] = json!(4_294_967_297u64)),
            s,
            c,
        ),
        (
            "the same method id twice",
            change!(|b| {
                let id = b["wraps"][0]["method_id"].clone();
                b["wraps"][1]["method_id"] = id;
            }),
            s,
            c,
        ),
        (
            "a zero method id",
            change!(|b| b["wraps"][0]["method_id"] = json!("0".repeat(32))),
            s,
            c,
        ),
        (
            "a passkey credential on a password wrap",
            change!(|b| b["wraps"][0]["credential_id"] = json!(b64url::encode(&[3u8; 16]))),
            s,
            c,
        ),
        (
            "a PRF salt on a recovery wrap",
            change!(|b| b["wraps"][1]["prf_salt"] = json!(b64url::encode(&[3u8; 32]))),
            s,
            c,
        ),
        (
            "checkpoint sequence 2",
            change!(|b| b["checkpoint"]["seq"] = json!(2)),
            s,
            c,
        ),
        (
            "checkpoint sequence 0",
            change!(|b| b["checkpoint"]["seq"] = json!(0)),
            s,
            c,
        ),
        (
            "a digest that is not the hash of the entries",
            change!(|b| {
                let mut digest =
                    b64url::decode(b["checkpoint"]["digest"].as_str().unwrap()).unwrap();
                digest[0] ^= 1;
                b["checkpoint"]["digest"] = json!(b64url::encode(&digest));
            }),
            s,
            c,
        ),
        (
            "entries that were changed under the digest",
            change!(|b| {
                let mut entries =
                    b64url::decode(b["checkpoint"]["entries"].as_str().unwrap()).unwrap();
                entries[20] ^= 1;
                b["checkpoint"]["entries"] = json!(b64url::encode(&entries));
            }),
            s,
            c,
        ),
        ("no entries", change!(|b| set_entries(b, &[])), s, c),
        (
            "an entry for another item",
            change!(|b| {
                let mut entries = entries_of(b);
                entries[0] = 0x42;
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "an entry at another revision",
            change!(|b| {
                let mut entries = entries_of(b);
                entries[23] = 2;
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "an entry for another envelope",
            change!(|b| {
                let mut entries = entries_of(b);
                entries[30] ^= 1;
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "a tombstone for the manifest",
            change!(|b| {
                let mut entries = entries_of(b);
                for byte in &mut entries[24..] {
                    *byte = 0;
                }
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "a second entry",
            change!(|b| {
                let mut entries = entries_of(b);
                let mut more = vec![0u8; 56];
                more[0] = 1;
                more[23] = 1;
                more[24..].fill(9);
                entries.extend(more);
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "entries that are not a whole number of rows",
            change!(|b| {
                let mut entries = entries_of(b);
                entries.push(0);
                set_entries(b, &entries);
            }),
            s,
            c,
        ),
        (
            "an authentication key of small order",
            change!(|b| {
                let mut key = [0u8; 32];
                key[0] = 1;
                b["pk_a"] = json!(b64url::encode(&key));
            }),
            s,
            c,
        ),
        (
            "an authentication key that is no point",
            change!(|b| b["pk_a"] = json!(b64url::encode(&non_point()))),
            s,
            c,
        ),
        (
            "a recovery key of small order",
            change!(|b| b["pk_r"] = json!(b64url::encode(&[0u8; 32]))),
            s,
            c,
        ),
        (
            "a recovery key that is no point",
            change!(|b| b["pk_r"] = json!(b64url::encode(&non_point()))),
            s,
            c,
        ),
    ];
    for profile in [0u64, 2, 255, 256, 4_294_967_295] {
        cases.push((
            "a profile the table does not know",
            Box::new(move |b: &mut Value| b["ksf_profile"] = json!(profile)),
            StatusCode::UNPROCESSABLE_ENTITY,
            "profile_rejected",
        ));
    }
    cases
}

fn entries_of(body: &Value) -> Vec<u8> {
    b64url::decode(body["checkpoint"]["entries"].as_str().unwrap()).unwrap()
}

/// Sets the entries of the checkpoint and makes the digest match, so that only
/// the content is wrong.
fn set_entries(body: &mut Value, entries: &[u8]) {
    body["checkpoint"]["entries"] = json!(b64url::encode(entries));
    body["checkpoint"]["digest"] = json!(b64url::encode(&Sha256::digest(entries)));
}

/// 32 bytes that are not the encoding of any point of the curve.
fn non_point() -> [u8; 32] {
    for y in 2u8..=255 {
        let mut bytes = [0u8; 32];
        bytes[0] = y;
        if ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_err() {
            return bytes;
        }
    }
    panic!("every small y is a point");
}

#[tokio::test]
async fn rejects_wrong_wrap_count_lengths_generation_and_duplicate_method_ids() {
    let app = server().await;
    for (n, (what, change, status, code)) in refusals().into_iter().enumerate() {
        let (_, mut finish) = prepared(&app, &format!("refuse{n}@example.test")).await;
        change(&mut finish);
        let res = call(&app, FINISH, &finish).await;
        assert_eq!(
            (res.status, error_of(&res).as_str()),
            (status, code),
            "{what}: {}",
            res.text()
        );
        assert!(res.set_cookies().is_empty(), "{what}");
        nothing_was_created(&app).await;
    }
}

#[tokio::test]
async fn the_unchanged_body_passes_all_the_checks_the_refusals_change() {
    // The control of the table above: every case there changes a body that the
    // server accepts.
    let app = server().await;
    let (_, finish) = prepared(&app, "control@example.test").await;
    let res = call(&app, FINISH, &finish).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
}

#[tokio::test]
async fn fields_the_client_may_not_send_are_refused() {
    let app = server().await;
    let c = client("extra@example.test");
    // The ids are the server's: a client that names them is refused.
    let mut start = c.start_body("extra@example.test", None);
    start["account_id"] = json!(hex16::encode(&[1; 16]));
    let res = call(&app, START, &start).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "bad_request")
    );

    let (_, mut finish) = prepared(&app, "extra@example.test").await;
    finish["account_id"] = json!(hex16::encode(&[1; 16]));
    let res = call(&app, FINISH, &finish).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    nothing_was_created(&app).await;

    // Fixed sizes fail at parse with the code of the field.
    let mut short = c.start_body("extra@example.test", None);
    short["request"] = json!(b64url::encode(&[1u8; 31]));
    let res = call(&app, START, &short).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "malformed_registration_request")
    );
    let (_, mut finish) = prepared(&app, "extra2@example.test").await;
    finish["record"] = json!(b64url::encode(&[1u8; 191]));
    let res = call(&app, FINISH, &finish).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "malformed_registration_record")
    );
}

#[tokio::test]
async fn a_record_that_is_not_a_record_is_refused() {
    let app = server().await;
    let (_, mut finish) = prepared(&app, "record@example.test").await;
    // 192 bytes, but the public key inside is not a point.
    finish["record"] = json!(b64url::encode(&[0xffu8; 192]));
    let res = call(&app, FINISH, &finish).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    assert_eq!(error_of(&res), "malformed_registration_record");
    nothing_was_created(&app).await;
}

#[tokio::test]
async fn pending_is_single_use_and_expires_after_600_seconds() {
    let app = server().await;

    // Used once.
    let (_, finish) = prepared(&app, "once@example.test").await;
    assert_eq!(
        call(&app, FINISH, &finish).await.status,
        StatusCode::CREATED
    );
    let again = call(&app, FINISH, &finish).await;
    assert_eq!(
        (again.status, error_of(&again).as_str()),
        (StatusCode::UNAUTHORIZED, "denied")
    );
    assert_eq!(count(&app, "users").await, 1);

    // An id that was never issued.
    let mut unknown = finish.clone();
    unknown["registration_id"] = json!(hex16::encode(&[9; 16]));
    let res = call(&app, FINISH, &unknown).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::UNAUTHORIZED, "denied")
    );
}

#[tokio::test]
async fn a_registration_is_valid_for_599_seconds_and_not_for_600() {
    let app = server().await;
    let (_, early) = prepared(&app, "early@example.test").await;
    app.clock.advance(599);
    let res = call(&app, FINISH, &early).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());

    let app = TestApp::builder()
        .proxies(ProxyList::parse(&["198.51.100.10".to_string()]).unwrap())
        .build()
        .await;
    let (_, late) = prepared(&app, "late@example.test").await;
    assert_eq!(count_registrations(&app).await, 1);
    app.clock.advance(600);
    let res = call(&app, FINISH, &late).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::UNAUTHORIZED, "denied")
    );
    nothing_was_created(&app).await;
    assert_eq!(
        count_registrations(&app).await,
        0,
        "the expired row is gone"
    );

    // A later start works and cleans up the rows that expired.
    let (_, later) = prepared(&app, "later@example.test").await;
    assert_eq!(count_registrations(&app).await, 1);
    assert_eq!(call(&app, FINISH, &later).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn account_and_vault_ids_are_server_assigned() {
    let app = server().await;
    let c1 = client("ids@example.test");
    let first = call(&app, START, &c1.start_body("ids@example.test", None))
        .await
        .json();
    let c2 = client("ids2@example.test");
    let second = call(&app, START, &c2.start_body("ids@example.test", None))
        .await
        .json();
    for field in ["registration_id", "account_id", "vault_id"] {
        assert_ne!(first[field], second[field], "{field}");
        assert_ne!(decode_id(&first[field]), [0u8; 16], "{field}");
    }
    assert_ne!(first["account_id"], first["vault_id"]);

    // One registration per login name: the second start replaced the first.
    assert_eq!(count_registrations(&app).await, 1);
    let stale = c1.finish_body(&first, None);
    let res = call(&app, FINISH, &stale).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::UNAUTHORIZED, "denied")
    );

    // The account that is made has the ids the server handed out.
    let done = call(&app, FINISH, &c2.finish_body(&second, None)).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    assert_eq!(done.json()["account_id"], second["account_id"]);
    assert_eq!(done.json()["vault_id"], second["vault_id"]);
    let account = decode_id(&second["account_id"]);
    let found = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM ferret_accounts a JOIN ferret_vaults v ON v.account_id = a.account_id
                 WHERE a.account_id = ?1",
                [account.as_slice()],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(found, 1);
}

#[tokio::test]
async fn email_longer_than_64_chars_is_rejected_with_a_clear_error() {
    let app = server().await;
    let c = client("long@example.test");
    let domain = "@example.test";
    let name = |len: usize| format!("{}{domain}", "a".repeat(len - domain.len()));
    for (email, ok) in [
        (name(64), true),
        (name(65), false),
        (name(200), false),
        ("a".repeat(300), false),
        (String::new(), false),
        ("   ".to_string(), false),
        ("white space@example.test".to_string(), false),
        ("semi;colon@example.test".to_string(), false),
        ("zero\u{200b}width@example.test".to_string(), false),
    ] {
        let res = call(&app, START, &c.start_body(&email, None)).await;
        if ok {
            assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        } else {
            assert_eq!(
                (res.status, error_of(&res).as_str()),
                (StatusCode::BAD_REQUEST, "malformed_login_name"),
                "{email:?}"
            );
        }
    }
    // Only the 64-character name left a row.
    assert_eq!(count_registrations(&app).await, 1);
}

#[tokio::test]
async fn https_url_without_trusted_proxy_header_gives_insecure_transport_and_creates_nothing() {
    // The vault URL of the tests is https. Case 1: no trusted proxy at all.
    let app = TestApp::new().await;
    let c = client("tls@example.test");
    let res = call(&app, START, &c.start_body("tls@example.test", None)).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "insecure_transport")
    );
    assert_eq!(count_registrations(&app).await, 0);

    // Case 2: the peer is a trusted proxy but does not say https.
    let app = server().await;
    let plain = Req::post(START)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "http")
        .json(&c.start_body("tls@example.test", None))
        .build();
    let res = app.call_raw(Which::Vault, plain).await;
    assert_eq!(error_of(&res), "insecure_transport");
    let bare = Req::post(START)
        .page_fetch(Which::Vault)
        .json(&c.start_body("tls@example.test", None))
        .build();
    assert_eq!(
        error_of(&app.call_raw(Which::Vault, bare).await),
        "insecure_transport"
    );
    assert_eq!(count_registrations(&app).await, 0);

    // Case 3: a forged header from a peer that is not a trusted proxy is not
    // believed.
    let stranger = TestApp::new().await;
    let forged = Req::post(START)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(&c.start_body("tls@example.test", None))
        .build();
    assert_eq!(
        error_of(&stranger.call_raw(Which::Vault, forged).await),
        "insecure_transport"
    );
    nothing_was_created(&stranger).await;
    assert_eq!(count_registrations(&stranger).await, 0);

    // `finish` refuses the same way, before it takes the pending row, and
    // creates nothing; the same try over HTTPS then works.
    let (_, finish) = prepared(&app, "tls2@example.test").await;
    let without = Req::post(FINISH)
        .page_fetch(Which::Vault)
        .json(&finish)
        .build();
    let res = app.call_raw(Which::Vault, without).await;
    assert_eq!(error_of(&res), "insecure_transport");
    assert!(res.set_cookies().is_empty());
    nothing_was_created(&app).await;
    assert_eq!(count_registrations(&app).await, 1);
    assert_eq!(
        call(&app, FINISH, &finish).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn throttled_register_start_does_no_work() {
    let throttle = Arc::new(RecordingThrottle::refusing(RetryAfter::new(7)));
    let app = proxied()
        .throttle(throttle.clone() as Arc<dyn Throttle>)
        .build()
        .await;
    let c = client("throttle@example.test");
    let res = call(&app, START, &c.start_body("throttle@example.test", None)).await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::TOO_MANY_REQUESTS, "throttled")
    );
    assert_eq!(res.header("retry-after"), "7");
    assert_eq!(count_registrations(&app).await, 0);
    nothing_was_created(&app).await;
    let calls = throttle.calls();
    assert!(
        matches!(
            calls.as_slice(),
            [ThrottleCall::Admit {
                stage: Stage::RegisterStart,
                ..
            }]
        ),
        "admit is the only call: {calls:?}"
    );

    // Admitted, the same request is reported once, as a success.
    throttle.clear();
    throttle.refuse_with(None);
    let res = call(&app, START, &c.start_body("throttle@example.test", None)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let calls = throttle.calls();
    assert!(
        matches!(
            calls.as_slice(),
            [
                ThrottleCall::Admit {
                    stage: Stage::RegisterStart,
                    ..
                },
                ThrottleCall::Record {
                    stage: Stage::RegisterStart,
                    ..
                }
            ]
        ),
        "{calls:?}"
    );
    assert_eq!(count_registrations(&app).await, 1);
}

#[tokio::test]
async fn bodies_must_be_json_and_small() {
    let app = server().await;
    let request = |content_type: Option<&str>, body: Vec<u8>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri(START)
            .header("origin", support::VAULT_URL)
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https");
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        builder.body(Body::from(body)).unwrap()
    };
    for (content_type, what) in [
        (None, "no content type"),
        (Some("text/plain"), "text"),
        (Some("application/x-www-form-urlencoded"), "a form"),
    ] {
        let res = app
            .call_raw(Which::Vault, request(content_type, b"{}".to_vec()))
            .await;
        assert_eq!(
            (res.status, error_of(&res).as_str()),
            (StatusCode::BAD_REQUEST, "bad_request"),
            "{what}"
        );
    }
    let res = app
        .call_raw(
            Which::Vault,
            request(Some("application/json"), b"not json".to_vec()),
        )
        .await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::BAD_REQUEST, "bad_request")
    );
    let res = app
        .call_raw(
            Which::Vault,
            request(Some("application/json"), vec![b' '; 300 * 1024]),
        )
        .await;
    assert_eq!(
        (res.status, error_of(&res).as_str()),
        (StatusCode::PAYLOAD_TOO_LARGE, "too_large")
    );
    // A charset on the type is fine.
    let c = client("json@example.test");
    let ok = app
        .call_raw(
            Which::Vault,
            request(
                Some("application/json; charset=utf-8"),
                c.start_body("json@example.test", None)
                    .to_string()
                    .into_bytes(),
            ),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
    // A repeated field is refused.
    let repeated = format!(
        r#"{{"email":"a@example.test","email":"b@example.test","request":"{}"}}"#,
        b64url::encode(&[0u8; 32])
    );
    let res = app
        .call_raw(
            Which::Vault,
            request(Some("application/json"), repeated.into_bytes()),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_post_is_served() {
    let app = server().await;
    for uri in [START, FINISH] {
        let get = Req::get(uri).build();
        let res = app.call_raw(Which::Vault, get).await;
        assert_eq!(res.status, StatusCode::METHOD_NOT_ALLOWED, "{uri}");
    }
}

#[tokio::test]
async fn admin_listener_has_no_register_route() {
    let app = server().await;
    let c = client("admin@example.test");
    for uri in [START, FINISH] {
        let req = Req::post(uri)
            .page_fetch(Which::Admin)
            .header("x-forwarded-proto", "https")
            .json(&c.start_body("admin@example.test", None))
            .build();
        let res = app.call_raw(Which::Admin, req).await;
        assert!(
            res.status == StatusCode::NOT_FOUND || res.status == StatusCode::FORBIDDEN,
            "{uri}: {} {}",
            res.status,
            res.text()
        );
        assert_ne!(res.status, StatusCode::OK);
    }
    assert_eq!(count_registrations(&app).await, 0);
    nothing_was_created(&app).await;
}

#[tokio::test]
async fn register_bytes_never_reach_the_log() {
    let log = log_buffer();
    set_setup_open_for_tests(Some(false));
    // The kit logs the token it makes up for itself on purpose, when it is first
    // asked for; that line is the kit's and is not a byte of a request, so the
    // token is not one of the canaries.
    let token = required_setup_token().expect("a token");
    let app = server().await;
    let email = "canary.mail.5c1d@example.test";
    let wrong_token = "canary-token-8e2b9f";
    let device = "canary-device-77aa";

    let c = client("canary");
    let request_text = b64url::encode(&c.request);
    // A wrong token, a bad name, then a real registration whose finish is
    // refused once and then accepted.
    let res = call(&app, START, &c.start_body(email, Some(wrong_token))).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    let res = call(
        &app,
        START,
        &c.start_body(&"canary-name".repeat(30), Some(&token)),
    )
    .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let started = call(&app, START, &c.start_body(email, Some(&token))).await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let started = started.json();
    let response_text = started["response"].as_str().unwrap().to_string();
    let mut finish = c.finish_body(&started, Some(device));
    let record_text = finish["record"].as_str().unwrap().to_string();
    let envelope_text = finish["manifest"]["envelope"].as_str().unwrap().to_string();
    let pk_text = finish["pk_a"].as_str().unwrap().to_string();
    let mut broken = finish.clone();
    broken["manifest"]["rev"] = json!(5);
    let res = call(&app, FINISH, &broken).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    // The pending row is burnt: start again for the accepted try.
    let c2 = client("canary two");
    let started = call(&app, START, &c2.start_body(email, Some(&token)))
        .await
        .json();
    finish = c2.finish_body(&started, Some(device));
    let done = call(&app, FINISH, &finish).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    let cookie_values: Vec<String> = done
        .set_cookies()
        .iter()
        .filter_map(|c| {
            c.split(';')
                .next()?
                .split_once('=')
                .map(|(_, v)| v.to_string())
        })
        .collect();
    assert!(!cookie_values.is_empty());

    let logged = String::from_utf8_lossy(
        &log.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    assert!(!logged.is_empty(), "the log was collected");
    let mut secrets = vec![
        email.to_string(),
        "canary.mail".to_string(),
        wrong_token.to_string(),
        device.to_string(),
        "canary-name".to_string(),
        request_text,
        response_text,
        record_text,
        envelope_text,
        pk_text,
        PASSWORD.to_string(),
    ];
    secrets.extend(cookie_values);
    for secret in secrets {
        assert!(!logged.contains(&secret), "{secret} reached the log");
    }
}
