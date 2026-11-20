//! `POST /api/auth/redeem`: a one-time sign-in code gives a session of the
//! scope `account_reset` and nothing more, once, and every refusal is the same
//! answer whatever the account. Spec: Fase 1 § 6.3 step 1, § 4.2 (F-06).

mod support;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Json, response::IntoResponse as _, response::Response};
use ferret_core::{MasterPassword, OsRng, opaque_login_start};
use ferret_server::auth::session::Origin;
use ferret_server::http::extract::{Cap, FreshReauth, ScopedSession, SessionAuth, caps};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::wire::b64url;
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::{Value, json};
use support::backup::capture_log;
use support::session::{Seeded, get_with, issue, seed, session_version};
use support::{Jar, PEER, Req, Res, TestApp, Which};
use vole_kit::auth::sign_in_codes;

/// The address requests come from unless a test says otherwise (behind the
/// trusted proxy of the tests).
const CLIENT: &str = "203.0.113.1";

fn proxies() -> ProxyList {
    ProxyList::parse(&[PEER.split(':').next().expect("an address").to_string()])
        .expect("a proxy list")
}

/// An app that believes the test peer as a proxy, so `https` requests count and
/// `X-Forwarded-For` names the client.
async fn app() -> TestApp {
    TestApp::builder().proxies(proxies()).build().await
}

fn email(n: u8) -> String {
    format!("user{n}@example.com")
}

/// A pending code for `user`, made and stored the way the kit's Users page
/// makes one.
async fn code_for(app: &TestApp, user: i64) -> String {
    let code = sign_in_codes::generate();
    let hash = sign_in_codes::hash(&code);
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::sign_in_codes::insert(conn, user, &hash, user)?;
            Ok(())
        })
        .await
        .expect("a code");
    code
}

async fn pending(app: &TestApp, user: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(vole_kit::db::sign_in_codes::count_pending(conn, user)?))
        .await
        .expect("a count")
}

async fn sql(app: &TestApp, statement: &'static str, user: i64) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(statement, [user])?;
            Ok(())
        })
        .await
        .expect("the statement");
}

/// The redeem request from `from`, with the cookies of `jar` if any.
fn redeem_req(email: &str, code: &str, from: &str, jar: Option<&Jar>) -> Request<Body> {
    let mut req = Req::post("/api/auth/redeem")
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-for", from)
        .json(&json!({ "email": email, "code": code }));
    if let Some(cookie) = jar.and_then(Jar::header) {
        req = req.header("cookie", &cookie);
    }
    req.build()
}

async fn redeem_from(app: &TestApp, email: &str, code: &str, from: &str) -> Res {
    app.call_raw(Which::Vault, redeem_req(email, code, from, None))
        .await
}

async fn redeem(app: &TestApp, email: &str, code: &str) -> Res {
    redeem_from(app, email, code, CLIENT).await
}

/// The cookies a redeem answer set, as a browser keeps them.
fn jar_of(res: &Res) -> Jar {
    let mut jar = Jar::default();
    jar.absorb(&res.headers);
    jar
}

async fn get_vault(app: &TestApp, jar: &Jar, uri: &str) -> Res {
    let mut req = Req::get(uri).page_fetch(Which::Vault);
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

/// The session rows of a user: `(sid, scope, origin, reauth_at, revoked_at)`.
type Row = (Vec<u8>, String, String, Option<i64>, Option<i64>);

async fn sessions_of(app: &TestApp, user: i64) -> Vec<Row> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT sid_hash, scope, origin, reauth_at, revoked_at
                 FROM ferret_sessions WHERE user_id = ?1 ORDER BY issued_at, sid_hash",
            )?;
            let rows = stmt
                .query_map([user], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<Result<Vec<Row>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the session rows")
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// The one refusal, as the first test of each kind saw it.
fn assert_denied(res: &Res, why: &str) {
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "{why}: {}",
        res.text()
    );
    assert_eq!(res.body, br#"{"error":"denied"}"#, "{why}");
    assert_eq!(res.header("cache-control"), "no-store", "{why}");
    assert!(res.set_cookies().is_empty(), "{why}");
}

// ------------------------------------------------------------- the session

#[tokio::test]
async fn a_valid_code_gives_an_account_reset_session_and_nothing_more() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let code = code_for(&app, user.user_id).await;

    let res = redeem(&app, &email(1), &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({ "scope": "account_reset" }));
    assert_eq!(res.header("cache-control"), "no-store");
    // Two cookies, both for the 30 minutes of a reset session.
    let cookies = res.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    for cookie in &cookies {
        assert!(cookie.contains("Max-Age=1800"), "{cookie}");
        assert!(cookie.starts_with("__Host-"), "{cookie}");
    }
    let jar = jar_of(&res);

    // One row: account_reset, on the vault origin, never fresh.
    let rows = sessions_of(&app, user.user_id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (_, scope, origin, reauth_at, revoked_at) = &rows[0];
    assert_eq!(
        (scope.as_str(), origin.as_str(), *reauth_at, *revoked_at),
        ("account_reset", "vault", None, None)
    );

    // The session answer says what it is; a nonce can be had.
    let res = get_vault(&app, &jar, "/api/auth/session").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let info = res.json();
    assert_eq!(info["scope"], "account_reset");
    assert_eq!(info["email"], email(1));
    assert!(info.get("reauth_until").is_none(), "{info}");
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/challenge")
                .page_fetch(Which::Vault)
                .header("cookie", &jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Nothing of the vault itself.
    let res = get_vault(&app, &jar, "/api/sync/changes?since=0").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // The code is spent.
    assert_eq!(pending(&app, user.user_id).await, 0);
}

#[tokio::test]
async fn the_reset_session_carries_the_new_session_version() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let before = session_version(&app, user.user_id).await;
    let code = code_for(&app, user.user_id).await;

    let res = redeem(&app, &email(1), &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let after = session_version(&app, user.user_id).await;
    assert_eq!(
        after,
        before + 1,
        "the redeem signs the user out everywhere"
    );
    assert_eq!(sessions_of(&app, user.user_id).await.len(), 1);
    // The version lives in the session's signed cookie and is checked against
    // the user's on every request: the session counts at the new version...
    let jar = jar_of(&res);
    let res = get_vault(&app, &jar, "/api/auth/session").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // ... and at no other: one more sign-out everywhere ends it.
    sql(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        user.user_id,
    )
    .await;
    let res = get_vault(&app, &jar, "/api/auth/session").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn redeem_signs_out_every_other_session_at_once() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let other = seed(&app, 2).await;
    let vault_a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let vault_b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let admin = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 3).await;
    let others = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 4).await;
    let code = code_for(&app, user.user_id).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    // The browser of session A redeems: its own session ends as well.
    let res = app
        .call_raw(
            Which::Vault,
            redeem_req(&email(1), &code, CLIENT, Some(&vault_a.jar)),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Each ended session is announced once; the new one and the other user's
    // are not.
    let mut announced: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    while let Ok(sid) = revocations.try_recv() {
        *announced.entry(sid.0).or_default() += 1;
    }
    let expected: BTreeMap<[u8; 32], usize> = [vault_a.sid.0, vault_b.sid.0, admin.sid.0]
        .into_iter()
        .map(|sid| (sid, 1))
        .collect();
    assert_eq!(announced, expected);

    // Their rows are ended now, and their cookies open nothing.
    let at = now(&app);
    for row in sessions_of(&app, user.user_id).await {
        if row.1 == "account_reset" {
            assert_eq!(row.4, None, "the new session lives");
        } else {
            assert_eq!(row.4, Some(at), "{row:?}");
        }
    }
    for issued in [&vault_a, &vault_b] {
        let res = get_vault(&app, &issued.jar, "/api/auth/session").await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
    let res = app
        .call_raw(
            Which::Admin,
            Req::get("/api/auth/session")
                .header("cookie", &admin.jar.header().expect("cookies"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // Another user's session goes on.
    let res = get_vault(&app, &others.jar, "/api/auth/session").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(
        sessions_of(&app, other.user_id)
            .await
            .iter()
            .all(|row| row.4.is_none())
    );
}

// ------------------------------------------------------------- the code

#[tokio::test]
async fn a_code_works_once() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let code = code_for(&app, user.user_id).await;
    assert_eq!(redeem(&app, &email(1), &code).await.status, StatusCode::OK);
    let version = session_version(&app, user.user_id).await;
    assert_denied(&redeem(&app, &email(1), &code).await, "a used code");
    assert_eq!(session_version(&app, user.user_id).await, version);
    assert_eq!(sessions_of(&app, user.user_id).await.len(), 1);

    // Two requests racing for one code: one session, one refusal.
    let code = code_for(&app, user.user_id).await;
    let name = email(1);
    let (a, b) = tokio::join!(
        redeem_from(&app, &name, &code, "203.0.113.2"),
        redeem_from(&app, &name, &code, "203.0.113.3"),
    );
    let mut statuses = [a.status, b.status];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::UNAUTHORIZED]);
    let live = sessions_of(&app, user.user_id)
        .await
        .into_iter()
        .filter(|row| row.4.is_none())
        .count();
    assert_eq!(live, 1);
}

#[tokio::test]
async fn a_newer_code_revokes_the_older() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let older = code_for(&app, user.user_id).await;
    let newer = code_for(&app, user.user_id).await;
    assert_denied(&redeem(&app, &email(1), &older).await, "the older code");
    assert_eq!(pending(&app, user.user_id).await, 1);
    assert_eq!(redeem(&app, &email(1), &newer).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_expired_code_is_refused() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let version = session_version(&app, user.user_id).await;
    let code = code_for(&app, user.user_id).await;
    // The kit's 24 hours are over (its clock is SQLite's).
    sql(
        &app,
        "UPDATE sign_in_codes SET expires_at = datetime('now', '-1 second') WHERE user_id = ?1",
        user.user_id,
    )
    .await;
    assert_denied(&redeem(&app, &email(1), &code).await, "an expired code");
    assert_eq!(session_version(&app, user.user_id).await, version);
    assert!(sessions_of(&app, user.user_id).await.is_empty());
    let used: Option<String> = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row("SELECT used_at FROM sign_in_codes", [], |r| r.get(0))?)
        })
        .await
        .expect("the code row");
    assert_eq!(used, None, "an expired code is not used up");
}

// ------------------------------------------------------- the same answer

/// What a refusal looks like on the wire: status, every header, the body.
type Shape = (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>);

fn shape(res: &Res) -> Shape {
    let mut headers: Vec<(String, Vec<u8>)> = res
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    headers.sort();
    (res.status, headers, res.body.clone())
}

#[tokio::test]
async fn unknown_email_wrong_code_and_disabled_user_answer_alike() {
    let app = app().await;
    let active = seed(&app, 1).await;
    let disabled = seed(&app, 2).await;
    let third = seed(&app, 3).await;
    let spent = seed(&app, 4).await;
    let code = code_for(&app, active.user_id).await;
    let disabled_code = code_for(&app, disabled.user_id).await;
    sql(
        &app,
        "UPDATE users SET active = 0 WHERE id = ?1",
        disabled.user_id,
    )
    .await;
    let third_code = code_for(&app, third.user_id).await;
    let used = code_for(&app, spent.user_id).await;
    assert_eq!(redeem(&app, &email(4), &used).await.status, StatusCode::OK);
    let versions = [
        session_version(&app, active.user_id).await,
        session_version(&app, disabled.user_id).await,
        session_version(&app, third.user_id).await,
    ];

    let wrong = sign_in_codes::generate();
    let long = "A".repeat(200);
    let cases: Vec<(&str, String, String)> = vec![
        ("unknown e-mail", "nobody@example.com".into(), code.clone()),
        ("wrong code", email(1), wrong.clone()),
        (
            "wrong code, other spelling",
            "USER1@Example.com".into(),
            wrong,
        ),
        ("disabled user", email(2), disabled_code),
        ("another user's code", email(1), third_code),
        ("a used code", email(4), used),
        ("not an e-mail address", "a\u{0}b".into(), code.clone()),
        ("a code too long", email(1), long),
        ("an empty code", email(1), String::new()),
    ];
    let mut shapes = Vec::new();
    for (i, (why, typed, code)) in cases.iter().enumerate() {
        let from = format!("203.0.113.{}", 10 + i);
        let res = redeem_from(&app, typed, code, &from).await;
        assert_denied(&res, why);
        shapes.push((*why, shape(&res)));
    }
    let (_, first) = &shapes[0];
    for (why, other) in &shapes {
        assert_eq!(other, first, "{why}");
    }

    // Nothing changed for anybody: the codes wait, nobody was signed out.
    assert_eq!(pending(&app, active.user_id).await, 1);
    assert_eq!(pending(&app, third.user_id).await, 1);
    assert_eq!(
        [
            session_version(&app, active.user_id).await,
            session_version(&app, disabled.user_id).await,
            session_version(&app, third.user_id).await,
        ],
        versions
    );
    for user in [active, disabled, third] {
        assert!(sessions_of(&app, user.user_id).await.is_empty());
    }
}

#[tokio::test]
async fn a_second_factor_user_spends_the_code_and_gets_the_common_refusal() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let full = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let version = session_version(&app, user.user_id).await;
    let code = code_for(&app, user.user_id).await;
    sql(
        &app,
        "UPDATE users SET totp_enabled = 1 WHERE id = ?1",
        user.user_id,
    )
    .await;

    let unknown = redeem_from(&app, "nobody@example.com", &code, "203.0.113.30").await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let res = redeem(&app, &email(1), &code).await;
    assert_denied(&res, "second factor on");
    assert_eq!(shape(&res), shape(&unknown));
    // The code was spent and the user signed out before the refusal: it fails
    // closed, and no reset session exists.
    assert_eq!(pending(&app, user.user_id).await, 0);
    assert_eq!(session_version(&app, user.user_id).await, version + 1);
    let at = now(&app);
    let rows = sessions_of(&app, user.user_id).await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!((rows[0].1.as_str(), rows[0].4), ("full", Some(at)));
    assert_eq!(revocations.try_recv().expect("announced").0, full.sid.0);
    assert!(revocations.try_recv().is_err());
    let res = get_vault(&app, &full.jar, "/api/auth/session").await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn unknown_email_takes_as_long_as_a_known_one() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let _pending = code_for(&app, user.user_id).await;
    let known = email(1);
    let unknown = "nobody@example.com".to_string();
    let wrong = sign_in_codes::generate();
    // The kit's own back-off per name would answer fast after ten failures;
    // it is cleared before every attempt, for both names alike, so each
    // attempt does the whole work. Every attempt comes from an address of its
    // own, so the address limits never answer either.
    let attempt = |name: &str, n: usize, kind: usize| {
        let name = name.to_string();
        let wrong = wrong.clone();
        let app = &app;
        async move {
            app.state
                .core
                .limits
                .code_account
                .clear(&format!("code:{name}"));
            let from = format!("10.{kind}.{}.{}", n / 200, n % 200 + 1);
            let started = Instant::now();
            let res = redeem_from(app, &name, &wrong, &from).await;
            let took = started.elapsed();
            assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
            took
        }
    };
    // The key the test clears is the kit's own key for the name. Pinned here:
    // eleven failures without clearing put the name in back-off under exactly
    // that key, and clearing it ends the back-off. If the kit changes the
    // format, this fails instead of the loop below quietly timing the throttle.
    let key = format!("code:{known}");
    for n in 0..11 {
        let from = format!("10.9.0.{}", n + 1);
        let res = redeem_from(&app, &known, &wrong, &from).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    }
    let limits = &app.state.core.limits;
    assert!(
        limits
            .code_account
            .retry_after(&key, Instant::now())
            .is_some(),
        "the kit's key for a name is code:<name>"
    );
    limits.code_account.clear(&key);
    assert!(
        limits
            .code_account
            .retry_after(&key, Instant::now())
            .is_none()
    );

    // What the comparison can catch: a coarse branch on whether the account
    // exists (a lookup, a key derivation or a second statement for one kind
    // of name only), measured in-process in a debug build with a tolerance of
    // 300 µs or a quarter. It cannot see the microseconds of decoding a found
    // row, which network jitter and the limits hide anyway.
    for n in 0..20 {
        attempt(&known, n, 0).await;
        attempt(&unknown, n, 1).await;
    }
    let (mut known_times, mut unknown_times) = (Vec::new(), Vec::new());
    for n in 20..220 {
        // Alternate which goes first, so a drift of the machine hits both.
        if n % 2 == 0 {
            known_times.push(attempt(&known, n, 2).await);
            unknown_times.push(attempt(&unknown, n, 3).await);
        } else {
            unknown_times.push(attempt(&unknown, n, 3).await);
            known_times.push(attempt(&known, n, 2).await);
        }
    }
    known_times.sort();
    unknown_times.sort();
    let quartiles = |times: &[Duration]| [times[50], times[100], times[150]];
    let (k, u) = (quartiles(&known_times), quartiles(&unknown_times));
    for (a, b) in k.iter().zip(u.iter()) {
        let (low, high) = if a < b { (*a, *b) } else { (*b, *a) };
        let allowed = Duration::from_micros(300).max(high / 4);
        assert!(
            high - low <= allowed,
            "known {k:?} and unknown {u:?} differ by more than {allowed:?}"
        );
    }
    assert_eq!(pending(&app, user.user_id).await, 1);
}

// ------------------------------------------------------------- throttle

#[tokio::test]
async fn redeem_is_throttled_per_ip_and_per_typed_email_and_never_reveals_a_real_account() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let wrong = sign_in_codes::generate();

    // Ten a minute from one address, whatever the names.
    let from = "203.0.113.40";
    for i in 0..10 {
        let res = redeem_from(&app, &format!("x{i}@example.com"), &wrong, from).await;
        assert_denied(&res, "within the address limit");
    }
    let res = redeem_from(&app, "x10@example.com", &wrong, from).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(res.json(), json!({ "error": "throttled" }));
    assert_eq!(res.header("retry-after"), "60");
    // Another address goes on; after the minute this one does too.
    assert_denied(
        &redeem_from(&app, "x10@example.com", &wrong, "203.0.113.41").await,
        "another address",
    );
    app.clock.advance(60);
    assert_denied(
        &redeem_from(&app, "x10@example.com", &wrong, from).await,
        "a minute later",
    );

    // Five an hour per typed name and address: the same answers, waits and
    // bytes for a name with an account and one without.
    let mut seen = Vec::new();
    for (typed, from) in [
        (email(1), "203.0.113.50"),
        ("nobody@example.com".to_string(), "203.0.113.51"),
    ] {
        let mut answers = Vec::new();
        for _ in 0..6 {
            let res = redeem_from(&app, &typed, &wrong, from).await;
            answers.push(shape(&res));
        }
        seen.push(answers);
    }
    assert_eq!(seen[0], seen[1], "a real account is limited like any name");
    for answer in &seen[0][..5] {
        assert_eq!(answer.0, StatusCode::UNAUTHORIZED);
    }
    let throttled = &seen[0][5];
    assert_eq!(throttled.0, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        throttled
            .1
            .contains(&("retry-after".to_string(), b"3600".to_vec())),
        "{:?}",
        throttled.1
    );

    // The limit is asked first: even the right code waits, and stays pending.
    let code = code_for(&app, user.user_id).await;
    let res = redeem_from(&app, &email(1), &code, "203.0.113.50").await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(pending(&app, user.user_id).await, 1);

    // Spellings of one name are one name.
    let from = "203.0.113.52";
    for typed in [
        "USER1@example.com",
        "user1@EXAMPLE.com",
        " user1@example.com ",
    ] {
        assert_denied(&redeem_from(&app, typed, &wrong, from).await, typed);
    }
    for _ in 0..2 {
        assert_denied(&redeem_from(&app, &email(1), &wrong, from).await, "same");
    }
    let res = redeem_from(&app, "User1@Example.Com", &wrong, from).await;
    assert_eq!(res.status, StatusCode::TOO_MANY_REQUESTS);

    // The same name from another address, and an hour later from the first.
    let res = redeem_from(&app, &email(1), &code, "203.0.113.53").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    app.clock.advance(3_600);
    assert_denied(
        &redeem_from(&app, &email(1), &code, "203.0.113.50").await,
        "an hour later, the used code",
    );
}

// ------------------------------------------------------------- side effects

#[tokio::test]
async fn redeem_never_sets_the_kit_password_hash() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let hash_of = |app: &TestApp, user: i64| {
        let db = app.state.vault_db.clone();
        async move {
            db.with_conn(move |conn| {
                Ok(conn.query_row(
                    "SELECT password_hash FROM users WHERE id = ?1",
                    [user],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .await
            .expect("the hash")
        }
    };
    let before = hash_of(&app, user.user_id).await;
    let code = code_for(&app, user.user_id).await;
    assert_eq!(redeem(&app, &email(1), &code).await.status, StatusCode::OK);
    assert_eq!(hash_of(&app, user.user_id).await, before);
    // A refused one neither.
    assert_denied(&redeem(&app, &email(1), &code).await, "used");
    assert_eq!(hash_of(&app, user.user_id).await, before);
}

#[tokio::test]
async fn the_code_never_reaches_the_log() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let code = code_for(&app, user.user_id).await;
    let wrong = sign_in_codes::generate();
    let (log, guard) = capture_log();
    // A code pasted into the e-mail field, a wrong code, throttled tries, and
    // the good one in another spelling.
    assert_denied(&redeem(&app, &code, &code).await, "code as e-mail");
    assert_denied(&redeem(&app, &email(1), &wrong).await, "a wrong code");
    let mut last = None;
    for _ in 0..6 {
        last = Some(
            redeem_from(&app, &email(1), &wrong, "203.0.113.60")
                .await
                .status,
        );
    }
    assert_eq!(last, Some(StatusCode::TOO_MANY_REQUESTS));
    drop(guard);
    let refusals = log.text();
    assert!(refusals.contains("sign-in code was refused"), "{refusals}");

    // The success, in a capture of its own. Its line is not asserted: whether
    // a line is written is cached per call site for the whole process, and
    // with the other tests of this file running in parallel threads the line
    // is sometimes not delivered to this thread's subscriber, even after the
    // cache is rebuilt. Whatever does arrive is checked below.
    let (log, guard) = capture_log();
    let spelled = code.to_lowercase().replace('-', " ");
    let res = redeem_from(&app, &email(1), &spelled, "203.0.113.61").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    drop(guard);
    let success = log.text();

    let text = format!("{refusals}{success}");
    let plain = code.replace('-', "");
    for secret in [
        code.as_str(),
        plain.as_str(),
        plain.to_lowercase().as_str(),
        spelled.as_str(),
        &code[..9],
        &wrong[..9],
        "user1@example.com",
    ] {
        assert!(!text.contains(secret), "the log holds {secret:?}:\n{text}");
    }
}

// ------------------------------------------------------- what it can reach

async fn scoped<C: Cap>(session: ScopedSession<C>) -> Json<Value> {
    Json(json!({ "scope": session.scope().as_str() }))
}

async fn fresh(_fresh: FreshReauth) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

fn cap_router(app: &TestApp) -> Router {
    Router::new()
        .route("/challenge", get(scoped::<caps::Challenge>))
        .route("/reregister", get(scoped::<caps::OpaqueRegisterStart>))
        .route("/recovery-read", get(scoped::<caps::RecoveryWrapRead>))
        .route("/recover", get(scoped::<caps::Recover>))
        .route("/password", get(scoped::<caps::PasswordPut>))
        .route("/unlock-methods", get(scoped::<caps::UnlockMethodsWrite>))
        .route("/sync-write", get(scoped::<caps::SyncWrite>))
        .route("/fresh", get(fresh))
        .with_state(SessionAuth::from_ref(&app.state))
}

#[tokio::test]
async fn the_reset_session_cannot_reach_sync_or_unlock_methods() {
    let app = app().await;
    let user: Seeded = seed(&app, 1).await;
    let code = code_for(&app, user.user_id).await;
    let res = redeem(&app, &email(1), &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let jar = jar_of(&res);
    let cookie = jar.header().expect("cookies");

    // The routes of the vault: the one 401 of a session that does not count.
    let item = format!("/api/sync/items/{}", "00".repeat(16));
    for (method, uri) in [
        ("GET", "/api/sync/changes?since=0"),
        ("GET", "/api/sync/items"),
        ("GET", "/api/sync/restore-rows"),
        ("GET", "/api/sync/checkpoint"),
        ("GET", "/api/sync/events"),
        ("GET", "/api/vault/unlock-methods"),
        ("PUT", item.as_str()),
        ("POST", "/api/sync/batch"),
        ("PUT", "/api/sync/checkpoint"),
    ] {
        let mut req = Req::new(method.parse().expect("a method"), uri)
            .page_fetch(Which::Vault)
            .header("cookie", &cookie);
        if method != "GET" {
            req = req.json(&json!({}));
        }
        let res = app.call_raw(Which::Vault, req.build()).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    // The writes of unlock methods and the import window: never a success.
    for (method, uri) in [
        ("PUT", "/api/vault/unlock-methods/password"),
        ("PUT", "/api/vault/unlock-methods/recovery"),
        ("POST", "/api/sync/import"),
    ] {
        let req = Req::new(method.parse().expect("a method"), uri)
            .page_fetch(Which::Vault)
            .header("cookie", &cookie)
            .json(&json!({}));
        let res = app.call_raw(Which::Vault, req.build()).await;
        assert!(
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::FORBIDDEN,
                StatusCode::NOT_FOUND
            ]
            .contains(&res.status),
            "{method} {uri}: {} {}",
            res.status,
            res.text()
        );
    }
    // No re-authentication: a reset session never proves a password.
    let input = MasterPassword::for_unlock(b"any password at all")
        .expect("a password")
        .opaque_input(None);
    let (ke1, _state) = opaque_login_start(&mut OsRng, &input).expect("KE1");
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/opaque/login/start")
                .page_fetch(Which::Vault)
                .header("x-forwarded-proto", "https")
                .header("cookie", &cookie)
                .json(&json!({
                    "email": email(1),
                    "ke1": b64url::encode(&ke1),
                    "purpose": "reauth",
                }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());

    // By capability: the five of § 6.3 step 1 and nothing else.
    let router = cap_router(&app);
    for path in ["/challenge", "/reregister", "/recovery-read", "/recover"] {
        let res = get_with(&router, &jar, path).await;
        assert_eq!(res.status, StatusCode::OK, "{path}: {}", res.text());
        assert_eq!(res.json()["scope"], "account_reset", "{path}");
    }
    for path in ["/password", "/unlock-methods", "/sync-write", "/fresh"] {
        let res = get_with(&router, &jar, path).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{path}: {}", res.text());
    }
}

// ------------------------------------------------------------- the request

#[tokio::test]
async fn a_body_over_the_limit_or_not_json_is_refused_before_any_work() {
    let app = app().await;
    let user = seed(&app, 1).await;
    let code = code_for(&app, user.user_id).await;
    let send = |body: Body| {
        Request::post("/api/auth/redeem")
            .header("origin", Which::Vault.url())
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https")
            .header("content-type", "application/json")
            .body(body)
            .expect("a request")
    };
    let padding = " ".repeat(9 * 1024);
    let big = format!(r#"{{"email":"{}","code":"{code}"}}{padding}"#, email(1));
    let res = app.call_raw(Which::Vault, send(Body::from(big))).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    for body in [
        "not json".to_string(),
        format!(r#"{{"email":"{}"}}"#, email(1)),
        format!(r#"{{"email":"{}","code":"{code}","extra":1}}"#, email(1)),
    ] {
        let res = app.call_raw(Which::Vault, send(Body::from(body))).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    }
    assert_eq!(pending(&app, user.user_id).await, 1);
    // Plain HTTP where the vault is `https`: no cookie would stick.
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/redeem")
                .page_fetch(Which::Vault)
                .json(&json!({ "email": email(1), "code": code }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json()["error"], "insecure_transport");
    assert_eq!(pending(&app, user.user_id).await, 1);
    // The good code still works.
    assert_eq!(redeem(&app, &email(1), &code).await.status, StatusCode::OK);
}
