//! Sessions: the random session id, the row keyed by its hash, the kit's signed
//! cookie next to it, and the extractors that need both to agree.

mod support;

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum_extra::extract::cookie::SignedCookieJar;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferret_core::OsRng;
use ferret_server::auth::login::{PURGE_MARGIN_SECS, purge_sessions};
use ferret_server::auth::session::{
    NewSession, Origin, RESET_SESSION_ABSOLUTE_SECS, RestoreSweep, SessionRow, end_all_credentials,
    end_everything_after_restore, insert_session, limits, lookup, new_session, revoke,
    revoke_all_for_user, scoped_session_cookies, session_cookies, set_parent, within_limits,
};
use ferret_server::ids::SidHash;
use ferret_server::product::{SESSION_COOKIE, SID_COOKIE};
use ferret_server_auth::{Clock as _, SessionScope};
use sha2::{Digest as _, Sha256};
use support::session::{self, Seeded, get_with, hex, issue, seed};
use support::{Jar, Res, TestApp};
use vole_kit::auth::session::SessionClaims;

const HOUR: u64 = 3600;
const DAY: u64 = 24 * HOUR;

async fn setup() -> (TestApp, Router, Seeded) {
    let app = TestApp::new().await;
    let router = session::router(&app);
    let user = seed(&app, 1).await;
    (app, router, user)
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

async fn db<T: Send + 'static>(
    app: &TestApp,
    f: impl FnOnce(&mut rusqlite::Connection) -> rusqlite::Result<T> + Send + 'static,
) -> T {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(f(conn)?))
        .await
        .expect("a database call")
}

async fn status(router: &Router, jar: &Jar, uri: &str) -> StatusCode {
    get_with(router, jar, uri).await.status
}

async fn session_rows(app: &TestApp, user_id: i64) -> i64 {
    db(app, move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE user_id = ?1",
            [user_id],
            |r| r.get(0),
        )
    })
    .await
}

fn unauthorized_json() -> serde_json::Value {
    serde_json::json!({ "error": "unauthorized" })
}

/// The status, the body and every header of an answer, for comparing causes.
fn shape(res: &Res) -> (StatusCode, Vec<u8>, Vec<(String, String)>) {
    let mut headers: Vec<(String, String)> = res
        .headers
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    headers.sort();
    (res.status, res.body.clone(), headers)
}

#[tokio::test]
async fn a_vault_session_reaches_the_route_with_its_account_vault_device_and_epoch() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 7).await;
    let res = get_with(&router, &signed_in.jar, "/vault").await;
    assert_eq!(res.status, StatusCode::OK);
    let body = res.json();
    assert_eq!(body["user_id"], user.user_id);
    assert_eq!(body["issued_at"], now(&app));
    assert_eq!(body["device"], hex(&session::device(7).0));
    assert_eq!(body["account"], hex(user.account.as_bytes()));
    assert_eq!(body["vault"], hex(user.vault.as_bytes()));
    assert_eq!(body["vk_epoch"], 3);
    // The admin route does not take a vault session.
    assert_eq!(
        status(&router, &signed_in.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn two_logins_in_the_same_second_get_two_rows_and_two_cookies() {
    let (app, router, user) = setup().await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    assert_eq!(a.claims.issued_at, b.claims.issued_at);
    assert_ne!(a.sid, b.sid);
    assert_ne!(a.secret, b.secret);
    assert_ne!(a.jar.get(SID_COOKIE), b.jar.get(SID_COOKIE));
    assert_eq!(session_rows(&app, user.user_id).await, 2);
    for signed_in in [&a, &b] {
        assert_eq!(
            status(&router, &signed_in.jar, "/vault").await,
            StatusCode::OK
        );
    }
}

#[tokio::test]
async fn logging_out_one_session_leaves_the_other() {
    let (app, router, user) = setup().await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let (sid, at) = (a.sid, now(&app));
    assert!(db(&app, move |c| revoke(c, &sid, at)).await);
    assert_eq!(
        status(&router, &a.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(status(&router, &b.jar, "/vault").await, StatusCode::OK);
}

#[tokio::test]
async fn revoked_row_is_never_reused() {
    let (app, router, user) = setup().await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let (sid, at) = (a.sid, now(&app));
    assert!(db(&app, move |c| revoke(c, &sid, at)).await);
    // Ending it again changes nothing, and the row stays with its time.
    assert!(!db(&app, move |c| revoke(c, &sid, at + 100)).await);
    let row = db(&app, move |c| lookup(c, &sid))
        .await
        .expect("the row stays");
    assert_eq!(row.revoked_at, Some(at));
    // Putting the same row in again is an error, not a revival.
    let again = NewSession {
        sid: row.sid,
        user_id: row.user_id,
        issued_at: row.issued_at,
        origin: row.origin,
        device: row.device,
        device_name: row.device_name.clone(),
        scope: row.scope,
    };
    assert!(
        db(&app, move |c| Ok(insert_session(c, &again).is_err())).await,
        "a second insert of the same session id must fail"
    );
    assert_eq!(
        status(&router, &a.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    // A new sign-in is a new row with a new id.
    let b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    assert_ne!(a.sid, b.sid);
    assert_eq!(status(&router, &b.jar, "/vault").await, StatusCode::OK);
    assert_eq!(session_rows(&app, user.user_id).await, 2);
}

#[tokio::test]
async fn revoking_all_sessions_of_a_user_can_spare_one() {
    let (app, router, user) = setup().await;
    let other = seed(&app, 2).await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let c = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 3).await;
    let of_other = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 4).await;
    let (uid, at, keep) = (user.user_id, now(&app), b.sid);
    let ended = db(&app, move |conn| {
        revoke_all_for_user(conn, uid, at, Some(&keep))
    })
    .await;
    assert_eq!(ended, 2);
    assert_eq!(
        status(&router, &a.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(status(&router, &b.jar, "/vault").await, StatusCode::OK);
    assert_eq!(
        status(&router, &c.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&router, &of_other.jar, "/vault").await,
        StatusCode::OK
    );
    // Without an exception every live session of the user ends.
    let ended = db(&app, move |conn| {
        revoke_all_for_user(conn, uid, at + 1, None)
    })
    .await;
    assert_eq!(ended, 1);
    assert_eq!(
        status(&router, &b.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn kit_cookie_alone_is_unauthorized() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let mut jar = Jar::default();
    jar.set(
        SESSION_COOKIE,
        signed_in.jar.get(SESSION_COOKIE).expect("the kit cookie"),
    );
    assert_eq!(
        status(&router, &jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn ferret_sid_alone_is_unauthorized() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let mut jar = Jar::default();
    jar.set(
        SID_COOKIE,
        signed_in.jar.get(SID_COOKIE).expect("the session id"),
    );
    assert_eq!(
        status(&router, &jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn kit_claims_with_other_issued_at_are_unauthorized() {
    let (app, router, user) = setup().await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    app.clock.advance(10);
    let b = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    assert_ne!(a.claims.issued_at, b.claims.issued_at);
    // The kit cookie of one sign-in with the session id of the other.
    for (kit, sid) in [(&a, &b), (&b, &a)] {
        let mut mixed = Jar::default();
        mixed.set(SESSION_COOKIE, kit.jar.get(SESSION_COOKIE).expect("kit"));
        mixed.set(SID_COOKIE, sid.jar.get(SID_COOKIE).expect("sid"));
        assert_eq!(
            status(&router, &mixed, "/vault").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Each on its own is fine.
    assert_eq!(status(&router, &a.jar, "/vault").await, StatusCode::OK);
    assert_eq!(status(&router, &b.jar, "/vault").await, StatusCode::OK);
}

#[tokio::test]
async fn kit_claims_of_another_user_are_unauthorized() {
    let (app, router, user) = setup().await;
    let other = seed(&app, 2).await;
    let mine = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let theirs = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let mut mixed = Jar::default();
    mixed.set(SESSION_COOKIE, theirs.jar.get(SESSION_COOKIE).expect("kit"));
    mixed.set(SID_COOKIE, mine.jar.get(SID_COOKIE).expect("sid"));
    assert_eq!(
        status(&router, &mixed, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn session_version_bump_ends_the_session() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::OK
    );
    let uid = user.user_id;
    db(&app, move |c| {
        vole_kit::db::users::bump_session_version(c, uid)
    })
    .await;
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_disabled_user_is_unauthorized() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let uid = user.user_id;
    db(&app, move |c| {
        c.execute("UPDATE users SET active = 0 WHERE id = ?1", [uid])
    })
    .await;
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn a_user_without_an_account_has_no_vault_session() {
    let app = TestApp::new().await;
    let router = session::router(&app);
    let user_id = db(&app, |c| {
        c.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('admin@example.com', 'x', 'admin')",
            [],
        )?;
        Ok(c.last_insert_rowid())
    })
    .await;
    // The vault needs an account; the admin pages do not.
    let vault = issue(&app, user_id, Origin::Vault, SessionScope::Full, 1).await;
    assert_eq!(
        status(&router, &vault.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    let admin = issue(&app, user_id, Origin::Admin, SessionScope::Full, 1).await;
    let res = get_with(&router, &admin.jar, "/admin").await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(res.json()["user_id"], user_id);
}

#[tokio::test]
async fn wrong_origin_row_is_unauthorized() {
    let (app, router, user) = setup().await;
    let admin = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 1).await;
    let vault = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    // An admin row on the vault listener, and a vault row on the admin one.
    assert_eq!(
        status(&router, &admin.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&router, &vault.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
    // Each on its own listener is fine.
    assert_eq!(status(&router, &vault.jar, "/vault").await, StatusCode::OK);
    assert_eq!(status(&router, &admin.jar, "/admin").await, StatusCode::OK);
}

#[tokio::test]
async fn non_full_scope_is_unauthorized_for_vault_routes() {
    let (app, router, user) = setup().await;
    for scope in [
        SessionScope::Pending2fa,
        SessionScope::AccountReset,
        SessionScope::Unverified,
    ] {
        for (origin, uri) in [(Origin::Vault, "/vault"), (Origin::Admin, "/admin")] {
            let signed_in = issue(&app, user.user_id, origin, scope, 1).await;
            assert_eq!(
                status(&router, &signed_in.jar, uri).await,
                StatusCode::UNAUTHORIZED,
                "{scope:?} on {uri}"
            );
        }
    }
    let full = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    assert_eq!(status(&router, &full.jar, "/vault").await, StatusCode::OK);
}

#[tokio::test]
async fn a_cookie_that_was_not_signed_by_the_server_is_unauthorized() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    // The bare session id, as an attacker who learned it would send it.
    let mut bare = signed_in.jar.clone();
    bare.set(SID_COOKIE, &signed_in.secret);
    assert_eq!(
        status(&router, &bare, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    // A signed value with its last character changed.
    let mut flipped = signed_in.jar.clone();
    let mut value = signed_in.jar.get(SID_COOKIE).expect("sid").to_string();
    let last = value.pop().expect("a value");
    value.push(if last == 'A' { 'B' } else { 'A' });
    flipped.set(SID_COOKIE, &value);
    assert_eq!(
        status(&router, &flipped, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    // Garbage.
    let mut garbage = signed_in.jar.clone();
    garbage.set(SID_COOKIE, "not a cookie");
    assert_eq!(
        status(&router, &garbage, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unauthorized_body_is_identical_for_every_cause() {
    let app = TestApp::new().await;
    let router = session::router(&app);
    let mut answers: Vec<(&str, Res)> = Vec::new();

    answers.push((
        "no cookies",
        get_with(&router, &Jar::default(), "/vault").await,
    ));

    let user = seed(&app, 1).await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let mut only_sid = Jar::default();
    only_sid.set(SID_COOKIE, signed_in.jar.get(SID_COOKIE).expect("sid"));
    answers.push(("sid only", get_with(&router, &only_sid, "/vault").await));
    let mut only_kit = Jar::default();
    only_kit.set(
        SESSION_COOKIE,
        signed_in.jar.get(SESSION_COOKIE).expect("kit"),
    );
    answers.push(("kit only", get_with(&router, &only_kit, "/vault").await));
    let mut bare = signed_in.jar.clone();
    bare.set(SID_COOKIE, &signed_in.secret);
    answers.push(("unsigned sid", get_with(&router, &bare, "/vault").await));

    // A session that was never stored.
    let version = session::session_version(&app, user.user_id).await;
    let (secret, _unsaved, claims) = new_session(
        &mut OsRng,
        now(&app),
        user.user_id,
        version,
        Origin::Vault,
        session::device(9),
        "",
        SessionScope::Full,
    );
    let unsaved = session_cookies(
        SignedCookieJar::new(app.state.core.session_key.clone()),
        &secret,
        &claims,
        true,
    );
    let mut unsaved_jar = Jar::default();
    {
        use axum::response::IntoResponse as _;
        unsaved_jar.absorb(unsaved.into_response().headers());
    }
    answers.push((
        "unknown row",
        get_with(&router, &unsaved_jar, "/vault").await,
    ));

    // One user per cause below, so one cause cannot hide behind another.
    let revoked_user = seed(&app, 2).await;
    let revoked = issue(
        &app,
        revoked_user.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let (sid, at) = (revoked.sid, now(&app));
    db(&app, move |c| revoke(c, &sid, at)).await;
    answers.push(("revoked", get_with(&router, &revoked.jar, "/vault").await));

    let origin_user = seed(&app, 3).await;
    let admin_row = issue(
        &app,
        origin_user.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    answers.push((
        "wrong origin",
        get_with(&router, &admin_row.jar, "/vault").await,
    ));

    let scope_user = seed(&app, 4).await;
    let pending = issue(
        &app,
        scope_user.user_id,
        Origin::Vault,
        SessionScope::Pending2fa,
        1,
    )
    .await;
    answers.push(("scope", get_with(&router, &pending.jar, "/vault").await));

    let mix_user = seed(&app, 5).await;
    let first = issue(&app, mix_user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    app.clock.advance(5);
    let second = issue(&app, mix_user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let mut mixed = Jar::default();
    mixed.set(SESSION_COOKIE, first.jar.get(SESSION_COOKIE).expect("kit"));
    mixed.set(SID_COOKIE, second.jar.get(SID_COOKIE).expect("sid"));
    answers.push(("other issued_at", get_with(&router, &mixed, "/vault").await));

    let version_user = seed(&app, 6).await;
    let bumped = issue(
        &app,
        version_user.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let uid = version_user.user_id;
    db(&app, move |c| {
        vole_kit::db::users::bump_session_version(c, uid)
    })
    .await;
    answers.push((
        "session version",
        get_with(&router, &bumped.jar, "/vault").await,
    ));

    let disabled_user = seed(&app, 7).await;
    let disabled = issue(
        &app,
        disabled_user.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let uid = disabled_user.user_id;
    db(&app, move |c| {
        c.execute("UPDATE users SET active = 0 WHERE id = ?1", [uid])
    })
    .await;
    answers.push((
        "disabled user",
        get_with(&router, &disabled.jar, "/vault").await,
    ));

    let admin_on_vault = seed(&app, 8).await;
    let expiring = issue(
        &app,
        admin_on_vault.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    app.clock.advance(DAY * 8);
    answers.push(("expired", get_with(&router, &expiring.jar, "/vault").await));

    let (_, reference) = &answers[0];
    for (cause, answer) in &answers {
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{cause}");
        assert_eq!(answer.json(), unauthorized_json(), "{cause}");
        assert_eq!(shape(answer), shape(reference), "{cause}");
    }
    assert!(answers.len() >= 12);
}

#[tokio::test]
async fn idle_12h_and_absolute_7d_limits_are_enforced_for_vault_and_1h_and_12h_for_admin_with_the_manual_clock()
 {
    assert_eq!(limits(Origin::Vault), (12 * 3600, 7 * 24 * 3600));
    assert_eq!(limits(Origin::Admin), (3600, 12 * 3600));

    let app = TestApp::new().await;
    let router = session::router(&app);
    let user = seed(&app, 1).await;

    // Vault, idle: exactly 12 hours is fine, one second more is not.
    let idle = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    app.clock.advance(12 * HOUR);
    assert_eq!(status(&router, &idle.jar, "/vault").await, StatusCode::OK);
    app.clock.advance(12 * HOUR + 1);
    assert_eq!(
        status(&router, &idle.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );

    // Vault, idle without any request in between.
    let quiet = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    app.clock.advance(12 * HOUR + 1);
    assert_eq!(
        status(&router, &quiet.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );

    // Vault, absolute: kept busy for 7 days, the limit still ends it.
    let busy = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 3).await;
    for step in 1..=28 {
        app.clock.advance(6 * HOUR);
        assert_eq!(
            status(&router, &busy.jar, "/vault").await,
            StatusCode::OK,
            "6 hours x {step}"
        );
    }
    app.clock.advance(1);
    assert_eq!(
        status(&router, &busy.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );

    // Admin, idle.
    let admin_idle = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 4).await;
    app.clock.advance(HOUR);
    assert_eq!(
        status(&router, &admin_idle.jar, "/admin").await,
        StatusCode::OK
    );
    app.clock.advance(HOUR + 1);
    assert_eq!(
        status(&router, &admin_idle.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
    let admin_quiet = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 5).await;
    app.clock.advance(HOUR + 1);
    assert_eq!(
        status(&router, &admin_quiet.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );

    // Admin, absolute: busy for 12 hours.
    let admin_busy = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 6).await;
    for step in 1..=24 {
        app.clock.advance(HOUR / 2);
        assert_eq!(
            status(&router, &admin_busy.jar, "/admin").await,
            StatusCode::OK,
            "30 minutes x {step}"
        );
    }
    app.clock.advance(1);
    assert_eq!(
        status(&router, &admin_busy.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn last_seen_is_touched_at_most_once_per_minute() {
    let (app, router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let start = now(&app);
    let sid = signed_in.sid;
    assert_eq!(last_seen(&app, sid).await, start);

    app.clock.advance(59);
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::OK
    );
    assert_eq!(last_seen(&app, sid).await, start, "59 seconds: not written");

    app.clock.advance(1);
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::OK
    );
    assert_eq!(
        last_seen(&app, sid).await,
        start + 60,
        "60 seconds: written"
    );

    app.clock.advance(30);
    status(&router, &signed_in.jar, "/vault").await;
    assert_eq!(
        last_seen(&app, sid).await,
        start + 60,
        "30 more: not written"
    );

    app.clock.advance(30);
    status(&router, &signed_in.jar, "/vault").await;
    assert_eq!(last_seen(&app, sid).await, start + 120, "60 more: written");
}

async fn last_seen(app: &TestApp, sid: SidHash) -> i64 {
    db(app, move |c| {
        Ok(lookup(c, &sid)?.expect("the row").last_seen)
    })
    .await
}

#[tokio::test]
async fn sid_hash_not_the_secret_is_stored() {
    let (app, _router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let secret = URL_SAFE_NO_PAD
        .decode(&signed_in.secret)
        .expect("the cookie value is base64url");
    assert_eq!(secret.len(), 32);

    // The key of the row is the domain-separated hash.
    let mut hasher = Sha256::new();
    hasher.update(b"ferret/v1/sid");
    hasher.update(&secret);
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&hasher.finalize());
    assert_eq!(signed_in.sid, SidHash(expected));
    assert_ne!(signed_in.sid.0.as_slice(), secret.as_slice());

    // No column of the table holds the secret, in any spelling.
    let dump: String = db(&app, |c| {
        c.query_row(
            "SELECT group_concat(hex(sid_hash) || hex(device_id) || device_name || origin || scope
                                 || user_id || issued_at || last_seen, '|')
             FROM ferret_sessions",
            [],
            |r| r.get(0),
        )
    })
    .await;
    assert!(!dump.to_lowercase().contains(&hex(&secret)));
    assert!(!dump.contains(&signed_in.secret));
    assert!(dump.to_lowercase().contains(&hex(&expected)));
    let by_secret = db(&app, move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE sid_hash = ?1",
            [secret],
            |r| r.get::<_, i64>(0),
        )
    })
    .await;
    assert_eq!(by_secret, 0);
}

#[tokio::test]
async fn cookies_have_host_prefix_secure_httponly_strict_and_no_domain() {
    let (app, _router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let find = |name: &str| -> &String {
        signed_in
            .set_cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no Set-Cookie for {name}: {:?}", signed_in.set_cookies))
    };
    for name in [SID_COOKIE, SESSION_COOKIE] {
        let cookie = find(name);
        assert!(name.starts_with("__Host-"), "{name}");
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(cookie.contains("; HttpOnly"), "{cookie}");
        assert!(cookie.contains("; Path=/"), "{cookie}");
    }
    assert!(find(SID_COOKIE).contains("; SameSite=Strict"));
    // Every cookie the sign-in touches is host-bound: no `Domain`, and the
    // prefix on every name (including those it removes).
    for cookie in &signed_in.set_cookies {
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        assert!(cookie.contains("; Secure"), "{cookie}");
        assert!(
            !cookie.to_ascii_lowercase().contains("domain"),
            "no Domain: {cookie}"
        );
        assert!(cookie.contains("; Path=/"), "{cookie}");
    }
    // The pending second factor and the re-auth grant are removed.
    assert!(
        signed_in
            .set_cookies
            .iter()
            .any(|c| c.starts_with("__Host-ferret_2fa=")),
        "{:?}",
        signed_in.set_cookies
    );
    assert!(
        signed_in
            .set_cookies
            .iter()
            .any(|c| c.starts_with("__Host-ferret_reauth=")),
        "{:?}",
        signed_in.set_cookies
    );
}

#[tokio::test]
async fn issued_at_in_row_equals_issued_at_in_kit_claims() {
    let app = TestApp::new().await;
    let user = seed(&app, 1).await;
    app.clock.advance(1234);
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let at = now(&app);

    // The claims the code made.
    assert_eq!(signed_in.claims.issued_at, at);
    assert_eq!(signed_in.claims.last_seen, at);

    // The claims the browser holds, read back through the signed cookie.
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&signed_in.jar.header().expect("cookies")).expect("a header"),
    );
    let jar = SignedCookieJar::from_headers(&headers, app.state.core.session_key.clone());
    let in_cookie = SessionClaims::decode(jar.get(SESSION_COOKIE).expect("kit cookie").value())
        .expect("claims");
    assert_eq!(in_cookie, signed_in.claims);

    // The row.
    let sid = signed_in.sid;
    let row = db(&app, move |c| lookup(c, &sid)).await.expect("the row");
    assert_eq!(row.issued_at, in_cookie.issued_at);
    assert_eq!(row.user_id, in_cookie.user_id);
    assert_eq!(row.last_seen, at);
    assert_eq!(row.origin, Origin::Vault);
    assert_eq!(row.scope, SessionScope::Full);
    assert_eq!(row.device, session::device(1));
    assert_eq!(row.device_name, "Test browser");
    assert_eq!(row.revoked_at, None);
}

#[tokio::test]
async fn lookup_of_an_unknown_session_is_none() {
    let (app, _router, _user) = setup().await;
    let missing = SidHash([7; 32]);
    assert!(db(&app, move |c| lookup(c, &missing)).await.is_none());
}

#[test]
fn new_sessions_draw_distinct_ids_and_share_the_issue_time() {
    let mut rng = OsRng;
    let make = |rng: &mut OsRng| {
        new_session(
            rng,
            1_000,
            5,
            42,
            Origin::Admin,
            session::device(1),
            "Laptop",
            SessionScope::Full,
        )
    };
    let (secret_a, a, claims_a) = make(&mut rng);
    let (secret_b, b, _) = make(&mut rng);
    assert_ne!(a.sid, b.sid);
    assert_ne!(secret_a.to_cookie(), secret_b.to_cookie());
    assert_eq!(a.sid, secret_a.hash());
    assert_eq!(a.issued_at, 1_000);
    assert_eq!(claims_a.issued_at, a.issued_at);
    assert_eq!(claims_a.last_seen, 1_000);
    assert_eq!((claims_a.user_id, claims_a.version), (5, 42));
}

#[tokio::test]
async fn clearing_the_cookies_removes_all_four_with_the_secure_flag() {
    use axum::response::IntoResponse as _;
    let (app, _router, user) = setup().await;
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let mut request = HeaderMap::new();
    request.insert(
        header::COOKIE,
        HeaderValue::from_str(&signed_in.jar.header().expect("cookies")).expect("a header"),
    );
    // The browser also holds a pending second factor and a re-auth grant.
    let key = app.state.core.session_key.clone();
    let extra = SignedCookieJar::new(key.clone())
        .add(axum_extra::extract::cookie::Cookie::new(
            "__Host-ferret_2fa",
            "x",
        ))
        .add(axum_extra::extract::cookie::Cookie::new(
            "__Host-ferret_reauth",
            "x",
        ))
        .into_response();
    let mut jar = signed_in.jar.clone();
    jar.absorb(extra.headers());
    request.insert(
        header::COOKIE,
        HeaderValue::from_str(&jar.header().expect("cookies")).expect("a header"),
    );
    let cleared =
        ferret_server::auth::session::clear_cookies(SignedCookieJar::from_headers(&request, key))
            .into_response();
    let mut names: Vec<String> = cleared
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().expect("text").to_string())
        .inspect(|c| {
            assert!(c.contains("; Secure") && c.contains("; Path=/"), "{c}");
            assert!(c.contains("Max-Age=0"), "{c}");
        })
        .map(|c| c.split('=').next().expect("a name").to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "__Host-ferret_2fa",
            "__Host-ferret_reauth",
            "__Host-ferret_session",
            "__Host-ferret_sid"
        ]
    );
}

// ------------------------------------------------- ending sessions in bulk

/// Whether the row of `sid` is ended.
async fn is_revoked(app: &TestApp, sid: SidHash) -> bool {
    db(app, move |c| {
        c.query_row(
            "SELECT revoked_at IS NOT NULL FROM ferret_sessions WHERE sid_hash = ?1",
            [sid.0.as_slice()],
            |r| r.get(0),
        )
    })
    .await
}

/// `end_all_credentials` in a transaction of its own.
async fn end_all(app: &TestApp, user_id: i64, keep: Option<SidHash>) -> Vec<SidHash> {
    let at = now(app);
    db(app, move |c| {
        let tx = c.transaction()?;
        let ended = end_all_credentials(&tx, user_id, keep.as_ref(), at)?;
        tx.commit()?;
        Ok(ended)
    })
    .await
}

async fn parent(app: &TestApp, child: SidHash, of: SidHash) {
    db(app, move |c| set_parent(c, &child, &of)).await;
}

fn sorted(sids: Vec<SidHash>) -> Vec<[u8; 32]> {
    let mut bytes: Vec<[u8; 32]> = sids.into_iter().map(|s| s.0).collect();
    bytes.sort_unstable();
    bytes
}

#[tokio::test]
async fn end_all_credentials_ends_both_origins_and_children_and_keeps_the_given_one() {
    let (app, router, user) = setup().await;
    let other = seed(&app, 2).await;
    let uid = user.user_id;
    let kept = issue(&app, uid, Origin::Vault, SessionScope::Full, 1).await;
    let vault = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let reset = issue(&app, uid, Origin::Vault, SessionScope::AccountReset, 3).await;
    let admin = issue(&app, uid, Origin::Admin, SessionScope::Full, 4).await;
    parent(&app, admin.sid, vault.sid).await;
    // The admin session handed over from the kept one is another session.
    let kept_child = issue(&app, uid, Origin::Admin, SessionScope::Full, 5).await;
    parent(&app, kept_child.sid, kept.sid).await;
    // A child that names a session of the user as its parent ends with it,
    // whoever it belongs to; also when the parent had ended before.
    let foreign_child = issue(&app, other.user_id, Origin::Admin, SessionScope::Full, 6).await;
    parent(&app, foreign_child.sid, vault.sid).await;
    let old = issue(&app, uid, Origin::Vault, SessionScope::Full, 7).await;
    let (old_sid, at) = (old.sid, now(&app));
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_sessions SET revoked_at = ?1 WHERE sid_hash = ?2",
            rusqlite::params![at, old_sid.0.as_slice()],
        )
    })
    .await;
    let orphan = issue(&app, other.user_id, Origin::Admin, SessionScope::Full, 8).await;
    parent(&app, orphan.sid, old.sid).await;
    let untouched = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 9).await;
    let code = code_for(&app, uid, 1).await;
    code_for(&app, other.user_id, 2).await;

    end_all(&app, uid, Some(kept.sid)).await;

    // The user's pending sign-in code is revoked with the sessions; another
    // user's is not.
    let pending = |user_id: i64| {
        db(&app, move |c| {
            vole_kit::db::sign_in_codes::count_pending(c, user_id)
        })
    };
    assert_eq!(pending(uid).await, 0);
    assert_eq!(pending(other.user_id).await, 1);
    let redeemed = db(&app, move |c| {
        vole_kit::db::sign_in_codes::redeem(c, &code, uid, None)
    })
    .await;
    assert_eq!(redeemed, None);

    assert!(!is_revoked(&app, kept.sid).await, "the kept session");
    assert_eq!(status(&router, &kept.jar, "/vault").await, StatusCode::OK);
    for (name, sid) in [
        ("vault", vault.sid),
        ("reset", reset.sid),
        ("admin child", admin.sid),
        ("child of the kept one", kept_child.sid),
        ("foreign child", foreign_child.sid),
        ("child of an ended one", orphan.sid),
    ] {
        assert!(is_revoked(&app, sid).await, "{name}");
    }
    assert_eq!(
        status(&router, &vault.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&router, &admin.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );
    assert!(!is_revoked(&app, untouched.sid).await, "another user's");
    assert_eq!(
        status(&router, &untouched.jar, "/vault").await,
        StatusCode::OK
    );

    // Without a session to keep, the last one ends too.
    end_all(&app, uid, None).await;
    assert!(is_revoked(&app, kept.sid).await);
    assert!(!is_revoked(&app, untouched.sid).await);
}

#[tokio::test]
async fn end_all_credentials_returns_every_ended_sid() {
    let (app, _router, user) = setup().await;
    let other = seed(&app, 2).await;
    let uid = user.user_id;
    let kept = issue(&app, uid, Origin::Vault, SessionScope::Full, 1).await;
    let a = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let b = issue(&app, uid, Origin::Admin, SessionScope::Full, 3).await;
    parent(&app, b.sid, a.sid).await;
    let c = issue(&app, uid, Origin::Vault, SessionScope::AccountReset, 4).await;
    let foreign_child = issue(&app, other.user_id, Origin::Admin, SessionScope::Full, 5).await;
    parent(&app, foreign_child.sid, c.sid).await;
    let ended_before = issue(&app, uid, Origin::Vault, SessionScope::Full, 6).await;
    let (sid, at) = (ended_before.sid, now(&app));
    db(&app, move |conn| revoke(conn, &sid, at)).await;
    issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 7).await;

    let ended = end_all(&app, uid, Some(kept.sid)).await;
    assert_eq!(ended.len(), 4, "each ended session once");
    assert_eq!(
        sorted(ended.clone()),
        sorted(vec![a.sid, b.sid, c.sid, foreign_child.sid]),
        "no session that had ended before, and not the kept one"
    );
    for sid in ended {
        assert!(is_revoked(&app, sid).await);
    }
    // Nothing left to end: nothing is returned, and a second call is harmless.
    assert!(end_all(&app, uid, Some(kept.sid)).await.is_empty());
    assert_eq!(end_all(&app, uid, None).await, vec![kept.sid]);
    assert!(end_all(&app, uid, None).await.is_empty());
}

/// Rows of every kind of pending sign-in step, one set per user in `users`.
async fn pending_steps(app: &TestApp, users: &[i64], sid: SidHash) {
    let users = users.to_vec();
    let at = now(app);
    db(app, move |c| {
        for (n, user) in users.iter().enumerate() {
            let n = u8::try_from(n).expect("a few users");
            c.execute(
                "INSERT INTO ferret_handoffs
                   (code_hash, sid_hash, user_id, purpose, next, challenge, expires_at)
                 VALUES (?1, ?2, ?3, 'login', '/', ?4, ?5)",
                rusqlite::params![vec![n; 32], sid.0.as_slice(), user, vec![n; 32], at + 60],
            )?;
            c.execute(
                "INSERT INTO ferret_login_states (key, sealed, expires_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![vec![n; 16], vec![n; 40], at + 60],
            )?;
            c.execute(
                "INSERT INTO ferret_registrations
                   (registration_id, account_id, vault_id, email, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    vec![n; 16],
                    vec![0xe0 | n; 16],
                    vec![0xf0 | n; 16],
                    format!("new{n}@example.com"),
                    at + 600
                ],
            )?;
        }
        Ok(())
    })
    .await;
}

/// A sign-in code for `user`, as the kit stores it; returns its hash.
async fn code_for(app: &TestApp, user: i64, n: u8) -> [u8; 32] {
    let hash = [n; 32];
    db(app, move |c| {
        vole_kit::db::sign_in_codes::insert(c, user, &hash, user).map(|_| ())
    })
    .await;
    hash
}

/// `end_everything_after_restore` in a transaction of its own.
async fn sweep(app: &TestApp) -> RestoreSweep {
    let at = now(app);
    db(app, move |c| {
        let tx = c.transaction()?;
        let swept = end_everything_after_restore(&tx, at)?;
        tx.commit()?;
        Ok(swept)
    })
    .await
}

async fn count(app: &TestApp, sql: &'static str) -> i64 {
    db(app, move |c| c.query_row(sql, [], |r| r.get(0))).await
}

#[tokio::test]
async fn end_everything_after_restore_ends_every_session_and_purges_states() {
    let (app, router, user) = setup().await;
    let other = seed(&app, 2).await;
    let a = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let b = issue(&app, user.user_id, Origin::Admin, SessionScope::Full, 2).await;
    let c = issue(
        &app,
        other.user_id,
        Origin::Vault,
        SessionScope::AccountReset,
        3,
    )
    .await;
    let d = issue(&app, other.user_id, Origin::Vault, SessionScope::Full, 4).await;
    let (sid, at) = (d.sid, now(&app));
    db(&app, move |conn| revoke(conn, &sid, at)).await;
    pending_steps(&app, &[user.user_id, other.user_id], a.sid).await;
    code_for(&app, user.user_id, 1).await;

    let swept = sweep(&app).await;
    assert_eq!(
        swept,
        RestoreSweep {
            sessions: 3,
            handoffs: 2,
            login_states: 2,
            registrations: 2,
            sign_in_codes: 1,
            users: 2,
        }
    );
    for sid in [a.sid, b.sid, c.sid, d.sid] {
        assert!(is_revoked(&app, sid).await);
    }
    for sql in [
        "SELECT COUNT(*) FROM ferret_handoffs",
        "SELECT COUNT(*) FROM ferret_login_states",
        "SELECT COUNT(*) FROM ferret_registrations",
        "SELECT COUNT(*) FROM ferret_sessions WHERE revoked_at IS NULL",
    ] {
        assert_eq!(count(&app, sql).await, 0, "{sql}");
    }
    assert_eq!(
        status(&router, &a.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&router, &b.jar, "/admin").await,
        StatusCode::UNAUTHORIZED
    );

    // A transaction that is rolled back leaves everything as it was.
    let e = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 5).await;
    let at = now(&app);
    db(&app, move |c| {
        let tx = c.transaction()?;
        end_everything_after_restore(&tx, at)?;
        tx.rollback()
    })
    .await;
    assert!(!is_revoked(&app, e.sid).await);
    assert_eq!(status(&router, &e.jar, "/vault").await, StatusCode::OK);
}

#[tokio::test]
async fn a_code_pending_in_the_backup_is_dead_after_the_restore_sweep() {
    let (app, _router, user) = setup().await;
    let other = seed(&app, 2).await;
    let (uid, oid) = (user.user_id, other.user_id);
    let of_other = code_for(&app, oid, 2).await;
    // A code past its time but never settled, as a backup may hold it. It
    // goes in by hand: the kit's insert would revoke the other pending code
    // of the same user.
    let expired = [3u8; 32];
    db(&app, move |c| {
        c.execute(
            "INSERT INTO sign_in_codes (user_id, code_hash, created_by, expires_at)
             VALUES (?1, ?2, ?1, datetime('now', '-1 hour'))",
            rusqlite::params![oid, expired.as_slice()],
        )
    })
    .await;
    // A code that was used before the backup.
    let used = code_for(&app, uid, 4).await;
    let redeemed = db(&app, move |c| {
        vole_kit::db::sign_in_codes::redeem(c, &used, uid, None)
    })
    .await;
    assert!(redeemed.is_some());
    let pending = code_for(&app, uid, 5).await;

    let swept = sweep(&app).await;
    assert_eq!(
        swept.sign_in_codes, 3,
        "the two pending ones and the expired one"
    );

    for (hash, user_id) in [(pending, uid), (of_other, oid), (expired, oid)] {
        let redeemed = db(&app, move |c| {
            vole_kit::db::sign_in_codes::redeem(c, &hash, user_id, None)
        })
        .await;
        assert_eq!(redeemed, None);
    }
    for user_id in [uid, oid] {
        let left = db(&app, move |c| {
            vole_kit::db::sign_in_codes::count_pending(c, user_id)
        })
        .await;
        assert_eq!(left, 0);
    }
    // The used code keeps its use and gets no revocation on top.
    let used_row: (bool, bool) = db(&app, move |c| {
        c.query_row(
            "SELECT used_at IS NOT NULL, revoked_at IS NOT NULL FROM sign_in_codes
             WHERE code_hash = ?1",
            [used.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
    })
    .await;
    assert_eq!(used_row, (true, false));
}

#[tokio::test]
async fn the_restore_sweep_raises_every_users_session_version() {
    let (app, router, user) = setup().await;
    let other = seed(&app, 2).await;
    let without_account = db(&app, |c| {
        c.execute(
            "INSERT INTO users (username, password_hash, role)
             VALUES ('admin@example.com', 'x', 'admin')",
            [],
        )?;
        Ok(c.last_insert_rowid())
    })
    .await;
    let users = [user.user_id, other.user_id, without_account];
    let mut before = Vec::new();
    for id in users {
        before.push(session::session_version(&app, id).await);
    }
    let signed_in = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 1).await;

    assert_eq!(sweep(&app).await.users, 3);
    for (id, was) in users.into_iter().zip(before) {
        assert_eq!(session::session_version(&app, id).await, was + 1);
    }
    // A row brought back to life by hand still fails: the kit's cookie names
    // the old version.
    let sid = signed_in.sid;
    db(&app, move |c| {
        c.execute(
            "UPDATE ferret_sessions SET revoked_at = NULL WHERE sid_hash = ?1",
            [sid.0.as_slice()],
        )
    })
    .await;
    assert_eq!(
        status(&router, &signed_in.jar, "/vault").await,
        StatusCode::UNAUTHORIZED
    );
}

// ------------------------------------------------------- the reset session

/// `GET /api/auth/session` on the vault listener with the cookies of `jar`.
async fn session_answer(app: &TestApp, jar: &Jar) -> Res {
    let mut req = support::Req::get("/api/auth/session");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(support::Which::Vault, req.build()).await
}

#[tokio::test]
async fn a_reset_session_ends_after_30_minutes() {
    assert_eq!(RESET_SESSION_ABSOLUTE_SECS, 30 * 60);
    let (app, _router, user) = setup().await;
    let reset = issue(
        &app,
        user.user_id,
        Origin::Vault,
        SessionScope::AccountReset,
        1,
    )
    .await;
    let full = issue(&app, user.user_id, Origin::Vault, SessionScope::Full, 2).await;
    let answer = session_answer(&app, &reset.jar).await;
    assert_eq!(answer.status, StatusCode::OK, "{}", answer.text());
    assert_eq!(answer.json()["scope"], "account_reset");

    // Kept busy, exactly 30 minutes is still fine; one second more is not.
    for _ in 0..6 {
        app.clock.advance(5 * 60);
        assert_eq!(
            session_answer(&app, &reset.jar).await.status,
            StatusCode::OK
        );
    }
    app.clock.advance(1);
    assert_eq!(
        session_answer(&app, &reset.jar).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        session::challenge_with(&app, &reset.jar).await.status,
        StatusCode::UNAUTHORIZED
    );
    // A full session of the same age goes on.
    assert_eq!(session_answer(&app, &full.jar).await.status, StatusCode::OK);

    // The rule itself, on the row.
    let reset_sid = reset.sid;
    let row = db(&app, move |c| lookup(c, &reset_sid))
        .await
        .expect("the row");
    let issued = row.issued_at;
    assert!(within_limits(&row, issued + RESET_SESSION_ABSOLUTE_SECS));
    assert!(!within_limits(
        &row,
        issued + RESET_SESSION_ABSOLUTE_SECS + 1
    ));
    let as_full = SessionRow {
        scope: SessionScope::Full,
        ..row.clone()
    };
    assert!(within_limits(
        &as_full,
        issued + RESET_SESSION_ABSOLUTE_SECS + 1
    ));

    // A day after it can no longer be used, the row is removed; the full
    // session of the same age stays.
    let at = issued + RESET_SESSION_ABSOLUTE_SECS + PURGE_MARGIN_SECS;
    assert_eq!(db(&app, move |c| purge_sessions(c, at)).await, 0);
    assert_eq!(db(&app, move |c| purge_sessions(c, at + 1)).await, 1);
    assert!(db(&app, move |c| lookup(c, &reset_sid)).await.is_none());
    let full_sid = full.sid;
    assert!(db(&app, move |c| lookup(c, &full_sid)).await.is_some());
}

/// The `Max-Age` of the cookie `name` among `set_cookies`.
fn max_age(set_cookies: &[String], name: &str) -> i64 {
    let cookie = set_cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .unwrap_or_else(|| panic!("no Set-Cookie for {name}: {set_cookies:?}"));
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age="))
        .unwrap_or_else(|| panic!("no Max-Age: {cookie}"))
        .parse()
        .expect("a number")
}

#[tokio::test]
async fn a_reset_sessions_cookies_live_30_minutes() {
    let (app, _router, user) = setup().await;
    let cookies_of = |scope: SessionScope| {
        let (secret, _, claims) = new_session(
            &mut OsRng,
            now(&app),
            user.user_id,
            1,
            Origin::Vault,
            session::device(1),
            "Test browser",
            scope,
        );
        let jar = SignedCookieJar::new(app.state.core.session_key.clone());
        let response = axum::response::IntoResponse::into_response(scoped_session_cookies(
            jar, &secret, &claims, true, scope,
        ));
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect::<Vec<_>>()
    };
    let reset = cookies_of(SessionScope::AccountReset);
    for name in [SID_COOKIE, SESSION_COOKIE] {
        assert_eq!(max_age(&reset, name), RESET_SESSION_ABSOLUTE_SECS, "{name}");
    }
    // A full session keeps the kit's lifetime, the same on both cookies.
    let full = cookies_of(SessionScope::Full);
    let kit = max_age(&full, SESSION_COOKIE);
    assert!(kit > RESET_SESSION_ABSOLUTE_SECS, "{kit}");
    assert_eq!(max_age(&full, SID_COOKIE), kit);
}
