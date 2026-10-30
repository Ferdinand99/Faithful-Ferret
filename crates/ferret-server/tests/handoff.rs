//! The hand-over of a session from the vault origin to the admin origin:
//! `GET /auth/handoff/begin`, `POST /api/auth/handoff` (vault listener) and
//! `POST /api/auth/handoff/redeem` (admin listener). Spec: Fase 1 § 2.4.

mod support;

use std::io;
use std::sync::{Arc, Mutex, Once};

use axum::http::StatusCode;
use axum_extra::extract::cookie::SignedCookieJar;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferret_server::auth::handoff::{CODE_TTL_SECS, challenge_of, purge_once};
use ferret_server::auth::session::{VAULT_ABSOLUTE_SECS, VAULT_IDLE_SECS, revoke};
use ferret_server::ids::SidHash;
use ferret_server::wire::parse_handoff_code;
use ferret_server_auth::SessionScope;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use support::handoff::{
    admin_user, begin, code_of, dump, grant_reauth, hand_over, mint, now, redeem, set_cookie,
    vault_session,
};
use support::session::{hex, seed};
use support::{ADMIN_URL, Jar, Req, TestApp, VAULT_URL, Which};
use tracing_subscriber::fmt::MakeWriter;
use vole_kit::auth::reauth;

const HANDOFF_COOKIE: &str = "__Host-ferret_handoff";
const SID_COOKIE: &str = "__Host-ferret_sid";
const SESSION_COOKIE: &str = "__Host-ferret_session";
const REAUTH_COOKIE: &str = "__Host-ferret_reauth";

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

async fn count(app: &TestApp, table: &'static str) -> i64 {
    db(app, move |c| {
        c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
    })
    .await
}

fn invalid() -> serde_json::Value {
    json!({ "error": "handoff_invalid" })
}

/// `GET /api/auth/session` on the admin listener, with the admin jar.
async fn admin_session(app: &TestApp) -> support::Res {
    app.call(Which::Admin, Req::get("/api/auth/session").build())
        .await
}

/// `GET /api/auth/session` on the vault listener, with the vault jar.
async fn vault_session_info(app: &TestApp) -> support::Res {
    app.call(Which::Vault, Req::get("/api/auth/session").build())
        .await
}

/// The origin, parent, end time and user of a session row.
type SessionSummary = (String, Option<Vec<u8>>, Option<i64>, i64);

/// A user, signed in on the vault origin, and an app.
async fn signed_in() -> (TestApp, support::session::Seeded, support::session::Issued) {
    let app = TestApp::new().await;
    let user = seed(&app, 1).await;
    let vault = vault_session(&app, user.user_id, 1).await;
    (app, user, vault)
}

// ------------------------------------------------------------------- begin

#[tokio::test]
async fn verifier_cookie_is_host_prefixed_strict_httponly_and_expires_after_120_seconds() {
    let app = TestApp::new().await;
    let begun = begin(&app, "next=%2Fsettings%2Fusers").await;
    assert_eq!(begun.res.status, StatusCode::FOUND);

    let cookie = set_cookie(&begun.res, HANDOFF_COOKIE).expect("the verifier cookie");
    for part in [
        "Max-Age=120",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
    ] {
        assert!(cookie.contains(part), "{part} in {cookie}");
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
    assert!(!cookie.contains("Expires"), "{cookie}");

    // The challenge in the redirect is the SHA-256 of the verifier.
    let value = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, v)| v.to_string())
        .expect("a value");
    let verifier = parse_handoff_code(&value).expect("32 bytes of base64url");
    let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier));
    assert_eq!(expected, URL_SAFE_NO_PAD.encode(challenge_of(&verifier)));
    assert_eq!(begun.challenge, expected);
    assert_eq!(begun.challenge.len(), 43);

    // The redirect goes to the vault origin's sign-in, with the cleaned `next`.
    let location = begun.res.header("location");
    assert!(
        location.starts_with(&format!("{VAULT_URL}/vault/login?handoff=1&challenge=")),
        "{location}"
    );
    assert!(
        location.ends_with("&next=%2Fsettings%2Fusers"),
        "{location}"
    );
    assert_eq!(begun.res.header("cache-control"), "no-store");

    // A re-authentication goes to the vault origin's re-auth page.
    let reauth = begin(&app, "next=%2Fsettings&purpose=reauth").await;
    assert!(
        reauth
            .res
            .header("location")
            .starts_with(&format!("{VAULT_URL}/vault/reauth?handoff=1&challenge=")),
        "{}",
        reauth.res.header("location")
    );
    // Every begin makes a new verifier.
    assert_ne!(reauth.challenge, begun.challenge);

    // A purpose that is none of the two is refused.
    let res = begin(&app, "purpose=admin").await.res;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert!(set_cookie(&res, HANDOFF_COOKIE).is_none());
}

#[tokio::test]
async fn begin_cleans_next_before_it_leaves_the_admin_origin() {
    let app = TestApp::new().await;
    for (raw, expected) in [
        ("%2Fsettings%2Fusers", "%2Fsettings%2Fusers"),
        ("%2F%2Fevil.test", "%2F"),
        ("https%3A%2F%2Fevil.test", "%2F"),
        ("%2F%5Cevil.test", "%2F"),
        ("%2F%09%2Fevil.test", "%2F"),
        ("javascript%3Aalert(1)", "%2F"),
        ("%2Fvault%2Flogin", "%2F"),
        ("%2Fauth%2Fhandoff%2Fbegin", "%2F"),
        ("%2Flogin", "%2F"),
    ] {
        let res = begin(&app, &format!("next={raw}")).await.res;
        assert!(
            res.header("location")
                .ends_with(&format!("&next={expected}")),
            "{raw}: {}",
            res.header("location")
        );
    }
    let res = begin(&app, "").await.res;
    assert!(res.header("location").ends_with("&next=%2F"));
}

// -------------------------------------------------------------- the round trip

#[tokio::test]
async fn handoff_roundtrip_gives_the_admin_origin_its_own_session_and_cookies() {
    let (app, user, vault) = signed_in().await;
    let vault_cookies_before = app.jar(Which::Vault).names();

    let begun = begin(&app, "next=%2Fsettings%2Fusers").await;
    let code = code_of(&mint(&app, "login", "/settings/users", &begun.challenge).await);
    assert_eq!(code.len(), 43);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // The `next` comes from the row, not from the client.
    assert_eq!(res.json(), json!({ "next": "/settings/users" }));
    assert_eq!(res.header("cache-control"), "no-store");

    // The admin origin has its own cookies; the verifier is gone.
    let admin = app.jar(Which::Admin);
    assert!(admin.get(SID_COOKIE).is_some());
    assert!(admin.get(SESSION_COOKIE).is_some());
    assert!(admin.get(HANDOFF_COOKIE).is_none());
    assert_ne!(admin.get(SID_COOKIE), vault.jar.get(SID_COOKIE));
    // (The kit's cookie holds the user, the version and the second of the
    // sign-in, so two sign-ins in one second give the same value: the session
    // id is what tells the sessions apart.)

    // The session works on the admin origin and says so.
    let info = admin_session(&app).await;
    assert_eq!(info.status, StatusCode::OK, "{}", info.text());
    let body = info.json();
    assert_eq!(body["origin"], "admin");
    assert_eq!(body["scope"], "full");
    assert_eq!(body["email"], "user1@example.com");

    // The vault session is as it was.
    assert_eq!(app.jar(Which::Vault).names(), vault_cookies_before);
    assert_eq!(vault_session_info(&app).await.status, StatusCode::OK);

    // Two rows: the vault one, and an admin one made from it.
    let rows: Vec<SessionSummary> = db(&app, |c| {
        c.prepare(
            "SELECT origin, parent_sid, revoked_at, user_id FROM ferret_sessions ORDER BY rowid",
        )?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect()
    })
    .await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, "vault");
    assert_eq!(rows[0].1, None);
    assert_eq!(rows[1].0, "admin");
    assert_eq!(rows[1].1.as_deref(), Some(vault.sid.0.as_slice()));
    assert!(rows.iter().all(|r| r.2.is_none() && r.3 == user.user_id));
    // The code is gone.
    assert_eq!(count(&app, "ferret_handoffs").await, 0);
}

#[tokio::test]
async fn admin_cookies_are_host_only_and_never_shared_with_the_vault_origin() {
    let (app, _user, vault) = signed_in().await;
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::OK);

    // Every cookie the redeem sets: `__Host-`, no Domain, Secure, HttpOnly,
    // SameSite=Strict, Path=/.
    let cookies = res.set_cookies();
    assert!(
        cookies.iter().any(|c| c.starts_with(SID_COOKIE)) && cookies.len() >= 3,
        "{cookies:?}"
    );
    for cookie in &cookies {
        assert!(cookie.starts_with("__Host-"), "{cookie}");
        assert!(!cookie.contains("Domain"), "{cookie}");
        for part in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
            assert!(cookie.contains(part), "{part} in {cookie}");
        }
    }

    // The admin cookies open nothing on the vault origin, and the vault cookies
    // open nothing on the admin origin, even when a browser were to send them.
    let admin = app.jar(Which::Admin);
    app.set_jar(Which::Vault, admin.clone());
    assert_eq!(
        vault_session_info(&app).await.status,
        StatusCode::UNAUTHORIZED
    );
    app.set_jar(Which::Admin, vault.jar.clone());
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    // Mixed: the vault's session id with the admin session's kit cookie.
    let mut mixed = Jar::default();
    mixed.set(SID_COOKIE, vault.jar.get(SID_COOKIE).expect("sid"));
    mixed.set(SESSION_COOKIE, admin.get(SESSION_COOKIE).expect("kit"));
    app.set_jar(Which::Admin, mixed);
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    app.set_jar(Which::Admin, admin);
    assert_eq!(admin_session(&app).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admin_row_copies_device_id_and_name_from_the_parent() {
    let (app, _user, vault) = signed_in().await;
    let res = hand_over(&app, "/", "login").await;
    assert_eq!(res.status, StatusCode::OK);
    let rows: Vec<(String, Vec<u8>, String, i64, i64)> = db(&app, |c| {
        c.prepare(
            "SELECT origin, device_id, device_name, issued_at, last_seen FROM ferret_sessions ORDER BY rowid",
        )?
        .query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect()
    })
    .await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, rows[1].1, "the device id");
    assert_eq!(rows[0].2, rows[1].2, "the device name");
    assert_eq!(rows[1].2, "Test browser");
    assert_eq!(rows[1].1, support::session::device(1).0.to_vec());
    // The admin row has its own times and its own id.
    let admin_issued = now(&app);
    assert_eq!((rows[1].3, rows[1].4), (admin_issued, admin_issued));
    let _ = vault;
}

// ------------------------------------------------------- the verifier cookie

#[tokio::test]
async fn redeem_without_the_matching_begin_cookie_is_denied() {
    let (app, _user, _vault) = signed_in().await;
    let first = begin(&app, "next=%2F").await;
    let first_verifier = app
        .jar(Which::Admin)
        .get(HANDOFF_COOKIE)
        .map(str::to_string);
    let code = code_of(&mint(&app, "login", "/", &first.challenge).await);

    // No cookie at all.
    app.clear_jar(Which::Admin);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());
    assert!(app.jar(Which::Admin).get(SID_COOKIE).is_none());

    // A verifier that belongs to another begin.
    let code = code_of(&mint(&app, "login", "/", &first.challenge).await);
    begin(&app, "next=%2F").await;
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());

    // A cookie that is not a verifier at all.
    let code = code_of(&mint(&app, "login", "/", &first.challenge).await);
    let mut garbage = Jar::default();
    garbage.set(HANDOFF_COOKIE, "not-a-verifier");
    app.set_jar(Which::Admin, garbage);
    let res = redeem(&app, &code).await;
    assert_eq!(res.json(), invalid());

    // The right one works (a positive control).
    let code = code_of(&mint(&app, "login", "/", &first.challenge).await);
    let mut right = Jar::default();
    right.set(HANDOFF_COOKIE, &first_verifier.expect("the first verifier"));
    app.set_jar(Which::Admin, right);
    assert_eq!(redeem(&app, &code).await.status, StatusCode::OK);
}

#[tokio::test]
async fn crafted_link_with_a_foreign_code_leaves_the_admin_session_unchanged() {
    let app = TestApp::new().await;
    // The victim is signed in on the admin origin.
    let (victim, _victim_vault) = admin_user(&app, 1).await;
    let victim_admin = app.jar(Which::Admin);
    let victim_sid = victim_admin.get(SID_COOKIE).map(str::to_string);
    let victim_vault_jar = app.jar(Which::Vault);

    // The attacker has an account too. Their browser begins a hand-over and
    // mints a code with their own challenge; the victim never sees any of it.
    let attacker = seed(&app, 2).await;
    app.clear_jar(Which::Admin);
    let theirs = begin(&app, "next=%2F").await;
    vault_session(&app, attacker.user_id, 2).await;
    let attackers_code = code_of(&mint(&app, "login", "/", &theirs.challenge).await);

    // The victim follows the attacker's link: their browser holds the victim's
    // admin session and a verifier of its own.
    app.set_jar(Which::Vault, victim_vault_jar);
    app.set_jar(Which::Admin, victim_admin.clone());
    begin(&app, "next=%2F").await;
    let res = redeem(&app, &attackers_code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());
    assert!(
        res.set_cookies()
            .iter()
            .all(|c| !c.starts_with("__Host-ferret_s")),
        "no session cookie is set: {:?}",
        res.set_cookies()
    );

    // The victim's session is the same one as before.
    assert_eq!(
        app.jar(Which::Admin).get(SID_COOKIE).map(str::to_string),
        victim_sid
    );
    let info = admin_session(&app).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.json()["email"], "user1@example.com");
    let admin_rows = db(&app, |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE origin = 'admin' AND revoked_at IS NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
    })
    .await;
    assert_eq!(admin_rows, 1);
    // The attacker's code is used up too.
    assert_eq!(count(&app, "ferret_handoffs").await, 0);
    let _ = victim;
}

// ----------------------------------------------------- same and other users

#[tokio::test]
async fn login_redeem_is_refused_while_an_admin_session_for_another_user_exists() {
    let app = TestApp::new().await;
    let (_first, _vault1) = admin_user(&app, 1).await;
    let first_admin = app.jar(Which::Admin);

    // Another user signs in on the vault origin of the same browser profile
    // (vault cookies replaced) and starts a hand-over; the admin cookies of the
    // first user are still in the browser.
    let second = seed(&app, 2).await;
    vault_session(&app, second.user_id, 2).await;
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());

    // The first user's session is untouched, and no session of the second exists.
    assert_eq!(
        app.jar(Which::Admin).get(SID_COOKIE),
        first_admin.get(SID_COOKIE)
    );
    let info = admin_session(&app).await;
    assert_eq!(info.status, StatusCode::OK);
    assert_eq!(info.json()["email"], "user1@example.com");
    let second_admin_rows = db(&app, move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE origin = 'admin' AND user_id = ?1",
            [second.user_id],
            |r| r.get::<_, i64>(0),
        )
    })
    .await;
    assert_eq!(second_admin_rows, 0);
}

#[tokio::test]
async fn redeem_for_the_same_user_replaces_the_admin_session() {
    let app = TestApp::new().await;
    let (_user, _vault) = admin_user(&app, 1).await;
    let old = app.jar(Which::Admin);
    assert_eq!(admin_session(&app).await.status, StatusCode::OK);

    // A second hand-over from the same vault session.
    let res = hand_over(&app, "/users", "login").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let new = app.jar(Which::Admin);
    assert_ne!(new.get(SID_COOKIE), old.get(SID_COOKIE));
    assert_eq!(admin_session(&app).await.status, StatusCode::OK);

    // The old one is over, on the server.
    app.set_jar(Which::Admin, old);
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    let rows: Vec<Option<i64>> = db(&app, |c| {
        c.prepare("SELECT revoked_at FROM ferret_sessions WHERE origin = 'admin' ORDER BY rowid")?
            .query_map([], |r| r.get(0))?
            .collect()
    })
    .await;
    assert_eq!(rows.len(), 2);
    assert!(rows[0].is_some() && rows[1].is_none(), "{rows:?}");
}

// ------------------------------------------------------------------ reauth

#[tokio::test]
async fn reauth_code_requires_a_fresh_vault_reauth_and_consumes_it() {
    let (app, _user, vault) = signed_in().await;
    let begun = begin(&app, "next=%2Fsettings&purpose=reauth").await;

    // No grant: refused, and nothing is stored.
    let res = mint(&app, "reauth", "/settings", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(res.json(), json!({ "error": "forbidden" }));
    assert_eq!(count(&app, "ferret_handoffs").await, 0);

    // A grant that is too old: refused.
    grant_reauth(&app, &vault, reauth::TTL_SECS + 1);
    let res = mint(&app, "reauth", "/settings", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(count(&app, "ferret_handoffs").await, 0);

    // A fresh grant: a code, and the grant is used up in the same answer.
    grant_reauth(&app, &vault, 5);
    assert!(app.jar(Which::Vault).get(REAUTH_COOKIE).is_some());
    let res = mint(&app, "reauth", "/settings", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["expires_in"], 60);
    let cleared = set_cookie(&res, REAUTH_COOKIE).expect("the grant is cleared");
    assert!(
        cleared.starts_with(&format!("{REAUTH_COOKIE}=;")) || cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    assert!(app.jar(Which::Vault).get(REAUTH_COOKIE).is_none());
    let purposes: Vec<String> = db(&app, |c| {
        c.prepare("SELECT purpose FROM ferret_handoffs")?
            .query_map([], |r| r.get(0))?
            .collect()
    })
    .await;
    assert_eq!(purposes, ["reauth"]);

    // Used up: the next one needs a new check of the password.
    let res = mint(&app, "reauth", "/settings", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);

    // A code for a plain login needs no grant.
    let res = mint(&app, "login", "/settings", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn reauth_redeem_gives_the_open_admin_session_the_grant_and_makes_no_new_session() {
    let app = TestApp::new().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let admin_before = app.jar(Which::Admin);
    let rows_before = count(&app, "ferret_sessions").await;

    let begun = begin(&app, "next=%2Fsettings%2Fsecurity&purpose=reauth").await;
    grant_reauth(&app, &vault, 1);
    let code = code_of(&mint(&app, "reauth", "/settings/security", &begun.challenge).await);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({ "next": "/settings/security" }));

    // The session is the same; there is a grant for it now.
    let admin = app.jar(Which::Admin);
    assert_eq!(admin.get(SID_COOKIE), admin_before.get(SID_COOKIE));
    assert_eq!(admin.get(SESSION_COOKIE), admin_before.get(SESSION_COOKIE));
    assert!(admin.get(REAUTH_COOKIE).is_some());
    assert!(admin.get(HANDOFF_COOKIE).is_none());
    assert_eq!(count(&app, "ferret_sessions").await, rows_before);
    let kit_jar = SignedCookieJar::from_headers(
        &{
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(
                axum::http::header::COOKIE,
                admin.header().expect("cookies").parse().expect("a header"),
            );
            headers
        },
        app.state.core.session_key.clone(),
    );
    assert!(reauth::is_fresh(&kit_jar, &app.state.core.session_key));
    assert_eq!(admin_session(&app).await.status, StatusCode::OK);
}

#[tokio::test]
async fn reauth_redeem_for_a_different_user_is_denied() {
    let app = TestApp::new().await;
    // User 2 has an open admin session in this browser.
    let (_second, _vault2) = admin_user(&app, 2).await;
    let second_admin = app.jar(Which::Admin);

    // User 1 confirms their password on the vault origin and hands over.
    let first = seed(&app, 1).await;
    let vault1 = vault_session(&app, first.user_id, 1).await;
    let begun = begin(&app, "next=%2Fsettings&purpose=reauth").await;
    grant_reauth(&app, &vault1, 1);
    let code = code_of(&mint(&app, "reauth", "/settings", &begun.challenge).await);
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());
    assert!(set_cookie(&res, REAUTH_COOKIE).is_none());
    assert_eq!(
        app.jar(Which::Admin).get(SID_COOKIE),
        second_admin.get(SID_COOKIE)
    );

    // And with no admin session at all a reauth code has nothing to confirm.
    app.clear_jar(Which::Admin);
    let begun = begin(&app, "next=%2Fsettings&purpose=reauth").await;
    grant_reauth(&app, &vault1, 1);
    let code = code_of(&mint(&app, "reauth", "/settings", &begun.challenge).await);
    let res = redeem(&app, &code).await;
    assert_eq!(res.json(), invalid());
    assert!(app.jar(Which::Admin).get(REAUTH_COOKIE).is_none());
}

// ---------------------------------------------------- the parent session

/// Mints a code, changes the database with `change` (given the user id, the
/// vault session id and the time), and redeems. Returns the answer.
async fn redeem_after(
    change: impl FnOnce(&mut rusqlite::Connection, i64, Vec<u8>, i64) -> rusqlite::Result<()>
    + Send
    + 'static,
) -> (TestApp, support::Res) {
    let (app, user, vault) = signed_in().await;
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    let sid = vault.sid.0.to_vec();
    let at = now(&app);
    db(&app, move |c| change(c, user.user_id, sid, at)).await;
    let res = redeem(&app, &code).await;
    (app, res)
}

async fn assert_denied(
    change: impl FnOnce(&mut rusqlite::Connection, i64, Vec<u8>, i64) -> rusqlite::Result<()>
    + Send
    + 'static,
    why: &str,
) {
    let (app, res) = redeem_after(change).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{why}: {}", res.text());
    assert_eq!(res.json(), invalid(), "{why}");
    assert!(
        res.set_cookies().iter().all(|c| !c.starts_with(SID_COOKIE)),
        "{why}"
    );
    assert!(app.jar(Which::Admin).get(SID_COOKIE).is_none(), "{why}");
    let admin_rows = db(&app, |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE origin = 'admin' AND parent_sid IS NOT NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
    })
    .await;
    assert_eq!(admin_rows, 0, "{why}");
    assert_eq!(
        count(&app, "ferret_handoffs").await,
        0,
        "{why}: the code is used up"
    );
}

#[tokio::test]
async fn code_from_a_revoked_or_expired_vault_session_is_denied() {
    // Positive controls: the limits are inclusive.
    let (_app, res) = redeem_after(|c, _, sid, at| {
        c.execute(
            "UPDATE ferret_sessions SET last_seen = ?2 WHERE sid_hash = ?1",
            rusqlite::params![sid, at - VAULT_IDLE_SECS],
        )?;
        c.execute(
            "UPDATE ferret_sessions SET issued_at = ?2 WHERE sid_hash = ?1",
            rusqlite::params![sid, at - VAULT_ABSOLUTE_SECS],
        )?;
        Ok(())
    })
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    assert_denied(
        |c, _, sid, at| {
            c.execute(
                "UPDATE ferret_sessions SET revoked_at = ?2 WHERE sid_hash = ?1",
                rusqlite::params![sid, at],
            )?;
            Ok(())
        },
        "ended",
    )
    .await;
    assert_denied(
        |c, _, sid, at| {
            c.execute(
                "UPDATE ferret_sessions SET last_seen = ?2 WHERE sid_hash = ?1",
                rusqlite::params![sid, at - VAULT_IDLE_SECS - 1],
            )?;
            Ok(())
        },
        "idle for more than 12 hours",
    )
    .await;
    assert_denied(
        |c, _, sid, at| {
            c.execute(
                "UPDATE ferret_sessions SET issued_at = ?2 WHERE sid_hash = ?1",
                rusqlite::params![sid, at - VAULT_ABSOLUTE_SECS - 1],
            )?;
            Ok(())
        },
        "older than 7 days",
    )
    .await;
    for scope in ["unverified", "pending_2fa", "account_reset"] {
        assert_denied(
            move |c, _, sid, _| {
                c.execute(
                    "UPDATE ferret_sessions SET scope = ?2 WHERE sid_hash = ?1",
                    rusqlite::params![sid, scope],
                )?;
                Ok(())
            },
            scope,
        )
        .await;
    }
    assert_denied(
        |c, user, _, _| {
            c.execute("UPDATE users SET active = 0 WHERE id = ?1", [user])?;
            Ok(())
        },
        "user disabled",
    )
    .await;
    assert_denied(
        |c, user, _, _| {
            c.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
                [user],
            )?;
            Ok(())
        },
        "session version moved",
    )
    .await;
    assert_denied(
        |c, _, sid, _| {
            c.execute(
                "DELETE FROM ferret_sessions WHERE sid_hash = ?1",
                rusqlite::params![sid],
            )?;
            Ok(())
        },
        "session row gone",
    )
    .await;
    // The vault session in the row is an admin one (not possible to make with
    // the routes, but a row is a row): refused.
    assert_denied(
        |c, _, sid, _| {
            c.execute(
                "UPDATE ferret_sessions SET origin = 'admin' WHERE sid_hash = ?1",
                rusqlite::params![sid],
            )?;
            Ok(())
        },
        "not a vault session",
    )
    .await;
}

#[tokio::test]
async fn vault_logout_ends_every_admin_session_handed_over_from_it() {
    let app = TestApp::new().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let first_admin = app.jar(Which::Admin);
    // A second admin session from the same vault session (another browser
    // profile on the admin origin).
    app.clear_jar(Which::Admin);
    assert_eq!(hand_over(&app, "/", "login").await.status, StatusCode::OK);
    let second_admin = app.jar(Which::Admin);
    assert_ne!(first_admin.get(SID_COOKIE), second_admin.get(SID_COOKIE));
    // And an admin session of another user, which has nothing to do with it.
    let other = seed(&app, 2).await;
    let other_vault = vault_session(&app, other.user_id, 2).await;
    app.clear_jar(Which::Admin);
    assert_eq!(hand_over(&app, "/", "login").await.status, StatusCode::OK);
    let other_admin = app.jar(Which::Admin);

    // The first user signs out of the vault.
    app.set_jar(Which::Vault, vault.jar.clone());
    let res = app
        .call(
            Which::Vault,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Vault)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);

    for (jar, alive, who) in [
        (first_admin, false, "first admin session"),
        (second_admin, false, "second admin session"),
        (other_admin, true, "other user's admin session"),
    ] {
        app.set_jar(Which::Admin, jar);
        let want = if alive {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(admin_session(&app).await.status, want, "{who}");
    }
    app.set_jar(Which::Vault, other_vault.jar.clone());
    assert_eq!(vault_session_info(&app).await.status, StatusCode::OK);
}

#[tokio::test]
async fn admin_logout_ends_only_its_own_row() {
    let app = TestApp::new().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let admin = app.jar(Which::Admin);
    let res = app
        .call(
            Which::Admin,
            Req::post("/api/auth/logout")
                .page_fetch(Which::Admin)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    app.set_jar(Which::Admin, admin);
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    // The vault session lives on.
    app.set_jar(Which::Vault, vault.jar);
    assert_eq!(vault_session_info(&app).await.status, StatusCode::OK);
}

#[tokio::test]
async fn revoking_a_session_row_ends_its_children_and_a_child_alone_ends_only_itself() {
    let app = TestApp::new().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let admin = app.jar(Which::Admin);
    let admin_sid = db(&app, |c| {
        c.query_row(
            "SELECT sid_hash FROM ferret_sessions WHERE origin = 'admin'",
            [],
            |r| r.get::<_, Vec<u8>>(0),
        )
    })
    .await;
    let admin_hash = SidHash(<[u8; 32]>::try_from(admin_sid).expect("32 bytes"));
    let at = now(&app);
    // The child alone.
    db(&app, move |c| revoke(c, &admin_hash, at)).await;
    let vault_alive = vault_session_info(&app).await;
    assert_eq!(vault_alive.status, StatusCode::OK);
    app.set_jar(Which::Admin, admin);
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    // The parent takes its children along.
    let (app2, _user2, vault2) = signed_in().await;
    assert_eq!(hand_over(&app2, "/", "login").await.status, StatusCode::OK);
    let sid = vault2.sid;
    let at = now(&app2);
    db(&app2, move |c| revoke(c, &sid, at)).await;
    assert_eq!(admin_session(&app2).await.status, StatusCode::UNAUTHORIZED);
    let _ = vault;
}

#[tokio::test]
async fn bump_of_session_version_ends_both() {
    let app = TestApp::new().await;
    let (user, vault) = admin_user(&app, 1).await;
    assert_eq!(admin_session(&app).await.status, StatusCode::OK);
    assert_eq!(vault_session_info(&app).await.status, StatusCode::OK);
    db(&app, move |c| {
        c.execute(
            "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
            [user.user_id],
        )
    })
    .await;
    assert_eq!(admin_session(&app).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        vault_session_info(&app).await.status,
        StatusCode::UNAUTHORIZED
    );
    let _ = vault;
}

// ------------------------------------------------------- the code itself

#[tokio::test]
async fn code_is_single_use_expires_after_60_seconds_and_a_failed_check_still_uses_it_up() {
    let (app, _user, _vault) = signed_in().await;

    // Single use.
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    assert_eq!(redeem(&app, &code).await.status, StatusCode::OK);
    let again = redeem(&app, &code).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert_eq!(again.json(), invalid());

    // Valid for 60 seconds and not a second more.
    assert_eq!(CODE_TTL_SECS, 60);
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    app.clock.advance(60);
    assert_eq!(redeem(&app, &code).await.status, StatusCode::OK);
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    app.clock.advance(61);
    let late = redeem(&app, &code).await;
    assert_eq!(late.status, StatusCode::BAD_REQUEST);
    assert_eq!(late.json(), invalid());
    // The expired code is used up as well.
    assert_eq!(count(&app, "ferret_handoffs").await, 0);

    // A failed check uses the code up: a second try with everything right fails.
    let begun = begin(&app, "next=%2F").await;
    let verifier = app
        .jar(Which::Admin)
        .get(HANDOFF_COOKIE)
        .map(str::to_string);
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    app.clear_jar(Which::Admin);
    assert_eq!(redeem(&app, &code).await.json(), invalid());
    let mut right = Jar::default();
    right.set(HANDOFF_COOKIE, &verifier.expect("a verifier"));
    app.set_jar(Which::Admin, right);
    let second = redeem(&app, &code).await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
    assert_eq!(second.json(), invalid());

    // A code of the wrong shape never reaches the database.
    for bad in ["", "short", &"A".repeat(44)[..], &"!".repeat(43)[..]] {
        let res = redeem(&app, bad).await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad:?}");
        assert_eq!(res.json(), invalid(), "{bad:?}");
    }
}

#[tokio::test]
async fn code_hash_not_code_is_stored() {
    let (app, user, vault) = signed_in().await;
    let begun = begin(&app, "next=%2Fsettings").await;
    let code = code_of(&mint(&app, "login", "/settings", &begun.challenge).await);
    let bytes = URL_SAFE_NO_PAD.decode(&code).expect("base64url");

    let rows = dump(&app, "ferret_handoffs").await;
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    // code_hash, sid_hash, user_id, purpose, next, challenge, expires_at, version
    assert_eq!(row[0], hex(&Sha256::digest(&bytes)));
    assert_eq!(row[1], hex(&vault.sid.0));
    assert_eq!(row[2], user.user_id.to_string());
    assert_eq!(row[3], "login");
    assert_eq!(row[4], "/settings");
    assert_eq!(
        row[5],
        hex(&URL_SAFE_NO_PAD.decode(&begun.challenge).expect("challenge"))
    );
    for cell in row {
        assert!(!cell.contains(&code), "the code itself is in the row");
        assert!(
            !cell.contains(&hex(&bytes)),
            "the code's bytes are in the row"
        );
    }
    // Nor anywhere else in the two tables a code touches.
    for table in ["ferret_sessions"] {
        for row in dump(&app, table).await {
            assert!(row.iter().all(|c| !c.contains(&code)), "{table}");
        }
    }
}

#[tokio::test]
async fn expired_handoff_rows_are_purged() {
    let (app, _user, _vault) = signed_in().await;
    let begun = begin(&app, "next=%2F").await;
    mint(&app, "login", "/", &begun.challenge).await;
    app.clock.advance(30);
    mint(&app, "login", "/", &begun.challenge).await;
    assert_eq!(count(&app, "ferret_handoffs").await, 2);

    // At the very second a code expires it is still there.
    app.clock.advance(30);
    assert_eq!(
        purge_once(&app.state.vault_db, app.clock.as_ref())
            .await
            .expect("purge"),
        0
    );
    // A second later the first is gone and the second stays.
    app.clock.advance(1);
    assert_eq!(
        purge_once(&app.state.vault_db, app.clock.as_ref())
            .await
            .expect("purge"),
        1
    );
    assert_eq!(count(&app, "ferret_handoffs").await, 1);
    app.clock.advance(30);
    assert_eq!(
        purge_once(&app.state.vault_db, app.clock.as_ref())
            .await
            .expect("purge"),
        1
    );
    assert_eq!(count(&app, "ferret_handoffs").await, 0);
}

#[tokio::test]
async fn a_session_keeps_only_its_newest_waiting_codes() {
    let (app, _user, _vault) = signed_in().await;
    let begun = begin(&app, "next=%2F").await;
    let mut codes = Vec::new();
    for _ in 0..10 {
        codes.push(code_of(&mint(&app, "login", "/", &begun.challenge).await));
    }
    assert_eq!(count(&app, "ferret_handoffs").await, 8);
    // The oldest two were pushed out; the newest works.
    let verifier = app.jar(Which::Admin);
    assert_eq!(redeem(&app, &codes[0]).await.json(), invalid());
    // (The refused redeem took the verifier out of the browser; put it back.)
    app.set_jar(Which::Admin, verifier);
    assert_eq!(redeem(&app, &codes[9]).await.status, StatusCode::OK);
}

#[tokio::test]
async fn next_is_sanitized_with_the_kits_function_stored_in_the_row_and_returned_by_redeem() {
    let (app, _user, _vault) = signed_in().await;
    for (sent, stored) in [
        ("/settings/users", "/settings/users"),
        ("/settings?tab=a", "/settings?tab=a"),
        ("//evil.test", "/"),
        ("/\\evil.test", "/"),
        ("/\t/evil.test", "/"),
        ("/\n/evil.test", "/"),
        ("/a\u{1}b", "/"),
        ("/a b", "/"),
        ("https://evil.test/", "/"),
        ("javascript:alert(1)", "/"),
        ("relative", "/"),
        ("/login", "/"),
        ("/logout", "/"),
        ("/setup", "/"),
        ("/vault/login", "/"),
        ("/vault/reauth?next=/x", "/"),
        ("/auth/handoff/begin", "/"),
        ("/api/auth/session", "/"),
    ] {
        let begun = begin(&app, "next=%2F").await;
        let code = code_of(&mint(&app, "login", sent, &begun.challenge).await);
        let row: String = db(&app, |c| {
            c.query_row("SELECT next FROM ferret_handoffs", [], |r| r.get(0))
        })
        .await;
        assert_eq!(row, stored, "stored for {sent:?}");
        let res = redeem(&app, &code).await;
        assert_eq!(res.status, StatusCode::OK, "{sent:?}");
        assert_eq!(res.json(), json!({ "next": stored }), "{sent:?}");
    }
}

// ------------------------------------------------- origin, listener, session

#[tokio::test]
async fn mint_requires_origin_equal_to_the_vault_url() {
    let app = TestApp::new().await;
    let body = json!({ "purpose": "login", "next": "/", "challenge": "A".repeat(43) });
    // No cookie, so only the route's own rule can refuse: it wants the right Origin.
    for origin in [
        None,
        Some(ADMIN_URL),
        Some("https://evil.test"),
        Some("null"),
    ] {
        let mut req = Req::post("/api/auth/handoff")
            .header("ferret-protocol", "1")
            .json(&body);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let res = app.call(Which::Vault, req.build()).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(
            res.json(),
            json!({ "error": "forbidden_origin" }),
            "{origin:?}"
        );
    }
    // The right Origin and no session: the one 401.
    let res = app
        .call(
            Which::Vault,
            Req::post("/api/auth/handoff")
                .page_fetch(Which::Vault)
                .json(&body)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(res.json(), json!({ "error": "unauthorized" }));
    // Without the protocol header: refused before anything else.
    let res = app
        .call(
            Which::Vault,
            Req::post("/api/auth/handoff")
                .header("origin", VAULT_URL)
                .json(&body)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn redeem_requires_origin_equal_to_the_admin_url_even_without_a_cookie() {
    let app = TestApp::new().await;
    let body = json!({ "code": "A".repeat(43) });
    for origin in [
        None,
        Some(VAULT_URL),
        Some("https://evil.test"),
        Some("null"),
    ] {
        let mut req = Req::post("/api/auth/handoff/redeem")
            .header("ferret-protocol", "1")
            .json(&body);
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        let res = app.call(Which::Admin, req.build()).await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(
            res.json(),
            json!({ "error": "forbidden_origin" }),
            "{origin:?}"
        );
    }
    // The right Origin and a code nobody made.
    let res = redeem(&app, &"A".repeat(43)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());
}

#[tokio::test]
async fn mint_needs_a_full_vault_session() {
    let (app, user, _vault) = signed_in().await;
    let begun = begin(&app, "next=%2F").await;
    // A session that is not a full one.
    for scope in [SessionScope::Pending2fa, SessionScope::Unverified] {
        let issued = support::session::issue(
            &app,
            user.user_id,
            ferret_server::auth::session::Origin::Vault,
            scope,
            7,
        )
        .await;
        app.set_jar(Which::Vault, issued.jar);
        let res = mint(&app, "login", "/", &begun.challenge).await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{scope:?}");
    }
    assert_eq!(count(&app, "ferret_handoffs").await, 0);
    // A body that is wrong in itself.
    let (app, _user, _vault) = signed_in().await;
    for body in [
        json!({ "purpose": "login", "next": "/", "challenge": "short" }),
        json!({ "purpose": "other", "next": "/", "challenge": "A".repeat(43) }),
        json!({ "purpose": "login", "next": "", "challenge": "A".repeat(43) }),
        json!({ "purpose": "login", "next": "/", "challenge": "A".repeat(43), "extra": 1 }),
        json!({ "purpose": "login", "next": "x".repeat(513), "challenge": "A".repeat(43) }),
    ] {
        let res = app
            .call(
                Which::Vault,
                Req::post("/api/auth/handoff")
                    .page_fetch(Which::Vault)
                    .json(&body)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{body}");
    }
    assert_eq!(count(&app, "ferret_handoffs").await, 0);
}

#[tokio::test]
async fn handoff_goes_only_from_vault_to_admin() {
    let app = TestApp::new().await;
    let (_user, vault) = admin_user(&app, 1).await;
    let admin = app.jar(Which::Admin);
    let begun = begin(&app, "next=%2F").await;
    let body = json!({ "purpose": "login", "next": "/", "challenge": begun.challenge });

    // Minting on the admin listener: there is no such route.
    let res = app
        .call(
            Which::Admin,
            Req::post("/api/auth/handoff")
                .page_fetch(Which::Admin)
                .json(&body)
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(count(&app, "ferret_handoffs").await, 0);

    // Redeeming on the vault listener: no such route either, and a code made
    // on the vault is not used up by the attempt.
    app.set_jar(Which::Vault, vault.jar.clone());
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    let res = app
        .call(
            Which::Vault,
            Req::post("/api/auth/handoff/redeem")
                .page_fetch(Which::Vault)
                .json(&json!({ "code": code }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(count(&app, "ferret_handoffs").await, 1);
    assert_eq!(redeem(&app, &code).await.status, StatusCode::OK);

    // An admin session cannot make a vault session or a code: put the admin
    // cookies where the vault's go.
    app.set_jar(Which::Vault, admin.clone());
    let res = mint(&app, "login", "/", &begun.challenge).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        vault_session_info(&app).await.status,
        StatusCode::UNAUTHORIZED
    );
    let res = app
        .call(Which::Vault, Req::get("/api/vault/unlock-methods").build())
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
}

// --------------------------------------------------------- page, log, canary

#[tokio::test]
async fn handoff_page_sends_no_referrer_and_has_no_other_scripts() {
    let app = TestApp::new().await;
    let page = app
        .call(Which::Admin, Req::get("/auth/handoff").build())
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.header("content-type").starts_with("text/html"));
    assert_eq!(page.header("referrer-policy"), "no-referrer");
    assert_eq!(page.header("cache-control"), "no-store");
    let csp = page.header("content-security-policy").to_string();
    assert!(csp.contains("script-src 'self'"), "{csp}");
    let script_src = csp
        .split(';')
        .find(|d| d.trim().starts_with("script-src"))
        .expect("script-src");
    assert!(!script_src.contains("unsafe"), "{csp}");
    assert!(!script_src.contains("http"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'") || page.header("x-frame-options") == "DENY");

    let html = page.text().to_ascii_lowercase();
    assert_eq!(html.matches("<script").count(), 1, "{html}");
    assert!(html.contains("src=\"/auth/handoff.mjs\""));
    assert!(!html.contains("type=\"password\"") && !html.contains(".wasm"));
    assert!(!html.contains("onclick") && !html.contains("javascript:"));

    let script = app
        .call(Which::Admin, Req::get("/auth/handoff.mjs").build())
        .await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(script.header("content-type").starts_with("text/javascript"));
    assert_eq!(script.header("referrer-policy"), "no-referrer");
    assert_eq!(
        script.text(),
        include_str!("../../../web/admin/handoff.mjs")
    );
    let source = script.text();
    assert!(!source.contains("WebAssembly") && !source.contains("eval("));

    // The begin redirect and the redeem answer carry the policy too.
    let begun = begin(&app, "next=%2F").await;
    assert_eq!(begun.res.header("referrer-policy"), "no-referrer");

    // Neither page is served on the vault listener.
    for path in ["/auth/handoff", "/auth/handoff.mjs", "/auth/handoff/begin"] {
        let res = app.call(Which::Vault, Req::get(path).build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{path}");
    }
}

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

fn log_sink() -> Sink {
    static ONCE: Once = Once::new();
    static SINK: Mutex<Option<Sink>> = Mutex::new(None);
    ONCE.call_once(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        // Tasks run on other threads, so the subscriber is the process's.
        let _ = tracing::subscriber::set_global_default(subscriber);
        *SINK.lock().expect("sink") = Some(sink);
    });
    SINK.lock().expect("sink").clone().expect("the sink")
}

#[tokio::test]
async fn code_never_appears_in_a_request_line_a_referer_or_the_log() {
    let sink = log_sink();
    let (app, _user, vault) = signed_in().await;
    let begun = begin(&app, "next=%2Fsettings").await;
    let verifier = app
        .jar(Which::Admin)
        .get(HANDOFF_COOKIE)
        .expect("verifier")
        .to_string();
    let minted = mint(&app, "login", "/settings", &begun.challenge).await;
    let code = code_of(&minted);
    let redeemed = redeem(&app, &code).await;
    assert_eq!(redeemed.status, StatusCode::OK);
    // A second try, and a try with a wrong code, make the log speak.
    let again = redeem(&app, &code).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    let wrong = redeem(&app, &URL_SAFE_NO_PAD.encode([9u8; 32])).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);

    let secrets = [
        code.clone(),
        verifier,
        begun.challenge.clone(),
        vault.secret.clone(),
        app.jar(Which::Admin)
            .get(SID_COOKIE)
            .expect("sid")
            .to_string(),
        app.jar(Which::Admin)
            .get(SESSION_COOKIE)
            .expect("kit")
            .to_string(),
    ];
    // Nowhere in a header of any answer (a request line is made of what the
    // server sent: a redirect, a link), and in the body of the mint only.
    for res in [&begun.res, &redeemed, &again, &wrong] {
        for (name, value) in &res.headers {
            let value = value.to_str().unwrap_or_default();
            assert!(
                !value.contains(&code),
                "the code is in the header {name}: {value}"
            );
        }
        assert!(!res.text().contains(&code));
    }
    assert!(begun.res.header("location").contains(&begun.challenge));
    assert!(!begun.res.header("location").contains(&secrets[1]));

    let log = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("a UTF-8 log");
    assert!(
        log.contains("hand-over refused"),
        "the log is being written: {log}"
    );
    for secret in &secrets {
        assert!(!log.contains(secret.as_str()), "the log holds {secret}");
    }
}

#[tokio::test]
async fn a_refused_redeem_removes_the_verifier() {
    let (app, _user, _vault) = signed_in().await;
    let remove_cookie = |res: &support::Res| {
        let cookie = set_cookie(res, HANDOFF_COOKIE).expect("the verifier is removed");
        assert!(
            cookie.starts_with(&format!("{HANDOFF_COOKIE}=;")) || cookie.contains("Max-Age=0"),
            "{cookie}"
        );
        assert!(
            cookie.contains("Secure") && cookie.contains("HttpOnly"),
            "{cookie}"
        );
    };

    // A wrong code, a code of the wrong shape, a wrong verifier: each one
    // takes the verifier out of the browser.
    let begun = begin(&app, "next=%2F").await;
    assert!(app.jar(Which::Admin).get(HANDOFF_COOKIE).is_some());
    let res = redeem(&app, &URL_SAFE_NO_PAD.encode([5u8; 32])).await;
    assert_eq!(res.json(), invalid());
    remove_cookie(&res);
    assert!(app.jar(Which::Admin).get(HANDOFF_COOKIE).is_none());

    begin(&app, "next=%2F").await;
    let res = redeem(&app, "short").await;
    assert_eq!(res.json(), invalid());
    remove_cookie(&res);
    assert!(app.jar(Which::Admin).get(HANDOFF_COOKIE).is_none());

    // The code of the first begin with the verifier of another begin.
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);
    begin(&app, "next=%2F").await;
    let res = redeem(&app, &code).await;
    assert_eq!(res.json(), invalid());
    remove_cookie(&res);
    assert!(app.jar(Which::Admin).get(HANDOFF_COOKIE).is_none());
    assert!(app.jar(Which::Admin).get(SID_COOKIE).is_none());
}

#[tokio::test]
async fn an_error_reading_the_presented_admin_session_is_an_error_and_uses_nothing_up() {
    let app = TestApp::new().await;
    // User 2 has an admin session in this browser; user 1 hands over.
    let (_second, _vault2) = admin_user(&app, 2).await;
    let first = seed(&app, 1).await;
    vault_session(&app, first.user_id, 1).await;
    let begun = begin(&app, "next=%2F").await;
    let code = code_of(&mint(&app, "login", "/", &begun.challenge).await);

    // Break the read of session rows, so that finding out who is signed in on
    // the admin origin fails with a database error and not with "nobody".
    db(&app, |c| {
        c.execute_batch("ALTER TABLE ferret_sessions RENAME COLUMN last_seen TO last_seen_x")
    })
    .await;
    let res = redeem(&app, &code).await;
    assert_eq!(
        res.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        res.text()
    );
    assert_eq!(res.json(), json!({ "error": "internal" }));
    assert!(set_cookie(&res, SID_COOKIE).is_none());
    // Nothing was used up: the code is still there.
    assert_eq!(count(&app, "ferret_handoffs").await, 1);

    // With the table whole again, the rule that another user's admin session is
    // never replaced still holds.
    db(&app, |c| {
        c.execute_batch("ALTER TABLE ferret_sessions RENAME COLUMN last_seen_x TO last_seen")
    })
    .await;
    let res = redeem(&app, &code).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    assert_eq!(res.json(), invalid());
    let first_admin_rows = db(&app, move |c| {
        c.query_row(
            "SELECT COUNT(*) FROM ferret_sessions WHERE origin = 'admin' AND user_id = ?1",
            [first.user_id],
            |r| r.get::<_, i64>(0),
        )
    })
    .await;
    assert_eq!(first_admin_rows, 0);
}
