//! Registration with an invitation: `register/start` with `invite`,
//! `register/finish` for an invited registration, and
//! `POST /api/auth/invite/check`, driven by the real client of `ferret-core`
//! against the whole server in process.
//!
//! The invitations are made with the kit's own `db::invites::insert`, as the
//! Users page makes them; the token is the kit's.
//!
//! Spec: Fase 1 § 4.2 ("Registration with an invitation"), § 11 (the limits).

mod support;

use std::io;
use std::sync::{Arc, Mutex, OnceLock};

use axum::http::{Method, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{OPAQUE_CONTEXT, OsRng, PinState, opaque_login_start};
use ferret_server::accounts::actions::issue_sign_in_code;
use ferret_server::accounts::invites::{INVITED_ROLE, InviteStarts, STARTS_PER_INVITE};
use ferret_server::accounts::log::Actor;
use ferret_server::auth::login;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::SMALL;
use ferret_server_auth::{Clock as _, PreloginPolicy};
use serde_json::{Value, json};
use support::accounts::{
    CLIENT_PASSWORD, add_account_to_app, opaque_input, post_recover, recovered,
};
use support::device::{DeviceClient, device_app};
use support::register::{START, call, error_of, registrant};
use support::{Jar, Req, Res, TestApp, Which};
use vole_kit::db::role::Role;

const CHECK: &str = "/api/auth/invite/check";
const EVENTS: &str = "/api/account/events";
const ADMIN_EMAIL: &str = "user1@example.com";
const NEW_PASSWORD: &str = "a brand new horse battery staple";

// ----------------------------------------------------------------- helpers

/// An app that trusts the test peer as a proxy, with one administrator
/// (`user1@example.com`, account 1, with a secret key). Returns the app and
/// the administrator's user id.
async fn with_admin() -> (TestApp, i64) {
    let app = device_app().await;
    let admin = add_account_to_app(&app, 1).await.user_id;
    sql(&app, "UPDATE users SET role = 'admin' WHERE id = ?1", admin).await;
    (app, admin)
}

async fn sql(app: &TestApp, statement: &'static str, id: i64) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(statement, [id])?;
            Ok(())
        })
        .await
        .expect("the statement");
}

async fn count(app: &TestApp, query: &'static str) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(conn.query_row(query, [], |r| r.get(0))?))
        .await
        .expect("a count")
}

/// An invitation made by `by` with `role`; returns its token.
async fn invite_as(app: &TestApp, by: i64, role: Role) -> String {
    let token = vole_kit::auth::invites::generate();
    let hash = vole_kit::auth::invites::hash(&token);
    app.state
        .vault_db
        .with_conn(move |conn| {
            vole_kit::db::invites::insert(conn, &hash, role, "", by)?;
            Ok(())
        })
        .await
        .expect("an invitation");
    token
}

/// A viewer invitation made by `by`.
async fn invite(app: &TestApp, by: i64) -> String {
    invite_as(app, by, Role::Viewer).await
}

/// Revokes the invitation of `token`.
async fn revoke(app: &TestApp, token: &str) {
    let hash = vole_kit::auth::invites::hash(token);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let found = vole_kit::db::invites::find_pending(conn, &hash)?.expect("pending");
            assert!(vole_kit::db::invites::revoke(conn, found.id)?);
            Ok(())
        })
        .await
        .expect("a revocation");
}

/// Makes the invitation of `token` run out a second ago.
async fn expire(app: &TestApp, token: &str) {
    let hash = vole_kit::auth::invites::hash(token);
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE invites SET expires_at = datetime('now', '-1 second')
                 WHERE token_hash = ?1",
                [hash.as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("an expiry");
}

/// Marks the invitation of `token` as used by `user`.
async fn use_up(app: &TestApp, token: &str, user: i64) {
    let hash = vole_kit::auth::invites::hash(token);
    app.state
        .vault_db
        .with_conn(move |conn| {
            assert!(vole_kit::db::invites::consume(conn, &hash, user)?);
            Ok(())
        })
        .await
        .expect("a use");
}

async fn is_pending(app: &TestApp, token: &str) -> bool {
    let hash = vole_kit::auth::invites::hash(token);
    app.state
        .vault_db
        .with_conn(move |conn| Ok(vole_kit::db::invites::find_pending(conn, &hash)?.is_some()))
        .await
        .expect("a lookup")
}

/// `invite/check` for `token` from the test peer.
async fn check(app: &TestApp, token: &str) -> Res {
    call(app, CHECK, &json!({ "invite": token })).await
}

/// `invite/check` for `token` from `address` behind the trusted proxy.
async fn check_from(app: &TestApp, token: &str, address: &str) -> Res {
    let req = support::register::post(CHECK, &json!({ "invite": token }))
        .header("x-forwarded-for", address)
        .build();
    app.call_raw(Which::Vault, req).await
}

/// The status, the sorted headers and the body of an answer.
type Whole = (StatusCode, Vec<(String, Vec<u8>)>, Vec<u8>);

/// The status, the headers and the body of an answer, to compare two.
fn whole(res: &Res) -> Whole {
    let mut headers: Vec<(String, Vec<u8>)> = res
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    headers.sort();
    (res.status, headers, res.body.clone())
}

fn assert_refused(res: &Res, status: StatusCode, code: &str) {
    assert_eq!(
        (res.status, error_of(res).as_str()),
        (status, code),
        "{}",
        res.text()
    );
    assert!(res.set_cookies().is_empty(), "{:?}", res.set_cookies());
}

/// The kit user of `email`.
async fn user_of(app: &TestApp, email: &'static str) -> Option<(i64, String, String)> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            use rusqlite::OptionalExtension as _;
            Ok(conn
                .query_row(
                    "SELECT id, role, password_hash FROM users WHERE username = ?1",
                    [email],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?)
        })
        .await
        .expect("a user")
}

/// The events of `user`: `(kind, actor, actor_name, at)`, oldest first.
async fn events_of(app: &TestApp, user: i64) -> Vec<(String, String, String, i64)> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT kind, actor, actor_name, at FROM ferret_account_events
                 WHERE user_id = ?1 ORDER BY id",
            )?;
            let rows = stmt
                .query_map([user], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the events")
}

/// Users, accounts, vaults, sessions and events: what a finish writes.
async fn written(app: &TestApp) -> [i64; 5] {
    [
        count(app, "SELECT COUNT(*) FROM users").await,
        count(app, "SELECT COUNT(*) FROM ferret_accounts").await,
        count(app, "SELECT COUNT(*) FROM ferret_vaults").await,
        count(app, "SELECT COUNT(*) FROM ferret_sessions").await,
        count(app, "SELECT COUNT(*) FROM ferret_account_events").await,
    ]
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

async fn get_with_jar(app: &TestApp, jar: &Jar, uri: &str) -> Res {
    let mut req = Req::get(uri).page_fetch(Which::Vault);
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn an_invited_person_registers_and_gets_a_viewer_account_with_a_vault_and_a_session() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;
    assert_eq!(INVITED_ROLE, Role::Viewer);

    let registered = registrant("bea")
        .started(&app, "Bea@Example.test", Some(&token), true)
        .await;
    assert_eq!(registered.started["ksf_profile"], 1);
    let done = registered.send(&app).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    assert_eq!(done.header("cache-control"), "no-store");
    assert_eq!(
        done.json(),
        json!({
            "account_id": registered.started["account_id"],
            "vault_id": registered.started["vault_id"],
        })
    );

    // A viewer with the kit's external password marker.
    let (user, role, hash) = user_of(&app, "bea@example.test").await.expect("the user");
    assert_eq!((role.as_str(), hash.as_str()), ("viewer", "!external"));
    // Its account and vault, under the ids the server gave.
    let account = registered.account_id();
    let vault = registered.vault_id();
    let (holder, vault_of) = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT a.user_id, v.vault_id FROM ferret_accounts a
                 JOIN ferret_vaults v ON v.account_id = a.account_id
                 WHERE a.account_id = ?1",
                [account.as_bytes().as_slice()],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?)),
            )?)
        })
        .await
        .expect("the account");
    assert_eq!((holder, vault_of), (user, vault.as_bytes().to_vec()));
    // The invitation is spent, by this user.
    assert!(!is_pending(&app, &token).await);
    let used_by = count(&app, "SELECT used_by FROM invites").await;
    assert_eq!(used_by, user);
    // The administrator's site settings are untouched, and the administrator
    // is still the one administrator.
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM users WHERE role = 'admin'").await,
        1
    );

    // The session is a full vault session of the new account.
    let jar = app.jar(Which::Vault);
    let events = get_with_jar(&app, &jar, EVENTS).await;
    assert_eq!(events.status, StatusCode::OK, "{}", events.text());
    let listed = events.json();
    assert_eq!(listed["events"][0]["kind"], "account_created");
    let (scope, origin) = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT scope, origin FROM ferret_sessions WHERE user_id = ?1",
                [user],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )?)
        })
        .await
        .expect("the session");
    assert_eq!((scope.as_str(), origin.as_str()), ("full", "vault"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_invitation_works_once_even_when_two_finish_at_once() {
    for round in 0..3 {
        let (app, admin) = with_admin().await;
        let token = invite(&app, admin).await;
        let one = registrant(&format!("one {round}"))
            .started(
                &app,
                &format!("one{round}@example.test"),
                Some(&token),
                false,
            )
            .await;
        let two = registrant(&format!("two {round}"))
            .started(
                &app,
                &format!("two{round}@example.test"),
                Some(&token),
                false,
            )
            .await;
        let app = Arc::new(app);
        let (a, b) = {
            let (app_a, app_b) = (app.clone(), app.clone());
            let a = tokio::spawn(async move { one.send_raw(&app_a).await });
            let b = tokio::spawn(async move { two.send_raw(&app_b).await });
            (a.await.expect("a"), b.await.expect("b"))
        };
        let (winner, loser) = if a.status == StatusCode::CREATED {
            (&a, &b)
        } else {
            (&b, &a)
        };
        assert_eq!(winner.status, StatusCode::CREATED, "round {round}");
        assert_refused(loser, StatusCode::FORBIDDEN, "invite_invalid");
        // One new user, one new account, one event.
        assert_eq!(
            count(&app, "SELECT COUNT(*) FROM users").await,
            2,
            "round {round}"
        );
        assert_eq!(
            count(&app, "SELECT COUNT(*) FROM ferret_accounts").await,
            2,
            "round {round}"
        );
        assert_eq!(
            count(&app, "SELECT COUNT(*) FROM ferret_account_events").await,
            1,
            "round {round}"
        );
    }
}

#[tokio::test]
async fn a_revoked_or_expired_invitation_is_refused_at_start_and_at_finish() {
    let (app, admin) = with_admin().await;
    let before = written(&app).await;

    // At start.
    let revoked = invite(&app, admin).await;
    revoke(&app, &revoked).await;
    let expired = invite(&app, admin).await;
    expire(&app, &expired).await;
    for token in [&revoked, &expired] {
        let res = registrant("late")
            .start(&app, "late@example.test", Some(token))
            .await;
        assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
    }
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );

    // Between the two steps.
    for (n, kill) in ["revoke", "expire"].into_iter().enumerate() {
        let token = invite(&app, admin).await;
        let registered = registrant(kill)
            .started(&app, &format!("gone{n}@example.test"), Some(&token), false)
            .await;
        if kill == "revoke" {
            revoke(&app, &token).await;
        } else {
            expire(&app, &token).await;
        }
        let res = registered.send_raw(&app).await;
        assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
        assert_eq!(written(&app).await, before, "{kill}: nothing was written");
    }
}

#[tokio::test]
async fn unknown_used_revoked_and_expired_invitations_answer_alike() {
    let (app, admin) = with_admin().await;
    let unknown = vole_kit::auth::invites::generate();
    let used = invite(&app, admin).await;
    use_up(&app, &used, admin).await;
    let revoked = invite(&app, admin).await;
    revoke(&app, &revoked).await;
    let expired = invite(&app, admin).await;
    expire(&app, &expired).await;

    let start_of = |token: String| {
        let app = &app;
        async move {
            registrant("alike")
                .start(app, "alike@example.test", Some(&token))
                .await
        }
    };
    let reference_start = start_of(unknown.clone()).await;
    assert_refused(&reference_start, StatusCode::FORBIDDEN, "invite_invalid");
    assert_eq!(reference_start.body, br#"{"error":"invite_invalid"}"#);
    let reference_check = check(&app, &unknown).await;
    assert_refused(&reference_check, StatusCode::FORBIDDEN, "invite_invalid");
    assert_eq!(reference_check.body, br#"{"error":"invite_invalid"}"#);
    for (what, token) in [
        ("used", &used),
        ("revoked", &revoked),
        ("expired", &expired),
    ] {
        let start = start_of(token.clone()).await;
        assert_eq!(whole(&start), whole(&reference_start), "start, {what}");
        let checked = check(&app, token).await;
        assert_eq!(whole(&checked), whole(&reference_check), "check, {what}");
    }
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );
}

#[tokio::test]
async fn an_invitation_with_another_role_is_refused() {
    let (app, admin) = with_admin().await;
    let unknown = check(&app, &vole_kit::auth::invites::generate()).await;
    for role in [Role::Editor, Role::Admin] {
        let token = invite_as(&app, admin, role).await;
        let res = registrant("role")
            .start(&app, "role@example.test", Some(&token))
            .await;
        assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
        let checked = check(&app, &token).await;
        assert_eq!(whole(&checked), whole(&unknown), "{role:?}");
        // The invitation stays as it was.
        assert!(is_pending(&app, &token).await);
    }
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );
    assert_eq!(count(&app, "SELECT COUNT(*) FROM users").await, 1);
}

#[tokio::test]
async fn a_taken_email_is_email_taken_only_with_a_valid_invitation() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;

    // With a valid invitation: the e-mail is taken, in any case of letters.
    for email in [ADMIN_EMAIL, "User1@Example.com"] {
        let res = registrant("taken").start(&app, email, Some(&token)).await;
        assert_refused(&res, StatusCode::CONFLICT, "email_taken");
    }
    // With an invitation that is not pending, a taken and a free e-mail
    // answer alike.
    let dead = vole_kit::auth::invites::generate();
    let taken = registrant("dead")
        .start(&app, ADMIN_EMAIL, Some(&dead))
        .await;
    let free = registrant("dead")
        .start(&app, "free@example.test", Some(&dead))
        .await;
    assert_eq!(whole(&taken), whole(&free));
    assert_refused(&taken, StatusCode::FORBIDDEN, "invite_invalid");
    // Without an invitation: closed, for both.
    let taken = registrant("none").start(&app, ADMIN_EMAIL, None).await;
    let free = registrant("none")
        .start(&app, "free@example.test", None)
        .await;
    assert_eq!(whole(&taken), whole(&free));
    assert_refused(&taken, StatusCode::CONFLICT, "registration_closed");
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );

    // An e-mail that got an account between the two steps.
    let registered = registrant("between")
        .started(&app, "between@example.test", Some(&token), false)
        .await;
    app.state
        .vault_db
        .with_conn(|conn| Ok(support::accounts::insert_user(conn, "between@example.test")))
        .await
        .expect("a user");
    let before = written(&app).await;
    let res = registered.send_raw(&app).await;
    assert_refused(&res, StatusCode::CONFLICT, "email_taken");
    assert_eq!(written(&app).await, before);
    assert!(
        is_pending(&app, &token).await,
        "the invitation is not spent"
    );
}

#[tokio::test]
async fn starts_per_invitation_are_capped() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;
    let other = invite(&app, admin).await;
    assert_eq!(STARTS_PER_INVITE, 10);

    // Starts that end in `email_taken` count as well: the cap is checked
    // before the e-mail.
    for _ in 0..5 {
        let res = registrant("cap")
            .start(&app, ADMIN_EMAIL, Some(&token))
            .await;
        assert_refused(&res, StatusCode::CONFLICT, "email_taken");
    }
    for n in 5..STARTS_PER_INVITE {
        let res = registrant("cap")
            .start(&app, &format!("cap{n}@example.test"), Some(&token))
            .await;
        assert_eq!(res.status, StatusCode::OK, "start {n}: {}", res.text());
    }
    let eleventh = registrant("cap")
        .start(&app, "cap11@example.test", Some(&token))
        .await;
    assert_refused(&eleventh, StatusCode::TOO_MANY_REQUESTS, "throttled");
    let wait: u64 = eleventh.header("retry-after").parse().expect("a wait");
    assert!((1..=3_600).contains(&wait), "{wait}");
    // A taken e-mail is not told past the cap.
    let taken = registrant("cap")
        .start(&app, ADMIN_EMAIL, Some(&token))
        .await;
    assert_refused(&taken, StatusCode::TOO_MANY_REQUESTS, "throttled");

    // Another invitation has a count of its own.
    let res = registrant("cap")
        .start(&app, "other@example.test", Some(&other))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // A made-up token is never counted: it stays `invite_invalid`.
    let unknown = vole_kit::auth::invites::generate();
    for _ in 0..(STARTS_PER_INVITE + 5) {
        let res = registrant("unknown")
            .start(&app, "x@example.test", Some(&unknown))
            .await;
        assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
    }

    // An hour later the invitation may start again.
    app.clock.advance(3_600);
    let res = registrant("cap")
        .start(&app, "later@example.test", Some(&token))
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[test]
fn the_start_count_holds_ten_an_hour_and_a_full_table_drops_the_oldest() {
    let starts = InviteStarts::new(2);
    let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    for _ in 0..STARTS_PER_INVITE {
        assert!(starts.allow(&a, 100));
    }
    assert!(!starts.allow(&a, 100), "the eleventh");
    assert!(!starts.allow(&a, 100 + 3_599), "still inside the hour");
    assert!(starts.allow(&a, 100 + 3_600), "the hour has gone");
    // A full table makes room by dropping the key added first: it never
    // refuses for lack of room.
    assert!(starts.allow(&b, 5_000));
    assert!(starts.allow(&c, 5_000));
}

#[tokio::test]
async fn without_users_an_invitation_is_refused_and_the_setup_token_path_is_unchanged() {
    let app = device_app().await;
    // An invitation whose maker is gone, on a server with no users.
    let gone = app
        .state
        .vault_db
        .with_conn(|conn| Ok(support::accounts::insert_user(conn, "gone@example.test")))
        .await
        .expect("a user");
    let token = invite(&app, gone).await;
    sql(&app, "DELETE FROM users WHERE id = ?1", gone).await;
    assert!(is_pending(&app, &token).await);

    let res = registrant("early")
        .start(&app, "early@example.test", Some(&token))
        .await;
    assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
    let res = registrant("early")
        .start(
            &app,
            "early@example.test",
            Some(&vole_kit::auth::invites::generate()),
        )
        .await;
    assert_refused(&res, StatusCode::FORBIDDEN, "invite_invalid");
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );
    assert!(is_pending(&app, &token).await);

    // The first administrator registers as before, with no invitation.
    let registered = registrant("first")
        .started(&app, "first@example.test", None, false)
        .await;
    let done = registered.send_raw(&app).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    let (user, role, _) = user_of(&app, "first@example.test").await.expect("a user");
    assert_eq!(role, "admin");
    // The first administrator gets no `account_created`: no administrator
    // made the account.
    assert!(events_of(&app, user).await.is_empty());
}

#[tokio::test]
async fn with_users_and_no_invitation_registration_stays_closed() {
    let (app, _) = with_admin().await;
    let res = registrant("closed")
        .start(&app, "closed@example.test", None)
        .await;
    assert_refused(&res, StatusCode::CONFLICT, "registration_closed");
    assert_eq!(res.body, br#"{"error":"registration_closed"}"#);
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        0
    );
}

#[tokio::test]
async fn invite_and_setup_token_together_are_bad_request() {
    for with_users in [false, true] {
        let app = if with_users {
            with_admin().await.0
        } else {
            device_app().await
        };
        let token = vole_kit::auth::invites::generate();
        let client = registrant("both");
        let mut body = client.start_body("both@example.test", Some(&token));
        body["setup_token"] = json!("a-setup-token");
        let res = call(&app, START, &body).await;
        assert_refused(&res, StatusCode::BAD_REQUEST, "bad_request");
        assert_eq!(
            count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
            0,
            "users: {with_users}"
        );
    }
}

#[tokio::test]
async fn finishing_an_invited_registration_leaves_other_waiting_rows() {
    let (app, admin) = with_admin().await;
    let first = invite(&app, admin).await;
    let second = invite(&app, admin).await;
    let one = registrant("first")
        .started(&app, "one@example.test", Some(&first), false)
        .await;
    let two = registrant("second")
        .started(&app, "two@example.test", Some(&second), false)
        .await;
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        2
    );
    let res = one.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    assert_eq!(
        count(&app, "SELECT COUNT(*) FROM ferret_registrations").await,
        1,
        "only the finished row is gone"
    );
    let res = two.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    assert_eq!(count(&app, "SELECT COUNT(*) FROM users").await, 3);
}

#[tokio::test]
async fn invite_check_answers_expiry_and_inviter_and_is_throttled_per_address() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;
    let before = written(&app).await;

    let res = check(&app, &token).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let hash = vole_kit::auth::invites::hash(&token);
    let expires_at: i64 = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT CAST(strftime('%s', expires_at) AS INTEGER) FROM invites
                 WHERE token_hash = ?1",
                [hash.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("the expiry");
    assert_eq!(
        res.json(),
        json!({ "expires_at": expires_at, "invited_by": ADMIN_EMAIL })
    );
    // It changes nothing.
    assert!(is_pending(&app, &token).await);
    assert_eq!(written(&app).await, before);

    // An invitation whose maker is gone names nobody.
    let maker = add_account_to_app(&app, 2).await.user_id;
    sql(&app, "UPDATE users SET role = 'admin' WHERE id = ?1", maker).await;
    let orphan = invite(&app, maker).await;
    sql(&app, "DELETE FROM users WHERE id = ?1", maker).await;
    let res = check(&app, &orphan).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["invited_by"], "");

    // 10 per minute per address, counted for good and bad tokens alike.
    let address = "203.0.113.40";
    let unknown = vole_kit::auth::invites::generate();
    for n in 0..10 {
        let given = if n % 2 == 0 { &token } else { &unknown };
        let res = check_from(&app, given, address).await;
        assert_ne!(res.status, StatusCode::TOO_MANY_REQUESTS, "check {n}");
    }
    let res = check_from(&app, &token, address).await;
    assert_refused(&res, StatusCode::TOO_MANY_REQUESTS, "throttled");
    assert!(res.header("retry-after").parse::<u32>().expect("a wait") >= 1);
    // Another address is not held up.
    let res = check_from(&app, &token, "203.0.113.41").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // A minute later the address may ask again.
    app.clock.advance(60);
    let res = check_from(&app, &token, address).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn register_finish_writes_account_created_with_the_inviter_in_the_same_transaction() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;
    let registered = registrant("logged")
        .started(&app, "logged@example.test", Some(&token), false)
        .await;
    let res = registered.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let (user, _, _) = user_of(&app, "logged@example.test").await.expect("a user");
    assert_eq!(
        events_of(&app, user).await,
        vec![(
            "account_created".to_string(),
            "admin".to_string(),
            ADMIN_EMAIL.to_string(),
            now(&app)
        )]
    );

    // The maker is gone: the actor is still `admin`, with no name.
    let maker = add_account_to_app(&app, 2).await.user_id;
    sql(&app, "UPDATE users SET role = 'admin' WHERE id = ?1", maker).await;
    let orphan = invite(&app, maker).await;
    sql(&app, "DELETE FROM users WHERE id = ?1", maker).await;
    let registered = registrant("orphan")
        .started(&app, "orphan@example.test", Some(&orphan), false)
        .await;
    let res = registered.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let (user, _, _) = user_of(&app, "orphan@example.test").await.expect("a user");
    let events = events_of(&app, user).await;
    assert_eq!(events.len(), 1);
    assert_eq!(
        (
            events[0].0.as_str(),
            events[0].1.as_str(),
            events[0].2.as_str()
        ),
        ("account_created", "admin", "")
    );

    // An event that cannot be written takes the whole registration with it.
    let token = invite(&app, admin).await;
    let registered = registrant("refused")
        .started(&app, "refused@example.test", Some(&token), false)
        .await;
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER no_events BEFORE INSERT ON ferret_account_events
                 BEGIN SELECT RAISE(ABORT, 'no events'); END;",
            )?;
            Ok(())
        })
        .await
        .expect("a trigger");
    let before = written(&app).await;
    let res = registered.send_raw(&app).await;
    assert_refused(&res, StatusCode::INTERNAL_SERVER_ERROR, "internal");
    assert_eq!(written(&app).await, before, "nothing was written");
    assert!(user_of(&app, "refused@example.test").await.is_none());
    assert!(
        is_pending(&app, &token).await,
        "the invitation is not spent"
    );
}

#[tokio::test]
async fn a_new_account_moves_the_prelogin_policy_at_once() {
    // One account, with a secret key: every made-up answer says "secret key".
    let (app, admin) = with_admin().await;
    login::refresh_once(&app.state.vault_db, &app.state.prelogin, app.clock.as_ref()).await;
    let policy = |app: &TestApp| app.state.prelogin.read().expect("the policy").clone();
    assert_eq!(
        policy(&app),
        PreloginPolicy::new(&[(1, 1000)], 1000).expect("a policy")
    );

    // A second account without one: half of the accounts have a secret key,
    // which is far outside the band of the stored bucket, so it must move.
    let token = invite(&app, admin).await;
    let registered = registrant("policy")
        .started(&app, "policy@example.test", Some(&token), false)
        .await;
    let res = registered.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    // No background round ran: the answer itself renewed the policy.
    assert_eq!(
        policy(&app),
        PreloginPolicy::new(&[(1, 1000)], 500).expect("a policy")
    );
    let stored: Vec<u8> = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row(
                "SELECT value FROM ferret_meta WHERE key = 'prelogin_buckets'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("the buckets");
    assert_eq!(stored, b"sk=500;p1=1000;");
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

fn logged_text(log: &Arc<Mutex<Vec<u8>>>) -> String {
    let bytes = log
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn the_invitation_token_never_reaches_the_log() {
    let log = log_buffer();
    let (app, admin) = with_admin().await;
    let good = invite(&app, admin).await;
    let revoked = invite(&app, admin).await;
    revoke(&app, &revoked).await;
    let unknown = vole_kit::auth::invites::generate();
    let mut answers = Vec::new();

    for token in [&good, &revoked, &unknown] {
        answers.push(check(&app, token).await);
        answers.push(
            registrant("canary")
                .start(&app, ADMIN_EMAIL, Some(token))
                .await,
        );
    }
    // One letter short: refused as a body, and the answer does not echo it.
    let short = &good[..42];
    answers.push(check(&app, short).await);
    answers.push(
        registrant("canary")
            .start(&app, "short@example.test", Some(short))
            .await,
    );
    let registered = registrant("canary")
        .started(&app, "canary@example.test", Some(&good), false)
        .await;
    let done = registered.send_raw(&app).await;
    assert_eq!(done.status, StatusCode::CREATED, "{}", done.text());
    answers.push(done);
    let again = registrant("canary2")
        .start(&app, "canary2@example.test", Some(&good))
        .await;
    assert_refused(&again, StatusCode::FORBIDDEN, "invite_invalid");
    answers.push(again);

    let logged = logged_text(&log);
    // Control: the capture sees the server's own line for the new account.
    assert!(
        logged.contains("an account was made from an invitation"),
        "the log capture does not see the server's lines"
    );
    for token in [&good, &revoked, &unknown, &short.to_string()] {
        assert!(!logged.contains(token.as_str()), "a token in the log");
        let hash = vole_kit::auth::invites::hash(token);
        assert!(
            !logged.contains(&b64url::encode(&hash)),
            "a token hash in the log"
        );
        for answer in &answers {
            assert!(
                !answer.text().contains(token.as_str()),
                "a token in an answer: {}",
                answer.text()
            );
            for (_, value) in &answer.headers {
                assert!(!String::from_utf8_lossy(value.as_bytes()).contains(token.as_str()));
            }
        }
    }
}

/// A sign-in of `email` with `password` from a new browser, through the
/// routes: the cookies of the answer, or the answer when it was refused.
async fn sign_in(app: &TestApp, email: &str, password: &str) -> Result<Jar, Box<Res>> {
    let input = opaque_input(password);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).expect("a start");
    let started = call(
        app,
        "/api/auth/opaque/login/start",
        &json!({ "email": email, "ke1": b64url::encode(&ke1) }),
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let answer: Value = started.json();
    let ke2 = b64url::decode(answer["ke2"].as_str().expect("a ke2")).expect("base64url");
    let ke3 = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .expect("the password opens the record")
    .finished
    .ke3;
    let res = call(
        app,
        "/api/auth/opaque/login/finish",
        &json!({
            "login_id": answer["login_id"],
            "ke3": b64url::encode(&ke3),
            "device_id": "07".repeat(16),
            "device_name": "Test browser",
        }),
    )
    .await;
    if res.status != StatusCode::OK {
        return Err(Box::new(res));
    }
    let mut jar = Jar::default();
    jar.absorb(&res.headers);
    Ok(jar)
}

#[tokio::test]
async fn the_new_account_signs_in_recovers_with_its_rk_and_gets_a_device() {
    let (app, admin) = with_admin().await;
    let token = invite(&app, admin).await;
    let email = "dora@example.test";
    let registered = registrant("dora")
        .started(&app, email, Some(&token), false)
        .await;
    let res = registered.send_raw(&app).await;
    assert_eq!(res.status, StatusCode::CREATED, "{}", res.text());
    let (user, _, _) = user_of(&app, "dora@example.test").await.expect("a user");
    let mut client = registered.client(user);

    // The account signs in with its master password (OPAQUE), from a new
    // browser.
    let jar = sign_in(&app, email, CLIENT_PASSWORD)
        .await
        .unwrap_or_else(|res| panic!("the sign-in: {} {}", res.status, res.text()));
    let events = get_with_jar(&app, &jar, EVENTS).await;
    assert_eq!(events.status, StatusCode::OK, "{}", events.text());

    // The master password is forgotten: the administrator makes a sign-in
    // code, the account redeems it and recovers with its recovery key.
    let by = Actor::Admin {
        user_id: Some(admin),
        name: ADMIN_EMAIL.to_string(),
    };
    let at = now(&app);
    let code = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let issued = issue_sign_in_code(conn, user, &by, at).expect("a code");
            Ok(issued.code().to_string())
        })
        .await
        .expect("a code");
    let redeemed = call(
        &app,
        "/api/auth/redeem",
        &json!({ "email": email, "code": code }),
    )
    .await;
    assert_eq!(redeemed.status, StatusCode::OK, "{}", redeemed.text());
    let mut reset = Jar::default();
    reset.absorb(&redeemed.headers);
    let recovery = recovered(&app, &reset, &mut client, NEW_PASSWORD, true).await;
    let res = post_recover(&app, &reset, &recovery).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // The new master password signs in a device with a DPoP key, and the
    // device's tokens read the account's own vault.
    let mut device = DeviceClient::new(7);
    let res = device.sign_in(&app, email, NEW_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/vault/unlock-methods"),
        )
        .await;
    assert!(
        res.status.is_success(),
        "the device reads its vault: {} {}",
        res.status,
        res.text()
    );
    // The log shows what was done, in order.
    let kinds: Vec<String> = events_of(&app, user)
        .await
        .into_iter()
        .map(|(kind, ..)| kind)
        .collect();
    assert_eq!(
        kinds,
        [
            "account_created",
            "sign_in_code_issued",
            "sign_in_code_redeemed"
        ]
    );
}
