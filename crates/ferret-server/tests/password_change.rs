//! `PUT /api/vault/unlock-methods/password`: changing the master password.
//!
//! The client is the one of `ferret-core`: the account is made as a
//! registration makes it, the new registration goes through
//! `reregister/start`, the core makes the new wrap and manifest and signs the
//! body. Spec: Fase 1 § 4.3 (changing MP) and § 4.6.

mod support;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{OPAQUE_CONTEXT, OsRng, PinState, opaque_login_start};
use ferret_server::auth::session::{Origin, lookup, set_parent};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::SidHash;
use ferret_server::vault::unlock_write::MAX_GENERATION_STEP;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::SMALL;
use ferret_server_auth::{Outcome, RetryAfter, SessionScope, Stage, Throttle, ThrottleKey};
use serde_json::{Value, json};
use support::accounts::{
    Client, PASSWORD_PATH, Snapshot, body_bytes, client_account, client_session, opaque_input,
    password_change, password_put_req, put_password, put_password_bytes, send_signed, snapshot,
};
use support::session::{issue, nonce_for};
use support::{Jar, PEER, Req, Res, TestApp, Which};
use tracing_subscriber::fmt::MakeWriter;

const NEW_PASSWORD: &str = "a brand new horse battery staple";
const SECOND: Duration = Duration::from_secs(1);

// ------------------------------------------------------------------ helpers

/// An app that believes the test peer as a proxy, so sign-ins over `https`
/// count.
async fn app() -> TestApp {
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    TestApp::builder().proxies(proxies).build().await
}

/// An app with client account `n` and a fresh full session of it.
async fn setup(n: u8) -> (TestApp, Client, Jar, SidHash) {
    let app = app().await;
    let client = client_account(&app, n).await;
    let issued = client_session(&app, &client, SessionScope::Full, 1).await;
    (app, client, issued.jar, issued.sid)
}

fn error_of(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

/// Sends a request on the vault listener as a browser on `https` would.
async fn send(app: &TestApp, jar: &mut Jar, mut req: Req) -> Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = app.call_raw(Which::Vault, req.build()).await;
    jar.absorb(&res.headers);
    res
}

fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

/// A sign-in half-way: the server answered `login/start` and the client has
/// made its third message. `None` when the client cannot finish (the password
/// is not the one of the record).
struct HalfWay {
    jar: Jar,
    login_id: Value,
    ke3: Vec<u8>,
}

/// The first half of a sign-in of `email` with `password` from a new browser.
async fn start_sign_in(app: &TestApp, email: &str, password: &str) -> Option<HalfWay> {
    let input = opaque_input(password);
    let mut jar = Jar::default();
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).expect("a start");
    let started = send(
        app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &json!({"email": email, "ke1": b64url::encode(&ke1)}),
        ),
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let answer = started.json();
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
    .ok()?
    .finished
    .ke3;
    Some(HalfWay {
        jar,
        login_id: answer["login_id"].clone(),
        ke3,
    })
}

/// The second half: `login/finish`.
async fn finish_sign_in(app: &TestApp, mut half: HalfWay) -> Res {
    send(
        app,
        &mut half.jar,
        vault_post(
            "/api/auth/opaque/login/finish",
            &json!({
                "login_id": half.login_id,
                "ke3": b64url::encode(&half.ke3),
                "device_id": "07".repeat(16),
                "device_name": "Test browser",
            }),
        ),
    )
    .await
}

/// A whole sign-in of `email` with `password` from a new browser. `None` when
/// the client cannot finish (the password is not the one of the record).
async fn sign_in(app: &TestApp, email: &str, password: &str) -> Option<Res> {
    let half = start_sign_in(app, email, password).await?;
    Some(finish_sign_in(app, half).await)
}

/// How many live sessions the user has.
async fn live_sessions(app: &TestApp, user_id: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*) FROM ferret_sessions WHERE user_id = ?1 AND revoked_at IS NULL",
                [user_id],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a count")
}

fn email(client: &Client) -> String {
    let n = client.ids.account_id.as_bytes()[1];
    format!("client{n}@example.com")
}

/// A GET on the vault listener with the cookies of `jar`.
async fn vault_get(app: &TestApp, jar: &Jar, path: &str) -> Res {
    let mut req = Req::get(path)
        .header("ferret-protocol", "1")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

/// Whether the session `sid` is ended in its row.
async fn ended(app: &TestApp, sid: SidHash) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
        .await
        .expect("a row")
        .expect("the session")
        .revoked_at
        .is_some()
}

/// A refused change left the account as it was and asked for no backup.
async fn nothing_changed(app: &TestApp, client: &Client, before: &Snapshot) {
    assert_eq!(&snapshot(app, client).await, before);
    assert!(
        !app.backup_status().has_request(),
        "no backup was asked for"
    );
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn a_signed_change_with_fresh_reauth_replaces_record_wrap_and_manifest_in_one_transaction() {
    let (app, mut client, jar, _) = setup(1).await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;

    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 2, "seq": 2}));
    assert_eq!(res.header("cache-control"), "no-store");

    let after = snapshot(&app, &client).await;
    // The record and the password wrap are the new ones, the wrap under the
    // same method id at the next generation; the recovery wrap and the keys
    // are untouched.
    assert_eq!(after.record, change.registration_record);
    assert_ne!(after.record, before.record);
    assert_eq!(after.ksf_profile, 1);
    let (password_before, recovery_before) = (&before.wraps[0], &before.wraps[1]);
    let (password_after, recovery_after) = (&after.wraps[0], &after.wraps[1]);
    assert_eq!(password_after.0, 1);
    assert_eq!(password_after.1, password_before.1, "the same method id");
    assert_eq!(password_after.2, 2);
    assert_eq!(password_after.3, change.wrap.wrap);
    assert_eq!(recovery_after, recovery_before);
    assert_eq!(
        (&after.pk_a, &after.pk_r, after.vk_epoch),
        (&before.pk_a, &before.pk_r, before.vk_epoch)
    );
    // The manifest is the next revision, at the vault's next seq.
    assert_eq!((after.manifest_rev, after.manifest_seq), (2, 2));
    assert_eq!(after.manifest_envelope, change.manifest.envelope);
    assert_eq!(after.manifest_tag, change.manifest.tag.to_vec());
    assert_eq!(after.vault_seq, 2);
    let grown = i64::try_from(change.manifest.envelope.len()).unwrap()
        - i64::try_from(before.manifest_envelope.len()).unwrap();
    assert_eq!(after.bytes_used, before.bytes_used + grown);

    // The new password signs in; the old one no longer opens the record.
    let signed_in = sign_in(&app, &email(&client), NEW_PASSWORD)
        .await
        .expect("the new password opens the new record");
    assert_eq!(signed_in.status, StatusCode::OK, "{}", signed_in.text());
    assert!(
        sign_in(&app, &email(&client), &client.password)
            .await
            .is_none(),
        "the old password does not open the new record"
    );

    // A second change goes on from the first: generation 3, revision 3.
    client.took_password(&change, NEW_PASSWORD);
    let again = password_change(&app, &jar, &mut client, "yet another horse battery").await;
    let res = put_password(&app, &jar, &client, &again).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 3, "seq": 3}));
}

#[tokio::test]
async fn without_fresh_reauth_is_403_and_nothing_changes() {
    let app = app().await;
    let mut client = client_account(&app, 2).await;
    // A full session that never proved the password again.
    let stale = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &stale.jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &stale.jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "reauth_required");
    nothing_changed(&app, &client, &before).await;

    // A session that did, 301 seconds ago.
    let fresh = client_session(&app, &client, SessionScope::Full, 2).await;
    let change = password_change(&app, &fresh.jar, &mut client, NEW_PASSWORD).await;
    app.clock.advance(301);
    let res = put_password(&app, &fresh.jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "reauth_required");
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn a_proof_over_other_bytes_is_401_and_the_nonce_is_gone() {
    let (app, mut client, jar, _) = setup(3).await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let body = body_bytes(&password_put_req(&change));
    let nonce = nonce_for(&app, &jar).await;
    let proof = change.sign(&client.vault, &nonce, &body).expect("a proof");

    // The same body with one more byte: the proof does not cover it.
    let mut other = body.clone();
    other.push(b' ');
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        PASSWORD_PATH,
        &nonce,
        &proof,
        other,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // The nonce went with it: the right bytes and proof are refused now.
    let res = send_signed(&app, &jar, Method::PUT, PASSWORD_PATH, &nonce, &proof, body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // A proof made by another key over the right bytes is refused too.
    let mut stranger = client_account(&app, 4).await;
    let nonce = nonce_for(&app, &jar).await;
    let body = body_bytes(&password_put_req(&change));
    let proof = change.sign(&client.vault, &nonce, &body).expect("a proof");
    let mut forged = proof;
    forged[0] ^= 1;
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        PASSWORD_PATH,
        &nonce,
        &forged,
        body,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    let other_change = password_change(&app, &jar, &mut stranger, NEW_PASSWORD).await;
    let nonce = nonce_for(&app, &jar).await;
    let body = body_bytes(&password_put_req(&change));
    let proof = other_change
        .sign(&stranger.vault, &nonce, &body)
        .expect("a proof by the other account's key");
    let res = send_signed(&app, &jar, Method::PUT, PASSWORD_PATH, &nonce, &proof, body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn a_generation_not_above_the_stored_is_409_write_conflict() {
    let (app, mut client, jar, _) = setup(5).await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    for generation in [1, 0] {
        let mut req = password_put_req(&change);
        req.kek_generation = generation;
        let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::CONFLICT,
            "{generation}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &before).await;
    }
    // A step above the bound, the top of the range among them, would use up
    // the generations for good: refused.
    for generation in [u32::MAX, 2 + MAX_GENERATION_STEP] {
        let mut req = password_put_req(&change);
        req.kek_generation = generation;
        let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::CONFLICT,
            "{generation}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &before).await;
    }
    // The largest step is taken.
    let mut req = password_put_req(&change);
    req.kek_generation = 1 + MAX_GENERATION_STEP;
    let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        snapshot(&app, &client).await.wraps[0].2,
        1 + MAX_GENERATION_STEP
    );
}

#[tokio::test]
async fn a_manifest_rev_other_than_current_plus_1_is_409() {
    let (app, mut client, jar, _) = setup(6).await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    for rev in [0, 1, 3, 9_007_199_254_740_991] {
        let mut req = password_put_req(&change);
        req.manifest.rev = rev;
        let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{rev}: {}", res.text());
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &before).await;
    }
}

#[tokio::test]
async fn a_bad_manifest_envelope_is_422() {
    let (app, mut client, jar, _) = setup(7).await;
    let before = snapshot(&app, &client).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let good = change.manifest.envelope.clone();
    let mut as_item = good.clone();
    as_item[2] = 1; // the kind byte of an item
    let mut other_version = good.clone();
    other_version[0] ^= 0x80;
    for (what, envelope) in [
        ("junk", vec![7u8; 100]),
        ("empty", Vec::new()),
        ("the kind of an item", as_item),
        ("another version", other_version),
        ("cut short", good[..good.len() - 1].to_vec()),
    ] {
        let mut req = password_put_req(&change);
        req.manifest.envelope = envelope;
        let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{what}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "unsupported_envelope", "{what}");
        nothing_changed(&app, &client, &before).await;
    }
}

#[tokio::test]
async fn a_lower_profile_is_refused() {
    let (app, mut client, jar, _) = setup(8).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    // A profile no table knows.
    for profile in [0u8, 2, 255] {
        let mut req = password_put_req(&change);
        req.ksf_profile = profile;
        let before = snapshot(&app, &client).await;
        let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{profile}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "profile_rejected");
        nothing_changed(&app, &client, &before).await;
    }
    // A stored profile above the one the change brings: the change would
    // lower it.
    let account = client.ids.account_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_accounts SET ksf_profile = 2 WHERE account_id = ?1",
                [account.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("raise the stored profile");
    let before = snapshot(&app, &client).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(
        res.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        res.text()
    );
    assert_eq!(error_of(&res), "profile_rejected");
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn two_concurrent_changes_give_one_winner_and_one_refusal() {
    let (app, mut client, jar, _) = setup(9).await;
    // Two changes made from the same state: both at generation 2 and
    // revision 2.
    let first = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let second = password_change(&app, &jar, &mut client, "a second horse battery staple").await;
    let first_body = body_bytes(&password_put_req(&first));
    let second_body = body_bytes(&password_put_req(&second));
    let first_nonce = nonce_for(&app, &jar).await;
    let second_nonce = nonce_for(&app, &jar).await;
    let first_proof = first
        .sign(&client.vault, &first_nonce, &first_body)
        .expect("a proof");
    let second_proof = second
        .sign(&client.vault, &second_nonce, &second_body)
        .expect("a proof");
    let (a, b) = tokio::join!(
        send_signed(
            &app,
            &jar,
            Method::PUT,
            PASSWORD_PATH,
            &first_nonce,
            &first_proof,
            first_body
        ),
        send_signed(
            &app,
            &jar,
            Method::PUT,
            PASSWORD_PATH,
            &second_nonce,
            &second_proof,
            second_body
        ),
    );
    let mut statuses = [a.status.as_u16(), b.status.as_u16()];
    statuses.sort_unstable();
    // The second waits for the first's write lock, then finds the revision
    // and the generation moved: `409 write_conflict`, nothing written.
    assert_eq!(statuses, [200, 409], "{a:?} {b:?}");
    let (winner, loser) = if a.status == StatusCode::OK {
        (&first, &b)
    } else {
        (&second, &a)
    };
    assert_eq!(error_of(loser), "write_conflict");
    let after = snapshot(&app, &client).await;
    assert_eq!(after.record, winner.registration_record);
    assert_eq!(after.wraps[0].3, winner.wrap.wrap);
    assert_eq!((after.manifest_rev, after.vault_seq), (2, 2));
}

#[tokio::test]
async fn a_change_signed_for_an_older_epoch_is_refused() {
    let (app, mut client, jar, _) = setup(10).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    // The vault key moved on to epoch 2 after the client made its change.
    let account = client.ids.account_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_accounts SET vk_epoch = 2 WHERE account_id = ?1",
                [account.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("move the epoch");
    let before = snapshot(&app, &client).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn every_other_session_of_both_origins_ends_and_its_stream_closes_at_once() {
    let (app, mut client, jar, this) = setup(11).await;
    let user = client.ids.user_id;
    let laptop = issue(&app, user, Origin::Vault, SessionScope::Full, 2).await;
    let phone = issue(&app, user, Origin::Vault, SessionScope::Full, 3).await;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 4).await;
    // Another user's session is not touched.
    let other = client_account(&app, 12).await;
    let bystander = issue(
        &app,
        other.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        5,
    )
    .await;
    let mut laptop_stream = app.events(&laptop.jar).await;
    laptop_stream.event("hello", SECOND).await;
    let mut phone_stream = app.events(&phone.jar).await;
    phone_stream.event("hello", SECOND).await;
    let mut bystander_stream = app.events(&bystander.jar).await;
    bystander_stream.event("hello", SECOND).await;

    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    laptop_stream.end(SECOND).await;
    phone_stream.end(SECOND).await;
    for sid in [laptop.sid, phone.sid, admin.sid] {
        assert!(ended(&app, sid).await, "every other session ended");
    }
    assert!(!ended(&app, this).await);
    assert!(!ended(&app, bystander.sid).await);
    bystander_stream.quiet(Duration::from_millis(300)).await;
    for jar in [&laptop.jar, &phone.jar] {
        let res = vault_get(&app, jar, "/api/vault/unlock-methods").await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn this_session_survives() {
    let (app, mut client, jar, this) = setup(13).await;
    // An admin session handed over from this one.
    let child = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        2,
    )
    .await
    .sid;
    app.state
        .vault_db
        .with_conn(move |conn| Ok(set_parent(conn, &child, &this)?))
        .await
        .expect("a parent");
    let mut stream = app.events(&jar).await;
    stream.event("hello", SECOND).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Its stream hears of the new manifest, and goes on.
    let sync = stream.event("sync", SECOND).await;
    assert_eq!(sync["seq"], json!(2), "{sync}");
    assert!(!ended(&app, this).await);
    // What was handed over from it does not: it fails safe.
    assert!(
        ended(&app, child).await,
        "the handed-over admin session ends"
    );
    let res = vault_get(&app, &jar, "/api/vault/unlock-methods").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // It is still fresh (a change does not use the re-authentication up),
    // so the next change, a minute later, needs no new sign-in.
    app.clock.advance(60);
    client.took_password(&change, NEW_PASSWORD);
    let again = password_change(&app, &jar, &mut client, "yet another horse battery").await;
    let res = put_password(&app, &jar, &client, &again).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_sign_in_started_with_the_old_password_cannot_finish_after_the_change() {
    let (app, mut client, jar, _) = setup(18).await;
    // Half-way with the old password, before the change: the server's state
    // holds what finishing needs.
    let half = start_sign_in(&app, &email(&client), &client.password)
        .await
        .expect("the old password opens the old record");
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let live = live_sessions(&app, client.ids.user_id).await;

    let res = finish_sign_in(&app, half).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    assert_eq!(live_sessions(&app, client.ids.user_id).await, live);

    // A sign-in with the new password, started after it, finishes.
    let res = sign_in(&app, &email(&client), NEW_PASSWORD)
        .await
        .expect("the new password");
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// A throttle that admits everything. On the first proof check of a record
/// replacement it says so on its channel and holds the check for 800 ms.
struct SlowProofCheck(Mutex<Option<std::sync::mpsc::Sender<()>>>);

impl Throttle for SlowProofCheck {
    fn admit(&self, stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        if stage == Stage::Replace {
            let first = self.0.lock().expect("the channel").take();
            if let Some(entered) = first {
                entered.send(()).expect("the test listens");
                std::thread::sleep(Duration::from_millis(800));
            }
        }
        Ok(())
    }

    fn record(&self, _stage: Stage, _keys: &[ThrottleKey], _outcome: Outcome, _now: u64) {}
}

#[tokio::test]
async fn a_change_committed_after_its_client_went_away_still_announces_and_asks_for_a_backup() {
    // A throttle that says when the proof check of the change has started
    // (inside the write transaction, on the database thread) and then holds
    // it there for a moment.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let throttle = Arc::new(SlowProofCheck(Mutex::new(Some(entered_tx))));
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    let app = TestApp::builder()
        .proxies(proxies)
        .throttle(throttle as Arc<dyn Throttle>)
        .build()
        .await;
    let mut client = client_account(&app, 19).await;
    let jar = client_session(&app, &client, SessionScope::Full, 1)
        .await
        .jar;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let body = body_bytes(&password_put_req(&change));
    let nonce = nonce_for(&app, &jar).await;
    let proof = change.sign(&client.vault, &nonce, &body).expect("a proof");
    let mut revocations = app.sync_events().subscribe_revocations();

    // The client goes away (the request's future is dropped) once the change
    // is inside its transaction, before it commits.
    {
        let request = send_signed(&app, &jar, Method::PUT, PASSWORD_PATH, &nonce, &proof, body);
        tokio::pin!(request);
        let entered = tokio::task::spawn_blocking(move || entered_rx.recv());
        tokio::select! {
            res = &mut request => panic!("the request ended first: {res:?}"),
            entered = entered => entered.expect("a thread").expect("the check started"),
        }
    }
    assert!(
        !app.backup_status().has_request(),
        "nothing is committed yet"
    );

    // The change commits on its own, and still announces what it did.
    support::events::wait_until(Duration::from_secs(5), || app.backup_status().has_request()).await;
    assert_eq!(app.backup_status().take_request(), Some("unlock_methods"));
    let revoked = tokio::time::timeout(SECOND, revocations.recv())
        .await
        .expect("in time")
        .expect("a revocation");
    assert_eq!(revoked, other.sid);
    let after = snapshot(&app, &client).await;
    assert_eq!(after.record, change.registration_record);
    assert_eq!(after.vault_seq, 2);
}

#[tokio::test]
async fn the_manifest_write_shows_in_changes_with_a_new_seq() {
    let (app, mut client, jar, _) = setup(14).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let res = vault_get(&app, &jar, "/api/sync/changes?since=1").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let page = res.json();
    assert_eq!(page["latest_seq"], json!(2));
    let changes = page["changes"].as_array().expect("changes");
    assert_eq!(changes.len(), 1, "{page}");
    let row = &changes[0];
    assert_eq!(row["id"], json!("00".repeat(16)), "the manifest row");
    assert_eq!(
        (row["rev"].clone(), row["seq"].clone()),
        (json!(2), json!(2))
    );
    assert_eq!(
        row["blob"],
        json!(b64url::encode(&change.manifest.envelope))
    );
    assert_eq!(row["tag"], json!(b64url::encode(&change.manifest.tag)));
    // Nothing is new after it.
    let res = vault_get(&app, &jar, "/api/sync/changes?since=2").await;
    assert_eq!(res.json()["changes"], json!([]));
}

#[tokio::test]
async fn a_committed_change_asks_for_a_backup() {
    let (app, mut client, jar, _) = setup(15).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    // A refused change asks for none.
    let mut req = password_put_req(&change);
    req.kek_generation = 1;
    let res = put_password_bytes(&app, &jar, &client, &change, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::CONFLICT);
    assert!(!app.backup_status().has_request());

    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(app.backup_status().take_request(), Some("unlock_methods"));
}

#[tokio::test]
async fn an_account_reset_session_cannot_use_this_route() {
    let app = app().await;
    let mut client = client_account(&app, 16).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 1).await;
    let before = snapshot(&app, &client).await;
    // A reset session may start a registration and ask for a nonce, but not
    // change the password with them.
    let change = password_change(&app, &reset.jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &reset.jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "forbidden");
    nothing_changed(&app, &client, &before).await;
    assert!(!ended(&app, reset.sid).await);

    // Without a session at all (and so without a nonce): 401.
    let body = body_bytes(&password_put_req(&change));
    let res = send_signed(
        &app,
        &Jar::default(),
        Method::PUT,
        PASSWORD_PATH,
        &[1; 32],
        &[2; 64],
        body,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;
}

// ------------------------------------------------------------------ the log

/// A writer that keeps every log line of the test binary.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

/// One subscriber for the whole test binary (every thread, the blocking pool
/// included), installed once.
fn log_sink() -> Sink {
    static SINK: OnceLock<Sink> = OnceLock::new();
    SINK.get_or_init(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        sink
    })
    .clone()
}

/// Every form in which a log line could carry `bytes`: base64url and hex of
/// the whole value, the inside of its `Debug` text, and the same for a slice
/// of it (from a multiple of 3 bytes, so its base64url is part of the whole
/// value's).
fn canaries_for(bytes: &[u8]) -> Vec<String> {
    fn inner_debug(bytes: &[u8]) -> String {
        format!("{bytes:?}")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }
    let mut forms = vec![
        b64url::encode(bytes),
        ferret_core::testing::hex_encode(bytes),
        inner_debug(bytes),
    ];
    if let Some(slice) = bytes.get(9..42) {
        forms.push(b64url::encode(slice));
        forms.push(ferret_core::testing::hex_encode(slice));
        forms.push(inner_debug(slice));
    }
    forms
}

#[tokio::test]
async fn request_bytes_never_reach_the_log() {
    let sink = log_sink();
    let (app, mut client, jar, _) = setup(17).await;
    let change = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let body = body_bytes(&password_put_req(&change));

    // The control: a value logged on purpose trips the forms built for it.
    let record = &change.registration_record;
    tracing::info!(record = ?record, "password canary self-test, Debug");
    tracing::info!(
        record = %b64url::encode(record),
        "password canary self-test, base64url"
    );
    tracing::info!(
        record = %ferret_core::testing::hex_encode(record),
        "password canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for form in canaries_for(&change.registration_record) {
        assert!(text.contains(&form), "the canary {form:.40} does not fire");
    }
    let mark = sink.0.lock().unwrap().len();

    // Refusals of every kind, then the change itself.
    let nonce = nonce_for(&app, &jar).await;
    let proof = change.sign(&client.vault, &nonce, &body).expect("a proof");
    let mut other = body.clone();
    other.push(b' ');
    let refused = send_signed(
        &app,
        &jar,
        Method::PUT,
        PASSWORD_PATH,
        &nonce,
        &proof,
        other,
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let mut bad = password_put_req(&change);
    bad.manifest.envelope = vec![9u8; 64];
    let refused = put_password_bytes(&app, &jar, &client, &change, body_bytes(&bad)).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let res = put_password_bytes(&app, &jar, &client, &change, body.clone()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let text = String::from_utf8(sink.0.lock().unwrap()[mark..].to_vec()).unwrap();
    let mut canaries = Vec::new();
    for value in [
        change.registration_record.as_slice(),
        change.wrap.wrap.as_slice(),
        change.manifest.envelope.as_slice(),
        change.manifest.tag.as_slice(),
        nonce.as_slice(),
        proof.as_slice(),
    ] {
        canaries.extend(canaries_for(value));
    }
    for canary in canaries {
        assert!(!text.contains(&canary), "the log holds {canary:.40}");
    }
    assert!(!text.contains(String::from_utf8_lossy(&body).as_ref()));
}

#[tokio::test]
async fn a_second_change_right_after_the_first_goes_through() {
    let (app, mut client, jar, _) = setup(20).await;
    let first = password_change(&app, &jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &jar, &client, &first).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    client.took_password(&first, NEW_PASSWORD);

    // One second later, a second change: there is no wait between changes.
    app.clock.advance(1);
    let second = password_change(&app, &jar, &mut client, "yet another horse battery").await;
    let res = put_password(&app, &jar, &client, &second).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 3, "seq": 3}));
}
