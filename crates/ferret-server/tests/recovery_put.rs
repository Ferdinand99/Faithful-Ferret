//! `PUT /api/vault/unlock-methods/recovery`: a new recovery key.
//!
//! The client is the one of `ferret-core`: the account is made as a
//! registration makes it, the core renews the recovery key (a new wrap under
//! the same method id, a new `pk_r`, the next manifest) and signs the body with
//! `sk_a`. Spec: Fase 1 § 4.6 and § 6.1.

mod support;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{
    AuthOp, ManifestRow, OPAQUE_CONTEXT, OsRng, PinState, RenewedRecovery, auth_sign,
    encode_recovery_key, opaque_login_start, recovery_public_key, recovery_sign, renew_recovery,
    renew_recovery_after_restore, verify_recovery_setup,
};
use ferret_server::auth::session::{Origin, lookup, set_parent};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::SidHash;
use ferret_server::vault::unlock_write::MAX_GENERATION_STEP;
use ferret_server::wire::b64url;
use ferret_server_auth::SessionScope;
use ferret_server_auth::testing::SMALL;
use serde_json::{Value, json};
use support::accounts::{
    Client, RECOVERY_PATH, Snapshot, body_bytes, client_account, client_session, opaque_input,
    password_change, put_password, put_recovery, recovery_put_req, renewed_recovery, send_signed,
    snapshot,
};
use support::session::{issue, nonce_for};
use support::{Jar, PEER, Req, Res, TestApp, Which};
use tracing_subscriber::fmt::MakeWriter;

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

/// The state after the server took `renewed`: the new wrap, manifest, pin
/// and recovery key.
fn took_recovery(client: &mut Client, renewed: RenewedRecovery) {
    client.pinned = renewed
        .pinned(&client.pinned)
        .expect("the pin after the renewal");
    client.recovery_wrap = renewed.recovery_wrap;
    client.manifest = renewed.manifest;
    client.recovery_key = renewed.recovery_key;
}

/// `PUT /api/vault/unlock-methods/recovery` with `body`, signed for
/// `renewed` over a fresh nonce of the session of `jar`.
async fn put_recovery_bytes(
    app: &TestApp,
    jar: &Jar,
    client: &Client,
    renewed: &RenewedRecovery,
    body: Vec<u8>,
) -> Res {
    let nonce = nonce_for(app, jar).await;
    let proof = renewed.sign(&client.vault, &nonce, &body).expect("a proof");
    send_signed(app, jar, Method::PUT, RECOVERY_PATH, &nonce, &proof, body).await
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
/// made its third message.
struct HalfWay {
    jar: Jar,
    login_id: Value,
    ke3: Vec<u8>,
}

/// The first half of a sign-in of `email` with `password` from a new browser.
async fn start_sign_in(app: &TestApp, email: &str, password: &str) -> HalfWay {
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
    .expect("the password opens the record")
    .finished
    .ke3;
    HalfWay {
        jar,
        login_id: answer["login_id"].clone(),
        ke3,
    }
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

/// A refused renewal left the account as it was and asked for no backup.
async fn nothing_changed(app: &TestApp, client: &Client, before: &Snapshot) {
    assert_eq!(&snapshot(app, client).await, before);
    assert!(
        !app.backup_status().has_request(),
        "no backup was asked for"
    );
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn a_signed_renewal_with_fresh_reauth_replaces_wrap_pk_r_and_manifest() {
    let (app, mut client, jar, _) = setup(1).await;
    let before = snapshot(&app, &client).await;
    let renewed = renewed_recovery(&mut client);

    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 2, "seq": 2}));
    assert_eq!(res.header("cache-control"), "no-store");

    let after = snapshot(&app, &client).await;
    // The recovery wrap is the new one, under the same method id at the next
    // generation; the record, the password wrap and `pk_a` are untouched.
    let (password_before, recovery_before) = (&before.wraps[0], &before.wraps[1]);
    let (password_after, recovery_after) = (&after.wraps[0], &after.wraps[1]);
    assert_eq!(password_after, password_before);
    assert_eq!(recovery_after.0, 2);
    assert_eq!(recovery_after.1, recovery_before.1, "the same method id");
    assert_eq!(recovery_after.2, 2);
    assert_eq!(recovery_after.3, renewed.recovery_wrap.wrap);
    assert_ne!(recovery_after.3, recovery_before.3);
    assert_eq!(
        (
            &after.record,
            after.ksf_profile,
            &after.pk_a,
            after.vk_epoch
        ),
        (
            &before.record,
            before.ksf_profile,
            &before.pk_a,
            before.vk_epoch
        )
    );
    // `pk_r` is the new key's: a recovery proof now has to come from the new
    // recovery key, and the stored wrap opens with it to this vault.
    assert_eq!(after.pk_r, renewed.pk_r.to_vec());
    assert_ne!(after.pk_r, before.pk_r);
    let account = client.vault.context().account_id;
    assert_eq!(
        recovery_public_key(&renewed.recovery_key, &account).expect("a key"),
        renewed.pk_r
    );
    verify_recovery_setup(
        &encode_recovery_key(&renewed.recovery_key),
        &renewed.recovery_wrap,
        &client.vault,
    )
    .expect("the new key opens the new wrap");
    // The manifest is the next revision, at the vault's next seq.
    assert_eq!((after.manifest_rev, after.manifest_seq), (2, 2));
    assert_eq!(after.manifest_envelope, renewed.manifest.envelope);
    assert_eq!(after.manifest_tag, renewed.manifest.tag.to_vec());
    assert_eq!(after.vault_seq, 2);
    let grown = i64::try_from(renewed.manifest.envelope.len()).unwrap()
        - i64::try_from(before.manifest_envelope.len()).unwrap();
    assert_eq!(after.bytes_used, before.bytes_used + grown);

    // The manifest row shows in the changes.
    let res = vault_get(&app, &jar, "/api/sync/changes?since=1").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let changes = res.json()["changes"].clone();
    assert_eq!(changes.as_array().map(Vec::len), Some(1), "{changes}");
    assert_eq!(changes[0]["id"], json!("00".repeat(16)));
    assert_eq!(
        changes[0]["blob"],
        json!(b64url::encode(&renewed.manifest.envelope))
    );

    // A second renewal right away goes on from the first (there is no wait
    // between changes): generation 3, revision 3.
    took_recovery(&mut client, renewed);
    let again = renewed_recovery(&mut client);
    let res = put_recovery(&app, &jar, &client, &again).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 3, "seq": 3}));
    assert_eq!(snapshot(&app, &client).await.pk_r, again.pk_r.to_vec());
}

#[tokio::test]
async fn without_fresh_reauth_is_403() {
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
    let renewed = renewed_recovery(&mut client);
    let res = put_recovery(&app, &stale.jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "reauth_required");
    nothing_changed(&app, &client, &before).await;

    // A session that did, 301 seconds ago.
    let fresh = client_session(&app, &client, SessionScope::Full, 2).await;
    app.clock.advance(301);
    let res = put_recovery(&app, &fresh.jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "reauth_required");
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn the_same_pk_r_is_refused() {
    let (app, mut client, jar, _) = setup(3).await;
    let before = snapshot(&app, &client).await;
    let renewed = renewed_recovery(&mut client);
    let stored: [u8; 32] = before.pk_r.clone().try_into().expect("32 bytes");

    // The stored key again: the old recovery key would still sign.
    let mut req = recovery_put_req(&renewed);
    req.pk_r = stored;
    let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    assert_eq!(error_of(&res), "malformed_recovery_key");
    nothing_changed(&app, &client, &before).await;

    // Keys that could never check a proof: the identity (with and without
    // the sign bit), a point of order 2, and a non-canonical encoding.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut identity_signed = identity;
    identity_signed[31] = 0x80;
    let mut order_two = [0u8; 32];
    order_two[0] = 0xec;
    order_two[1..31].fill(0xff);
    order_two[31] = 0x7f;
    let mut non_canonical = [0xffu8; 32];
    non_canonical[0] = 0xee;
    non_canonical[31] = 0x7f;
    for (what, key) in [
        ("identity", identity),
        ("identity with the sign bit", identity_signed),
        ("order 2", order_two),
        ("non-canonical", non_canonical),
    ] {
        let mut req = recovery_put_req(&renewed);
        req.pk_r = key;
        let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{what}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "malformed_recovery_key", "{what}");
        nothing_changed(&app, &client, &before).await;
    }

    // The renewal as made goes through.
    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_generation_not_above_is_409() {
    let (app, mut client, jar, _) = setup(4).await;
    let before = snapshot(&app, &client).await;
    let renewed = renewed_recovery(&mut client);
    // Not above the stored one, or so far above it that it would use up the
    // generations for good (the top of the range among them).
    for generation in [1, 0, u32::MAX, 2 + MAX_GENERATION_STEP] {
        let mut req = recovery_put_req(&renewed);
        req.kek_generation = generation;
        let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::CONFLICT,
            "{generation}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &before).await;
    }
    // A manifest revision other than the current one plus 1 is refused the
    // same way.
    for rev in [1, 3] {
        let mut req = recovery_put_req(&renewed);
        req.manifest.rev = rev;
        let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{rev}: {}", res.text());
        assert_eq!(error_of(&res), "write_conflict");
        nothing_changed(&app, &client, &before).await;
    }
    // A generation further up than the next one is taken (the client goes
    // above its pinned floor, which the server does not know).
    let mut req = recovery_put_req(&renewed);
    req.kek_generation = 7;
    let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 7, "seq": 2}));
    assert_eq!(snapshot(&app, &client).await.wraps[1].2, 7);
}

#[tokio::test]
async fn a_proof_for_the_password_op_is_401() {
    let (app, mut client, jar, _) = setup(5).await;
    let before = snapshot(&app, &client).await;
    let renewed = renewed_recovery(&mut client);
    let body = body_bytes(&recovery_put_req(&renewed));

    // `sk_a` over the exact body, but for `unlock-method.password.put`.
    let nonce = nonce_for(&app, &jar).await;
    let proof = auth_sign(
        &client.vault,
        AuthOp::UnlockMethodPasswordPut,
        &nonce,
        &body,
    )
    .expect("a proof");
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        RECOVERY_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // The nonce went with it: the right proof over it is refused now.
    let proof = renewed.sign(&client.vault, &nonce, &body).expect("a proof");
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        RECOVERY_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // The old recovery key's proof (`sk_r`, the recovery label) over the same
    // body does not count either: renewing needs `sk_a`.
    let nonce = nonce_for(&app, &jar).await;
    let ctx = client.vault.context();
    let proof = recovery_sign(
        &client.recovery_key,
        &ctx.account_id,
        ctx.vk_epoch,
        &nonce,
        &body,
    )
    .expect("a proof");
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        RECOVERY_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;

    // The same proof over one more byte.
    let nonce = nonce_for(&app, &jar).await;
    let proof = renewed.sign(&client.vault, &nonce, &body).expect("a proof");
    let mut other = body.clone();
    other.push(b' ');
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        RECOVERY_PATH,
        &nonce,
        &proof,
        other,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;

    // A proof by another account's `sk_a` over the right bytes.
    let mut stranger = client_account(&app, 6).await;
    let theirs = renewed_recovery(&mut stranger);
    let nonce = nonce_for(&app, &jar).await;
    let proof = theirs
        .sign(&stranger.vault, &nonce, &body)
        .expect("a proof");
    let res = send_signed(&app, &jar, Method::PUT, RECOVERY_PATH, &nonce, &proof, body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn no_session_ends() {
    let (app, mut client, jar, this) = setup(7).await;
    let user = client.ids.user_id;
    let laptop = issue(&app, user, Origin::Vault, SessionScope::Full, 2).await;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 3).await;
    // An admin session handed over from this one.
    let child = issue(&app, user, Origin::Admin, SessionScope::Full, 4)
        .await
        .sid;
    app.state
        .vault_db
        .with_conn(move |conn| Ok(set_parent(conn, &child, &this)?))
        .await
        .expect("a parent");
    let mut this_stream = app.events(&jar).await;
    this_stream.event("hello", SECOND).await;
    let mut laptop_stream = app.events(&laptop.jar).await;
    laptop_stream.event("hello", SECOND).await;
    // A sign-in half-way, started before the renewal.
    let half = start_sign_in(&app, &email(&client), &client.password).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    let renewed = renewed_recovery(&mut client);
    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Every stream of the vault hears of the new manifest, and goes on.
    for stream in [&mut this_stream, &mut laptop_stream] {
        let sync = stream.event("sync", SECOND).await;
        assert_eq!(sync["seq"], json!(2), "{sync}");
        stream.quiet(Duration::from_millis(300)).await;
    }
    for sid in [this, laptop.sid, admin.sid, child] {
        assert!(!ended(&app, sid).await, "no session ends");
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(300), revocations.recv())
            .await
            .is_err(),
        "no session is announced as ended"
    );
    for jar in [&jar, &laptop.jar] {
        let res = vault_get(&app, jar, "/api/vault/unlock-methods").await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    }
    // The half-way sign-in finishes: a new recovery key changes nothing about
    // how the user signs in.
    let res = finish_sign_in(&app, half).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // This session is still fresh (a renewal does not use the
    // re-authentication up), and there is no wait after the renewal: a
    // password change right after it needs no new sign-in and goes through.
    took_recovery(&mut client, renewed);
    let change = password_change(&app, &jar, &mut client, "a brand new horse battery").await;
    let res = put_password(&app, &jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_committed_renewal_asks_for_a_backup() {
    let (app, mut client, jar, _) = setup(8).await;
    let renewed = renewed_recovery(&mut client);
    // A refused renewal asks for none.
    let mut req = recovery_put_req(&renewed);
    req.kek_generation = 1;
    let res = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
    assert!(!app.backup_status().has_request());

    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(app.backup_status().take_request(), Some("unlock_methods"));
}

#[tokio::test]
async fn an_account_reset_session_cannot_renew() {
    let app = app().await;
    let mut client = client_account(&app, 9).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 1).await;
    let before = snapshot(&app, &client).await;
    // A reset session may ask for a nonce, but not renew the recovery key
    // with it.
    let renewed = renewed_recovery(&mut client);
    let res = put_recovery(&app, &reset.jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "forbidden");
    nothing_changed(&app, &client, &before).await;
    assert!(!ended(&app, reset.sid).await);

    // Without a session at all: 401.
    let body = body_bytes(&recovery_put_req(&renewed));
    let res = send_signed(
        &app,
        &Jar::default(),
        Method::PUT,
        RECOVERY_PATH,
        &[1; 32],
        &[2; 64],
        body,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn two_concurrent_renewals_give_one_winner() {
    let (app, mut client, jar, _) = setup(10).await;
    // Two renewals made from the same state: both at generation 2 and
    // revision 2.
    let first = renewed_recovery(&mut client);
    let second = renewed_recovery(&mut client);
    let first_body = body_bytes(&recovery_put_req(&first));
    let second_body = body_bytes(&recovery_put_req(&second));
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
            RECOVERY_PATH,
            &first_nonce,
            &first_proof,
            first_body
        ),
        send_signed(
            &app,
            &jar,
            Method::PUT,
            RECOVERY_PATH,
            &second_nonce,
            &second_proof,
            second_body
        ),
    );
    let mut statuses = [a.status.as_u16(), b.status.as_u16()];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409], "{a:?} {b:?}");
    let (winner, loser) = if a.status == StatusCode::OK {
        (&first, &b)
    } else {
        (&second, &a)
    };
    assert_eq!(error_of(loser), "write_conflict");
    let after = snapshot(&app, &client).await;
    assert_eq!(after.pk_r, winner.pk_r.to_vec());
    assert_eq!(after.wraps[1].3, winner.recovery_wrap.wrap);
    assert_eq!((after.manifest_rev, after.vault_seq), (2, 2));
}

#[tokio::test]
async fn a_renewal_after_a_restore_of_an_older_backup_goes_above_the_pinned_floor() {
    let (app, mut client, jar, _) = setup(11).await;
    let backup = snapshot(&app, &client).await;
    let old_wrap = client.recovery_wrap.clone();
    let old_manifest = client.manifest.clone();

    // The key is renewed (generation 2), and the device pins that floor.
    let renewed = renewed_recovery(&mut client);
    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    took_recovery(&mut client, renewed);

    // The server is put back to the backup made before it: the recovery wrap
    // at generation 1, the old `pk_r`, the manifest at revision 1.
    let account = client.ids.account_id;
    let vault = client.ids.vault_id;
    let restored = backup.clone();
    app.state
        .vault_db
        .with_conn(move |conn| {
            let (_, method_id, generation, wrap) = &restored.wraps[1];
            conn.execute(
                "UPDATE ferret_unlock_methods SET wrap = ?1, kek_generation = ?2
                 WHERE method_id = ?3",
                rusqlite::params![wrap, i64::from(*generation), method_id.as_slice()],
            )?;
            conn.execute(
                "UPDATE ferret_accounts SET pk_r = ?1 WHERE account_id = ?2",
                rusqlite::params![restored.pk_r, account.as_bytes().as_slice()],
            )?;
            conn.execute(
                "UPDATE ferret_items SET rev = ?1, seq = ?2, blob = ?3, tag = ?4, size = ?5
                 WHERE vault_id = ?6 AND item_id = ?7",
                rusqlite::params![
                    restored.manifest_rev,
                    restored.manifest_seq,
                    restored.manifest_envelope,
                    restored.manifest_tag,
                    i64::try_from(restored.manifest_envelope.len()).expect("a size"),
                    vault.as_bytes().as_slice(),
                    support::accounts::MANIFEST.as_bytes().as_slice(),
                ],
            )?;
            conn.execute(
                "UPDATE ferret_vaults SET seq = ?1, bytes_used = ?2 WHERE vault_id = ?3",
                rusqlite::params![
                    restored.vault_seq,
                    restored.bytes_used,
                    vault.as_bytes().as_slice()
                ],
            )?;
            Ok(())
        })
        .await
        .expect("restore the backup");
    assert_eq!(snapshot(&app, &client).await, backup);

    // The default renewal refuses a server wrap below the pinned floor; the
    // one after an accepted restore goes above the floor.
    let manifest = ManifestRow {
        rev: old_manifest.rev,
        envelope: &old_manifest.envelope,
        tag: &old_manifest.tag,
    };
    assert!(
        renew_recovery(
            &mut client.rng,
            &client.vault,
            &client.pinned,
            &old_wrap,
            &manifest
        )
        .is_err(),
        "the default renewal refuses"
    );
    let renewed = renew_recovery_after_restore(
        &mut client.rng,
        &client.vault,
        &client.pinned,
        &old_wrap,
        &manifest,
    )
    .expect("the renewal after a restore");
    assert_eq!(renewed.recovery_wrap.kek_generation, 3);

    // The server takes the jump from 1 to 3: it only asks for a generation
    // above its own.
    let res = put_recovery(&app, &jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"kek_generation": 3, "seq": 2}));
    let after = snapshot(&app, &client).await;
    assert_eq!(after.wraps[1].2, 3);
    assert_eq!(after.pk_r, renewed.pk_r.to_vec());
    assert_eq!(after.manifest_rev, 2);
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
    if let Some(slice) = bytes.get(9..30) {
        forms.push(b64url::encode(slice));
        forms.push(ferret_core::testing::hex_encode(slice));
        forms.push(inner_debug(slice));
    }
    forms
}

#[tokio::test]
async fn renewal_bytes_never_reach_the_log() {
    let sink = log_sink();
    let (app, mut client, jar, _) = setup(12).await;
    let renewed = renewed_recovery(&mut client);
    let body = body_bytes(&recovery_put_req(&renewed));

    // The control: a value logged on purpose trips the forms built for it.
    let wrap = &renewed.recovery_wrap.wrap;
    tracing::info!(wrap = ?wrap, "recovery canary self-test, Debug");
    tracing::info!(
        wrap = %b64url::encode(wrap),
        "recovery canary self-test, base64url"
    );
    tracing::info!(
        wrap = %ferret_core::testing::hex_encode(wrap),
        "recovery canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for form in canaries_for(wrap) {
        assert!(text.contains(&form), "the canary {form:.40} does not fire");
    }
    let mark = sink.0.lock().unwrap().len();

    // Refusals of every kind, then the renewal itself.
    let nonce = nonce_for(&app, &jar).await;
    let proof = renewed.sign(&client.vault, &nonce, &body).expect("a proof");
    let mut other = body.clone();
    other.push(b' ');
    let refused = send_signed(
        &app,
        &jar,
        Method::PUT,
        RECOVERY_PATH,
        &nonce,
        &proof,
        other,
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let mut bad = recovery_put_req(&renewed);
    bad.manifest.envelope = vec![9u8; 64];
    let refused = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&bad)).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut stale = recovery_put_req(&renewed);
    stale.kek_generation = 1;
    let refused = put_recovery_bytes(&app, &jar, &client, &renewed, body_bytes(&stale)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    let res = put_recovery_bytes(&app, &jar, &client, &renewed, body.clone()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let text = String::from_utf8(sink.0.lock().unwrap()[mark..].to_vec()).unwrap();
    let mut canaries = Vec::new();
    for value in [
        renewed.recovery_wrap.wrap.as_slice(),
        renewed.pk_r.as_slice(),
        renewed.manifest.envelope.as_slice(),
        renewed.manifest.tag.as_slice(),
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
