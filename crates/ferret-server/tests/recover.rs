//! `GET /api/vault/recovery` and `POST /api/vault/recover`: recovering an
//! account with the recovery key.
//!
//! The client is the one of `ferret-core`: the account is made as a
//! registration makes it, the new registration goes through
//! `reregister/start`, the core opens the vault with the recovery key, makes
//! the new password wrap, the new recovery key with its wrap and `pk_r`, and
//! the new manifest, and signs the body with the old recovery key. Spec: Fase
//! 1 § 6.3 and § 4.6.

mod support;

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{
    AuthOp, OPAQUE_CONTEXT, OsRng, PinState, Recovered, auth_sign, opaque_login_start,
    recovery_sign,
};
use ferret_server::auth::session::{Origin, lookup, set_parent};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::SidHash;
use ferret_server::product::{PENDING_2FA_COOKIE, SESSION_COOKIE, SID_COOKIE};
use ferret_server::wire::{RecoveryRes, b64url};
use ferret_server_auth::SessionScope;
use ferret_server_auth::testing::SMALL;
use serde_json::{Value, json};
use support::accounts::{
    Client, RECOVER_PATH, Snapshot, body_bytes, client_account, client_session, opaque_input,
    password_change, password_put_req, post_recover, recover_req, recovered as recovery_of,
    send_signed, snapshot, stored_wraps,
};
use support::session::{challenge_with, issue, nonce_for};
use support::{Jar, PEER, Req, Res, TestApp, VAULT_URL, Which};
use tracing_subscriber::fmt::MakeWriter;

const NEW_PASSWORD: &str = "a brand new horse battery staple";
const RECOVERY_PATH: &str = "/api/vault/recovery";
const SECOND: Duration = Duration::from_secs(1);

// ------------------------------------------------------------------ helpers

/// An app that believes the test peer as a proxy, so sign-ins over `https`
/// count.
async fn app() -> TestApp {
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    TestApp::builder().proxies(proxies).build().await
}

/// An app with client account `n` and a reset session of it, as a redeemed
/// one-time code leaves it.
async fn setup(n: u8) -> (TestApp, Client, Jar, SidHash) {
    let app = app().await;
    let client = client_account(&app, n).await;
    let issued = client_session(&app, &client, SessionScope::AccountReset, 1).await;
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
/// made its third message.
struct HalfWay {
    jar: Jar,
    login_id: Value,
    ke3: Vec<u8>,
}

/// The first half of a sign-in of `email` with `password` from a new browser.
/// `None` when the client cannot finish (the password is not the one of the
/// record).
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
/// the client cannot finish.
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

/// A refused recovery left the account as it was and asked for no backup.
async fn nothing_changed(app: &TestApp, client: &Client, before: &Snapshot) {
    assert_eq!(&snapshot(app, client).await, before);
    assert!(
        !app.backup_status().has_request(),
        "no backup was asked for"
    );
}

/// `POST /api/vault/recover` with `body`, signed with the old recovery key of
/// `recovered` over a fresh nonce of the session of `jar`.
async fn post_recover_bytes(app: &TestApp, jar: &Jar, recovered: &Recovered, body: Vec<u8>) -> Res {
    let nonce = nonce_for(app, jar).await;
    let proof = recovered.sign(&nonce, &body).expect("a proof");
    send_signed(app, jar, Method::POST, RECOVER_PATH, &nonce, &proof, body).await
}

/// The client after the server took `recovered`: the vault, both wraps, the
/// new recovery key, the manifest, the pin and the password.
fn took_recovery(client: &mut Client, recovered: Recovered, password: &str) {
    client.pinned = recovered
        .pinned(VAULT_URL, Some(&client.pinned))
        .expect("the pin after the recovery");
    let Recovered {
        vault,
        recovery_key,
        password_wrap,
        recovery_wrap,
        manifest,
        ..
    } = recovered;
    client.vault = vault;
    client.recovery_key = recovery_key;
    client.password_wrap = password_wrap;
    client.recovery_wrap = recovery_wrap;
    client.manifest = manifest;
    client.password = password.to_string();
}

/// Sets the stored profile of `client`'s account.
async fn set_stored_profile(app: &TestApp, client: &Client, profile: i64) {
    let account = client.ids.account_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_accounts SET ksf_profile = ?1 WHERE account_id = ?2",
                rusqlite::params![profile, account.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("set the stored profile");
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn a_reset_session_reads_the_recovery_wrap_and_nothing_else() {
    let (app, client, jar, _) = setup(1).await;
    let before = snapshot(&app, &client).await;

    let res = vault_get(&app, &jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let body = res.json();
    let mut keys: Vec<&str> = body
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "account_id",
            "ksf_profile",
            "manifest",
            "vault_id",
            "vk_epoch",
            "wrap"
        ]
    );
    let read: RecoveryRes = serde_json::from_value(body.clone()).expect("the wire shape");
    read.validate().expect("a recovery wrap");
    assert_eq!(read.account_id, *client.ids.account_id.as_bytes());
    assert_eq!(read.vault_id, *client.ids.vault_id.as_bytes());
    assert_eq!(read.vk_epoch, 1);
    assert_eq!(read.ksf_profile, 1);
    // The recovery wrap the server holds, and only that one.
    let recovery = &before.wraps[1];
    assert_eq!(recovery.0, 2);
    assert_eq!(read.wrap.method_id, recovery.1);
    assert_eq!(read.wrap.kek_generation, u64::from(recovery.2));
    assert_eq!(read.wrap.wrap, recovery.3);
    assert_eq!(read.wrap.wrap, client.recovery_wrap.wrap);
    let text = res.text();
    let password_wrap = &before.wraps[0].3;
    for secretless_but_other in [
        b64url::encode(password_wrap),
        b64url::encode(&before.record),
        b64url::encode(&before.pk_a),
        b64url::encode(&before.pk_r),
    ] {
        assert!(!text.contains(&secretless_but_other), "{text}");
    }
    assert_eq!(read.manifest.rev, 1);
    assert_eq!(read.manifest.envelope, before.manifest_envelope);
    assert_eq!(read.manifest.tag.to_vec(), before.manifest_tag);

    // Nothing else of the vault: the unlock methods, the changes, the items
    // and the event stream need a full session; a new password needs one too.
    for path in ["/api/vault/unlock-methods", "/api/sync/changes?since=0"] {
        let res = vault_get(&app, &jar, path).await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{path}: {}",
            res.text()
        );
    }
    let change_body = json!({});
    let res = send_signed(
        &app,
        &jar,
        Method::PUT,
        "/api/vault/unlock-methods/password",
        &[1; 32],
        &[2; 64],
        serde_json::to_vec(&change_body).unwrap(),
    )
    .await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());

    // A full session may read it too (to recover from a device that is
    // signed in); no session, and a session before its second factor, may
    // not.
    let full = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let res = vault_get(&app, &full.jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = vault_get(&app, &Jar::default(), RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    let pending = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Pending2fa,
        3,
    )
    .await;
    let res = vault_get(&app, &pending.jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());

    // Another account's reset session reads its own wrap, never this one.
    let other = client_account(&app, 2).await;
    let other_reset = client_session(&app, &other, SessionScope::AccountReset, 4).await;
    let res = vault_get(&app, &other_reset.jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let theirs: RecoveryRes = serde_json::from_value(res.json()).expect("the wire shape");
    assert_eq!(theirs.account_id, *other.ids.account_id.as_bytes());
    assert_eq!(theirs.wrap.wrap, other.recovery_wrap.wrap);

    // Reading changes nothing.
    nothing_changed(&app, &client, &before).await;
}

#[tokio::test]
async fn a_recover_signed_with_the_old_recovery_key_replaces_record_wraps_pk_r_and_manifest() {
    let (app, mut client, jar, _) = setup(3).await;
    let before = snapshot(&app, &client).await;
    // A new browser: the device holds no pinned record.
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"session_ended": true, "seq": 2}));
    assert_eq!(res.header("cache-control"), "no-store");

    let after = snapshot(&app, &client).await;
    // The record is the new one, with its profile.
    assert_eq!(after.record, recovered.registration_record);
    assert_ne!(after.record, before.record);
    assert_eq!(after.ksf_profile, 1);
    // Both wraps are the new ones, under their stored method ids, one
    // generation up.
    let (password_before, recovery_before) = (&before.wraps[0], &before.wraps[1]);
    let (password_after, recovery_after) = (&after.wraps[0], &after.wraps[1]);
    assert_eq!((password_after.0, recovery_after.0), (1, 2));
    assert_eq!(password_after.1, password_before.1, "the same method id");
    assert_eq!(recovery_after.1, recovery_before.1, "the same method id");
    assert_eq!((password_after.2, recovery_after.2), (2, 2));
    assert_eq!(password_after.3, recovered.password_wrap.wrap);
    assert_eq!(recovery_after.3, recovered.recovery_wrap.wrap);
    // `pk_r` is the new key's; `pk_a` and the epoch stay.
    assert_eq!(after.pk_r, recovered.pk_r.to_vec());
    assert_ne!(after.pk_r, before.pk_r);
    assert_eq!(
        (&after.pk_a, after.vk_epoch),
        (&before.pk_a, before.vk_epoch)
    );
    // The manifest is the next revision, at the vault's next seq.
    assert_eq!((after.manifest_rev, after.manifest_seq), (2, 2));
    assert_eq!(after.manifest_envelope, recovered.manifest.envelope);
    assert_eq!(after.manifest_tag, recovered.manifest.tag.to_vec());
    assert_eq!(after.vault_seq, 2);
    let grown = i64::try_from(recovered.manifest.envelope.len()).unwrap()
        - i64::try_from(before.manifest_envelope.len()).unwrap();
    assert_eq!(after.bytes_used, before.bytes_used + grown);

    // The new password signs in; the forgotten one no longer opens the
    // record.
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

    // The new recovery key is the one that works now: a second recovery, in
    // a new reset session a minute later, signs with it and goes on from the
    // first (generation 3, revision 3).
    app.clock.advance(60);
    took_recovery(&mut client, recovered, NEW_PASSWORD);
    let reset = client_session(&app, &client, SessionScope::AccountReset, 2).await;
    let again =
        recovered_with_pin(&app, &reset.jar, &mut client, "yet another horse battery").await;
    let res = post_recover(&app, &reset.jar, &again).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"session_ended": true, "seq": 3}));
    let wraps = stored_wraps(&app, client.ids.account_id).await;
    assert_eq!((wraps[0].2, wraps[1].2), (3, 3));
}

/// A recovery on a device that holds the client's pinned record.
async fn recovered_with_pin(
    app: &TestApp,
    jar: &Jar,
    client: &mut Client,
    password: &str,
) -> Recovered {
    recovery_of(app, jar, client, password, true).await
}

#[tokio::test]
async fn a_recover_signed_with_the_auth_key_is_401() {
    let (app, mut client, jar, reset) = setup(4).await;
    let before = snapshot(&app, &client).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    let body = body_bytes(&recover_req(&recovered));

    // `sk_a` signs the body for each operation it may sign: none is a
    // recovery, and the server checks against `pk_r`.
    for op in AuthOp::ALL {
        let nonce = nonce_for(&app, &jar).await;
        let proof = auth_sign(&client.vault, op, &nonce, &body).expect("a proof by sk_a");
        let res = send_signed(
            &app,
            &jar,
            Method::POST,
            RECOVER_PATH,
            &nonce,
            &proof,
            body.clone(),
        )
        .await;
        assert_eq!(
            res.status,
            StatusCode::UNAUTHORIZED,
            "{op:?}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "denied");
        nothing_changed(&app, &client, &before).await;

        // The nonce went with it: the right proof over it is refused now.
        let right = recovered.sign(&nonce, &body).expect("a proof");
        let res = send_signed(
            &app,
            &jar,
            Method::POST,
            RECOVER_PATH,
            &nonce,
            &right,
            body.clone(),
        )
        .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
        nothing_changed(&app, &client, &before).await;
    }

    // The new recovery key is not known to the server yet.
    let ctx = *recovered.vault.context();
    let nonce = nonce_for(&app, &jar).await;
    let proof = recovery_sign(
        &recovered.recovery_key,
        &ctx.account_id,
        ctx.vk_epoch,
        &nonce,
        &body,
    )
    .expect("a proof by the new key");
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // Another account's recovery key, over this body: refused.
    let mut stranger = client_account(&app, 5).await;
    let stranger_reset = client_session(&app, &stranger, SessionScope::AccountReset, 2).await;
    let theirs = recovery_of(
        &app,
        &stranger_reset.jar,
        &mut stranger,
        NEW_PASSWORD,
        false,
    )
    .await;
    let nonce = nonce_for(&app, &jar).await;
    let proof = theirs.sign(&nonce, &body).expect("a proof by another key");
    let res = send_signed(&app, &jar, Method::POST, RECOVER_PATH, &nonce, &proof, body).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    nothing_changed(&app, &client, &before).await;
    // The reset session is still there: refusals do not end it.
    assert!(!ended(&app, reset).await);
}

#[tokio::test]
async fn a_recover_with_the_same_pk_r_is_refused() {
    let (app, mut client, jar, _) = setup(6).await;
    let before = snapshot(&app, &client).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;

    // The key the server holds now: the old recovery key would stay valid.
    let mut req = recover_req(&recovered);
    req.pk_r_new = <[u8; 32]>::try_from(before.pk_r.as_slice()).unwrap();
    let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    assert_eq!(error_of(&res), "malformed_recovery_key");
    nothing_changed(&app, &client, &before).await;

    // Keys no proof could ever be checked against: the identity point, with
    // and without the sign bit, and a point of order 2.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut signed_identity = identity;
    signed_identity[31] = 0x80;
    let mut order_two = [0u8; 32];
    order_two[0] = 0xec;
    order_two[1..31].fill(0xff);
    order_two[31] = 0x7f;
    for key in [identity, signed_identity, order_two] {
        let mut req = recover_req(&recovered);
        req.pk_r_new = key;
        let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{key:?}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "malformed_recovery_key");
        nothing_changed(&app, &client, &before).await;
    }

    // The new key goes through.
    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_recover_may_set_a_lower_profile() {
    let (app, mut client, jar, _) = setup(7).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;

    // A profile the server's table does not know is refused, whatever the
    // stored one.
    for profile in [0u8, 2, 255] {
        let mut req = recover_req(&recovered);
        req.ksf_profile = profile;
        let before = snapshot(&app, &client).await;
        let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{profile}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "profile_rejected");
        nothing_changed(&app, &client, &before).await;
    }

    // A stored profile above the one the recovery brings (a client that
    // claimed one it did not use): the recovery may lower it, unlike a
    // password change.
    set_stored_profile(&app, &client, 2).await;
    let full = client_session(&app, &client, SessionScope::Full, 2).await;
    let change = password_change(
        &app,
        &full.jar,
        &mut client,
        "a password change would not lower it",
    )
    .await;
    let res = support::accounts::put_password(&app, &full.jar, &client, &change).await;
    assert_eq!(
        res.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        res.text()
    );
    assert_eq!(error_of(&res), "profile_rejected");

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let after = snapshot(&app, &client).await;
    assert_eq!(after.ksf_profile, 1);
    assert_eq!(after.record, recovered.registration_record);
    // The lowered profile is what the reset-session read hands out next.
    let reset = client_session(&app, &client, SessionScope::AccountReset, 4).await;
    let res = vault_get(&app, &reset.jar, RECOVERY_PATH).await;
    assert_eq!(res.json()["ksf_profile"], json!(1));
}

#[tokio::test]
async fn a_reset_session_ends_after_recover_and_its_cookies_are_cleared() {
    let (app, mut client, mut jar, reset) = setup(8).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    let old_jar = jar.clone();
    assert!(jar.get(SID_COOKIE).is_some() && jar.get(SESSION_COOKIE).is_some());
    let mut revocations = app.sync_events().subscribe_revocations();

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["session_ended"], json!(true));

    // The answer removes the session's cookies.
    let set_cookies = res.set_cookies();
    for name in [SID_COOKIE, SESSION_COOKIE] {
        let cookie = set_cookies
            .iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} is cleared: {set_cookies:?}"));
        assert!(
            cookie.starts_with(&format!("{name}=;")) || cookie.contains("Max-Age=0"),
            "{cookie}"
        );
        assert!(cookie.contains("Path=/"), "{cookie}");
    }
    jar.absorb(&res.headers);
    assert!(jar.get(SID_COOKIE).is_none());
    assert!(jar.get(SESSION_COOKIE).is_none());

    // The row has ended, its streams heard of it, and the cookies a browser
    // might still send no longer count.
    assert!(ended(&app, reset).await);
    let revoked = tokio::time::timeout(SECOND, revocations.recv())
        .await
        .expect("in time")
        .expect("a revocation");
    assert_eq!(revoked, reset);
    let res = vault_get(&app, &old_jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    let res = challenge_with(&app, &old_jar).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
}

/// The names of the cookies that `set_cookies` removes, sorted.
fn removed_names<'a>(set_cookies: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut names: Vec<String> = set_cookies
        .into_iter()
        .filter(|c| {
            c.to_ascii_lowercase().contains("max-age=0")
                || c.split(';').next().is_some_and(|p| p.ends_with('='))
        })
        .map(|c| c.split('=').next().expect("a name").to_string())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_recovery_clears_the_same_cookies_as_a_sign_out() {
    use axum::response::IntoResponse as _;
    use axum_extra::extract::cookie::{Cookie, SignedCookieJar};

    let (app, mut client, mut jar, _) = setup(17).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    // The browser also holds a pending second factor and a re-auth grant, so
    // every cookie a sign-out clears is there to be cleared. They are signed:
    // a signed jar reads only cookies that verify.
    let key = app.state.core.session_key.clone();
    let extra = SignedCookieJar::new(key.clone())
        .add(Cookie::new(PENDING_2FA_COOKIE, "x"))
        .add(Cookie::new(vole_kit::auth::reauth::cookie_name(), "x"))
        .into_response();
    jar.absorb(extra.headers());

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["session_ended"], json!(true));
    let by_recovery = removed_names(res.set_cookies().iter().map(String::as_str));

    // What the session module clears for the same request.
    let mut request = axum::http::HeaderMap::new();
    request.insert(
        axum::http::header::COOKIE,
        axum::http::HeaderValue::from_str(&jar.header().expect("cookies")).expect("a header"),
    );
    let cleared =
        ferret_server::auth::session::clear_cookies(SignedCookieJar::from_headers(&request, key))
            .into_response();
    let by_sign_out = removed_names(
        cleared
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .map(|v| v.to_str().expect("text")),
    );
    assert_eq!(by_sign_out.len(), 4, "{by_sign_out:?}");
    assert_eq!(by_recovery, by_sign_out);
}

#[tokio::test]
async fn a_full_session_keeps_itself_after_recover() {
    let app = app().await;
    let mut client = client_account(&app, 9).await;
    // A full session that has not proved the password again: a recovery needs
    // none (the password may be what was forgotten).
    let full = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        1,
    )
    .await;
    let (jar, this) = (full.jar, full.sid);
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
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, true).await;

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"session_ended": false, "seq": 2}));
    // Nothing in the answer removes its cookies.
    let mut kept = jar.clone();
    kept.absorb(&res.headers);
    assert!(kept.get(SID_COOKIE).is_some() && kept.get(SESSION_COOKIE).is_some());

    // Its stream hears of the new manifest, and goes on.
    let sync = stream.event("sync", SECOND).await;
    assert_eq!(sync["seq"], json!(2), "{sync}");
    assert!(!ended(&app, this).await);
    // What was handed over from it does not.
    assert!(
        ended(&app, child).await,
        "the handed-over admin session ends"
    );
    let res = vault_get(&app, &jar, "/api/vault/unlock-methods").await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn every_other_session_ends_and_its_stream_closes() {
    let (app, mut client, jar, this) = setup(10).await;
    let user = client.ids.user_id;
    let laptop = issue(&app, user, Origin::Vault, SessionScope::Full, 2).await;
    let phone = issue(&app, user, Origin::Vault, SessionScope::Full, 3).await;
    let admin = issue(&app, user, Origin::Admin, SessionScope::Full, 4).await;
    let other_reset = issue(&app, user, Origin::Vault, SessionScope::AccountReset, 5).await;
    // Another user's session is not touched.
    let other = client_account(&app, 11).await;
    let bystander = issue(
        &app,
        other.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        6,
    )
    .await;
    let mut laptop_stream = app.events(&laptop.jar).await;
    laptop_stream.event("hello", SECOND).await;
    let mut phone_stream = app.events(&phone.jar).await;
    phone_stream.event("hello", SECOND).await;
    let mut bystander_stream = app.events(&bystander.jar).await;
    bystander_stream.event("hello", SECOND).await;
    // Someone who still knows the old password is half-way through a
    // sign-in.
    let half = start_sign_in(&app, &email(&client), &client.password)
        .await
        .expect("the old password opens the old record");

    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    laptop_stream.end(SECOND).await;
    phone_stream.end(SECOND).await;
    for sid in [laptop.sid, phone.sid, admin.sid, other_reset.sid, this] {
        assert!(ended(&app, sid).await, "every session of the user ended");
    }
    assert_eq!(live_sessions(&app, user).await, 0);
    assert!(!ended(&app, bystander.sid).await);
    bystander_stream.quiet(Duration::from_millis(300)).await;
    for jar in [&laptop.jar, &phone.jar] {
        let res = vault_get(&app, jar, "/api/vault/unlock-methods").await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    }

    // The sign-in that started with the old password cannot finish.
    let res = finish_sign_in(&app, half).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    assert_eq!(live_sessions(&app, user).await, 0);
}

#[tokio::test]
async fn a_committed_recover_asks_for_a_backup() {
    let (app, mut client, jar, _) = setup(12).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    // A refused recovery asks for none.
    for (pw, rk) in [(1, 2), (2, 1), (0, 0)] {
        let mut req = recover_req(&recovered);
        req.pw_kek_generation = pw;
        req.rk_kek_generation = rk;
        let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
        assert_eq!(
            res.status,
            StatusCode::CONFLICT,
            "{pw} {rk}: {}",
            res.text()
        );
        assert_eq!(error_of(&res), "write_conflict");
        assert!(!app.backup_status().has_request());
    }
    let mut req = recover_req(&recovered);
    req.manifest.rev = 3;
    let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
    assert_eq!(res.status, StatusCode::CONFLICT, "{}", res.text());
    let mut req = recover_req(&recovered);
    req.manifest.envelope = vec![7u8; 100];
    let res = post_recover_bytes(&app, &jar, &recovered, body_bytes(&req)).await;
    assert_eq!(
        res.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        res.text()
    );
    assert!(!app.backup_status().has_request());

    let res = post_recover(&app, &jar, &recovered).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(app.backup_status().take_request(), Some("unlock_methods"));
}

#[tokio::test]
async fn a_replayed_body_with_a_new_nonce_is_401() {
    let app = app().await;
    let mut client = client_account(&app, 13).await;
    // A full session, which goes on after the recovery, so the replays below
    // are refused for their proof and not for a lost session.
    let jar = client_session(&app, &client, SessionScope::Full, 1)
        .await
        .jar;
    let before = snapshot(&app, &client).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, true).await;
    let body = body_bytes(&recover_req(&recovered));
    let nonce = nonce_for(&app, &jar).await;
    let proof = recovered.sign(&nonce, &body).expect("a proof");

    // Someone who saw the body and its proof asks for a nonce of their own:
    // the proof covers the nonce it was made for.
    let fresh = nonce_for(&app, &jar).await;
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &fresh,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &before).await;

    // The request as it was made goes through.
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let after = snapshot(&app, &client).await;

    // A minute later: the same bytes again, with their own nonce (gone), and
    // with a new nonce signed again by the old recovery key (no longer the
    // server's `pk_r`).
    app.clock.advance(60);
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &nonce,
        &proof,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    let again = nonce_for(&app, &jar).await;
    let resigned = recovered
        .sign(&again, &body)
        .expect("a proof by the old key");
    app.backup_status().take_request();
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &again,
        &resigned,
        body,
    )
    .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), "denied");
    nothing_changed(&app, &client, &after).await;
}

#[tokio::test]
async fn concurrent_recover_and_password_change_give_one_winner() {
    let app = app().await;
    let mut client = client_account(&app, 14).await;
    // A signed-in browser changes the password while a reset session
    // recovers; both were made from the same state.
    let full = client_session(&app, &client, SessionScope::Full, 1).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 2).await;
    let change = password_change(&app, &full.jar, &mut client, NEW_PASSWORD).await;
    let recovered = recovery_of(
        &app,
        &reset.jar,
        &mut client,
        "a recovered horse battery",
        false,
    )
    .await;
    let change_body = body_bytes(&password_put_req(&change));
    let recover_body = body_bytes(&recover_req(&recovered));
    let change_nonce = nonce_for(&app, &full.jar).await;
    let recover_nonce = nonce_for(&app, &reset.jar).await;
    let change_proof = change
        .sign(&client.vault, &change_nonce, &change_body)
        .expect("a proof");
    let recover_proof = recovered
        .sign(&recover_nonce, &recover_body)
        .expect("a proof");
    let (a, b) = tokio::join!(
        send_signed(
            &app,
            &full.jar,
            Method::PUT,
            "/api/vault/unlock-methods/password",
            &change_nonce,
            &change_proof,
            change_body
        ),
        send_signed(
            &app,
            &reset.jar,
            Method::POST,
            RECOVER_PATH,
            &recover_nonce,
            &recover_proof,
            recover_body
        ),
    );
    // The second waits for the first's write lock. Then its session has
    // ended (the first ended every other session: 401), or the account was
    // changed a moment ago (429), or what it read moved (409). It never
    // writes over the first.
    let winners = [a.status, b.status]
        .iter()
        .filter(|s| **s == StatusCode::OK)
        .count();
    assert_eq!(winners, 1, "{a:?} {b:?}");
    let loser = if a.status == StatusCode::OK { &b } else { &a };
    assert!(
        matches!(loser.status.as_u16(), 401 | 409 | 429),
        "{loser:?}"
    );
    let after = snapshot(&app, &client).await;
    if a.status == StatusCode::OK {
        assert_eq!(after.record, change.registration_record);
        assert_eq!(after.wraps[0].3, change.wrap.wrap);
        assert_eq!(after.wraps[1].2, 1, "the recovery wrap is untouched");
        assert!(ended(&app, reset.sid).await);
    } else {
        assert_eq!(after.record, recovered.registration_record);
        assert_eq!(after.wraps[0].3, recovered.password_wrap.wrap);
        assert_eq!(after.wraps[1].3, recovered.recovery_wrap.wrap);
        assert_eq!(after.pk_r, recovered.pk_r.to_vec());
        assert!(ended(&app, full.sid).await);
    }
    assert_eq!((after.manifest_rev, after.vault_seq), (2, 2));
}

#[tokio::test]
async fn admin_listener_has_neither_route() {
    let app = app().await;
    let client = client_account(&app, 15).await;
    let admin = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    for jar in [&admin.jar, &Jar::default()] {
        let mut get = Req::get(RECOVERY_PATH)
            .header("ferret-protocol", "1")
            .header("sec-fetch-site", "same-origin");
        if let Some(cookie) = jar.header() {
            get = get.header("cookie", &cookie);
        }
        let res = app.call_raw(Which::Admin, get.build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());

        let mut post = Req::post(RECOVER_PATH)
            .page_fetch(Which::Admin)
            .header("ferret-nonce", &b64url::encode(&[1; 32]))
            .header("ferret-proof", &b64url::encode(&[2; 64]))
            .json(&json!({}));
        if let Some(cookie) = jar.header() {
            post = post.header("cookie", &cookie);
        }
        let res = app.call_raw(Which::Admin, post.build()).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
    }
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
async fn recover_bytes_never_reach_the_log() {
    let sink = log_sink();
    let (app, mut client, jar, _) = setup(16).await;
    let recovered = recovery_of(&app, &jar, &mut client, NEW_PASSWORD, false).await;
    let body = body_bytes(&recover_req(&recovered));

    // The control: a value logged on purpose trips the forms built for it.
    let record = &recovered.registration_record;
    tracing::info!(record = ?record, "recover canary self-test, Debug");
    tracing::info!(
        record = %b64url::encode(record),
        "recover canary self-test, base64url"
    );
    tracing::info!(
        record = %ferret_core::testing::hex_encode(record),
        "recover canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    for form in canaries_for(record) {
        assert!(text.contains(&form), "the canary {form:.40} does not fire");
    }
    let mark = sink.0.lock().unwrap().len();

    // The read of the wrap, refusals of every kind, then the recovery.
    let res = vault_get(&app, &jar, RECOVERY_PATH).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let nonce = nonce_for(&app, &jar).await;
    let proof = recovered.sign(&nonce, &body).expect("a proof");
    let mut other = body.clone();
    other.push(b' ');
    let refused = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &nonce,
        &proof,
        other,
    )
    .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let mut bad = recover_req(&recovered);
    bad.manifest.envelope = vec![9u8; 64];
    let refused = post_recover_bytes(&app, &jar, &recovered, body_bytes(&bad)).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut same_key = recover_req(&recovered);
    same_key.pk_r_new =
        <[u8; 32]>::try_from(snapshot(&app, &client).await.pk_r.as_slice()).unwrap();
    let refused = post_recover_bytes(&app, &jar, &recovered, body_bytes(&same_key)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    let nonce_ok = nonce_for(&app, &jar).await;
    let proof_ok = recovered.sign(&nonce_ok, &body).expect("a proof");
    let res = send_signed(
        &app,
        &jar,
        Method::POST,
        RECOVER_PATH,
        &nonce_ok,
        &proof_ok,
        body.clone(),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let text = String::from_utf8(sink.0.lock().unwrap()[mark..].to_vec()).unwrap();
    let mut canaries = Vec::new();
    for value in [
        recovered.registration_record.as_slice(),
        recovered.password_wrap.wrap.as_slice(),
        recovered.recovery_wrap.wrap.as_slice(),
        recovered.pk_r.as_slice(),
        recovered.manifest.envelope.as_slice(),
        recovered.manifest.tag.as_slice(),
        client.recovery_wrap.wrap.as_slice(),
        nonce.as_slice(),
        proof.as_slice(),
        nonce_ok.as_slice(),
        proof_ok.as_slice(),
    ] {
        canaries.extend(canaries_for(value));
    }
    for canary in canaries {
        assert!(!text.contains(&canary), "the log holds {canary:.40}");
    }
    assert!(!text.contains(String::from_utf8_lossy(&body).as_ref()));
}
