//! The page "Devices" of the web vault and every way an account's trust
//! changes: `GET /api/auth/devices` lists the devices with tokens and the
//! browsers, `DELETE /api/auth/devices/{id}` revokes one, `revoke-all` (after
//! the master password again) and `forget-old` revoke many; a change of the
//! master password, a recovery, a redeemed sign-in code and a restore from a
//! backup revoke every device too. Driven through the real router, with
//! devices that signed in with the real OPAQUE client and proofs of test keys,
//! and browsers with the session rows a sign-in writes.
//!
//! Spec: Fase 1 § 4.6, § 6.3, § 7.6, § 8.2 and § 11.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use ferret_server::auth::devices::FORGET_OLD_SECS;
use ferret_server::auth::session::{Origin, end_everything_after_restore, lookup, set_parent};
use ferret_server::backup::restore;
use ferret_server::backup::set::SECRET_FILES;
use ferret_server::ids::{DeviceId, SidHash};
use ferret_server::product::DB_FILE;
use ferret_server::vault::notify::Revoked;
use ferret_server::wire::{DevicesRes, MAX_DEVICE_LIST};
use ferret_server_auth::SessionScope;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};
use support::accounts::{
    CLIENT_PASSWORD, Client, client_account, client_session, password_change, post_recover,
    put_password, recovered,
};
use support::backup::{cfg, make};
use support::device::{DEVICE_NAME, DeviceClient, device_app, now};
use support::session::{Issued, issue, make_fresh};
use support::{Jar, Req, Res, TestApp, Which};
use vole_kit::auth::sign_in_codes;

const DEVICES: &str = "/api/auth/devices";
const REVOKE_ALL: &str = "/api/auth/devices/revoke-all";
const FORGET_OLD: &str = "/api/auth/devices/forget-old";
const REFRESH: &str = "/api/auth/token/refresh";
const SYNC: &str = "/api/sync/changes";
const NEW_PASSWORD: &str = "a brand new horse battery staple";

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

fn error_of(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Client account `n` and a fresh full session of it from browser 1.
async fn account(app: &TestApp, n: u8) -> (Client, Issued) {
    let client = client_account(app, n).await;
    let issued = client_session(app, &client, SessionScope::Full, 1).await;
    (client, issued)
}

/// A device of account `n` with key `key`, signed in.
async fn signed_in(app: &TestApp, n: u8, key: u8) -> DeviceClient {
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    device
}

fn id_of(device: &DeviceClient) -> [u8; 16] {
    device.device_id.expect("signed in")
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

async fn list_res(app: &TestApp, jar: &Jar) -> Res {
    app.call_raw(Which::Vault, page(Method::GET, DEVICES, jar).build())
        .await
}

/// The list, checked as the client checks it.
async fn list(app: &TestApp, jar: &Jar) -> DevicesRes {
    let res = list_res(app, jar).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");
    let list: DevicesRes = serde_json::from_slice(&res.body).expect("the wire shape");
    list.validate().expect("a valid list");
    list
}

async fn delete(app: &TestApp, jar: &Jar, id: &[u8]) -> Res {
    app.call_raw(
        Which::Vault,
        page(Method::DELETE, &format!("{DEVICES}/{}", hex(id)), jar).build(),
    )
    .await
}

async fn post(app: &TestApp, jar: &Jar, path: &str) -> Res {
    app.call_raw(Which::Vault, page(Method::POST, path, jar).build())
        .await
}

/// A sync request of `device` with its access token.
async fn sync(app: &TestApp, device: &DeviceClient) -> Res {
    device
        .send(app, device.token_req(app, Method::GET, SYNC))
        .await
}

/// A renewal of `device`'s refresh token with a good proof.
async fn refresh(app: &TestApp, device: &DeviceClient) -> Res {
    let token = device.refresh.as_ref().expect("signed in");
    let proof = device.proof(app, "POST", REFRESH, None);
    device
        .send(
            app,
            Req::post(REFRESH)
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .header("dpop", &proof)
                .json(&json!({ "refresh_token": token.to_wire() })),
        )
        .await
}

/// `revoked_at` of a device row, if the row is there.
async fn device_revoked_at(app: &TestApp, id: [u8; 16]) -> Option<Option<i64>> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn
                .query_row(
                    "SELECT revoked_at FROM ferret_devices WHERE device_id = ?1",
                    [id.as_slice()],
                    |r| r.get(0),
                )
                .ok())
        })
        .await
        .expect("a read")
}

async fn is_revoked(app: &TestApp, device: &DeviceClient) -> bool {
    matches!(device_revoked_at(app, id_of(device)).await, Some(Some(_)))
}

async fn session_ended(app: &TestApp, sid: SidHash) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
        .await
        .expect("a read")
        .expect("the row")
        .revoked_at
        .is_some()
}

/// Both tokens of a revoked device answer `device_revoked`, and nothing else
/// works.
async fn assert_stopped(app: &TestApp, device: &DeviceClient, code: &str) {
    let res = sync(app, device).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), code, "sync");
    let res = refresh(app, device).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(error_of(&res), code, "refresh");
}

/// Every revocation heard so far.
fn heard(rx: &mut tokio::sync::broadcast::Receiver<Revoked>) -> Vec<Revoked> {
    let mut out = Vec::new();
    while let Ok(revoked) = rx.try_recv() {
        out.push(revoked);
    }
    out
}

fn sorted(revoked: Vec<Revoked>) -> Vec<String> {
    let mut out: Vec<String> = revoked.iter().map(|r| format!("{r:?}")).collect();
    out.sort();
    out
}

/// Adds a session row of `user_id` for browser `device_n` with `name`, signed
/// in at `issued_at` and seen at `last_seen`.
async fn browser_row(
    app: &TestApp,
    user_id: i64,
    device_n: u8,
    name: &'static str,
    issued_at: i64,
    last_seen: i64,
) {
    let mut sid = [0u8; 32];
    sid[0] = 0x5e;
    sid[1] = device_n;
    sid[2..10].copy_from_slice(&issued_at.to_be_bytes());
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "INSERT INTO ferret_sessions
                   (sid_hash, user_id, issued_at, origin, device_id, device_name, scope, last_seen)
                 VALUES (?1, ?2, ?3, 'vault', ?4, ?5, 'full', ?6)",
                rusqlite::params![
                    sid.as_slice(),
                    user_id,
                    issued_at,
                    support::session::device(device_n).0.as_slice(),
                    name,
                    last_seen
                ],
            )?;
            Ok(())
        })
        .await
        .expect("a session row");
}

// ---------------------------------------------------------------- the list

#[tokio::test]
async fn devices_page_lists_the_extension_with_its_name() {
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;

    let list = list(&app, &browser.jar).await;
    assert_eq!(list.more, None);
    let rows: Vec<Value> = serde_json::to_value(&list).expect("json")["devices"]
        .as_array()
        .expect("rows")
        .clone();
    assert_eq!(rows.len(), 2, "{rows:?}");
    // This browser first, then the extension.
    assert_eq!(rows[0]["kind"], "web");
    assert_eq!(rows[0]["current"], true);
    assert_eq!(rows[0]["id"], hex(&support::session::device(1).0));
    assert_eq!(rows[1]["kind"], "device");
    assert_eq!(rows[1]["name"], DEVICE_NAME);
    assert_eq!(rows[1]["platform"], "windows");
    assert_eq!(rows[1]["current"], false);
    assert_eq!(rows[1]["id"], hex(&id_of(&device)));
    let at = u64::try_from(now(&app)).expect("a time");
    assert_eq!(
        (
            rows[1]["created_at"].as_u64(),
            rows[1]["last_seen"].as_u64()
        ),
        (Some(at), Some(at))
    );
}

#[tokio::test]
async fn device_list_has_no_token_or_key_material() {
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    // The device's refresh token and its key's thumbprint, and the browser's
    // session id and its hash, in every form a leak could take.
    let (jkt, sid_hash): (Vec<u8>, Vec<u8>) = {
        let id = id_of(&device);
        let sid = browser.sid;
        app.state
            .vault_db
            .with_conn(move |conn| {
                let jkt: Vec<u8> = conn.query_row(
                    "SELECT jkt FROM ferret_devices WHERE device_id = ?1",
                    [id.as_slice()],
                    |r| r.get(0),
                )?;
                Ok((jkt, sid.0.to_vec()))
            })
            .await
            .expect("a read")
    };
    let res = list_res(&app, &browser.jar).await;
    assert_eq!(res.status, StatusCode::OK);
    let text = res.text();
    let b64 = |bytes: &[u8]| ferret_server::wire::b64url::encode(bytes);
    for secret in [
        device.access.as_ref().expect("a token").to_wire(),
        device.refresh.as_ref().expect("a token").to_wire(),
        device
            .access
            .as_ref()
            .expect("a token")
            .hash()
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        device
            .refresh
            .as_ref()
            .expect("a token")
            .hash()
            .0
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        hex(&jkt),
        b64(&jkt),
        hex(&sid_hash),
        b64(&sid_hash),
        browser.secret.clone(),
        device.key.x.clone(),
        device.key.y.clone(),
    ] {
        assert!(!text.contains(&secret), "the list holds a secret");
    }
    // Exactly the keys of the wire shape, nothing more.
    for row in res.json()["devices"].as_array().expect("rows") {
        let keys: BTreeSet<&str> = row
            .as_object()
            .expect("a row")
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = [
            "id",
            "kind",
            "name",
            "platform",
            "created_at",
            "last_seen",
            "current",
        ]
        .into();
        assert!(keys.is_subset(&allowed), "{keys:?}");
    }
}

#[tokio::test]
async fn a_browser_appears_once_per_device_id_with_its_latest_name() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let uid = client.ids.user_id;
    let at = now(&app);
    // Browser 2 signed in three times; the newest sign-in named it last.
    browser_row(&app, uid, 2, "Firefox on the laptop", at - 3000, at - 2500).await;
    browser_row(&app, uid, 2, "Firefox (renamed)", at - 1000, at - 900).await;
    browser_row(&app, uid, 2, "", at - 2000, at - 100).await;
    // Browser 3: one session, ended; it is not listed.
    browser_row(&app, uid, 3, "Old browser", at - 500, at - 500).await;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_sessions SET revoked_at = ?1 WHERE device_id = ?2",
                rusqlite::params![at, support::session::device(3).0.as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("ended");
    // Browser 4: idle for longer than the vault's idle limit; not listed.
    browser_row(&app, uid, 4, "Idle browser", at - 50_000, at - 43_201).await;
    // Another user's browser 5 is never listed.
    let other = client_account(&app, 2).await;
    browser_row(&app, other.ids.user_id, 5, "Not mine", at - 10, at - 10).await;

    let list = list(&app, &browser.jar).await;
    let webs: Vec<_> = list
        .devices
        .iter()
        .filter(|row| matches!(row.kind, ferret_server::wire::DeviceKindJson::Web))
        .collect();
    assert_eq!(webs.len(), 2, "this browser and browser 2");
    assert!(webs[0].current);
    let two = webs[1];
    assert_eq!(two.id, support::session::device(2).0);
    // The newest session (by sign-in) gave the name; the first live session
    // gave the time; the last seen is the latest of all.
    assert_eq!(two.name, "Firefox (renamed)");
    assert_eq!(two.created_at, u64::try_from(at - 3000).expect("a time"));
    assert_eq!(two.last_seen, u64::try_from(at - 100).expect("a time"));
    assert!(!two.current);
}

#[tokio::test]
async fn a_long_list_is_cut_and_says_how_many_were_left_out() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let uid = client.ids.user_id;
    let at = now(&app);
    for n in 2..=210u8 {
        browser_row(
            &app,
            uid,
            n,
            "A browser",
            at - i64::from(n),
            at - i64::from(n),
        )
        .await;
    }
    let list = list(&app, &browser.jar).await;
    assert_eq!(list.devices.len(), MAX_DEVICE_LIST);
    assert_eq!(list.more, Some(10));
    assert!(list.devices[0].current, "this browser is never cut");
    // The most recently seen come first.
    assert_eq!(list.devices[1].id, support::session::device(2).0);
}

#[tokio::test]
async fn the_list_needs_a_full_session_of_the_vault() {
    let app = device_app().await;
    let (client, _browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    // No session.
    let res = list_res(&app, &Jar::default()).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // A reset session.
    let reset = client_session(&app, &client, SessionScope::AccountReset, 2).await;
    let res = list_res(&app, &reset.jar).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // A device with its token: no route of the list takes one.
    for (method, path) in [
        (Method::GET, DEVICES.to_string()),
        (
            Method::DELETE,
            format!("{DEVICES}/{}", hex(&id_of(&device))),
        ),
        (Method::POST, REVOKE_ALL.to_string()),
        (Method::POST, FORGET_OLD.to_string()),
    ] {
        let res = device
            .send(&app, device.token_req(&app, method.clone(), &path))
            .await;
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    assert!(!is_revoked(&app, &device).await);
}

// ----------------------------------------------------------- revoking one

#[tokio::test]
async fn revoking_a_device_stops_sync_at_once_and_its_refresh_fails() {
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let other = signed_in(&app, 1, 2).await;
    let res = sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let mut revocations = app.sync_events().subscribe_revocations();

    let res = delete(&app, &browser.jar, &id_of(&device)).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());
    assert_eq!(res.header("cache-control"), "no-store");

    // The streams of the device hear of it at once, and of nothing else.
    assert_eq!(
        heard(&mut revocations),
        vec![Revoked::Device(DeviceId(id_of(&device)))]
    );
    assert_stopped(&app, &device, "device_revoked").await;
    // The other device and the browser go on.
    let res = sync(&app, &other).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(!session_ended(&app, browser.sid).await);
    // The list no longer shows it, and a second revocation finds nothing.
    let list = list(&app, &browser.jar).await;
    assert!(list.devices.iter().all(|row| row.id != id_of(&device)));
    let res = delete(&app, &browser.jar, &id_of(&device)).await;
    assert_eq!(res.status, StatusCode::NOT_FOUND);
    assert_eq!(error_of(&res), "not_found");
}

#[tokio::test]
async fn revoking_a_browser_ends_its_sessions_and_their_admin_children() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let uid = client.ids.user_id;
    let laptop = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let laptop_again = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let laptop_admin = issue(&app, uid, Origin::Admin, SessionScope::Full, 9).await;
    let (child, parent) = (laptop_admin.sid, laptop.sid);
    app.state
        .vault_db
        .with_conn(move |conn| Ok(set_parent(conn, &child, &parent)?))
        .await
        .expect("a hand-over");
    let phone = issue(&app, uid, Origin::Vault, SessionScope::Full, 3).await;
    let device = signed_in(&app, 1, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    let res = delete(&app, &browser.jar, &support::session::device(2).0).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());

    for sid in [laptop.sid, laptop_again.sid, laptop_admin.sid] {
        assert!(session_ended(&app, sid).await);
    }
    assert_eq!(
        sorted(heard(&mut revocations)),
        sorted(vec![
            Revoked::Session(laptop.sid),
            Revoked::Session(laptop_again.sid),
            Revoked::Session(laptop_admin.sid),
        ])
    );
    for sid in [browser.sid, phone.sid] {
        assert!(!session_ended(&app, sid).await);
    }
    assert!(!is_revoked(&app, &device).await);
    let res = app
        .call_raw(
            Which::Vault,
            page(Method::GET, "/api/auth/session", &laptop.jar).build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_own_browser_cannot_be_revoked_from_the_list() {
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let res = delete(&app, &browser.jar, &support::session::device(1).0).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST, "{}", res.text());
    assert_eq!(error_of(&res), "bad_request");
    assert!(!session_ended(&app, browser.sid).await);
    assert!(heard(&mut revocations).is_empty());
    // A malformed id is refused as well, and changes nothing.
    for bad in ["xyz", "00112233445566778899AABBCCDDEEFF", "0011"] {
        let res = app
            .call_raw(
                Which::Vault,
                page(Method::DELETE, &format!("{DEVICES}/{bad}"), &browser.jar).build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    assert!(!session_ended(&app, browser.sid).await);
}

#[tokio::test]
async fn a_session_with_this_browsers_id_is_listed_apart_and_can_be_revoked() {
    let app = device_app().await;
    let (client, victim) = account(&app, 1).await;
    let uid = client.ids.user_id;
    // Someone with the password signs in again with the victim browser's id
    // (a browser chooses its id), names it like the victim's, and opens the
    // admin pages from it.
    app.clock.advance(60);
    let intruder = issue(&app, uid, Origin::Vault, SessionScope::Full, 1).await;
    let intruder_admin = issue(&app, uid, Origin::Admin, SessionScope::Full, 9).await;
    let (child, parent, sid) = (intruder_admin.sid, intruder.sid, intruder.sid);
    app.state
        .vault_db
        .with_conn(move |conn| {
            set_parent(conn, &child, &parent)?;
            conn.execute(
                "UPDATE ferret_sessions SET device_name = 'Firefox on the laptop' WHERE sid_hash = ?1",
                [sid.0.as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("the intruder's rows");

    // The victim sees this browser alone as "this browser", and the other
    // session as a row of its own with the same id, which can be revoked.
    let rows = list(&app, &victim.jar).await.devices;
    let own = support::session::device(1).0;
    let webs: Vec<_> = rows.iter().filter(|row| row.id == own).collect();
    assert_eq!(webs.len(), 2, "two rows with this browser's id");
    assert!(webs[0].current);
    assert_eq!(
        webs[0].name, "Test browser",
        "the asking session's own name"
    );
    assert!(!webs[1].current);
    assert_eq!(webs[1].name, "Firefox on the laptop");
    // The intruder's own list marks the intruder's session as current, not
    // the victim's.
    let theirs = list(&app, &intruder.jar).await.devices;
    assert_eq!(theirs.iter().filter(|row| row.current).count(), 1);
    assert_eq!(theirs[0].name, "Firefox on the laptop");

    let mut revocations = app.sync_events().subscribe_revocations();
    let res = delete(&app, &victim.jar, &own).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT, "{}", res.text());
    assert!(session_ended(&app, intruder.sid).await);
    assert!(session_ended(&app, intruder_admin.sid).await);
    assert!(
        !session_ended(&app, victim.sid).await,
        "the asking session stays"
    );
    assert_eq!(
        sorted(heard(&mut revocations)),
        sorted(vec![
            Revoked::Session(intruder.sid),
            Revoked::Session(intruder_admin.sid),
        ])
    );
    let res = app
        .call_raw(
            Which::Vault,
            page(Method::GET, "/api/auth/session", &intruder.jar).build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // Now only this browser carries the id: a second call is refused.
    let res = delete(&app, &victim.jar, &own).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    let rows = list(&app, &victim.jar).await.devices;
    assert_eq!(rows.len(), 1);
    assert!(rows[0].current);
}

#[tokio::test]
async fn the_three_changes_refuse_a_request_from_another_site() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let laptop = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    // Old enough for "forget old devices".
    app.clock
        .advance(u64::try_from(FORGET_OLD_SECS).expect("secs"));
    let fresh = client_session(&app, &client, SessionScope::Full, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let cookie = fresh.jar.header().expect("cookies");
    let paths = [
        (
            Method::DELETE,
            format!("{DEVICES}/{}", hex(&id_of(&device))),
        ),
        (Method::POST, REVOKE_ALL.to_string()),
        (Method::POST, FORGET_OLD.to_string()),
    ];
    for (method, path) in &paths {
        // No protocol header.
        let res = app
            .call_raw(
                Which::Vault,
                Req::new(method.clone(), path)
                    .header("origin", support::VAULT_URL)
                    .header("x-forwarded-proto", "https")
                    .header("cookie", &cookie)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::BAD_REQUEST, "{method} {path}");
        assert_eq!(error_of(&res), "protocol_header_missing");
        // The browser says another site sent it.
        let res = app
            .call_raw(
                Which::Vault,
                Req::new(method.clone(), path)
                    .page_fetch(Which::Vault)
                    .header("x-forwarded-proto", "https")
                    .header("sec-fetch-site", "cross-site")
                    .header("cookie", &cookie)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(error_of(&res), "forbidden_origin");
        // Another origin.
        let res = app
            .call_raw(
                Which::Vault,
                Req::new(method.clone(), path)
                    .header("origin", "https://evil.example")
                    .header("ferret-protocol", "1")
                    .header("x-forwarded-proto", "https")
                    .header("cookie", &cookie)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(error_of(&res), "forbidden_origin");
    }
    // Nothing was revoked, ended or announced.
    assert!(!is_revoked(&app, &device).await);
    assert!(!session_ended(&app, laptop.sid).await);
    assert!(heard(&mut revocations).is_empty());
    // The same requests from the page itself go through.
    let res = post(&app, &fresh.jar, FORGET_OLD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    drop(browser);
}

#[tokio::test]
async fn a_device_of_another_user_is_404() {
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let (other, other_browser) = account(&app, 2).await;
    let theirs = signed_in(&app, 2, 2).await;
    let their_laptop = issue(
        &app,
        other.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        7,
    )
    .await;

    for id in [id_of(&theirs), support::session::device(7).0, [0x42; 16]] {
        let res = delete(&app, &browser.jar, &id).await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{}", res.text());
        assert_eq!(error_of(&res), "not_found");
    }
    assert!(!is_revoked(&app, &theirs).await);
    assert!(!session_ended(&app, their_laptop.sid).await);
    assert!(!session_ended(&app, other_browser.sid).await);
    let res = sync(&app, &theirs).await;
    assert_eq!(res.status, StatusCode::OK);
    // And it is not in the list.
    let list = list(&app, &browser.jar).await;
    assert!(list.devices.iter().all(|row| row.id != id_of(&theirs)));
}

// ---------------------------------------------------------- revoking many

#[tokio::test]
async fn revoke_all_needs_fresh_reauth() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let mut revocations = app.sync_events().subscribe_revocations();

    // Stale: the re-authentication is more than 300 seconds old.
    app.clock.advance(301);
    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN, "{}", res.text());
    assert_eq!(error_of(&res), "reauth_required");
    // Never re-authenticated.
    let res = post(&app, &other.jar, REVOKE_ALL).await;
    assert_eq!(error_of(&res), "reauth_required");
    // A reset session may not.
    let reset = client_session(&app, &client, SessionScope::AccountReset, 3).await;
    let res = post(&app, &reset.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&res), "forbidden");
    // No session.
    let res = post(&app, &Jar::default(), REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
    // A second factor the server cannot ask for: refused, fresh or not.
    make_fresh(&app, browser.sid).await;
    let uid = client.ids.user_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?1", [uid])?;
            Ok(())
        })
        .await
        .expect("2FA on");
    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::FORBIDDEN);
    assert_eq!(error_of(&res), "second_factor_required");

    // Nothing was revoked or announced.
    assert!(heard(&mut revocations).is_empty());
    assert!(!is_revoked(&app, &device).await);
    assert!(!session_ended(&app, other.sid).await);
    let res = sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Fresh, without a second factor: it goes through.
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute("UPDATE users SET totp_enabled = 0 WHERE id = ?1", [uid])?;
            Ok(())
        })
        .await
        .expect("2FA off");
    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn revoke_all_keeps_this_session_and_ends_every_other_and_every_device() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let uid = client.ids.user_id;
    let first = signed_in(&app, 1, 1).await;
    let second = signed_in(&app, 1, 2).await;
    let laptop = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let admin = issue(&app, uid, Origin::Admin, SessionScope::Full, 3).await;
    // This browser's own admin session, handed over from it.
    let own_admin = issue(&app, uid, Origin::Admin, SessionScope::Full, 1).await;
    let (child, parent) = (own_admin.sid, browser.sid);
    app.state
        .vault_db
        .with_conn(move |conn| Ok(set_parent(conn, &child, &parent)?))
        .await
        .expect("a hand-over");
    let (_other, other_browser) = account(&app, 2).await;
    let theirs = signed_in(&app, 2, 3).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"revoked": 5}));
    assert_eq!(res.header("cache-control"), "no-store");

    assert!(
        !session_ended(&app, browser.sid).await,
        "this browser stays"
    );
    // This browser's admin session ends too, as after a password change: it
    // fails safe, and the admin pages are opened again.
    for sid in [laptop.sid, admin.sid, own_admin.sid] {
        assert!(session_ended(&app, sid).await);
    }
    for device in [&first, &second] {
        assert!(is_revoked(&app, device).await);
        assert_stopped(&app, device, "device_revoked").await;
    }
    assert_eq!(
        sorted(heard(&mut revocations)),
        sorted(vec![
            Revoked::Session(laptop.sid),
            Revoked::Session(admin.sid),
            Revoked::Session(own_admin.sid),
            Revoked::Device(DeviceId(id_of(&first))),
            Revoked::Device(DeviceId(id_of(&second))),
        ])
    );
    // The list holds this browser only.
    let list = list(&app, &browser.jar).await;
    assert_eq!(list.devices.len(), 1);
    assert!(list.devices[0].current);
    // Another user is untouched.
    assert!(!is_revoked(&app, &theirs).await);
    assert!(!session_ended(&app, other_browser.sid).await);
    // A device may sign in again afterwards (with a new key).
    let again = signed_in(&app, 1, 4).await;
    let res = sync(&app, &again).await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn forget_old_revokes_only_token_devices_unused_for_7_days() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let old = signed_in(&app, 1, 1).await;
    let edge = signed_in(&app, 1, 2).await;
    let recent = signed_in(&app, 1, 3).await;
    let start = now(&app);
    // Seen: `old` 7 days and more ago, `edge` one second less, `recent` now.
    for (device, seen) in [
        (&old, start),
        (&edge, start + 1),
        (&recent, start + FORGET_OLD_SECS),
    ] {
        let id = id_of(device);
        app.state
            .vault_db
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE ferret_devices SET last_seen = ?1 WHERE device_id = ?2",
                    rusqlite::params![seen, id.as_slice()],
                )?;
                Ok(())
            })
            .await
            .expect("seen");
    }
    let laptop = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    drop(browser);
    app.clock
        .advance(u64::try_from(FORGET_OLD_SECS).expect("secs"));
    // The browser's session is used now, so it is live.
    let fresh = client_session(&app, &client, SessionScope::Full, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();

    let res = post(&app, &fresh.jar, FORGET_OLD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({"revoked": 1}));
    assert_eq!(
        heard(&mut revocations),
        vec![Revoked::Device(DeviceId(id_of(&old)))]
    );
    assert!(is_revoked(&app, &old).await);
    assert!(!is_revoked(&app, &edge).await);
    assert!(!is_revoked(&app, &recent).await);
    assert!(
        !session_ended(&app, laptop.sid).await,
        "browsers are not touched"
    );
    assert!(!session_ended(&app, fresh.sid).await);
    // Nothing more to forget.
    let res = post(&app, &fresh.jar, FORGET_OLD).await;
    assert_eq!(res.json(), json!({"revoked": 0}));
}

// ------------------------------------------------- every way trust changes

/// A pending sign-in code for `user`, as the admin pages make one.
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

#[tokio::test]
async fn recover_and_password_change_revoke_every_device() {
    // A change of the master password.
    let app = device_app().await;
    let (mut client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let change = password_change(&app, &browser.jar, &mut client, NEW_PASSWORD).await;
    let res = put_password(&app, &browser.jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(is_revoked(&app, &device).await);
    assert_stopped(&app, &device, "device_revoked").await;
    assert!(heard(&mut revocations).contains(&Revoked::Device(DeviceId(id_of(&device)))));
    assert!(
        !session_ended(&app, browser.sid).await,
        "the asking browser stays"
    );

    // A recovery with the recovery key, in a reset session.
    let app = device_app().await;
    let mut client = client_account(&app, 2).await;
    let device = signed_in(&app, 2, 2).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 1).await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let recovery = recovered(&app, &reset.jar, &mut client, NEW_PASSWORD, false).await;
    let res = post_recover(&app, &reset.jar, &recovery).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(is_revoked(&app, &device).await);
    assert_stopped(&app, &device, "device_revoked").await;
    assert!(heard(&mut revocations).contains(&Revoked::Device(DeviceId(id_of(&device)))));

    // A redeemed sign-in code.
    let app = device_app().await;
    let client = client_account(&app, 3).await;
    let device = signed_in(&app, 3, 3).await;
    let code = code_for(&app, client.ids.user_id).await;
    let mut revocations = app.sync_events().subscribe_revocations();
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/redeem")
                .page_fetch(Which::Vault)
                .header("x-forwarded-proto", "https")
                .json(&json!({ "email": email(3), "code": code }))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(is_revoked(&app, &device).await);
    assert_stopped(&app, &device, "device_revoked").await;
    assert!(heard(&mut revocations).contains(&Revoked::Device(DeviceId(id_of(&device)))));
}

#[tokio::test]
async fn a_new_recovery_key_revokes_no_device() {
    let app = device_app().await;
    let (mut client, browser) = account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let renewed = support::accounts::renewed_recovery(&mut client);
    let res = support::accounts::put_recovery(&app, &browser.jar, &client, &renewed).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(!is_revoked(&app, &device).await);
    let res = sync(&app, &device).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn every_ended_credential_is_announced_after_commit_and_not_before() {
    let app = device_app().await;
    let (client, browser) = account(&app, 1).await;
    let uid = client.ids.user_id;
    let first = signed_in(&app, 1, 1).await;
    let second = signed_in(&app, 1, 2).await;
    let laptop = issue(&app, uid, Origin::Vault, SessionScope::Full, 2).await;
    let phone = issue(&app, uid, Origin::Vault, SessionScope::Full, 3).await;

    // A listener that, for every revocation it hears, reads the row through
    // another connection at once: it must already be ended there.
    let mut revocations = app.sync_events().subscribe_revocations();
    let db = app.state.vault_db.clone();
    // A session id no row has: the test sends it last, to end the listener.
    let done = SidHash([0xff; 32]);
    let listener = tokio::spawn(async move {
        let mut seen = Vec::new();
        while let Ok(Ok(revoked)) =
            tokio::time::timeout(Duration::from_secs(10), revocations.recv()).await
        {
            if revoked == Revoked::Session(done) {
                break;
            }
            let committed = db
                .with_conn(move |conn| {
                    Ok(match revoked {
                        Revoked::Session(sid) => lookup(conn, &sid)?
                            .is_some_and(|row| row.revoked_at.is_some()),
                        Revoked::Device(id) => conn
                            .query_row(
                                "SELECT revoked_at IS NOT NULL FROM ferret_devices WHERE device_id = ?1",
                                [id.0.as_slice()],
                                |r| r.get::<_, bool>(0),
                            )?,
                    })
                })
                .await
                .expect("a read");
            seen.push((revoked, committed));
        }
        seen
    });

    // A refused change announces nothing.
    app.clock.advance(301);
    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(error_of(&res), "reauth_required");
    // One device, one browser, then all the rest.
    let res = delete(&app, &browser.jar, &id_of(&first)).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let res = delete(&app, &browser.jar, &support::session::device(2).0).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    make_fresh(&app, browser.sid).await;
    let res = post(&app, &browser.jar, REVOKE_ALL).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    app.sync_events().session_revoked(done);
    let seen = listener.await.expect("the listener");
    let revoked: Vec<Revoked> = seen.iter().map(|(r, _)| *r).collect();
    assert_eq!(
        sorted(revoked),
        sorted(vec![
            Revoked::Device(DeviceId(id_of(&first))),
            Revoked::Session(laptop.sid),
            Revoked::Session(phone.sid),
            Revoked::Device(DeviceId(id_of(&second))),
        ]),
        "each once, and nothing for the refused change"
    );
    for (revoked, committed) in seen {
        assert!(committed, "{revoked:?} was heard before its commit");
    }
}

// ------------------------------------------------------------ the restore

#[tokio::test]
async fn restore_invalidates_every_token_and_revokes_every_device() {
    // Through `end_everything_after_restore`, on the live database.
    let app = device_app().await;
    let (_client, browser) = account(&app, 1).await;
    let first = signed_in(&app, 1, 1).await;
    let second = signed_in(&app, 1, 2).await;
    let _theirs_client = client_account(&app, 2).await;
    let theirs = signed_in(&app, 2, 3).await;
    // One device was revoked before: it stays revoked, with its time.
    let res = delete(&app, &browser.jar, &id_of(&second)).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    let second_at = device_revoked_at(&app, id_of(&second)).await;
    app.clock.advance(10);
    let at = now(&app);
    let swept = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction()?;
            let swept = end_everything_after_restore(&tx, at)?;
            tx.commit()?;
            Ok(swept)
        })
        .await
        .expect("a sweep");
    assert_eq!(swept.devices, 2, "the two live devices");
    for (table, n) in [("ferret_access", 0), ("ferret_refresh", 0)] {
        let count: i64 = app
            .state
            .vault_db
            .with_conn(move |conn| {
                Ok(conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?)
            })
            .await
            .expect("a count");
        assert_eq!(count, n, "{table}");
    }
    for device in [&first, &theirs] {
        assert_eq!(device_revoked_at(&app, id_of(device)).await, Some(Some(at)));
        // The token rows are gone: the tokens are unknown.
        assert_stopped(&app, device, "token_expired").await;
    }
    assert_eq!(device_revoked_at(&app, id_of(&second)).await, second_at);
    let res = list_res(&app, &browser.jar).await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "every session ended too"
    );

    // Through `backup::restore`: a set taken while the devices were live.
    let app = device_app().await;
    let _client = client_account(&app, 1).await;
    let device = signed_in(&app, 1, 1).await;
    let cfg = cfg(&app);
    let t1 = now(&app) + 60;
    let set = make(&app, &cfg, t1).await.expect("the backup");
    let data = Dir::new("devices");
    let later = make(&app, &cfg, t1 + 60).await.expect("the later set");
    copy_data(&cfg.dir.join(&later.name), data.path());
    let report = restore::restore(data.path(), &cfg.dir.join(&set.name), None, t1 + 3600)
        .expect("a restore");
    assert!(report.restore_epoch > 0);
    let db = data.path().join(DB_FILE);
    let conn = Connection::open_with_flags(
        format!("file:{}?immutable=1", db.display()),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open the restored database");
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).expect("a count") };
    assert_eq!(count("SELECT COUNT(*) FROM ferret_access"), 0);
    assert_eq!(count("SELECT COUNT(*) FROM ferret_refresh"), 0);
    assert_eq!(
        count("SELECT COUNT(*) FROM ferret_devices WHERE revoked_at IS NULL"),
        0
    );
    let id = id_of(&device);
    let revoked_at: Option<i64> = conn
        .query_row(
            "SELECT revoked_at FROM ferret_devices WHERE device_id = ?1",
            [id.as_slice()],
            |r| r.get(0),
        )
        .expect("the device row");
    assert_eq!(revoked_at, Some(t1 + 3600));
}

/// A folder of its own under the temporary directory, removed when dropped.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferret-devices-test-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("a directory");
        Dir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The database and the secret files of a set, as the data of a server.
fn copy_data(set_dir: &Path, data: &Path) {
    for name in [DB_FILE].into_iter().chain(SECRET_FILES) {
        std::fs::copy(set_dir.join(name), data.join(name)).expect("a copy");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(data.join(name), std::fs::Permissions::from_mode(0o600))
                .expect("private");
        }
    }
}
