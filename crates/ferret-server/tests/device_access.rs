//! A device on the sync routes: an access token with a DPoP proof of the
//! device key reaches exactly the sync routes, and nothing else; a token and a
//! cookie never go together; the event stream of a device ends with its token,
//! its device or its account's `session_version`. Driven through the real
//! routers, with a device that signed in through the real sign-in.
//!
//! Spec: Fase 1 § 7.6, § 8.2; RFC 9449 § 4.3, § 7.1, § 11.1.

mod support;

use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::{Method, StatusCode};
use ferret_server::ids::{DeviceId, TokenSecret};
use ferret_server::vault::events::{HEARTBEAT, LIFETIME};
use ferret_server::vault::notify::CAPACITY;
use ferret_server::wire::ACCESS_TOKEN_SECS;
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use support::accounts::{CLIENT_PASSWORD, Client, client_account, client_session};
use support::device::{DeviceClient, device_app, device_body, finish_req, login_start, now};
use support::dpop::{DeviceKey, b64};
use support::events::{Next, Stream, wait_until};
use support::session::{Issued, issue};
use support::sync::{as_op, hex_of, item, live_body};
use support::{Req, Res, TestApp, VAULT_URL, Which};
use syn::visit::{self, Visit};

use ferret_server::auth::session::Origin;

const SECOND: Duration = Duration::from_secs(1);
const SHORT: Duration = Duration::from_millis(400);

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

fn error_code(res: &Res) -> String {
    serde_json::from_slice::<Value>(&res.body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

fn status_and_code(res: &Res) -> (u16, String) {
    (res.status.as_u16(), error_code(res))
}

/// An account with a device that signed in with key `key`.
async fn signed_in(app: &TestApp, n: u8, key: u8) -> (Client, DeviceClient) {
    let client = client_account(app, n).await;
    let mut device = DeviceClient::new(key);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    (client, device)
}

fn device_id(device: &DeviceClient) -> [u8; 16] {
    device.device_id.expect("signed in")
}

fn access(device: &DeviceClient) -> &TokenSecret {
    device.access.as_ref().expect("signed in")
}

/// A request with `device`'s access token and a proof signed by `key`
/// (another key than the device's when a test wants one).
fn req_signed_by(
    app: &TestApp,
    device: &DeviceClient,
    key: &DeviceKey,
    method: Method,
    path: &str,
) -> Req {
    let token = access(device);
    let proof = key.proof(
        method.as_str(),
        &format!("{VAULT_URL}{path}"),
        now(app),
        Some(token),
    );
    Req::new(method, path)
        .header("authorization", &format!("DPoP {}", token.to_wire()))
        .header("dpop", &proof)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
}

/// A request of the web vault with the cookies of `jar`.
fn cookie_req(jar: &Issued, method: Method, path: &str) -> Req {
    Req::new(method, path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("cookie", &jar.jar.header().expect("a cookie"))
}

async fn exec(app: &TestApp, sql: &'static str, user_id: i64) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(sql, [user_id])?;
            Ok(())
        })
        .await
        .expect("an update");
}

async fn revoke_in_db(app: &TestApp, device: [u8; 16]) {
    let at = now(app);
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_devices SET revoked_at = ?2 WHERE device_id = ?1",
                rusqlite::params![device.as_slice(), at],
            )?;
            Ok(())
        })
        .await
        .expect("a revocation");
}

fn replay_len(app: &TestApp) -> usize {
    app.state.device_auth.replay().len()
}

async fn revoked_at(app: &TestApp, device: [u8; 16]) -> Option<i64> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT revoked_at FROM ferret_devices WHERE device_id = ?1",
                [device.as_slice()],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a device row")
}

/// The body of a batch with one live write.
fn batch_body(client: &Client, n: u16, idem: u32) -> Value {
    json!({"ops": [as_op(item(n), &live_body(&client.vault, item(n), 0, "batched", idem))]})
}

/// A stream opened with `req`, which must say hello.
async fn open_stream(app: &TestApp, req: Req) -> Stream {
    let mut stream = app.open_stream(req.build()).await;
    if stream.status != StatusCode::OK {
        let status = stream.status;
        panic!("{status}: {}", stream.text().await);
    }
    stream.event("hello", SECOND).await;
    // Let the stream's task set its timers before a test pauses the clock.
    stream.quiet(Duration::from_millis(50)).await;
    stream
}

fn events_req(app: &TestApp, device: &DeviceClient) -> Req {
    device.token_req(app, Method::GET, "/api/sync/events")
}

// ------------------------------------------------------- the sync routes

#[tokio::test]
async fn vault_routes_accept_a_device_token_with_a_proof() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;

    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let seq = res.json()["latest_seq"].as_u64().expect("a seq");

    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/vault/unlock-methods"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert!(res.json()["methods"].is_array());

    let path = format!("/api/sync/items/{}", hex_of(item(1)));
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::PUT, &path).json(&live_body(
                &client.vault,
                item(1),
                0,
                "one",
                1,
            )),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["rev"], 1);

    let res = device
        .send(
            &app,
            device
                .token_req(&app, Method::POST, "/api/sync/batch")
                .json(&batch_body(&client, 2, 2)),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["results"][0]["status"], 200);

    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/checkpoint"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let stored = res.json();
    let body = json!({
        "seq": stored["seq"],
        "digest": stored["digest"],
        "mac": stored["mac"],
        "entries": stored["entries"],
    });
    let res = device
        .send(
            &app,
            device
                .token_req(&app, Method::PUT, "/api/sync/checkpoint")
                .json(&body),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["latest_seq"].as_u64(), Some(seq + 2));

    let mut stream = app.open_stream(events_req(&app, &device).build()).await;
    assert_eq!(stream.status, StatusCode::OK);
    assert_eq!(stream.event("hello", SECOND).await, json!({"seq": seq + 2}));
}

#[tokio::test]
async fn a_token_request_answers_like_the_session_of_the_same_account() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    for path in ["/api/sync/changes", "/api/vault/unlock-methods"] {
        let by_token = device
            .send(&app, device.token_req(&app, Method::GET, path))
            .await;
        let by_cookie = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, Method::GET, path).build(),
            )
            .await;
        assert_eq!(by_token.status, StatusCode::OK, "{path}");
        assert_eq!(by_token.json(), by_cookie.json(), "{path}");
    }
}

/// The full listing and the frozen rows of a restore, the way a client leaves a
/// `410` or a restore, answer a device exactly as they answer the session of
/// the same account, and refuse a proof of another key and a revoked device.
#[tokio::test]
async fn the_listing_and_the_restore_rows_accept_a_device_token_with_a_proof() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let path = format!("/api/sync/items/{}", hex_of(item(1)));
    let res = app
        .call_raw(
            Which::Vault,
            cookie_req(&session, Method::PUT, &path)
                .json(&live_body(&client.vault, item(1), 0, "one", 1))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // A restore freezes the rows (and ends every device: the device signs in
    // after it, as a device does).
    let at = now(&app);
    app.state
        .vault_db
        .with_conn(move |conn| ferret_server::vault::reconcile::bump(conn, None, at))
        .await
        .expect("a bump");
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let mut device = DeviceClient::new(1);
    let res = device.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    for path in ["/api/sync/items", "/api/sync/restore-rows"] {
        let by_token = device
            .send(&app, device.token_req(&app, Method::GET, path))
            .await;
        let by_cookie = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, Method::GET, path).build(),
            )
            .await;
        assert_eq!(
            by_token.status,
            StatusCode::OK,
            "{path}: {}",
            by_token.text()
        );
        assert_eq!(by_token.json(), by_cookie.json(), "{path}");
        assert_eq!(by_token.header("cache-control"), "no-store", "{path}");
    }
    let listed = device
        .send(&app, device.token_req(&app, Method::GET, "/api/sync/items"))
        .await
        .json();
    let wanted = hex_of(item(1));
    let holds = |rows: &Value| {
        rows.as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["id"] == wanted.as_str()))
    };
    assert!(holds(&listed["items"]), "the listing holds the item");
    let frozen = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/restore-rows"),
        )
        .await
        .json();
    assert!(holds(&frozen["rows"]), "the frozen rows hold the item");

    // A proof of another key, and a device that was revoked.
    let before = replay_len(&app);
    for path in ["/api/sync/items", "/api/sync/restore-rows"] {
        let res = device
            .send(
                &app,
                req_signed_by(&app, &device, &DeviceKey::new(9), Method::GET, path),
            )
            .await;
        assert_eq!(
            status_and_code(&res),
            (401, "dpop_invalid".into()),
            "{path}: {}",
            res.text()
        );
    }
    assert_eq!(replay_len(&app), before, "a refused proof records nothing");
    revoke_in_db(&app, device_id(&device)).await;
    for path in ["/api/sync/items", "/api/sync/restore-rows"] {
        let res = device
            .send(&app, device.token_req(&app, Method::GET, path))
            .await;
        assert_eq!(
            status_and_code(&res),
            (401, "device_revoked".into()),
            "{path}: {}",
            res.text()
        );
    }
}

// ---------------------------------------------------------- the guard

#[tokio::test]
async fn cookie_and_authorization_together_are_400() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let cookie = session.jar.header().expect("a cookie");
    let before = replay_len(&app);
    for (method, path) in [
        (Method::GET, "/api/sync/changes"),
        (Method::GET, "/api/sync/events"),
        (Method::POST, "/api/sync/batch"),
        (Method::GET, "/api/auth/session"),
        (Method::POST, "/api/auth/logout"),
    ] {
        // The device's own request with the browser's cookie.
        let res = device
            .send(
                &app,
                device
                    .token_req(&app, method.clone(), path)
                    .header("cookie", &cookie),
            )
            .await;
        assert_eq!(
            status_and_code(&res),
            (400, "bad_request".into()),
            "{method} {path}"
        );
        // A page's request with a token header added.
        let res = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, method.clone(), path)
                    .header(
                        "authorization",
                        &format!("DPoP {}", access(&device).to_wire()),
                    )
                    .build(),
            )
            .await;
        assert_eq!(
            status_and_code(&res),
            (400, "bad_request".into()),
            "{method} {path}"
        );
        let res = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, method.clone(), path)
                    .header("dpop", "x.y.z")
                    .build(),
            )
            .await;
        assert_eq!(
            status_and_code(&res),
            (400, "bad_request".into()),
            "{method} {path}"
        );
    }
    // Any cookie counts, not only the session's.
    let res = device
        .send(
            &app,
            device
                .token_req(&app, Method::GET, "/api/sync/changes")
                .header("cookie", "other=1"),
        )
        .await;
    assert_eq!(status_and_code(&res), (400, "bad_request".into()));
    assert_eq!(replay_len(&app), before, "no proof was taken");
    // Both still work alone.
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    let res = app
        .call_raw(
            Which::Vault,
            cookie_req(&session, Method::GET, "/api/sync/changes").build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
}

#[tokio::test]
async fn token_headers_that_read_more_than_one_way_are_400() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let path = "/api/sync/changes";
    // Two proofs.
    let req = device.token_req(&app, Method::GET, path).header(
        "dpop",
        &device.proof(&app, "GET", path, device.access.as_ref()),
    );
    let res = device.send(&app, req).await;
    assert_eq!(status_and_code(&res), (400, "bad_request".into()));
    // A DPoP authorization and another one.
    for other in ["Basic dXNlcjpwYXNz", "Bearer abc", "DPoP abc"] {
        let req = device
            .token_req(&app, Method::GET, path)
            .header("authorization", other);
        let res = device.send(&app, req).await;
        assert_eq!(
            status_and_code(&res),
            (400, "bad_request".into()),
            "{other}"
        );
    }
}

#[tokio::test]
async fn token_request_without_ferret_protocol_is_refused_also_for_get() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let before = replay_len(&app);
    for (method, path, body) in [
        (Method::GET, "/api/sync/changes", None),
        (Method::GET, "/api/sync/checkpoint", None),
        (Method::GET, "/api/vault/unlock-methods", None),
        (Method::GET, "/api/sync/events", None),
        (
            Method::POST,
            "/api/sync/batch",
            Some(batch_body(&client, 1, 1)),
        ),
    ] {
        for protocol in [None, Some("2"), Some("")] {
            let token = access(&device);
            let mut req = Req::new(method.clone(), path)
                .header("authorization", &format!("DPoP {}", token.to_wire()))
                .header(
                    "dpop",
                    &device.proof(&app, method.as_str(), path, Some(token)),
                )
                .header("x-forwarded-proto", "https");
            if let Some(value) = protocol {
                req = req.header("ferret-protocol", value);
            }
            if let Some(body) = &body {
                req = req.json(body);
            }
            let res = device.send(&app, req).await;
            assert_eq!(
                status_and_code(&res),
                (400, "protocol_header_missing".into()),
                "{method} {path} {protocol:?}"
            );
        }
    }
    assert_eq!(replay_len(&app), before);
}

#[tokio::test]
async fn token_request_skips_the_origin_check_cookie_request_does_not() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 2).await;
    let n = std::cell::Cell::new(0u16);
    let body = || {
        n.set(n.get() + 1);
        batch_body(&client, n.get(), u32::from(n.get()))
    };
    for (origin, site) in [
        (None, None),
        (Some("https://evil.test"), Some("cross-site")),
        (Some("moz-extension://abc"), Some("none")),
        (Some("null"), None),
    ] {
        let mut req = device
            .token_req(&app, Method::POST, "/api/sync/batch")
            .json(&body());
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        if let Some(site) = site {
            req = req.header("sec-fetch-site", site);
        }
        let res = device.send(&app, req).await;
        assert_eq!(res.status, StatusCode::OK, "{origin:?}: {}", res.text());
    }
    // The cookie request from another origin is still refused.
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/sync/batch")
                .header("origin", "https://evil.test")
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .header("cookie", &session.jar.header().expect("a cookie"))
                .json(&body())
                .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), (403, "forbidden_origin".into()));
    // The hand-over routes still need their own origin, token or not.
    let res = device
        .send(
            &app,
            device
                .token_req(&app, Method::POST, "/api/auth/handoff")
                .json(&json!({})),
        )
        .await;
    assert_eq!(status_and_code(&res), (403, "forbidden_origin".into()));
}

#[tokio::test]
async fn no_cors_header_is_ever_sent() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let mut requests = Vec::new();
    for path in [
        "/api/sync/changes",
        "/api/sync/batch",
        "/api/sync/events",
        "/api/auth/token/refresh",
    ] {
        // A pre-flight that asks for the token headers, with and without them.
        let preflight = || {
            Req::new(Method::OPTIONS, path)
                .header("origin", "https://evil.test")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "authorization, dpop, ferret-protocol",
                )
        };
        requests.push((Which::Vault, preflight()));
        requests.push((
            Which::Vault,
            device
                .token_req(&app, Method::OPTIONS, path)
                .header("origin", "https://evil.test")
                .header("access-control-request-method", "POST"),
        ));
        requests.push((Which::Admin, preflight()));
    }
    requests.push((
        Which::Vault,
        device
            .token_req(&app, Method::GET, "/api/sync/changes")
            .header("origin", "https://evil.test"),
    ));
    requests.push((
        Which::Vault,
        device
            .token_req(&app, Method::POST, "/api/sync/batch")
            .header("origin", "moz-extension://abc")
            .json(&batch_body(&client, 1, 1)),
    ));
    for (which, req) in requests {
        let res = app.call_raw(which, req.build()).await;
        for name in res.headers.keys() {
            assert!(
                !name.as_str().starts_with("access-control-"),
                "{which:?} {}: {name}",
                res.status
            );
        }
        assert_ne!(res.status, StatusCode::NO_CONTENT);
    }
}

#[tokio::test]
async fn a_device_login_with_a_cookie_is_400() {
    let app = device_app().await;
    let client = client_account(&app, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let device = DeviceClient::new(3);
    let req = finish_req(&device_body(&half), Some(&device.login_proof(&app)))
        .header("cookie", &session.jar.header().expect("a cookie"));
    let res = app.call_raw(Which::Vault, req.build()).await;
    assert_eq!(status_and_code(&res), (400, "bad_request".into()));
    assert!(res.set_cookies().is_empty());
    let devices: i64 = app
        .state
        .vault_db
        .with_conn(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM ferret_devices", [], |r| r.get(0))?)
        })
        .await
        .expect("a count");
    assert_eq!(devices, 0);
}

#[tokio::test]
async fn admin_listener_refuses_dpop_authorization_and_the_dpop_header() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let admin = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    let token = access(&device).to_wire();
    for path in [
        "/api/auth/session",
        "/healthz",
        "/login",
        "/api/sync/changes",
    ] {
        for (name, value) in [
            ("authorization", format!("DPoP {token}")),
            ("authorization", format!("dpop {token}")),
            ("authorization", "DPOP".to_string()),
            ("dpop", "x.y.z".to_string()),
        ] {
            let req = Req::get(path)
                .header("ferret-protocol", "1")
                .header(name, &value);
            let res = app.call_raw(Which::Admin, req.build()).await;
            assert_eq!(
                status_and_code(&res),
                (400, "bad_request".into()),
                "{path} {name}"
            );
            // With the admin session's cookie too.
            let req = Req::get(path)
                .header("ferret-protocol", "1")
                .header("cookie", &admin.jar.header().expect("a cookie"))
                .header(name, &value);
            let res = app.call_raw(Which::Admin, req.build()).await;
            assert_eq!(
                status_and_code(&res),
                (400, "bad_request".into()),
                "{path} {name}"
            );
        }
    }
    // The admin session itself is fine.
    let res = app
        .call_raw(
            Which::Admin,
            Req::get("/api/auth/session")
                .header("cookie", &admin.jar.header().expect("a cookie"))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn basic_auth_from_a_proxy_changes_nothing_for_cookie_requests() {
    let app = device_app().await;
    let (client, _device) = signed_in(&app, 1, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let admin = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        1,
    )
    .await;
    let basic = "Basic dXNlcjpwYXNzd29yZA==";

    // Vault listener: reads, a write and the stream.
    for path in [
        "/api/sync/changes",
        "/api/auth/session",
        "/api/vault/unlock-methods",
    ] {
        let plain = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, Method::GET, path).build(),
            )
            .await;
        let with_basic = app
            .call_raw(
                Which::Vault,
                cookie_req(&session, Method::GET, path)
                    .header("authorization", basic)
                    .build(),
            )
            .await;
        assert_eq!(
            with_basic.status,
            StatusCode::OK,
            "{path}: {}",
            with_basic.text()
        );
        assert_eq!(plain.body, with_basic.body, "{path}");
    }
    let path = format!("/api/sync/items/{}", hex_of(item(1)));
    let res = app
        .call_raw(
            Which::Vault,
            cookie_req(&session, Method::PUT, &path)
                .header("authorization", basic)
                .json(&live_body(&client.vault, item(1), 0, "one", 1))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let stream = cookie_req(&session, Method::GET, "/api/sync/events")
        .header("sec-fetch-site", "same-origin")
        .header("authorization", basic);
    let _open = open_stream(&app, stream).await;
    // Without a cookie, Basic is no credential.
    let res = app
        .call_raw(
            Which::Vault,
            Req::get("/api/sync/changes")
                .header("ferret-protocol", "1")
                .header("authorization", basic)
                .build(),
        )
        .await;
    assert_eq!(status_and_code(&res), (401, "unauthorized".into()));

    // Admin listener.
    let plain = app
        .call_raw(
            Which::Admin,
            Req::get("/api/auth/session")
                .header("cookie", &admin.jar.header().expect("a cookie"))
                .build(),
        )
        .await;
    let with_basic = app
        .call_raw(
            Which::Admin,
            Req::get("/api/auth/session")
                .header("cookie", &admin.jar.header().expect("a cookie"))
                .header("authorization", basic)
                .build(),
        )
        .await;
    assert_eq!(with_basic.status, StatusCode::OK, "{}", with_basic.text());
    assert_eq!(plain.body, with_basic.body);
}

// ------------------------------------------------------ closed by default

#[tokio::test]
async fn handoff_reauth_reconcile_and_sensitive_routes_refuse_a_token() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let before = replay_len(&app);
    for (method, path, origin) in [
        (Method::POST, "/api/auth/challenge", false),
        (Method::POST, "/api/auth/handoff", true),
        (Method::GET, "/api/auth/session", false),
        (Method::POST, "/api/auth/opaque/reregister/start", false),
        (Method::PUT, "/api/vault/unlock-methods/password", false),
        (Method::PUT, "/api/vault/unlock-methods/recovery", false),
        (Method::GET, "/api/vault/recovery", false),
        (Method::POST, "/api/vault/recover", false),
        (Method::POST, "/api/sync/import", false),
    ] {
        let mut req = device.token_req(&app, method.clone(), path);
        if origin {
            req = req.header("origin", VAULT_URL);
        }
        if method != Method::GET {
            req = req.json(&json!({}));
        }
        let res = device.send(&app, req).await;
        assert_eq!(
            status_and_code(&res),
            (401, "unauthorized".into()),
            "{method} {path}: {}",
            res.text()
        );
    }
    // A re-authentication is the sign-in of a session: with a token and no
    // cookie it names no session, and the device sign-in body has no purpose.
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let body = json!({
        "login_id": half.login_id,
        "ke3": ferret_server::wire::b64url::encode(&half.ke3),
        "device_id": "00000000000000000000000000000001",
        "purpose": "reauth",
    });
    let path = "/api/auth/opaque/login/finish";
    let res = device
        .send(&app, device.token_req(&app, Method::POST, path).json(&body))
        .await;
    assert_eq!(res.status.as_u16() / 100, 4, "{}", res.text());
    assert!(res.set_cookies().is_empty());
    assert_eq!(replay_len(&app), before, "no route took the token's proof");
}

/// Whether a type is, or holds, a `VaultCaller` that an extractor makes, or a
/// name that the file gives it (`type C = VaultCaller;`, `use … VaultCaller as
/// C;`): bare, as the argument of a generic (`Result<VaultCaller, _>`,
/// `Option<..>`, a wrapper extractor), through a path (`extract::VaultCaller`),
/// in a tuple or a slice. A reference is a helper that is handed one, not an
/// extractor, and is not looked into.
struct NamesCaller<'a> {
    aliases: &'a [String],
    found: bool,
}

impl<'ast> Visit<'ast> for NamesCaller<'_> {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if ident == "VaultCaller" || self.aliases.iter().any(|alias| ident == alias) {
            self.found = true;
        }
    }

    fn visit_type_reference(&mut self, _: &'ast syn::TypeReference) {}
}

fn names_caller(ty: &syn::Type, aliases: &[String]) -> bool {
    let mut names = NamesCaller {
        aliases,
        found: false,
    };
    names.visit_type(ty);
    names.found
}

/// The names a file gives `VaultCaller`: a type alias whose type names it (or
/// another alias of the file), and a `use` that renames it.
fn aliases_of(file: &syn::File) -> Vec<String> {
    struct Aliases(Vec<String>);
    impl<'ast> Visit<'ast> for Aliases {
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if names_caller(&item.ty, &self.0) {
                self.0.push(item.ident.to_string());
            }
        }

        fn visit_use_rename(&mut self, rename: &'ast syn::UseRename) {
            if rename.ident == "VaultCaller" {
                self.0.push(rename.rename.to_string());
            }
        }
    }
    let mut aliases = Aliases(Vec::new());
    aliases.visit_file(file);
    aliases.0
}

/// What the sources under `src/` say about `VaultCaller`: the handlers that
/// take one (a parameter whose type names it anywhere), and the files whose
/// code names it at all (comments and documentation are not code; `syn` does
/// not see them).
fn caller_routes() -> (Vec<String>, Vec<String>) {
    struct Finder<'a> {
        file: &'a str,
        found: Vec<String>,
        named: bool,
        aliases: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Finder<'_> {
        fn visit_signature(&mut self, sig: &'ast syn::Signature) {
            let takes = sig.inputs.iter().any(|input| match input {
                syn::FnArg::Typed(typed) => names_caller(&typed.ty, &self.aliases),
                syn::FnArg::Receiver(_) => false,
            });
            if takes {
                self.found.push(format!("{}::{}", self.file, sig.ident));
            }
            visit::visit_signature(self, sig);
        }

        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            if ident == "VaultCaller" {
                self.named = true;
            }
        }
    }
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&src, &mut files);
    assert!(files.len() > 40, "the sources were found");
    let mut found = Vec::new();
    let mut named = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file");
        let parsed = syn::parse_file(&text).expect("a Rust file");
        let name = file
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        let mut finder = Finder {
            file: &name,
            found: Vec::new(),
            named: false,
            aliases: aliases_of(&parsed),
        };
        finder.visit_file(&parsed);
        found.extend(finder.found);
        if finder.named {
            named.push(name);
        }
    }
    found.sort();
    named.sort();
    (found, named)
}

#[test]
fn only_the_sync_routes_take_a_token() {
    // The sync routes and nothing else: a new route that takes a token must
    // be added here on purpose, and every other route stays closed.
    let (routes, files) = caller_routes();
    assert_eq!(
        routes,
        [
            "vault/batch.rs::post_batch",
            "vault/changes.rs::get_changes",
            "vault/checkpoint.rs::get_checkpoint",
            "vault/checkpoint.rs::put_checkpoint",
            "vault/events.rs::get_events",
            "vault/items.rs::put_item",
            "vault/methods.rs::get_methods",
            "vault/reconcile.rs::get_items",
            "vault/reconcile.rs::get_restore_rows",
        ]
    );
    // The files whose code names `VaultCaller`: the extractor and the nine
    // handlers. A handler that takes it through an alias, a wrapper extractor
    // or a macro is not found above, but it is found here, in a file that is
    // not in this list, and the list is then edited on purpose.
    assert_eq!(
        files,
        [
            "http/extract.rs",
            "vault/batch.rs",
            "vault/changes.rs",
            "vault/checkpoint.rs",
            "vault/events.rs",
            "vault/items.rs",
            "vault/methods.rs",
            "vault/reconcile.rs",
        ]
    );
}

#[test]
fn the_route_scan_sees_a_caller_behind_generics_and_wrappers() {
    // The scan itself is tried on text that is not in the sources: a caller
    // as the argument of a generic, through a path, behind a reference and
    // inside a tuple is named; another type is not.
    for named in [
        "Result<VaultCaller, Response>",
        "Option<crate::http::extract::VaultCaller>",
        "(Json<Body>, VaultCaller)",
        "Wrapped<Vec<VaultCaller>>",
        "extract::VaultCaller",
    ] {
        let ty: syn::Type = syn::parse_str(named).expect("a type");
        assert!(names_caller(&ty, &[]), "{named}");
    }
    for other in [
        "VaultSession",
        "Result<VaultSession, Response>",
        "Json<VaultCallerBody>",
        "&VaultCaller",
        "&mut Option<VaultCaller>",
    ] {
        let ty: syn::Type = syn::parse_str(other).expect("a type");
        assert!(!names_caller(&ty, &[]), "{other}");
    }
}

#[test]
fn the_route_scan_follows_an_alias_of_the_caller_inside_a_file() {
    // A handler that takes the extractor under another name is found: the
    // names a file gives it are collected first.
    let file: syn::File = syn::parse_str(
        "use crate::http::extract::VaultCaller as Who; type Caller = Who; type Both = (u8, Caller); type Other = String; fn f(a: Both) {} fn g(b: Other) {}",
    )
    .expect("a file");
    let aliases = aliases_of(&file);
    assert_eq!(aliases, ["Who", "Caller", "Both"]);
    let ty: syn::Type = syn::parse_str("Both").expect("a type");
    assert!(names_caller(&ty, &aliases));
    let ty: syn::Type = syn::parse_str("Other").expect("a type");
    assert!(!names_caller(&ty, &aliases));
}

// --------------------------------------------------------- the token itself

#[tokio::test]
async fn an_access_token_with_a_proof_from_another_key_is_dpop_invalid_and_revokes_nothing() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    // Another key that is bound to a device of its own, and one bound to none.
    let (_other_client, other) = signed_in(&app, 2, 2).await;
    let unbound = DeviceKey::new(9);
    let latest_seq = |res: Res| res.json()["latest_seq"].as_u64();
    let seq = latest_seq(
        device
            .send(
                &app,
                device.token_req(&app, Method::GET, "/api/sync/changes"),
            )
            .await,
    );
    let before = replay_len(&app);
    let path = format!("/api/sync/items/{}", hex_of(item(1)));
    for key in [&other.key, &unbound] {
        for (method, path, body) in [
            (Method::GET, "/api/sync/changes", None),
            (Method::GET, "/api/vault/unlock-methods", None),
            (Method::GET, "/api/sync/checkpoint", None),
            (Method::PUT, "/api/sync/checkpoint", Some(json!({}))),
            (
                Method::PUT,
                path.as_str(),
                Some(live_body(&client.vault, item(1), 0, "x", 1)),
            ),
            (
                Method::POST,
                "/api/sync/batch",
                Some(batch_body(&client, 2, 2)),
            ),
            (Method::GET, "/api/sync/events", None),
        ] {
            let mut req = req_signed_by(&app, &device, key, method.clone(), path);
            if let Some(body) = &body {
                req = req.json(body);
            }
            let res = device.send(&app, req).await;
            assert_eq!(
                status_and_code(&res),
                (401, "dpop_invalid".into()),
                "{method} {path}"
            );
            assert!(!res.header("date").is_empty(), "{method} {path}");
            assert_eq!(
                replay_len(&app),
                before,
                "{method} {path}: nothing recorded"
            );
        }
    }
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
    assert_eq!(revoked_at(&app, device_id(&other)).await, None);
    // Nothing was written, and the device still works.
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK);
    assert_eq!(latest_seq(res), seq);
}

#[tokio::test]
async fn a_proof_that_does_not_fit_the_request_is_dpop_invalid() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let token = access(&device);
    let path = "/api/sync/changes";
    let at = now(&app);
    let start = replay_len(&app);
    let proofs = [
        // Another method, another path, a query, another origin.
        device
            .key
            .proof("POST", &format!("{VAULT_URL}{path}"), at, Some(token)),
        device.key.proof(
            "GET",
            &format!("{VAULT_URL}/api/sync/checkpoint"),
            at,
            Some(token),
        ),
        device.key.proof(
            "GET",
            &format!("{VAULT_URL}{path}?since=0"),
            at,
            Some(token),
        ),
        device
            .key
            .proof("GET", &format!("https://evil.test{path}"), at, Some(token)),
        // No `ath`, and the `ath` of another token.
        device
            .key
            .proof("GET", &format!("{VAULT_URL}{path}"), at, None),
        device.key.proof(
            "GET",
            &format!("{VAULT_URL}{path}"),
            at,
            Some(&TokenSecret::from_wire(&b64(&[7; 32])).expect("a token")),
        ),
        // Too old and too new.
        device
            .key
            .proof("GET", &format!("{VAULT_URL}{path}"), at - 61, Some(token)),
        device
            .key
            .proof("GET", &format!("{VAULT_URL}{path}"), at + 61, Some(token)),
    ];
    for proof in proofs {
        let req = Req::get(path)
            .header("authorization", &format!("DPoP {}", token.to_wire()))
            .header("dpop", &proof)
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https");
        let res = device.send(&app, req).await;
        assert_eq!(status_and_code(&res), (401, "dpop_invalid".into()));
    }
    // No proof at all.
    let req = Req::get(path)
        .header("authorization", &format!("DPoP {}", token.to_wire()))
        .header("ferret-protocol", "1");
    assert_eq!(
        status_and_code(&device.send(&app, req).await),
        (401, "dpop_invalid".into())
    );
    // Nothing of it was recorded. The query of a request is not part of
    // `htu`: a proof for the path alone fits a request with a query.
    let before = replay_len(&app);
    assert_eq!(before, start);
    let proof = device
        .key
        .proof("GET", &format!("{VAULT_URL}{path}"), at, Some(token));
    let req = Req::get(&format!("{path}?since=0&limit=5"))
        .header("authorization", &format!("DPoP {}", token.to_wire()))
        .header("dpop", &proof)
        .header("ferret-protocol", "1");
    let res = device.send(&app, req).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(replay_len(&app), before + 1);
}

#[tokio::test]
async fn a_token_that_is_not_one_is_401_unauthorized() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let token = access(&device).to_wire();
    let path = "/api/sync/changes";
    for value in [
        "DPoP".to_string(),
        "DPoP ".to_string(),
        format!("DPoP {}", &token[..42]),
        format!("DPoP {token}="),
        format!("DPoP {token} extra"),
        format!("DPoP\t{token}"),
    ] {
        let proof = device.proof(&app, "GET", path, device.access.as_ref());
        let req = Req::get(path)
            .header("authorization", &value)
            .header("dpop", &proof)
            .header("ferret-protocol", "1");
        let res = device.send(&app, req).await;
        assert_eq!(
            status_and_code(&res),
            (401, "unauthorized".into()),
            "{value:?}"
        );
    }
    // The scheme in any case, and more than one space, are read.
    for value in [format!("dpop {token}"), format!("DPOP  {token}")] {
        let proof = device.proof(&app, "GET", path, device.access.as_ref());
        let req = Req::get(path)
            .header("authorization", &value)
            .header("dpop", &proof)
            .header("ferret-protocol", "1");
        let res = device.send(&app, req).await;
        assert_eq!(res.status, StatusCode::OK, "{value:?}");
    }
    // An unknown token with a good proof for it.
    let unknown = TokenSecret::from_wire(&b64(&[5; 32])).expect("a token");
    let proof = device.key.proof(
        "GET",
        &format!("{VAULT_URL}{path}"),
        now(&app),
        Some(&unknown),
    );
    let req = Req::get(path)
        .header("authorization", &format!("DPoP {}", unknown.to_wire()))
        .header("dpop", &proof)
        .header("ferret-protocol", "1");
    let res = device.send(&app, req).await;
    assert_eq!(status_and_code(&res), (401, "token_expired".into()));
}

#[tokio::test]
async fn an_expired_access_token_is_token_expired() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    app.clock.advance(u64::from(ACCESS_TOKEN_SECS) - 1);
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "one second before");
    app.clock.advance(1);
    let before = replay_len(&app);
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(status_and_code(&res), (401, "token_expired".into()));
    assert!(!res.header("date").is_empty());
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(replay_len(&app), before);
    assert_eq!(revoked_at(&app, device_id(&device)).await, None);
}

#[tokio::test]
async fn a_revoked_device_is_device_revoked() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    revoke_in_db(&app, device_id(&device)).await;
    let before = replay_len(&app);
    for path in [
        "/api/sync/changes",
        "/api/vault/unlock-methods",
        "/api/sync/events",
    ] {
        let res = device
            .send(&app, device.token_req(&app, Method::GET, path))
            .await;
        assert_eq!(
            status_and_code(&res),
            (401, "device_revoked".into()),
            "{path}"
        );
    }
    assert_eq!(replay_len(&app), before);
}

#[tokio::test]
async fn a_raised_session_version_ends_device_access() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    exec(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        client.ids.user_id,
    )
    .await;
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(status_and_code(&res), (401, "device_revoked".into()));
    // A disabled user too.
    let (client, device) = signed_in(&app, 2, 2).await;
    exec(
        &app,
        "UPDATE users SET active = 0 WHERE id = ?1",
        client.ids.user_id,
    )
    .await;
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::GET, "/api/sync/changes"),
        )
        .await;
    assert_eq!(status_and_code(&res), (401, "device_revoked".into()));
}

#[tokio::test]
async fn the_same_access_proof_twice_is_refused() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let start = replay_len(&app);
    let first = device.token_req(&app, Method::GET, "/api/sync/changes");
    // The same request twice, header for header.
    let token = access(&device);
    let proof = device.proof(&app, "GET", "/api/sync/changes", Some(token));
    let again = || {
        Req::get("/api/sync/changes")
            .header("authorization", &format!("DPoP {}", token.to_wire()))
            .header("dpop", &proof)
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https")
    };
    assert_eq!(device.send(&app, first).await.status, StatusCode::OK);
    assert_eq!(device.send(&app, again()).await.status, StatusCode::OK);
    let res = device.send(&app, again()).await;
    assert_eq!(status_and_code(&res), (401, "dpop_invalid".into()));
    // Also on another route: the `jti` is spent for the key.
    let res = device
        .send(
            &app,
            Req::get("/api/sync/checkpoint")
                .header("authorization", &format!("DPoP {}", token.to_wire()))
                .header("dpop", &proof)
                .header("ferret-protocol", "1"),
        )
        .await;
    assert_eq!(status_and_code(&res), (401, "dpop_invalid".into()));
    assert_eq!(replay_len(&app), start + 2);
}

#[tokio::test]
async fn idem_rate_limits_and_stream_places_use_the_server_device_id() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let id = device_id(&device);
    let path = format!("/api/sync/items/{}", hex_of(item(1)));
    let res = device
        .send(
            &app,
            device.token_req(&app, Method::PUT, &path).json(&live_body(
                &client.vault,
                item(1),
                0,
                "one",
                1,
            )),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let devices: Vec<Vec<u8>> = app
        .state
        .vault_db
        .with_conn(|conn| {
            let mut statement = conn.prepare("SELECT device_id FROM ferret_idem")?;
            let rows = statement
                .query_map([], |r| r.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the idem rows");
    assert_eq!(devices, vec![id.to_vec()]);

    // Two streams for the device, and the third is refused; a browser of the
    // same account has places of its own.
    let _a = open_stream(&app, events_req(&app, &device)).await;
    let _b = open_stream(&app, events_req(&app, &device)).await;
    let mut third = app.open_stream(events_req(&app, &device).build()).await;
    assert_eq!(third.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(third.header("retry-after"), "30");
    assert_eq!(third.error().await, "throttled");
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let browser = cookie_req(&session, Method::GET, "/api/sync/events")
        .header("sec-fetch-site", "same-origin");
    let _c = open_stream(&app, browser).await;
    assert_eq!(app.state.streams.open(), 3);
}

// ------------------------------------------------------------- the stream

#[tokio::test]
async fn sse_with_a_token_closes_when_the_device_is_revoked() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let (_other_client, other) = signed_in(&app, 2, 2).await;
    let mut stream = open_stream(&app, events_req(&app, &device)).await;
    let mut theirs = open_stream(&app, events_req(&app, &other)).await;
    // Another device's revocation and a session's leave it open.
    app.state.events.device_revoked(DeviceId(device_id(&other)));
    app.state
        .events
        .session_revoked(ferret_server::ids::SidHash([0; 32]));
    theirs.end(SECOND).await;
    stream.quiet(SHORT).await;
    // Its own closes it at once.
    revoke_in_db(&app, device_id(&device)).await;
    app.state
        .events
        .device_revoked(DeviceId(device_id(&device)));
    stream.end(SECOND).await;
    wait_until(SECOND, || app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn a_device_revocation_that_lagged_is_read_from_the_database() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let mut stream = open_stream(&app, events_req(&app, &device)).await;
    revoke_in_db(&app, device_id(&device)).await;
    // The runtime runs one thread: the stream's receiver falls behind, and
    // none of what it missed named this device. The database says it is over.
    for n in 0..(CAPACITY * 3) {
        let mut sid = [0u8; 32];
        sid[..8].copy_from_slice(&u64::try_from(n).expect("a number").to_be_bytes());
        app.state
            .events
            .session_revoked(ferret_server::ids::SidHash(sid));
    }
    stream.end(SECOND).await;
}

#[tokio::test]
async fn a_token_stream_ends_when_its_access_token_expires() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let mut stream = open_stream(&app, events_req(&app, &device)).await;
    tokio::time::pause();
    let lifetime = Duration::from_secs(u64::from(ACCESS_TOKEN_SECS));
    assert!(lifetime < LIFETIME);
    tokio::time::advance(lifetime - SECOND).await;
    let (frames, ended) = stream.frames(SHORT).await;
    assert!(!ended, "{frames:?}");
    tokio::time::advance(SECOND * 2).await;
    stream.end(SECOND * 2).await;
    wait_until(SECOND, || app.state.streams.open() == 0).await;
}

#[tokio::test]
async fn a_token_stream_ends_at_the_heartbeat_after_its_token_expired() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    let mut stream = open_stream(&app, events_req(&app, &device)).await;
    tokio::time::pause();
    // The server's clock passes the token's end; the next heartbeat sees it.
    app.clock.advance(u64::from(ACCESS_TOKEN_SECS));
    tokio::time::advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
}

#[tokio::test]
async fn a_token_stream_ends_at_the_heartbeat_after_the_session_version_moved() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let mut stream = open_stream(&app, events_req(&app, &device)).await;
    tokio::time::pause();
    tokio::time::advance(HEARTBEAT + SECOND).await;
    assert!(
        matches!(stream.next(SECOND).await, Next::Frame(_)),
        "a heartbeat"
    );
    exec(
        &app,
        "UPDATE users SET session_version = session_version + 1 WHERE id = ?1",
        client.ids.user_id,
    )
    .await;
    tokio::time::advance(HEARTBEAT + SECOND).await;
    stream.end(SECOND * 2).await;
}

#[tokio::test]
async fn a_token_stream_with_sec_fetch_site_none_or_cross_site_is_accepted() {
    let app = device_app().await;
    let (_client, device) = signed_in(&app, 1, 1).await;
    for site in ["none", "cross-site", "same-site", "same-origin"] {
        let req = events_req(&app, &device).header("sec-fetch-site", site);
        let stream = open_stream(&app, req).await;
        drop(stream);
        wait_until(SECOND, || app.state.streams.open() == 0).await;
    }
}

/// The fetch-metadata check of a session's stream stays: see
/// `a_cookie_stream_with_cross_site_is_still_refused` in `tests/events.rs`.
#[tokio::test]
async fn a_token_stream_and_a_cookie_stream_differ_only_in_fetch_metadata() {
    let app = device_app().await;
    let (client, device) = signed_in(&app, 1, 1).await;
    let session = client_session(&app, &client, SessionScope::Full, 1).await;
    let req = cookie_req(&session, Method::GET, "/api/sync/events")
        .header("sec-fetch-site", "cross-site");
    let mut refused = app.open_stream(req.build()).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN);
    assert_eq!(refused.error().await, "forbidden_origin");
    let req = events_req(&app, &device).header("sec-fetch-site", "cross-site");
    let _open = open_stream(&app, req).await;
}
