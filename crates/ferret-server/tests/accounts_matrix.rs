//! Two accounts on one server never cross: account B, with its own session or
//! its own device token, goes through every route of the vault listener with
//! the ids of account A in the path, the query or the body, and A is left as
//! it was, row for row, in memory and on its streams.
//!
//! The two accounts are made by the client of `ferret-core` against the app's
//! own OPAQUE keys (`support::accounts::client_account`), and their browser
//! sessions carry the same device id, as two accounts in one browser do. A
//! third account is the administrator that makes the sign-in codes.
//!
//! What is checked for every answer to B:
//!
//! * its status and code, decided before it is sent;
//! * that nothing of A is in it: A's account, vault, item, method and device
//!   ids, its e-mail, the ciphertext of its item and the name in its log;
//! * at the end, that every row of A in every table that holds rows of an
//!   account is what it was, that A's session, token, import window and
//!   nonce still work, and that A's stream heard nothing.
//!
//! The routes, as `server::vault_router` mounts them (and the hand-over
//! redeem of the admin listener):
//!
//! * sync: changes, items, restore rows, PUT of an item, batch, import window,
//!   checkpoint GET and PUT, events (session and token);
//! * the vault: unlock methods GET, POST (with quick-unlock) and DELETE of one
//!   (with quick-unlock), the password, the recovery wrap GET, a new recovery
//!   key, recover, policy;
//! * auth: session, challenge and reregister start (both under every signed
//!   route above), devices, revoking one, forget old, redeem, token refresh and
//!   sign-out, the hand-over and its redeem, logout; revoke-all in
//!   `revoke_all_and_a_redeemed_code_of_b_leave_a_alone`; the account log.
//!
//! Not here, because they take neither a session nor an id of an account:
//! sign-in start and finish, registration start and finish, the invitation
//! check (`login.rs`, `register.rs`, `invites.rs`), and the static files.
//!
//! Spec: Fase 1 § 4.6, § 7.6, § 8 (sync), § 11 (several accounts); Global
//! Constraint 84 of the L1 plan.

mod support;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use ferret_server::accounts::actions::issue_sign_in_code;
use ferret_server::accounts::log::Actor;
use ferret_server::ids::TokenSecret;
use ferret_server::wire::{b64url, hex16};
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::{Value, json};
use support::accounts::{
    CLIENT_PASSWORD, Client, add_account_to_app, body_bytes, client_account, client_session,
    password_change, password_put_req, post_recover, put_recovery, recovered, renewed_recovery,
    send_signed,
};
use support::device::{DeviceClient, device_app};
use support::events::Stream;
use support::session::{Issued, nonce_for};
use support::sync::{as_op, hex_of, item, live_body};
use support::{Jar, Res, TestApp, VAULT_URL, Which};

const SECOND: Duration = Duration::from_secs(1);
const SHORT: Duration = Duration::from_millis(400);
/// The name in A's log, which B must never see.
const A_LOG_NAME: &str = "marker-of-the-log-of-a@example.com";
const NEW_PASSWORD: &str = "a new horse for the matrix";

// ------------------------------------------------------------------ helpers

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

/// Bytes as lower-case hexadecimal, as the passkey routes take them.
#[cfg(feature = "quick-unlock")]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn code_of(res: &Res) -> String {
    serde_json::from_slice::<Value>(&res.body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// A request as a page of the vault sends it, with the cookies of `jar`.
fn page(method: Method, uri: &str, jar: &Jar, body: Option<&Value>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https");
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string())),
        None => builder.body(Body::empty()),
    }
    .expect("a request")
}

async fn send(app: &TestApp, method: Method, uri: &str, jar: &Jar, body: Option<&Value>) -> Res {
    app.call_raw(Which::Vault, page(method, uri, jar, body))
        .await
}

const REFRESH: &str = "/api/auth/token/refresh";
const REVOKE: &str = "/api/auth/token/revoke";

/// `POST` of a refresh token to `path` (to renew or to sign out), with a
/// proof of `device`, as a device client sends it.
async fn token_post(app: &TestApp, device: &DeviceClient, path: &str, token: &TokenSecret) -> Res {
    let proof = device.proof(app, "POST", path, None);
    let req = support::Req::post(path)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
        .header("dpop", &proof)
        .json(&json!({ "refresh_token": token.to_wire() }));
    app.call_raw(Which::Vault, req.build()).await
}

/// The change that adds a passkey with the method id `id` to `client`'s
/// vault, as the core makes it.
#[cfg(feature = "quick-unlock")]
fn passkey_change(client: &mut Client, id: [u8; 16]) -> ferret_core::MethodChange {
    use ferret_core::{CurrentManifest, Kek, Method as WrapMethod, PasskeyMeta, PrfOutput};
    let credential_id = vec![0x5c; 24];
    let output = PrfOutput::from_slice(&[0x16; 32]).expect("a PRF output");
    let kek = Kek::from_prf(&credential_id, &output).expect("a key");
    let wrap = client
        .vault
        .wrap_for_method(
            &mut client.rng,
            &kek,
            ferret_server::ids::MethodId::from_bytes(id),
            1,
            WrapMethod::Prf {
                credential_id,
                prf_salt: [0x4c; 32],
            },
        )
        .expect("a wrap");
    ferret_core::manifest_add_method(
        &mut client.rng,
        &client.vault,
        &CurrentManifest {
            rev: client.manifest.rev,
            envelope: &client.manifest.envelope,
            tag: &client.manifest.tag,
        },
        wrap,
        &PasskeyMeta {
            aaguid: [0x9d; 16],
            name: "Laptop of B",
            be: false,
            bs: false,
        },
    )
    .expect("the core adds the passkey")
}

/// A request of a device client with its access token.
async fn token_send(
    app: &TestApp,
    device: &DeviceClient,
    method: Method,
    path: &str,
    body: Option<&Value>,
) -> Res {
    let mut req = device.token_req(app, method, path);
    if let Some(body) = body {
        req = req.json(body);
    }
    device.send(app, req).await
}

/// What of account A may never be in an answer to B, as the text that would
/// be there.
struct Traces(Vec<(&'static str, String)>);

impl Traces {
    fn of(a: &Client, extra: &[(&'static str, String)]) -> Self {
        let mut list = vec![
            ("account id", hex16::encode(a.ids.account_id.as_bytes())),
            ("vault id", hex16::encode(a.ids.vault_id.as_bytes())),
            (
                "account id (base64url)",
                b64url::encode(a.ids.account_id.as_bytes()),
            ),
            (
                "vault id (base64url)",
                b64url::encode(a.ids.vault_id.as_bytes()),
            ),
            (
                "password method",
                hex16::encode(a.password_wrap.method_id.as_bytes()),
            ),
            (
                "recovery method",
                hex16::encode(a.recovery_wrap.method_id.as_bytes()),
            ),
            ("password wrap", b64url::encode(&a.password_wrap.wrap)),
            ("manifest", b64url::encode(&a.manifest.envelope)),
            ("e-mail", email(1)),
            ("log name", A_LOG_NAME.to_string()),
        ];
        list.extend_from_slice(extra);
        Traces(list)
    }

    /// The labels of the traces of A that `res` holds, in its body or its
    /// headers.
    fn found_in(&self, res: &Res) -> Vec<&'static str> {
        let mut text = String::from_utf8_lossy(&res.body).to_string();
        for (name, value) in &res.headers {
            text.push_str(name.as_str());
            text.push_str(&String::from_utf8_lossy(value.as_bytes()));
        }
        self.0
            .iter()
            .filter(|(_, value)| text.contains(value.as_str()))
            .map(|(label, _)| *label)
            .collect()
    }
}

/// Collects what went wrong, so one run names every route that crossed.
struct Matrix<'a> {
    traces: &'a Traces,
    problems: Vec<String>,
    rows: usize,
}

impl Matrix<'_> {
    /// The answer to B must be `status` with `code` (`""` for a success), and
    /// hold nothing of A.
    fn check(&mut self, label: &str, res: &Res, status: StatusCode, code: &str) {
        self.rows += 1;
        let got = (res.status, code_of(res));
        if got.0 != status || got.1 != code {
            self.problems.push(format!(
                "{label}: wanted {status} {code:?}, got {} {:?}: {}",
                got.0,
                got.1,
                res.text().chars().take(300).collect::<String>()
            ));
        }
        let found = self.traces.found_in(res);
        if !found.is_empty() {
            self.problems
                .push(format!("{label}: the answer holds A's {found:?}"));
        }
    }

    fn fact(&mut self, label: &str, holds: bool) {
        self.rows += 1;
        if !holds {
            self.problems.push(format!("{label}: does not hold"));
        }
    }

    fn done(self, wanted_rows: usize) {
        assert!(
            self.problems.is_empty(),
            "routes that crossed or answered otherwise:\n{}",
            self.problems.join("\n")
        );
        assert!(
            self.rows >= wanted_rows,
            "only {} rows of the matrix were checked",
            self.rows
        );
    }
}

/// Every row that belongs to the account of `user`, `account` and `vault`, in
/// every table that holds rows of an account, as text: two dumps are equal
/// when nothing of the account changed.
async fn rows_of(app: &TestApp, a: &Client) -> Vec<String> {
    let (user, account, vault) = (a.ids.user_id, a.ids.account_id, a.ids.vault_id);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let by_user = [
                "SELECT * FROM users WHERE id = ?1",
                "SELECT * FROM ferret_accounts WHERE user_id = ?1",
                "SELECT * FROM ferret_sessions WHERE user_id = ?1 ORDER BY sid_hash",
                "SELECT * FROM ferret_devices WHERE user_id = ?1 ORDER BY device_id",
                "SELECT * FROM ferret_refresh WHERE device_id IN
                   (SELECT device_id FROM ferret_devices WHERE user_id = ?1) ORDER BY token_hash",
                "SELECT * FROM ferret_access WHERE device_id IN
                   (SELECT device_id FROM ferret_devices WHERE user_id = ?1) ORDER BY token_hash",
                "SELECT * FROM ferret_account_events WHERE user_id = ?1 ORDER BY id",
                "SELECT * FROM sign_in_codes WHERE user_id = ?1 ORDER BY id",
                "SELECT * FROM ferret_handoffs WHERE user_id = ?1 ORDER BY code_hash",
            ];
            let by_account =
                ["SELECT * FROM ferret_unlock_methods WHERE account_id = ?1 ORDER BY method_id"];
            let by_vault = [
                "SELECT * FROM ferret_vaults WHERE vault_id = ?1",
                "SELECT * FROM ferret_items WHERE vault_id = ?1 ORDER BY item_id",
                "SELECT * FROM ferret_idem WHERE vault_id = ?1 ORDER BY device_id, idem",
                "SELECT * FROM ferret_checkpoints WHERE vault_id = ?1",
                "SELECT * FROM ferret_restore_rows WHERE vault_id = ?1 ORDER BY item_id",
            ];
            let mut out = Vec::new();
            let mut dump = |sql: &str, param: rusqlite::types::Value| -> rusqlite::Result<()> {
                let mut stmt = conn.prepare(sql)?;
                let columns = stmt.column_count();
                let mut rows = stmt.query([param])?;
                let mut n = 0;
                while let Some(row) = rows.next()? {
                    let mut line = format!("{sql} #{n}:");
                    for i in 0..columns {
                        line.push_str(&format!(" {:?}", row.get_ref(i)?));
                    }
                    out.push(line);
                    n += 1;
                }
                Ok(())
            };
            for sql in by_user {
                dump(sql, rusqlite::types::Value::Integer(user))?;
            }
            for sql in by_account {
                dump(
                    sql,
                    rusqlite::types::Value::Blob(account.as_bytes().to_vec()),
                )?;
            }
            for sql in by_vault {
                dump(sql, rusqlite::types::Value::Blob(vault.as_bytes().to_vec()))?;
            }
            Ok(out)
        })
        .await
        .expect("the rows of the account")
}

async fn sql(app: &TestApp, statement: &'static str, args: Vec<rusqlite::types::Value>) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(statement, rusqlite::params_from_iter(args))?;
            Ok(())
        })
        .await
        .expect("a statement");
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// One account of the matrix: the client, a browser session on device 1 and
/// a device client that signed in with its own key.
struct Account {
    client: Client,
    browser: Issued,
    device: DeviceClient,
}

async fn account(app: &TestApp, n: u8) -> Account {
    let client = client_account(app, n).await;
    // The same browser for both accounts: the session's device id is the
    // same one.
    let browser = client_session(app, &client, SessionScope::Full, 1).await;
    let mut device = DeviceClient::new(n);
    let res = device.sign_in(app, &email(n), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    Account {
        client,
        browser,
        device,
    }
}

/// The administrator that makes the sign-in codes: account 9.
async fn admin(app: &TestApp) -> i64 {
    let user = add_account_to_app(app, 9).await.user_id;
    sql(
        app,
        "UPDATE users SET role = 'admin' WHERE id = ?1",
        vec![rusqlite::types::Value::Integer(user)],
    )
    .await;
    user
}

/// A sign-in code for `user` made by the administrator `by` on the Users page.
async fn sign_in_code(app: &TestApp, user: i64, by: i64) -> String {
    let actor = Actor::Admin {
        user_id: Some(by),
        name: email(9).replace("client", "user"),
    };
    let at = now(app);
    app.state
        .vault_db
        .with_conn(move |conn| {
            let issued = issue_sign_in_code(conn, user, &actor, at).expect("a code");
            Ok(issued.code().to_string())
        })
        .await
        .expect("a code")
}

/// A stream of the session of `jar` that has said hello.
async fn stream(app: &TestApp, jar: &Jar) -> Stream {
    let mut stream = app.events(jar).await;
    assert_eq!(stream.status, StatusCode::OK);
    stream.event("hello", SECOND).await;
    stream.quiet(Duration::from_millis(50)).await;
    stream
}

/// The ids in a JSON answer's list `field`, under `key`.
fn ids_in(res: &Res, field: &str, key: &str) -> Vec<String> {
    res.json()[field]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row[key].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// --------------------------------------------------------------- the matrix

#[tokio::test]
async fn accounts_matrix_no_route_crosses_accounts() {
    let app = device_app().await;
    let admin = admin(&app).await;
    let mut a = account(&app, 1).await;
    let mut b = account(&app, 2).await;
    let a_jar = a.browser.jar.clone();
    let b_jar = b.browser.jar.clone();
    let a_device = hex16::encode(&a.device.device_id.expect("a device id"));
    let b_device = hex16::encode(&b.device.device_id.expect("a device id"));
    let browser_device = hex16::encode(&support::session::device(1).0);

    // A's state: an item, an event in its log with a name, an import window,
    // a passkey method (with quick-unlock), and a pending sign-in code.
    let a_item = item(1);
    let a_body = live_body(&a.client.vault, a_item, 0, "secret of a", 1);
    let res = send(
        &app,
        Method::PUT,
        &format!("/api/sync/items/{}", hex_of(a_item)),
        &a_jar,
        Some(&a_body),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    sql(
        &app,
        "INSERT INTO ferret_account_events (user_id, at, kind, actor, actor_name)
         VALUES (?1, ?2, 'account_disabled', 'admin', ?3)",
        vec![
            rusqlite::types::Value::Integer(a.client.ids.user_id),
            rusqlite::types::Value::Integer(now(&app)),
            rusqlite::types::Value::Text(A_LOG_NAME.to_string()),
        ],
    )
    .await;
    let res = send(
        &app,
        Method::POST,
        "/api/sync/import",
        &a_jar,
        Some(&json!({"ops": 5})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let a_window = res.json()["window_id"]
        .as_str()
        .expect("a window")
        .to_string();
    let a_prf: [u8; 16] = [0xe1; 16];
    #[cfg(feature = "quick-unlock")]
    sql(
        &app,
        "INSERT INTO ferret_unlock_methods
           (method_id, account_id, method_type, wrap, kek_generation, credential_id, prf_salt,
            aaguid, created_at)
         VALUES (?1, ?2, 3, zeroblob(100), 1, ?3, zeroblob(32), NULL, ?4)",
        vec![
            rusqlite::types::Value::Blob(a_prf.to_vec()),
            rusqlite::types::Value::Blob(a.client.ids.account_id.as_bytes().to_vec()),
            rusqlite::types::Value::Blob(vec![0xc7; 24]),
            rusqlite::types::Value::Integer(now(&app)),
        ],
    )
    .await;
    let a_code = sign_in_code(&app, a.client.ids.user_id, admin).await;
    let a_nonce = nonce_for(&app, &a_jar).await;
    let mut a_stream = stream(&app, &a_jar).await;

    let traces = Traces::of(
        &a.client,
        &[
            (
                "item blob",
                a_body["blob"].as_str().expect("a blob").to_string(),
            ),
            (
                "item tag",
                a_body["tag"].as_str().expect("a tag").to_string(),
            ),
            ("token device", a_device.clone()),
            ("passkey method", hex16::encode(&a_prf)),
            ("import window", a_window.clone()),
            ("sign-in code", a_code.clone()),
        ],
    );
    let before = rows_of(&app, &a.client).await;
    let mut m = Matrix {
        traces: &traces,
        problems: Vec::new(),
        rows: 0,
    };

    // ---- the session of B on the vault listener

    let res = send(&app, Method::GET, "/api/auth/session", &b_jar, None).await;
    m.check("session info", &res, StatusCode::OK, "");
    m.fact(
        "session info is B's",
        res.text().contains(&email(2)) || res.json()["user_id"] == json!(b.client.ids.user_id),
    );

    // The feed, the listing and the restore rows list B's vault only.
    let res = send(
        &app,
        Method::GET,
        "/api/sync/changes?since=0&limit=500",
        &b_jar,
        None,
    )
    .await;
    m.check("changes", &res, StatusCode::OK, "");
    m.fact(
        "changes: B's manifest only",
        ids_in(&res, "changes", "id").len() == 1,
    );
    m.fact(
        "changes: not A's item",
        !res.text().contains(&hex_of(a_item)),
    );
    let res = send(&app, Method::GET, "/api/sync/items?limit=500", &b_jar, None).await;
    m.check("items", &res, StatusCode::OK, "");
    m.fact("items: not A's item", !res.text().contains(&hex_of(a_item)));
    let after_a = format!(
        "/api/sync/items?after={}&limit=500",
        hex16::encode(&[0u8; 16])
    );
    let res = send(&app, Method::GET, &after_a, &b_jar, None).await;
    m.check("items after the manifest", &res, StatusCode::OK, "");
    let res = send(&app, Method::GET, "/api/sync/restore-rows", &b_jar, None).await;
    m.check("restore rows", &res, StatusCode::OK, "");

    // A write to A's item id, on A's revision: there is no such row in B's
    // vault, so it is a conflict that says the row is absent. (From here on
    // B has rows of its own under A's item id, which B may: the ids of two
    // vaults are apart.)
    let item_path = format!("/api/sync/items/{}", hex_of(a_item));
    let res = send(
        &app,
        Method::PUT,
        &item_path,
        &b_jar,
        Some(&live_body(&b.client.vault, a_item, 1, "b over a", 7)),
    )
    .await;
    m.check("put on A's revision", &res, StatusCode::CONFLICT, "");
    m.fact(
        "put on A's revision: the row is absent in B's vault",
        res.json()["current_rev"] == json!(0),
    );
    // A's idem, from the same device id, on A's item id: B's vault has no
    // record of that idem, so it is a new row of B, and not A's stored answer
    // (nor a refusal of an idem used with another body).
    let res = send(
        &app,
        Method::PUT,
        &item_path,
        &b_jar,
        Some(&live_body(&b.client.vault, a_item, 0, "b with a's idem", 1)),
    )
    .await;
    m.check("A's request replayed by B", &res, StatusCode::OK, "");
    m.fact(
        "A's request replayed by B is a new row",
        res.json()["replayed"] != json!(true),
    );
    let res = send(
        &app,
        Method::POST,
        "/api/sync/batch",
        &b_jar,
        Some(&json!({"ops": [as_op(a_item, &live_body(&b.client.vault, a_item, 9, "b", 8))]})),
    )
    .await;
    m.check("batch on A's revision", &res, StatusCode::OK, "");
    m.fact(
        "batch on A's revision is a conflict",
        res.json()["results"][0]["status"] == json!(409),
    );
    // A's import window is A's: the batch of B that names it is refused.
    let res = send(
        &app,
        Method::POST,
        "/api/sync/batch",
        &b_jar,
        Some(&json!({
            "ops": [as_op(item(2), &live_body(&b.client.vault, item(2), 0, "b", 9))],
            "import_window": a_window,
        })),
    )
    .await;
    m.check(
        "batch in A's import window",
        &res,
        StatusCode::CONFLICT,
        "import_window_invalid",
    );
    // B opens its own window from the same device id: A's open window does
    // not hold B's vault back.
    let res = send(
        &app,
        Method::POST,
        "/api/sync/import",
        &b_jar,
        Some(&json!({"ops": 1})),
    )
    .await;
    m.check("import window of B", &res, StatusCode::OK, "");

    // The checkpoint is B's; A's checkpoint uploaded by B is checked against
    // B's vault only.
    let res = send(&app, Method::GET, "/api/sync/checkpoint", &b_jar, None).await;
    m.check("checkpoint", &res, StatusCode::OK, "");
    let theirs = send(&app, Method::GET, "/api/sync/checkpoint", &a_jar, None)
        .await
        .json();
    let upload = json!({
        "seq": theirs["seq"],
        "digest": theirs["digest"],
        "mac": theirs["mac"],
        "entries": theirs["entries"],
    });
    let res = send(
        &app,
        Method::PUT,
        "/api/sync/checkpoint",
        &b_jar,
        Some(&upload),
    )
    .await;
    // At A's seq it is no newer than B's own: stale, and the answer names
    // B's stored seq only.
    m.check(
        "A's checkpoint uploaded by B",
        &res,
        StatusCode::CONFLICT,
        "checkpoint_stale",
    );
    // At B's own head it replaces B's checkpoint (the server cannot tell
    // whose entries they are; that is the client's check), and only B's.
    let head = send(
        &app,
        Method::GET,
        "/api/sync/changes?since=0&limit=1",
        &b_jar,
        None,
    )
    .await
    .json()["latest_seq"]
        .clone();
    let mut newer = upload.clone();
    newer["seq"] = head;
    let res = send(
        &app,
        Method::PUT,
        "/api/sync/checkpoint",
        &b_jar,
        Some(&newer),
    )
    .await;
    m.check(
        "A's checkpoint at B's head, uploaded by B",
        &res,
        StatusCode::OK,
        "",
    );

    // Devices: B's list, A's token device unknown to B, the shared browser id
    // is B's own browser, and forgetting old devices is B's.
    let res = send(&app, Method::GET, "/api/auth/devices", &b_jar, None).await;
    m.check("devices", &res, StatusCode::OK, "");
    let listed = ids_in(&res, "devices", "id");
    m.fact(
        "devices: B's token device is listed",
        listed.contains(&b_device),
    );
    let res = send(
        &app,
        Method::DELETE,
        &format!("/api/auth/devices/{a_device}"),
        &b_jar,
        None,
    )
    .await;
    m.check(
        "revoke A's token device",
        &res,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let res = send(
        &app,
        Method::DELETE,
        &format!("/api/auth/devices/{browser_device}"),
        &b_jar,
        None,
    )
    .await;
    m.check(
        "revoke the shared browser id",
        &res,
        StatusCode::BAD_REQUEST,
        "bad_request",
    );
    let res = send(
        &app,
        Method::POST,
        "/api/auth/devices/forget-old",
        &b_jar,
        None,
    )
    .await;
    m.check("forget old devices", &res, StatusCode::OK, "");

    // The unlock methods and the recovery wrap are B's.
    let res = send(&app, Method::GET, "/api/vault/unlock-methods", &b_jar, None).await;
    m.check("unlock methods", &res, StatusCode::OK, "");
    m.fact(
        "unlock methods: B's password method",
        res.text()
            .contains(&hex16::encode(b.client.password_wrap.method_id.as_bytes())),
    );
    let res = send(&app, Method::GET, "/api/vault/recovery", &b_jar, None).await;
    m.check("recovery wrap", &res, StatusCode::OK, "");
    m.fact(
        "recovery wrap: B's account",
        res.text()
            .contains(&hex16::encode(b.client.ids.account_id.as_bytes())),
    );
    #[cfg(feature = "quick-unlock")]
    {
        // B removes A's passkey method: B signs a removal that names A's id;
        // B's account has no such method.
        let body = serde_json::to_vec(&json!({
            "method_id": hex16::encode(&a_prf),
            "manifest": {
                "rev": b.client.manifest.rev + 1,
                "envelope": hex(&b.client.manifest.envelope),
                "tag": hex(&b.client.manifest.tag),
            },
        }))
        .expect("a body");
        let nonce = nonce_for(&app, &b_jar).await;
        let proof = ferret_core::auth_sign(
            &b.client.vault,
            ferret_core::AuthOp::UnlockMethodRemove,
            &nonce,
            &body,
        )
        .expect("a proof");
        let res = send_signed(
            &app,
            &b_jar,
            Method::DELETE,
            &format!("/api/vault/unlock-methods/{}", hex16::encode(&a_prf)),
            &nonce,
            &proof,
            body,
        )
        .await;
        m.check(
            "remove A's passkey method",
            &res,
            StatusCode::NOT_FOUND,
            "not_found",
        );
    }

    // A recovery made from A's recovery key, sent in B's session: the proof
    // is checked against B's keys only.
    let stolen = recovered(&app, &b_jar, &mut a.client, NEW_PASSWORD, true).await;
    let res = post_recover(&app, &b_jar, &stolen).await;
    m.check(
        "recover with A's recovery key",
        &res,
        StatusCode::UNAUTHORIZED,
        "denied",
    );
    // A new recovery key that A's client made, signed with A's key, sent in
    // B's session: the proof is checked against B's key.
    let renewal = renewed_recovery(&mut a.client);
    let res = put_recovery(&app, &b_jar, &a.client, &renewal).await;
    m.check(
        "A's new recovery key in B's session",
        &res,
        StatusCode::UNAUTHORIZED,
        "denied",
    );
    #[cfg(feature = "quick-unlock")]
    {
        // B adds a passkey under the id of A's passkey method: the id is
        // taken (on any account), and A's method is not touched.
        let change = passkey_change(&mut b.client, a_prf);
        let nonce = nonce_for(&app, &b_jar).await;
        let proof = ferret_core::auth_sign(&b.client.vault, change.op, &nonce, &change.body)
            .expect("a proof");
        let res = send_signed(
            &app,
            &b_jar,
            Method::POST,
            "/api/vault/unlock-methods",
            &nonce,
            &proof,
            change.body.clone(),
        )
        .await;
        m.check(
            "a passkey of B under A's method id",
            &res,
            StatusCode::CONFLICT,
            "conflict",
        );
    }

    // The account log and the policy.
    let res = send(
        &app,
        Method::GET,
        "/api/account/events?limit=100",
        &b_jar,
        None,
    )
    .await;
    m.check("account events", &res, StatusCode::OK, "");
    m.fact(
        "account events: none of A's",
        !res.text().contains("account_disabled"),
    );
    let res = send(&app, Method::GET, "/api/vault/policy", &b_jar, None).await;
    m.check("policy", &res, StatusCode::OK, "");
    let a_policy = send(&app, Method::GET, "/api/vault/policy", &a_jar, None).await;
    m.fact(
        "policy is the server's, the same for both",
        a_policy.body == res.body,
    );

    // A's nonce in B's session, with a proof B made over it.
    let change = password_change(&app, &b_jar, &mut b.client, NEW_PASSWORD).await;
    let body = body_bytes(&password_put_req(&change));
    let proof = change
        .sign(&b.client.vault, &a_nonce, &body)
        .expect("a proof");
    let res = send_signed(
        &app,
        &b_jar,
        Method::PUT,
        "/api/vault/unlock-methods/password",
        &a_nonce,
        &proof,
        body,
    )
    .await;
    m.check(
        "A's nonce in B's session",
        &res,
        StatusCode::UNAUTHORIZED,
        "denied",
    );

    // The sign-in code of A with B's e-mail, from the browser that holds B's
    // session: a code is good for its own account only. (A's code with A's
    // e-mail is A's own recovery, which ends A's sessions on purpose; the last
    // test of this file uses it.)
    let res = app
        .call_raw(
            Which::Vault,
            page(
                Method::POST,
                "/api/auth/redeem",
                &b_jar,
                Some(&json!({"email": email(2), "code": a_code})),
            ),
        )
        .await;
    m.check(
        "A's code with B's e-mail",
        &res,
        StatusCode::UNAUTHORIZED,
        "denied",
    );

    // ---- the device token of B

    let res = token_send(&app, &b.device, Method::GET, "/api/sync/changes", None).await;
    m.check("token: changes", &res, StatusCode::OK, "");
    let res = token_send(&app, &b.device, Method::GET, "/api/sync/items", None).await;
    m.check("token: items", &res, StatusCode::OK, "");
    let res = token_send(&app, &b.device, Method::GET, "/api/sync/restore-rows", None).await;
    m.check("token: restore rows", &res, StatusCode::OK, "");
    let res = token_send(&app, &b.device, Method::GET, "/api/sync/checkpoint", None).await;
    m.check("token: checkpoint", &res, StatusCode::OK, "");
    let res = token_send(
        &app,
        &b.device,
        Method::PUT,
        &item_path,
        Some(&live_body(&b.client.vault, a_item, 2, "token over a", 11)),
    )
    .await;
    m.check("token: put on A's revision", &res, StatusCode::CONFLICT, "");
    let res = token_send(
        &app,
        &b.device,
        Method::POST,
        "/api/sync/batch",
        Some(&json!({
            "ops": [as_op(item(3), &live_body(&b.client.vault, item(3), 0, "t", 12))],
            "import_window": a_window,
        })),
    )
    .await;
    m.check(
        "token: batch in A's window",
        &res,
        StatusCode::CONFLICT,
        "import_window_invalid",
    );
    let res = token_send(
        &app,
        &b.device,
        Method::GET,
        "/api/vault/unlock-methods",
        None,
    )
    .await;
    m.check("token: unlock methods", &res, StatusCode::OK, "");
    let res = token_send(
        &app,
        &b.device,
        Method::DELETE,
        &format!("/api/auth/devices/{a_device}"),
        None,
    )
    .await;
    m.fact(
        "token: the device routes are not for a token",
        res.status == StatusCode::UNAUTHORIZED || res.status == StatusCode::FORBIDDEN,
    );
    let res = token_send(&app, &b.device, Method::GET, "/api/account/events", None).await;
    m.fact(
        "token: the account log is not for a token",
        res.status == StatusCode::UNAUTHORIZED || res.status == StatusCode::FORBIDDEN,
    );
    // B's device renews and then signs out with its own refresh token: only
    // B's token rows change.
    let renewed = token_post(
        &app,
        &b.device,
        REFRESH,
        b.device.refresh.as_ref().expect("signed in"),
    )
    .await;
    m.check("token: refresh of B", &renewed, StatusCode::OK, "");
    let refresh = renewed.json()["refresh_token"]
        .as_str()
        .and_then(|t| TokenSecret::from_wire(t).ok());
    m.fact("token: refresh of B gives a token", refresh.is_some());
    if let Some(refresh) = refresh {
        let res = token_post(&app, &b.device, REVOKE, &refresh).await;
        m.check("token: sign-out of B", &res, StatusCode::NO_CONTENT, "");
    }

    // ---- the rest of B's session, on both listeners

    // The hand-over to the admin pages: B is no administrator, and a code that
    // was never made is nothing on the admin listener.
    let res = send(
        &app,
        Method::POST,
        "/api/auth/handoff",
        &b_jar,
        Some(&json!({
            "purpose": "login",
            "next": "/settings/general",
            "challenge": b64url::encode(&[7u8; 32]),
        })),
    )
    .await;
    m.check("hand-over of B", &res, StatusCode::FORBIDDEN, "forbidden");
    let res = app
        .call_raw(
            Which::Admin,
            support::Req::post("/api/auth/handoff/redeem")
                .page_fetch(Which::Admin)
                .json(&json!({ "code": b64url::encode(&[9u8; 32]) }))
                .build(),
        )
        .await;
    m.check(
        "a made-up hand-over code",
        &res,
        StatusCode::BAD_REQUEST,
        "handoff_invalid",
    );
    // B's own event stream opens and says hello; A's stream (checked below)
    // hears nothing of it.
    let b_stream = stream(&app, &b_jar).await;
    m.fact("B's stream opens", b_stream.status == StatusCode::OK);
    drop(b_stream);
    // B signs out last, from the browser id that A's session carries too.
    let res = send(&app, Method::POST, "/api/auth/logout", &b_jar, None).await;
    m.check("sign-out of B", &res, StatusCode::NO_CONTENT, "");
    let res = send(&app, Method::GET, "/api/auth/session", &b_jar, None).await;
    m.check(
        "B is signed out",
        &res,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );

    // ---- A is as it was

    m.fact(
        "A's rows are unchanged",
        rows_of(&app, &a.client).await == before,
    );
    // A's stream heard none of B's writes.
    m.fact(
        "A's stream is quiet",
        matches!(a_stream.next(SHORT).await, support::events::Next::Quiet),
    );
    // A's session, token, window and nonce still work.
    let res = send(
        &app,
        Method::GET,
        "/api/sync/changes?since=0&limit=500",
        &a_jar,
        None,
    )
    .await;
    m.fact(
        "A's session sees its item",
        res.status == StatusCode::OK && ids_in(&res, "changes", "id").contains(&hex_of(a_item)),
    );
    let res = token_send(&app, &a.device, Method::GET, "/api/sync/changes", None).await;
    m.fact(
        "A's token sees its item",
        res.status == StatusCode::OK && ids_in(&res, "changes", "id").contains(&hex_of(a_item)),
    );
    let res = send(
        &app,
        Method::POST,
        "/api/sync/batch",
        &a_jar,
        Some(&json!({
            "ops": [as_op(item(5), &live_body(&a.client.vault, item(5), 0, "a again", 20))],
            "import_window": a_window,
        })),
    )
    .await;
    m.fact(
        "A's window still takes A's batch",
        res.status == StatusCode::OK && res.json()["results"][0]["status"] == json!(200),
    );
    let change = password_change(&app, &a_jar, &mut a.client, NEW_PASSWORD).await;
    let body = body_bytes(&password_put_req(&change));
    let proof = change
        .sign(&a.client.vault, &a_nonce, &body)
        .expect("a proof");
    let res = send_signed(
        &app,
        &a_jar,
        Method::PUT,
        "/api/vault/unlock-methods/password",
        &a_nonce,
        &proof,
        body,
    )
    .await;
    m.fact(
        &format!("A's nonce still signs for A ({})", res.status),
        res.status == StatusCode::OK,
    );
    drop(a_stream);
    m.done(55);
}

// ------------------------------------------------------- a challenge of one

#[tokio::test]
async fn a_challenge_of_one_account_does_not_sign_for_another() {
    let app = device_app().await;
    let mut a = account(&app, 1).await;
    let mut b = account(&app, 2).await;
    let (a_jar, b_jar) = (a.browser.jar.clone(), b.browser.jar.clone());
    let a_before = rows_of(&app, &a.client).await;
    let b_before = rows_of(&app, &b.client).await;

    let put = |jar: Jar, nonce: [u8; 32], proof: [u8; 64], body: Vec<u8>| {
        let app = &app;
        async move {
            send_signed(
                app,
                &jar,
                Method::PUT,
                "/api/vault/unlock-methods/password",
                &nonce,
                &proof,
                body,
            )
            .await
        }
    };
    let denied = |res: &Res, who: &str| {
        assert_eq!(
            (res.status, code_of(res).as_str()),
            (StatusCode::UNAUTHORIZED, "denied"),
            "{who}: {}",
            res.text()
        );
    };

    // Each account has a nonce, and a change signed by its own key.
    let a_nonce = nonce_for(&app, &a_jar).await;
    let b_nonce = nonce_for(&app, &b_jar).await;
    let a_change = password_change(&app, &a_jar, &mut a.client, NEW_PASSWORD).await;
    let b_change = password_change(&app, &b_jar, &mut b.client, NEW_PASSWORD).await;
    let a_body = body_bytes(&password_put_req(&a_change));
    let b_body = body_bytes(&password_put_req(&b_change));
    let sign_a = |nonce: &[u8; 32]| {
        a_change
            .sign(&a.client.vault, nonce, &a_body)
            .expect("a proof")
    };
    let sign_b = |nonce: &[u8; 32]| {
        b_change
            .sign(&b.client.vault, nonce, &b_body)
            .expect("a proof")
    };

    // A's nonce in B's session, signed by B: the nonce is bound to A's
    // session, so B's session does not find it (and it is not spent).
    let res = put(b_jar.clone(), a_nonce, sign_b(&a_nonce), b_body.clone()).await;
    denied(&res, "A's nonce, B's proof, B's session");
    // B's nonce in A's session, signed by A: the same the other way round.
    let res = put(a_jar.clone(), b_nonce, sign_a(&b_nonce), a_body.clone()).await;
    denied(&res, "B's nonce, A's proof, A's session");
    // B's key over A's nonce in A's session: the proof is checked against
    // A's key, never B's (the nonce is spent by the try).
    let res = put(a_jar.clone(), a_nonce, sign_b(&a_nonce), b_body.clone()).await;
    denied(&res, "A's nonce, B's proof, A's session");
    assert_eq!(rows_of(&app, &a.client).await, a_before, "A is untouched");
    assert_eq!(rows_of(&app, &b.client).await, b_before, "B is untouched");

    // B's nonce was never found by another session, so it still signs B's
    // own change in B's session, once.
    let res = put(b_jar.clone(), b_nonce, sign_b(&b_nonce), b_body.clone()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = put(b_jar.clone(), b_nonce, sign_b(&b_nonce), b_body.clone()).await;
    denied(&res, "B's nonce a second time");
    assert_eq!(rows_of(&app, &a.client).await, a_before, "A is untouched");
}

// ------------------------------------------------ a write wakes its own only

#[tokio::test]
async fn a_write_in_one_vault_wakes_only_its_own_streams() {
    let app = device_app().await;
    let a = account(&app, 1).await;
    let b = account(&app, 2).await;
    let (a_jar, b_jar) = (a.browser.jar.clone(), b.browser.jar.clone());
    // Both browsers carry the same device id; each has a stream, and each
    // token device has one too.
    let mut a_browser = stream(&app, &a_jar).await;
    let mut b_browser = stream(&app, &b_jar).await;
    let mut a_token = {
        let req = a.device.token_req(&app, Method::GET, "/api/sync/events");
        let mut s = app.open_stream(req.build()).await;
        assert_eq!(s.status, StatusCode::OK);
        s.event("hello", SECOND).await;
        s
    };
    let mut b_token = {
        let req = b.device.token_req(&app, Method::GET, "/api/sync/events");
        let mut s = app.open_stream(req.build()).await;
        assert_eq!(s.status, StatusCode::OK);
        s.event("hello", SECOND).await;
        s
    };

    // A writes with its session: A's two streams hear it, B's hear nothing.
    let res = send(
        &app,
        Method::PUT,
        &format!("/api/sync/items/{}", hex_of(item(1))),
        &a_jar,
        Some(&live_body(&a.client.vault, item(1), 0, "a", 1)),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let seq = res.json()["seq"].clone();
    for s in [&mut a_browser, &mut a_token] {
        let data = s.event("sync", SECOND * 2).await;
        assert_eq!(data["seq"], seq);
    }
    b_browser.quiet(Duration::from_millis(900)).await;
    b_token.quiet(SHORT).await;

    // B writes a batch with its token: the other way round.
    let res = token_send(
        &app,
        &b.device,
        Method::POST,
        "/api/sync/batch",
        Some(&json!({"ops": [as_op(item(1), &live_body(&b.client.vault, item(1), 0, "b", 2))]})),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    for s in [&mut b_browser, &mut b_token] {
        s.event("sync", SECOND * 2).await;
    }
    a_browser.quiet(Duration::from_millis(900)).await;
    a_token.quiet(SHORT).await;

    // A change of B's unlock methods (a password change) is a sync for B's
    // streams and nothing for A's.
    let mut client = b.client;
    let change = password_change(&app, &b_jar, &mut client, NEW_PASSWORD).await;
    let res = support::accounts::put_password(&app, &b_jar, &client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let (frames, _) = a_browser.frames(Duration::from_millis(900)).await;
    assert!(
        frames
            .iter()
            .all(|f| !f.is_event("sync") && !f.is_event("revoked")),
        "A's stream heard B's change: {frames:?}"
    );
    let (frames, _) = a_token.frames(SHORT).await;
    assert!(
        frames
            .iter()
            .all(|f| !f.is_event("sync") && !f.is_event("revoked")),
        "A's token stream heard B's change: {frames:?}"
    );
}

// ------------------------------------- revoke-all and a redeemed code of B

#[tokio::test]
async fn revoke_all_and_a_redeemed_code_of_b_leave_a_alone() {
    let app = device_app().await;
    let admin = admin(&app).await;
    let a = account(&app, 1).await;
    let b = account(&app, 2).await;
    let (a_jar, b_jar) = (a.browser.jar.clone(), b.browser.jar.clone());
    let a_code = sign_in_code(&app, a.client.ids.user_id, admin).await;
    let mut a_browser = stream(&app, &a_jar).await;
    let mut a_token = {
        let req = a.device.token_req(&app, Method::GET, "/api/sync/events");
        let mut s = app.open_stream(req.build()).await;
        assert_eq!(s.status, StatusCode::OK);
        s.event("hello", SECOND).await;
        s
    };
    let before = rows_of(&app, &a.client).await;

    // B ends every other device and browser of its own.
    let res = send(
        &app,
        Method::POST,
        "/api/auth/devices/revoke-all",
        &b_jar,
        None,
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = token_send(&app, &b.device, Method::GET, "/api/sync/changes", None).await;
    assert_eq!(
        res.status,
        StatusCode::UNAUTHORIZED,
        "B's own token is ended"
    );

    // B forgets its password: the administrator makes B a code, and B redeems
    // it in its browser.
    let b_code = sign_in_code(&app, b.client.ids.user_id, admin).await;
    let res = app
        .call_raw(
            Which::Vault,
            page(
                Method::POST,
                "/api/auth/redeem",
                &b_jar,
                Some(&json!({"email": email(2), "code": b_code})),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // A's browser and token sessions, its streams, its pending code and its
    // log are as they were: the only change on the server for A is none.
    assert_eq!(rows_of(&app, &a.client).await, before);
    let (frames, ended) = a_browser.frames(Duration::from_millis(900)).await;
    assert!(
        !ended && frames.iter().all(|f| !f.is_event("revoked")),
        "{frames:?}"
    );
    let (frames, ended) = a_token.frames(SHORT).await;
    assert!(
        !ended && frames.iter().all(|f| !f.is_event("revoked")),
        "{frames:?}"
    );
    let res = send(&app, Method::GET, "/api/auth/session", &a_jar, None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let res = token_send(&app, &a.device, Method::GET, "/api/sync/changes", None).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // A's own code still works, once, for A.
    let res = app
        .call_raw(
            Which::Vault,
            page(
                Method::POST,
                "/api/auth/redeem",
                &Jar::default(),
                Some(&json!({"email": email(1), "code": a_code})),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}
