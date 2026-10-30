//! Sessions for tests: a user with an account, a session row and its two
//! cookies for a listener, and a small router that uses the session extractors
//! with nothing but the narrow `SessionAuth` as state.
//!
//! The rows are written with plain SQL, so these helpers depend on the schema
//! and on the session code only.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::FromRef;
use axum::http::{Request, header};
use axum::response::IntoResponse as _;
use axum::routing::get;
use axum::{Json, response::Response};
use axum_extra::extract::cookie::{Cookie, SignedCookieJar};
use ferret_core::OsRng;
use ferret_server::auth::session::{Origin, insert_session, new_session, session_cookies};
use ferret_server::http::extract::{AdminSession, SessionAuth, VaultSession};
use ferret_server::ids::{AccountId, DeviceId, SidHash, VaultId};
use ferret_server_auth::{Clock as _, SessionScope};
use serde_json::json;
use tower::ServiceExt as _;

use super::{Jar, Res, TestApp};

/// A kit user with an account and a vault, as registration leaves them.
#[derive(Clone, Copy, Debug)]
pub struct Seeded {
    pub user_id: i64,
    pub account: AccountId,
    pub vault: VaultId,
}

/// A session that was inserted, with the cookies of a browser that signed in.
pub struct Issued {
    pub sid: SidHash,
    /// The `__Host-ferret_sid` value before signing: the session id itself.
    pub secret: String,
    pub claims: vole_kit::auth::session::SessionClaims,
    pub jar: Jar,
    /// The `Set-Cookie` headers the sign-in answered with.
    pub set_cookies: Vec<String>,
}

fn id16(kind: u8, n: u8) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0] = kind;
    bytes[1] = n;
    bytes
}

/// The device of test device `n`.
pub fn device(n: u8) -> DeviceId {
    DeviceId(id16(0xd0, n))
}

/// Adds a kit user, a vault account and its vault; `n` makes the ids differ.
pub async fn seed(app: &TestApp, n: u8) -> Seeded {
    let account = AccountId::from_bytes(id16(0xa0, n));
    let vault = VaultId::from_bytes(id16(0xb0, n));
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    let user_id = app
        .state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?1, 'x', 'editor')",
                [format!("user{n}@example.com")],
            )?;
            let user_id = conn.last_insert_rowid();
            conn.execute(
                "INSERT INTO ferret_accounts
                   (account_id, user_id, vault_id, opaque_record, ksf_profile, sk_hint,
                    pk_a, pk_r, vk_epoch, created_at)
                 VALUES (?1, ?2, ?3, zeroblob(192), 1, 0, zeroblob(32), zeroblob(32), 3, ?4)",
                rusqlite::params![
                    account.as_bytes().as_slice(),
                    user_id,
                    vault.as_bytes().as_slice(),
                    now
                ],
            )?;
            conn.execute(
                "INSERT INTO ferret_vaults (vault_id, account_id) VALUES (?1, ?2)",
                rusqlite::params![vault.as_bytes().as_slice(), account.as_bytes().as_slice()],
            )?;
            Ok(user_id)
        })
        .await
        .expect("seed a user");
    Seeded {
        user_id,
        account,
        vault,
    }
}

/// The kit's `session_version` of a user.
pub async fn session_version(app: &TestApp, user_id: i64) -> i64 {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT session_version FROM users WHERE id = ?1",
                [user_id],
                |r| r.get(0),
            )?)
        })
        .await
        .expect("a session version")
}

/// Signs `user_id` in at the clock's time: a new row and the cookies.
pub async fn issue(
    app: &TestApp,
    user_id: i64,
    origin: Origin,
    scope: SessionScope,
    device_n: u8,
) -> Issued {
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    let version = session_version(app, user_id).await;
    let (secret, session, claims) = new_session(
        &mut OsRng,
        now,
        user_id,
        version,
        origin,
        device(device_n),
        "Test browser",
        scope,
    );
    let sid = session.sid;
    app.state
        .vault_db
        .with_conn(move |conn| Ok(insert_session(conn, &session)?))
        .await
        .expect("insert the session");
    // The request of a browser that was half-way through a sign-in: the pending
    // second factor and a re-auth grant are in its jar, and the sign-in removes them.
    let key = app.state.core.session_key.clone();
    let earlier = SignedCookieJar::new(key.clone())
        .add(Cookie::new("__Host-ferret_2fa", "old"))
        .add(Cookie::new("__Host-ferret_reauth", "old"))
        .into_response();
    let mut earlier_jar = Jar::default();
    earlier_jar.absorb(earlier.headers());
    let mut request = axum::http::HeaderMap::new();
    request.insert(
        header::COOKIE,
        header::HeaderValue::from_str(&earlier_jar.header().expect("cookies")).expect("a header"),
    );
    let jar = session_cookies(
        SignedCookieJar::from_headers(&request, key),
        &secret,
        &claims,
        true,
    );
    let response = jar.into_response();
    let mut browser = Jar::default();
    browser.absorb(response.headers());
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect();
    Issued {
        sid,
        secret: secret.to_cookie(),
        claims,
        jar: browser,
        set_cookies,
    }
}

/// A router with one route per extractor, and only the narrow `SessionAuth` as
/// state: `/vault` answers with the vault session, `/admin` with the admin one.
pub fn router(app: &TestApp) -> Router {
    async fn vault(session: VaultSession) -> Response {
        Json(json!({
            "user_id": session.user_id,
            "issued_at": session.issued_at,
            "device": hex(&session.device.0),
            "account": hex(session.account.as_bytes()),
            "vault": hex(session.vault.as_bytes()),
            "vk_epoch": session.vk_epoch,
        }))
        .into_response()
    }
    async fn admin(session: AdminSession) -> Response {
        Json(json!({ "user_id": session.user_id })).into_response()
    }
    Router::new()
        .route("/vault", get(vault))
        .route("/admin", get(admin))
        .with_state(SessionAuth::from_ref(&app.state))
}

/// Sends a `GET` with the cookies of `jar`.
pub async fn get_with(router: &Router, jar: &Jar, uri: &str) -> Res {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::empty()).expect("a request"))
        .await
        .expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.expect("a body");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
