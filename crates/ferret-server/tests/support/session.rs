//! Sessions for tests: a user with an account, a session row and its two
//! cookies for a listener, and a small router that uses the session extractors
//! with nothing but the narrow `SessionAuth` as state.
//!
//! The rows are written with plain SQL, so these helpers depend on the schema
//! and on the session code only.
//!
//! For signed requests: [`seed_signer`] adds an account whose `pk_a` is a real
//! key, [`sign`] makes its proofs, and [`reset_session`] gives it a session of
//! the scope `account_reset`.

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse as _;
use axum::routing::{get, post};
use axum::{Json, response::Response};
use axum_extra::extract::cookie::{Cookie, SignedCookieJar};
use ferret_core::{
    AuthOp, AuthPublicKey, MutationOp, OsRng, RecoveryPublicKey, TestRng, UnlockedVault,
    VaultContext, VaultKey, auth_sign,
};
use ferret_server::auth::session::{Origin, insert_session, new_session, session_cookies};
use ferret_server::auth::throttle::caller_from;
use ferret_server::error::ApiError;
use ferret_server::http::extract::{
    AdminSession, FreshReauth, ScopedSession, SessionAuth, SignedBody, VaultSession, caps,
};
use ferret_server::ids::{AccountId, DeviceId, SidHash, VaultId};
use ferret_server::state::{Proofs, VaultDb};
use ferret_server::wire::b64url;
use ferret_server_auth::{Clock as _, SessionScope, SignedAccount};
use serde_json::json;
use tower::ServiceExt as _;

use super::{Jar, Req, Res, TestApp, Which};

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

// ------------------------------------------------------- signed requests

/// The number of the account whose `pk_a` is a real key: [`sign`] signs for
/// it.
pub const SIGNER: u8 = 0x5a;

/// The vault key epoch [`seed`] stores for every account, which [`sign`]
/// signs for.
pub const SIGNER_EPOCH: u64 = 3;

/// The unlocked vault of the signer: a fixed vault key, so every call gives
/// the same `sk_a`.
fn signer_vault() -> UnlockedVault {
    let ctx = VaultContext {
        account_id: AccountId::from_bytes(id16(0xa0, SIGNER)),
        vault_id: VaultId::from_bytes(id16(0xb0, SIGNER)),
        vk_epoch: SIGNER_EPOCH,
    };
    UnlockedVault::from_vault_key(ctx, VaultKey::generate(&mut TestRng::new(b"signer vault")))
        .expect("the signer's vault")
}

/// Adds the signer ([`SIGNER`]) as [`seed`] does, with the real `pk_a` of its
/// vault key, so [`sign`] makes proofs the server accepts.
pub async fn seed_signer(app: &TestApp) -> Seeded {
    let seeded = seed(app, SIGNER).await;
    let pk_a = signer_vault().auth_public_key();
    let account = seeded.account;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_accounts SET pk_a = ?1 WHERE account_id = ?2",
                rusqlite::params![pk_a.as_slice(), account.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("store the signer's pk_a");
    seeded
}

/// The proof of `op` over `nonce` and `body`, signed with the signer's `sk_a`
/// for its account and epoch.
pub fn sign(op: AuthOp, nonce: &[u8; 32], body: &[u8]) -> [u8; 64] {
    auth_sign(&signer_vault(), op, nonce, body).expect("a proof")
}

/// The signer ([`seed_signer`]) with a session of the scope `account_reset` on
/// the vault listener, as a redeemed sign-in code leaves it. Its cookies become
/// the vault jar of `app`. Call it once per app.
pub async fn reset_session(app: &TestApp) -> (Seeded, Issued) {
    let seeded = seed_signer(app).await;
    let issued = issue(
        app,
        seeded.user_id,
        Origin::Vault,
        SessionScope::AccountReset,
        1,
    )
    .await;
    app.set_jar(Which::Vault, issued.jar.clone());
    (seeded, issued)
}

/// The path of the route of [`signed_probe`].
pub const PROBE: &str = "/api/test/signed";

/// The body the probe parses after the permit.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeBody {
    n: u32,
}

/// What the server holds for the signer of a request in the session of
/// `account`: its keys and epoch as stored, and the row version 0.
pub async fn signed_account(
    db: &VaultDb,
    account_id: AccountId,
) -> Result<SignedAccount, ApiError> {
    let (pk_a, pk_r, vk_epoch) = db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT pk_a, pk_r, vk_epoch FROM ferret_accounts WHERE account_id = ?1",
                [account_id.as_bytes().as_slice()],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )?)
        })
        .await?;
    Ok(SignedAccount {
        account_id,
        pk_a: AuthPublicKey::new(pk_a.try_into().expect("32 bytes")),
        pk_r: RecoveryPublicKey::new(pk_r.try_into().expect("32 bytes")),
        vk_epoch: u64::try_from(vk_epoch).expect("an epoch"),
        row_version: 0,
    })
}

/// A vault router with one signed route, built the way the routes of signed
/// requests are: `ScopedSession<UnlockMethodsWrite>`, then `FreshReauth`, then
/// `SignedBody`, then `Proofs::signed` for `unlock-method.recovery.put` with
/// the account as stored, and only then `SignedBody::parse`. The answer is
/// `{"n": n}` of a body `{"n": n}`. The vault listener's layers are around it.
/// The session must have re-authenticated ([`make_fresh`]).
pub fn signed_probe(app: &TestApp) -> Router {
    async fn probe(
        State(proofs): State<Proofs>,
        State(db): State<VaultDb>,
        headers: HeaderMap,
        scoped: ScopedSession<caps::UnlockMethodsWrite>,
        fresh: FreshReauth,
        signed: SignedBody,
    ) -> Result<Response, ApiError> {
        let account = signed_account(&db, scoped.session().account()).await?;
        let permit = proofs.signed(
            &scoped,
            &fresh,
            &signed,
            caller_from(&headers, None),
            MutationOp::UnlockMethodRecoveryPut,
            &account,
        )?;
        let body: ProbeBody = signed.parse(&permit)?;
        Ok(Json(json!({ "n": body.n })).into_response())
    }
    let router = Router::new()
        .route(PROBE, post(probe))
        .with_state(app.state.clone());
    ferret_server::http::vault_layers(router, &app.state)
}

/// A `POST` to the probe with the cookies of `jar`, the headers of a page of
/// the vault, and the two proof headers as given (`None` leaves one out).
pub async fn call_probe(
    router: &Router,
    jar: &Jar,
    nonce: Option<&str>,
    proof: Option<&str>,
    body: impl Into<Body>,
) -> Res {
    let mut builder = Request::builder()
        .method("POST")
        .uri(PROBE)
        .header(header::HOST, Which::Vault.host())
        .header("origin", Which::Vault.url())
        .header("ferret-protocol", "1")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(nonce) = nonce {
        builder = builder.header("ferret-nonce", nonce);
    }
    if let Some(proof) = proof {
        builder = builder.header("ferret-proof", proof);
    }
    let mut request = builder.body(body.into()).expect("a request");
    let peer: std::net::SocketAddr = super::PEER.parse().expect("a peer");
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let response = router.clone().oneshot(request).await.expect("a response");
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, 1024 * 1024).await.expect("a body");
    Res {
        status: parts.status,
        headers: parts.headers,
        body: body.to_vec(),
    }
}

/// `POST /api/auth/challenge` with the cookies of `jar`.
pub async fn challenge_with(app: &TestApp, jar: &Jar) -> Res {
    let mut req = Req::post("/api/auth/challenge").page_fetch(Which::Vault);
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

/// A nonce for the session of `jar`; panics unless the server gives one.
pub async fn nonce_for(app: &TestApp, jar: &Jar) -> [u8; 32] {
    let res = challenge_with(app, jar).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let text = res.json()["nonce"].as_str().expect("a nonce").to_string();
    b64url::decode(&text)
        .expect("base64url")
        .try_into()
        .expect("32 bytes")
}

/// Sets `reauth_at` of the session `sid`, as a re-authentication would.
pub async fn set_reauth_at(app: &TestApp, sid: SidHash, reauth_at: Option<i64>) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_sessions SET reauth_at = ?1 WHERE sid_hash = ?2",
                rusqlite::params![reauth_at, sid.0.as_slice()],
            )?;
            Ok(())
        })
        .await
        .expect("set reauth_at");
}

/// Marks the session `sid` as re-authenticated at the clock's time.
pub async fn make_fresh(app: &TestApp, sid: SidHash) {
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    set_reauth_at(app, sid, Some(now)).await;
}

/// The signer ([`seed_signer`]) with a `full` session on the vault listener
/// that proved the master password again just now: the row is marked with
/// `auth::session::mark_reauth` at the clock's time, as a sign-in with
/// `purpose: "reauth"` leaves it, so the session is fresh for 300 seconds. Its
/// cookies become the vault jar of `app`. Call it once per app.
pub async fn reauth(app: &TestApp) -> (Seeded, Issued) {
    let seeded = seed_signer(app).await;
    let issued = issue(app, seeded.user_id, Origin::Vault, SessionScope::Full, 1).await;
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    let sid = issued.sid;
    let marked = app
        .state
        .vault_db
        .with_conn(move |conn| Ok(ferret_server::auth::session::mark_reauth(conn, &sid, now)?))
        .await
        .expect("mark the re-authentication");
    assert!(marked, "a live full session is marked");
    app.set_jar(Which::Vault, issued.jar.clone());
    (seeded, issued)
}

/// The restore epoch of every vault goes up (`reconcile::bump_restore_epoch`,
/// whose transaction also ends every session and raises every user's session
/// version), and then the sessions that were live and the session versions are
/// put back: for the tests of the epoch and of the sync, whose sessions are
/// meant to be the same ones after the bump. What a bump ends is tested where
/// the bump is (`restore_epoch.rs`, `restore.rs`).
pub fn bump_epoch_keeping_sessions(
    conn: &mut rusqlite::Connection,
    at_least: Option<u64>,
    now: i64,
) -> Result<u64, ferret_server::error::StoreError> {
    let live: Vec<Vec<u8>> = conn
        .prepare("SELECT sid_hash FROM ferret_sessions WHERE revoked_at IS NULL")?
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    let epoch = ferret_server::vault::reconcile::bump_restore_epoch(conn, at_least, now)?;
    let tx = conn.transaction()?;
    tx.execute("UPDATE users SET session_version = session_version - 1", [])?;
    for sid in live {
        tx.execute(
            "UPDATE ferret_sessions SET revoked_at = NULL WHERE sid_hash = ?1",
            [sid],
        )?;
    }
    tx.commit()?;
    Ok(epoch)
}
