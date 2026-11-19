//! `Proofs`, the handle through which the vault routes check the proof of a
//! signed request: each of its three methods gives the library's permit for a
//! good request, and refuses the rest. Spec: Fase 1 § 4.6 and § 6.3.
//!
//! The routes here are built the way the routes of the vault are: the
//! extractors of `http::extract`, then the handle from the state through
//! `FromRef`. The replacements run inside `VaultDb::with_conn`, as a route
//! runs them inside the transaction that writes the result.

mod support;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use ferret_core::{
    AccountId, AuthOp, MutationOp, RecoveryKey, RecoveryPublicKey, TestRng, recovery_public_key,
    recovery_sign,
};
use ferret_server::auth::session::Origin;
use ferret_server::auth::throttle::caller_from;
use ferret_server::error::ApiError;
use ferret_server::http::extract::{FreshReauth, ScopedSession, SignedBody, caps};
use ferret_server::state::{Proofs, VaultDb};
use ferret_server::wire::b64url;
use ferret_server_auth::testing::made_up_record;
use ferret_server_auth::{
    AccountAuthState, AuthError, Clock as _, CredentialId, Malformed, ManualClock, ReplaceFields,
    SessionScope, StoredRecord,
};
use serde_json::{Value, json};
use support::session::{
    Issued, SIGNER_EPOCH, Seeded, issue, make_fresh, nonce_for, seed_signer, set_reauth_at, sign,
    signed_account,
};
use support::{Jar, Res, TestApp, Which};
use tower::ServiceExt as _;

const SIGNED: &str = "/api/test/proofs/signed";
const PASSWORD: &str = "/api/test/proofs/password";
const RECOVER: &str = "/api/test/proofs/recover";

/// What the test routes do differently from a real route, to reach each
/// refusal of the handle.
#[derive(Clone)]
struct Opts {
    /// The operation `signed` is asked to check.
    op: MutationOp,
    /// Another account than the session's, in place of the stored one.
    account: Option<AccountId>,
    /// A time the clock is set to after the extractors ran and before the
    /// handle is asked: the re-authentication goes stale in between. (A
    /// `FreshReauth` cannot be made or changed outside its extractor.)
    clock_at: Option<u64>,
    /// The app's clock, for `clock_at`.
    clock: Arc<ManualClock>,
    /// The record stored for the account now.
    current: Arc<StoredRecord>,
}

async fn signed_route(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    Extension(opts): Extension<Opts>,
    headers: HeaderMap,
    session: ScopedSession<caps::UnlockMethodsWrite>,
    fresh: FreshReauth,
    body: SignedBody,
) -> Result<Response, ApiError> {
    let mut account = signed_account(&db, session.session().account()).await?;
    if let Some(other) = opts.account {
        account.account_id = other;
    }
    if let Some(at) = opts.clock_at {
        opts.clock.set(at);
    }
    let permit = proofs.signed(
        &session,
        &fresh,
        &body,
        caller_from(&headers, None),
        opts.op,
        &account,
    )?;
    let parsed: Value = body.parse(&permit)?;
    Ok(Json(json!({
        "op": format!("{:?}", permit.op),
        "effect": format!("{:?}", permit.session_effect),
        "n": parsed["n"],
    }))
    .into_response())
}

async fn password_route(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    Extension(opts): Extension<Opts>,
    headers: HeaderMap,
    session: ScopedSession<caps::PasswordPut>,
    fresh: FreshReauth,
    body: SignedBody,
) -> Result<Response, ApiError> {
    let mut account = signed_account(&db, session.session().account()).await?;
    if let Some(other) = opts.account {
        account.account_id = other;
    }
    if let Some(at) = opts.clock_at {
        opts.clock.set(at);
    }
    let caller = caller_from(&headers, None);
    let permit = db
        .with_conn(move |_conn| {
            let state = AccountAuthState {
                account,
                current: &opts.current,
            };
            Ok(proofs.password_put(&session, &fresh, &body, caller, &state, parse_fields))
        })
        .await??;
    Ok(Json(answer(&permit)).into_response())
}

async fn recover_route(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    Extension(opts): Extension<Opts>,
    headers: HeaderMap,
    session: ScopedSession<caps::Recover>,
    body: SignedBody,
) -> Result<Response, ApiError> {
    let mut account = signed_account(&db, session.session().account()).await?;
    if let Some(other) = opts.account {
        account.account_id = other;
    }
    let caller = caller_from(&headers, None);
    let permit = db
        .with_conn(move |_conn| {
            let state = AccountAuthState {
                account,
                current: &opts.current,
            };
            Ok(proofs.recover(&session, &body, caller, &state, parse_fields))
        })
        .await??;
    Ok(Json(answer(&permit)).into_response())
}

fn answer(permit: &ferret_server_auth::ReplacePermit) -> Value {
    json!({
        "kind": format!("{:?}", permit.kind),
        "profile": permit.new.ksf_profile,
        "stored": permit.stored_ksf_profile,
        "new_pk_r": permit.new_pk_r.map(|k| hex(k.as_bytes())),
        "effect": format!("{:?}", permit.session_effect),
    })
}

/// The body of a replacement in these tests: `{"record": hex, "ksf_profile":
/// n, "pk_r": hex | null}`.
fn parse_fields(bytes: &[u8]) -> Result<ReplaceFields, AuthError> {
    let bad = || AuthError::Malformed(Malformed::RegistrationRecord);
    let value: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
    let record = unhex(value["record"].as_str().ok_or_else(bad)?).ok_or_else(bad)?;
    let ksf_profile =
        u32::try_from(value["ksf_profile"].as_u64().ok_or_else(bad)?).map_err(|_| bad())?;
    let pk_r_new = match &value["pk_r"] {
        Value::Null => None,
        Value::String(text) => {
            let bytes: [u8; 32] = unhex(text)
                .and_then(|b| b.try_into().ok())
                .ok_or_else(bad)?;
            Some(RecoveryPublicKey::new(bytes))
        }
        _ => return Err(bad()),
    };
    Ok(ReplaceFields {
        record,
        ksf_profile,
        pk_r_new,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

// ------------------------------------------------------------------ helpers

/// The signer, its recovery key (whose `pk_r` is stored) and the app.
struct Setup {
    app: TestApp,
    signer: Seeded,
    rk: RecoveryKey,
}

impl Setup {
    async fn new() -> Self {
        let app = TestApp::new().await;
        let signer = seed_signer(&app).await;
        let rk = RecoveryKey::generate(&mut TestRng::new(b"proofs recovery key"));
        let pk_r = recovery_public_key(&rk, &signer.account).expect("pk_r");
        let account = signer.account;
        app.state
            .vault_db
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE ferret_accounts SET pk_r = ?1 WHERE account_id = ?2",
                    rusqlite::params![pk_r.as_slice(), account.as_bytes().as_slice()],
                )?;
                Ok(())
            })
            .await
            .expect("store pk_r");
        Setup { app, signer, rk }
    }

    fn now(&self) -> i64 {
        i64::try_from(self.app.clock.now_unix()).expect("a time")
    }

    /// A full vault session of the signer on device `n`, re-authenticated
    /// now when `fresh`.
    async fn full(&self, n: u8, fresh: bool) -> Issued {
        let issued = issue(
            &self.app,
            self.signer.user_id,
            Origin::Vault,
            SessionScope::Full,
            n,
        )
        .await;
        if fresh {
            make_fresh(&self.app, issued.sid).await;
        }
        issued
    }

    /// A session of the scope `account_reset`, as a redeemed code leaves it.
    async fn reset(&self, n: u8) -> Issued {
        issue(
            &self.app,
            self.signer.user_id,
            Origin::Vault,
            SessionScope::AccountReset,
            n,
        )
        .await
    }

    /// A record as the server stores one, made from the server's own keys
    /// for the credential of `n`, with the profile `profile`.
    fn record(&self, n: u8, profile: u8) -> StoredRecord {
        let id = CredentialId::from(&AccountId::from_bytes([n; 16]));
        made_up_record(
            &self.app.state.secrets.keys,
            &self.app.state.secrets.prelogin,
            &id,
            profile,
        )
    }

    /// The three test routes over the server's state, with the vault
    /// listener's layers.
    fn router(&self, opts: Opts) -> Router {
        let router = Router::new()
            .route(SIGNED, post(signed_route))
            .route(PASSWORD, post(password_route))
            .route(RECOVER, post(recover_route))
            .layer(Extension(opts))
            .with_state(self.app.state.clone());
        ferret_server::http::vault_layers(router, &self.app.state)
    }

    fn opts(&self) -> Opts {
        Opts {
            op: MutationOp::UnlockMethodRecoveryPut,
            account: None,
            clock_at: None,
            clock: self.app.clock.clone(),
            current: Arc::new(self.record(1, 1)),
        }
    }

    fn stored_nonces(&self) -> usize {
        self.app.challenges().store().len()
    }

    /// A replacement body with a new record of profile `profile` and the
    /// `pk_r` given.
    fn replacement(&self, profile: u32, pk_r: Option<[u8; 32]>) -> Vec<u8> {
        let record = self.record(2, 1);
        serde_json::to_vec(&json!({
            "record": hex(record.record.as_bytes()),
            "ksf_profile": profile,
            "pk_r": pk_r.map(|k| hex(&k)),
        }))
        .expect("a body")
    }

    /// The recovery proof of `body` over `nonce`.
    fn recovery_proof(&self, nonce: &[u8; 32], body: &[u8]) -> [u8; 64] {
        recovery_sign(&self.rk, &self.signer.account, SIGNER_EPOCH, nonce, body).expect("a proof")
    }

    /// The `pk_r` that is stored for the signer now.
    fn stored_pk_r(&self) -> [u8; 32] {
        recovery_public_key(&self.rk, &self.signer.account).expect("pk_r")
    }
}

/// A new `pk_r`, of another recovery key.
fn new_pk_r(account: &AccountId) -> [u8; 32] {
    let rk = RecoveryKey::generate(&mut TestRng::new(b"proofs new recovery key"));
    recovery_public_key(&rk, account).expect("pk_r")
}

/// A `POST` to `path` with the cookies of `jar`, the headers of a page of the
/// vault, and the two proof headers.
async fn call(
    router: &Router,
    path: &str,
    jar: &Jar,
    nonce: &[u8; 32],
    proof: &[u8; 64],
    body: &[u8],
) -> Res {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::HOST, Which::Vault.host())
        .header("origin", Which::Vault.url())
        .header("ferret-protocol", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .header("ferret-nonce", b64url::encode(nonce))
        .header("ferret-proof", b64url::encode(proof));
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    let mut request = builder.body(Body::from(body.to_vec())).expect("a request");
    let peer: std::net::SocketAddr = support::PEER.parse().expect("a peer");
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

fn assert_code(res: &Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.text());
    assert_eq!(res.json()["error"], code, "{}", res.text());
}

const BODY: &[u8] = br#"{"n":7}"#;

// ------------------------------------------------------------------- signed

#[tokio::test]
async fn signed_gives_the_permit_of_its_op_to_a_fresh_session() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    for (op, auth) in [
        (
            MutationOp::UnlockMethodRecoveryPut,
            AuthOp::UnlockMethodRecoveryPut,
        ),
        (MutationOp::UnlockMethodAdd, AuthOp::UnlockMethodAdd),
        (MutationOp::UnlockMethodRemove, AuthOp::UnlockMethodRemove),
    ] {
        let router = setup.router(Opts { op, ..setup.opts() });
        let nonce = nonce_for(&setup.app, &session.jar).await;
        let proof = sign(auth, &nonce, BODY);
        let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
        assert_eq!(res.status, StatusCode::OK, "{op:?}: {}", res.text());
        assert_eq!(res.json()["op"], format!("{op:?}"));
        assert_eq!(res.json()["effect"], "Keep");
        assert_eq!(res.json()["n"], 7);
        assert_eq!(setup.stored_nonces(), 0, "the nonce is used up");
    }
}

#[tokio::test]
async fn signed_refuses_a_reauth_that_is_not_fresh_now_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodRecoveryPut, &nonce, BODY);
    let now = setup.now();
    let start = u64::try_from(now).expect("a time");
    // Fresh when the extractor looked; 301 seconds old, or not yet made, by
    // the time the handle looks.
    for at in [start + 301, start - 1] {
        let router = setup.router(Opts {
            clock_at: Some(at),
            ..setup.opts()
        });
        let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
        setup.app.clock.set(start);
        assert_code(&res, StatusCode::FORBIDDEN, "reauth_required");
        assert_eq!(setup.stored_nonces(), 1, "the nonce is still there");
    }
    // Exactly 300 seconds old is still fresh, and the same nonce works.
    set_reauth_at(&setup.app, session.sid, Some(now - 300)).await;
    let router = setup.router(setup.opts());
    let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn signed_refuses_an_op_its_capability_does_not_cover_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let nonce = nonce_for(&setup.app, &session.jar).await;
    for (op, auth) in [
        (
            MutationOp::UnlockMethodPasswordPut,
            AuthOp::UnlockMethodPasswordPut,
        ),
        (MutationOp::Recover, AuthOp::UnlockMethodRecoveryPut),
        (MutationOp::Rekey, AuthOp::Rekey),
    ] {
        let router = setup.router(Opts { op, ..setup.opts() });
        let proof = sign(auth, &nonce, BODY);
        let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
        assert_code(&res, StatusCode::INTERNAL_SERVER_ERROR, "internal");
        assert_eq!(setup.stored_nonces(), 1, "{op:?}: the nonce is still there");
    }
}

#[tokio::test]
async fn signed_refuses_an_account_other_than_the_sessions_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodRecoveryPut, &nonce, BODY);
    let router = setup.router(Opts {
        account: Some(AccountId::from_bytes([0x77; 16])),
        ..setup.opts()
    });
    let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
    assert_code(&res, StatusCode::INTERNAL_SERVER_ERROR, "internal");
    assert_eq!(setup.stored_nonces(), 1);
}

#[tokio::test]
async fn signed_uses_up_the_nonce_of_a_wrong_proof() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let router = setup.router(setup.opts());
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodAdd, &nonce, BODY);
    let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
    assert_eq!(setup.stored_nonces(), 0);
    let proof = sign(AuthOp::UnlockMethodRecoveryPut, &nonce, BODY);
    let res = call(&router, SIGNED, &session.jar, &nonce, &proof, BODY).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
}

// ------------------------------------------------------------- password_put

#[tokio::test]
async fn password_put_gives_the_permit_for_the_new_record() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let router = setup.router(setup.opts());
    let body = setup.replacement(1, None);
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let json = res.json();
    assert_eq!(json["kind"], "PasswordPut");
    assert_eq!(json["profile"], 1);
    assert_eq!(json["stored"], 1);
    assert_eq!(json["new_pk_r"], Value::Null);
    assert_eq!(json["effect"], "Keep");
    assert_eq!(setup.stored_nonces(), 0);
}

#[tokio::test]
async fn password_put_refuses_a_reauth_that_is_not_fresh_now_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let body = setup.replacement(1, None);
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let start = u64::try_from(setup.now()).expect("a time");
    let router = setup.router(Opts {
        clock_at: Some(start + 301),
        ..setup.opts()
    });
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    setup.app.clock.set(start);
    assert_code(&res, StatusCode::FORBIDDEN, "reauth_required");
    assert_eq!(setup.stored_nonces(), 1);

    // Without a re-authentication at all, the extractor refuses first.
    let stale = setup.full(2, false).await;
    let router = setup.router(setup.opts());
    let res = call(&router, PASSWORD, &stale.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::FORBIDDEN, "reauth_required");
    assert_eq!(setup.stored_nonces(), 1);
}

#[tokio::test]
async fn password_put_refuses_a_profile_below_the_stored_one() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let router = setup.router(Opts {
        current: Arc::new(setup.record(1, 2)),
        ..setup.opts()
    });
    let body = setup.replacement(1, None);
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::UNPROCESSABLE_ENTITY, "profile_rejected");
}

#[tokio::test]
async fn password_put_refuses_a_recovery_proof_and_a_new_pk_r() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let router = setup.router(setup.opts());

    // Signed with the recovery key: not the password's proof.
    let body = setup.replacement(1, None);
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = setup.recovery_proof(&nonce, &body);
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");

    // A password change brings no recovery key.
    let body = setup.replacement(1, Some(new_pk_r(&setup.signer.account)));
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::BAD_REQUEST, "malformed_recovery_key");
}

#[tokio::test]
async fn password_put_refuses_an_account_other_than_the_sessions_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let session = setup.full(1, true).await;
    let router = setup.router(Opts {
        account: Some(AccountId::from_bytes([0x77; 16])),
        ..setup.opts()
    });
    let body = setup.replacement(1, None);
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let res = call(&router, PASSWORD, &session.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::INTERNAL_SERVER_ERROR, "internal");
    assert_eq!(setup.stored_nonces(), 1);
}

// ------------------------------------------------------------------ recover

#[tokio::test]
async fn recover_gives_the_permit_to_a_reset_session_that_ends_it() {
    let setup = Setup::new().await;
    let reset = setup.reset(1).await;
    // The stored profile is higher: a recovery may set a lower one.
    let router = setup.router(Opts {
        current: Arc::new(setup.record(1, 2)),
        ..setup.opts()
    });
    let pk_r = new_pk_r(&setup.signer.account);
    let body = setup.replacement(1, Some(pk_r));
    let nonce = nonce_for(&setup.app, &reset.jar).await;
    let proof = setup.recovery_proof(&nonce, &body);
    let res = call(&router, RECOVER, &reset.jar, &nonce, &proof, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let json = res.json();
    assert_eq!(json["kind"], "Recover");
    assert_eq!(json["profile"], 1);
    assert_eq!(json["stored"], 2);
    assert_eq!(json["new_pk_r"], hex(&pk_r));
    assert_eq!(json["effect"], "EndSession");
    assert_eq!(setup.stored_nonces(), 0);

    // The reset session reaches neither of the other two.
    let nonce = nonce_for(&setup.app, &reset.jar).await;
    for path in [PASSWORD, SIGNED] {
        let res = call(&router, path, &reset.jar, &nonce, &proof, &body).await;
        assert_code(&res, StatusCode::FORBIDDEN, "forbidden");
    }
    assert_eq!(setup.stored_nonces(), 1);
}

#[tokio::test]
async fn recover_in_a_full_session_needs_no_reauth_and_keeps_the_session() {
    let setup = Setup::new().await;
    let session = setup.full(1, false).await;
    let router = setup.router(setup.opts());
    let body = setup.replacement(1, Some(new_pk_r(&setup.signer.account)));
    let nonce = nonce_for(&setup.app, &session.jar).await;
    let proof = setup.recovery_proof(&nonce, &body);
    let res = call(&router, RECOVER, &session.jar, &nonce, &proof, &body).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["effect"], "Keep");
}

#[tokio::test]
async fn recover_refuses_a_proof_made_with_the_auth_key() {
    let setup = Setup::new().await;
    let reset = setup.reset(1).await;
    let router = setup.router(setup.opts());
    let body = setup.replacement(1, Some(new_pk_r(&setup.signer.account)));
    let nonce = nonce_for(&setup.app, &reset.jar).await;
    let proof = sign(AuthOp::UnlockMethodPasswordPut, &nonce, &body);
    let res = call(&router, RECOVER, &reset.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
    assert_eq!(setup.stored_nonces(), 0, "the nonce is used up");
}

#[tokio::test]
async fn recover_refuses_the_stored_pk_r_and_a_missing_one() {
    let setup = Setup::new().await;
    let reset = setup.reset(1).await;
    let router = setup.router(setup.opts());
    for pk_r in [Some(setup.stored_pk_r()), None] {
        let body = setup.replacement(1, pk_r);
        let nonce = nonce_for(&setup.app, &reset.jar).await;
        let proof = setup.recovery_proof(&nonce, &body);
        let res = call(&router, RECOVER, &reset.jar, &nonce, &proof, &body).await;
        assert_code(&res, StatusCode::BAD_REQUEST, "malformed_recovery_key");
    }
}

#[tokio::test]
async fn recover_refuses_an_account_other_than_the_sessions_and_keeps_the_nonce() {
    let setup = Setup::new().await;
    let reset = setup.reset(1).await;
    let router = setup.router(Opts {
        account: Some(AccountId::from_bytes([0x77; 16])),
        ..setup.opts()
    });
    let body = setup.replacement(1, Some(new_pk_r(&setup.signer.account)));
    let nonce = nonce_for(&setup.app, &reset.jar).await;
    let proof = setup.recovery_proof(&nonce, &body);
    let res = call(&router, RECOVER, &reset.jar, &nonce, &proof, &body).await;
    assert_code(&res, StatusCode::INTERNAL_SERVER_ERROR, "internal");
    assert_eq!(setup.stored_nonces(), 1);
}
