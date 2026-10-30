//! Registration: `POST /api/auth/opaque/register/{start,finish}` (vault
//! listener only). Spec: Fase 1 § 4.2 ("Registrering") and § 6.1.
//!
//! In this version only the first administrator registers: the kit's setup
//! token opens the door, and a server that has a user refuses with
//! `409 registration_closed`.
//!
//! # `start`
//!
//! 1. A vault URL of `https` needs a request that came through a trusted proxy
//!    that says so (`insecure_transport` otherwise): the session cookies of the
//!    answer to `finish` would be dropped by the browser.
//! 2. The login name and the setup token are checked for length and shape, and
//!    the setup token against the kit's (which counts wrong guesses per
//!    address and answers `429` when they come too fast).
//! 3. The server assigns the account id, the vault id and the registration id
//!    from the operating system's generator: the client never picks them.
//! 4. `ferret_server_auth::register_start` asks the throttle (the first thing
//!    it does) and answers the client's OPAQUE message. Only then is a row made
//!    in `ferret_registrations` (ten minutes, one per login name), so a request
//!    the throttle refused leaves nothing behind.
//!
//! # `finish`
//!
//! 1. The row is taken atomically: a registration id is good for one try, and
//!    a try that fails burns it.
//! 2. [`validate_new_account`] checks everything the client sent before any row
//!    is written. The server never sees the master password, the secret key,
//!    the recovery key or the vault key: it checks shapes, lengths, the
//!    generation, the digest and the entry of the first checkpoint, and that
//!    the two public keys are real Ed25519 keys.
//! 3. One transaction writes the kit user, the site settings, the account with
//!    its vault, wraps, manifest and checkpoint, and the session. Either all of
//!    it is there or none of it.
//! 4. The answer is `201` with the cookies of the new session.

use std::fmt;
use std::net::SocketAddr;
use std::sync::LazyLock;

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, FromRef, FromRequest, Request, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::IntoResponse as _;
use axum::routing::post;
use axum_extra::extract::cookie::SignedCookieJar;
use ed25519_dalek::VerifyingKey;
use ferret_core::envelope::MAX_ENVELOPE_LEN;
use ferret_core::integrity::checkpoint::parse_entries;
use ferret_core::wrap::{WRAP_LEN, WRAP_WITH_COMMIT_LEN};
use ferret_core::{
    FIRST_GENERATION, FIRST_MANIFEST_REV, FIRST_SEQ, KsfProfile, OsRng, SecureRng, parse_envelope,
};
use ferret_server_auth::{
    AuthError, CredentialId, DenyReason, ProfileRules, RegisterStartRequest, RegistrationAuthority,
    RegistrationKind, SessionScope, StoredRecord, normalize_login_name, register_finish,
    register_start as library_register_start,
};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};
use vole_kit::auth::pages::{SetupTokenError, check_setup_token};
use vole_kit::auth::session::SessionClaims;
use vole_kit::auth::{reauth, username_problem};
use vole_kit::db::{settings, users};

use crate::auth::session::{Origin, insert_session, new_session, session_cookies};
use crate::auth::throttle::caller_from;
use crate::error::{ApiError, StoreError};
use crate::http::proxy_guard::request_is_https;
use crate::ids::{AccountId, DeviceId, MANIFEST_ITEM_ID, MethodId, SessionSecret, VaultId};
use crate::state::FerretState;
use crate::vault::store::{CheckpointIn, ManifestIn, MethodRow, NewAccountRows, create_account};
use crate::wire::{
    RegisterFinishReq, RegisterFinishRes, RegisterStartReq, RegisterStartRes, WrapJson,
    refusal_code,
};

/// How long a registration waits for its second step, in seconds. It is valid
/// while the clock is below the time it was made plus this.
const PENDING_TTL_SECS: u64 = 600;

/// The most registrations that wait at once. The oldest are dropped first, so
/// a flood of first steps cannot fill the table.
const MAX_PENDING: i64 = 64;

/// The longest login name, in characters. It is the kit's limit for a user
/// name, and the name is stored as one.
const NAME_MAX_CHARS: usize = 64;

/// The longest text looked at for a login name, in bytes, before it is
/// normalized. A name of 64 characters is far below this.
const NAME_RAW_MAX_BYTES: usize = 256;

/// The longest setup token looked at, in bytes. The kit's own is 32 characters.
const SETUP_TOKEN_MAX_BYTES: usize = 256;

/// The largest request body of the two routes, in bytes. The largest field is
/// the manifest (65 536 bytes, 87 382 in base64url).
const BODY_LIMIT: usize = 256 * 1024;

/// The password hash of a kit user whose password the kit never sees: it is no
/// hash, so nothing verifies against it.
const EXTERNAL_HASH: &str = "!external";

/// The name of the site, set when the first administrator is made.
const SITE_NAME: &str = "Faithful Ferret";

/// The time zone of the site, set when the first administrator is made.
const TIMEZONE: &str = "UTC";

/// The profile every new account is told to use.
const NEW_ACCOUNT_PROFILE: KsfProfile = KsfProfile::P1;

/// `method_type` of the password wrap.
const TYPE_PASSWORD: u8 = 1;
/// `method_type` of the recovery wrap.
const TYPE_RECOVERY: u8 = 2;
/// `kind` of the manifest envelope.
const KIND_MANIFEST: u8 = 2;

static RULES: LazyLock<ProfileRules> = LazyLock::new(ProfileRules::ferret_v1);

/// The registration routes: both steps, `POST` only, on the vault listener.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route("/api/auth/opaque/register/start", post(register_start))
        .route(
            "/api/auth/opaque/register/finish",
            post(register_finish_step),
        )
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

// ------------------------------------------------------------- the answers

/// The answer for an error of the OPAQUE library. The status is the one of the code
/// (`error::status_of`). The cause of an internal
/// error goes to the log and never to the client.
fn auth_error(error: AuthError) -> ApiError {
    match error {
        AuthError::Internal(kind) => {
            tracing::error!(?kind, "registration failed inside the server");
            ApiError::internal()
        }
        other => ApiError::from(other),
    }
}

// ------------------------------------------------------------- the request

/// A JSON request body that answers with the server's own error body: `400`
/// with the code of the field that failed, `413` for a body over the limit.
/// Unknown and repeated fields are refused by the shapes of `wire`.
pub(crate) struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let is_json = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"));
        if !is_json {
            return Err(ApiError::coded("bad_request"));
        }
        let bytes = Bytes::from_request(req, state).await.map_err(|rejection| {
            if rejection.into_response().status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::coded("too_large")
            } else {
                ApiError::coded("bad_request")
            }
        })?;
        serde_json::from_slice(&bytes)
            .map(ApiJson)
            .map_err(|e| ApiError::coded(refusal_code(&e.to_string())))
    }
}

/// The clock, as the library wants it (`u64`) and as the database wants it
/// (`i64`). A clock that cannot tell the time reads as `u64::MAX`, and nothing
/// is done then.
fn now_of(state: &FerretState) -> Result<(u64, i64), ApiError> {
    let now = state.clock.now_unix();
    let signed = i64::try_from(now).map_err(|_| {
        tracing::error!("the clock cannot tell the time");
        ApiError::internal()
    })?;
    Ok((now, signed))
}

/// Refuses a request that did not reach the server over HTTPS when the vault
/// URL says it must have.
fn require_transport(
    state: &FerretState,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<(), ApiError> {
    if state.origins.vault_is_https() && !request_is_https(headers, peer.ip(), &state.proxies, true)
    {
        return Err(ApiError::coded("insecure_transport"));
    }
    Ok(())
}

/// The login name as the kit stores it: normalized, at most 64 characters, and
/// only the characters a kit user name allows. Every refusal is
/// `malformed_login_name`.
fn login_name(raw: &str) -> Result<String, ApiError> {
    let refused = || ApiError::coded("malformed_login_name");
    if raw.len() > NAME_RAW_MAX_BYTES {
        return Err(refused());
    }
    let name = normalize_login_name(raw).map_err(auth_error)?;
    let name = name.as_str();
    if name.chars().count() > NAME_MAX_CHARS || username_problem(name).is_some() {
        return Err(refused());
    }
    Ok(name.to_string())
}

/// Checks the setup token the kit asks for. A missing or wrong one is `403`,
/// and guesses that come too fast are `429`: the kit counts them per address.
fn check_token(
    state: &FerretState,
    headers: &HeaderMap,
    peer: SocketAddr,
    given: Option<&str>,
) -> Result<(), ApiError> {
    if given.is_some_and(|token| token.len() > SETUP_TOKEN_MAX_BYTES) {
        return Err(ApiError::coded("bad_request"));
    }
    match check_setup_token(&state.core, headers, Some(peer), given) {
        Ok(()) => Ok(()),
        Err(SetupTokenError::Missing | SetupTokenError::Wrong) => Err(ApiError::coded("forbidden")),
        Err(SetupTokenError::Throttled(wait)) => Err(ApiError::throttled(
            u32::try_from(wait.as_secs().saturating_add(1)).unwrap_or(u32::MAX),
        )),
    }
}

// ------------------------------------------------------------------- start

/// The registration a first step left behind.
pub(crate) struct Pending {
    pub(crate) account_id: [u8; 16],
    pub(crate) vault_id: [u8; 16],
    /// The normalized login name.
    pub(crate) email: String,
}

impl fmt::Debug for Pending {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pending([redacted])")
    }
}

/// What making the row came to.
enum Stored {
    Done,
    Closed,
}

/// Makes the row of a registration. Rows that expired are removed first, then
/// any earlier row of the same login name, then the oldest rows beyond the
/// limit. Refused (`Closed`) when the server has a user already.
fn store_pending(
    conn: &mut Connection,
    registration_id: [u8; 16],
    pending: &Pending,
    now: i64,
    expires_at: i64,
) -> Result<Stored, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let has_users: bool = tx.query_row("SELECT EXISTS (SELECT 1 FROM users)", [], |r| r.get(0))?;
    if has_users {
        return Ok(Stored::Closed);
    }
    tx.execute(
        "DELETE FROM ferret_registrations WHERE expires_at <= ?1 OR email = ?2",
        params![now, pending.email],
    )?;
    tx.execute(
        "DELETE FROM ferret_registrations WHERE registration_id IN (
           SELECT registration_id FROM ferret_registrations ORDER BY expires_at
           LIMIT max(0, (SELECT COUNT(*) FROM ferret_registrations) - ?1))",
        params![MAX_PENDING.saturating_sub(1)],
    )?;
    tx.execute(
        "INSERT INTO ferret_registrations (registration_id, account_id, vault_id, email, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            registration_id.as_slice(),
            pending.account_id.as_slice(),
            pending.vault_id.as_slice(),
            pending.email,
            expires_at,
        ],
    )?;
    tx.commit()?;
    Ok(Stored::Done)
}

/// A fresh 16-byte id from the operating system's generator.
fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill(&mut id);
    id
}

/// `POST /api/auth/opaque/register/start`.
async fn register_start(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<RegisterStartReq>,
) -> Result<Json<RegisterStartRes>, ApiError> {
    require_transport(&state, &headers, peer)?;
    let email = login_name(&req.email)?;
    check_token(&state, &headers, peer, req.setup_token.as_deref())?;
    let (now, signed_now) = now_of(&state)?;
    let expires_at = now
        .checked_add(PENDING_TTL_SECS)
        .and_then(|t| i64::try_from(t).ok())
        .ok_or_else(ApiError::internal)?;

    let (account_id, vault_id, registration_id) = (random_id(), random_id(), random_id());

    // The library asks the throttle first and answers the OPAQUE message. The
    // credential id is the server's own, never the client's.
    let response = library_register_start(
        &state.secrets.keys,
        state.throttle.as_ref(),
        now,
        &RegisterStartRequest {
            caller: caller_from(&headers, Some(peer)),
            authority: RegistrationAuthority::NewAccount,
            credential: CredentialId::from_bytes(account_id),
            request: &req.request,
        },
    )
    .map_err(auth_error)?;

    let pending = Pending {
        account_id,
        vault_id,
        email,
    };
    let stored = state
        .vault_db
        .with_conn(move |conn| {
            store_pending(conn, registration_id, &pending, signed_now, expires_at)
        })
        .await?;
    if matches!(stored, Stored::Closed) {
        return Err(ApiError::coded("registration_closed"));
    }
    Ok(Json(RegisterStartRes {
        registration_id,
        account_id,
        vault_id,
        response,
        ksf_profile: NEW_ACCOUNT_PROFILE.number(),
    }))
}

// ------------------------------------------------------------------ finish

/// Takes the row of a registration, once. The row is gone afterwards whatever
/// comes next, and an expired row is gone without being returned.
fn take_pending(
    conn: &Connection,
    registration_id: &[u8; 16],
    now: i64,
) -> Result<Option<Pending>, StoreError> {
    let row: Option<(Vec<u8>, Vec<u8>, String, i64)> = conn
        .query_row(
            "DELETE FROM ferret_registrations WHERE registration_id = ?1
             RETURNING account_id, vault_id, email, expires_at",
            params![registration_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((account_id, vault_id, email, expires_at)) = row else {
        return Ok(None);
    };
    if now >= expires_at {
        return Ok(None);
    }
    let fixed = |bytes: Vec<u8>| {
        <[u8; 16]>::try_from(bytes).map_err(|_| StoreError::Invalid("a registration id"))
    };
    Ok(Some(Pending {
        account_id: fixed(account_id)?,
        vault_id: fixed(vault_id)?,
        email,
    }))
}

/// What the client sent for a new account, checked and ready to write.
pub(crate) struct ValidatedNewAccount {
    device: DeviceId,
    device_name: String,
    record: StoredRecord,
    sk_hint: bool,
    pk_a: [u8; 32],
    pk_r: [u8; 32],
    methods: Vec<MethodRow>,
    manifest: ManifestIn,
    checkpoint: CheckpointIn,
}

impl fmt::Debug for ValidatedNewAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedNewAccount([redacted])")
    }
}

/// A real Ed25519 public key: it decodes to a point, and not one of small
/// order.
fn is_public_key(bytes: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(bytes).is_ok_and(|key| !key.is_weak())
}

/// One wrap of the request as a row: of generation 1, of the right length, with
/// no passkey fields and an id that is neither zero nor one of the server's
/// own ids.
fn method_row(wrap: &WrapJson, wrap_len: usize, pending: &Pending) -> Result<MethodRow, ApiError> {
    // `kek_generation` is a number up to 2^53 on the wire; the table keeps a
    // `u32` from 1.
    let generation = u32::try_from(wrap.kek_generation)
        .ok()
        .filter(|g| *g != 0)
        .ok_or_else(|| ApiError::coded("bad_request"))?;
    if u64::from(generation) != FIRST_GENERATION
        || wrap.wrap.len() != wrap_len
        || wrap.method_id == [0u8; 16]
        || wrap.method_id == pending.account_id
        || wrap.method_id == pending.vault_id
        || wrap.credential_id.is_some()
        || wrap.prf_salt.is_some()
    {
        return Err(ApiError::coded("bad_request"));
    }
    Ok(MethodRow {
        method_id: MethodId::from_bytes(wrap.method_id),
        method_type: wrap.method_type,
        wrap: wrap.wrap.clone(),
        kek_generation: generation,
        credential_id: None,
        prf_salt: None,
        aaguid: None,
    })
}

/// Checks everything of a new account that the server can check without a key.
///
/// * exactly two wraps, one password (104 bytes) and one recovery (72 bytes),
///   both of generation 1, with different non-zero method ids;
/// * the manifest is at revision 1 and is a well-formed manifest envelope of at
///   most 65 536 bytes;
/// * the checkpoint is at sequence 1, its digest is the SHA-256 of its entries,
///   and the entries are exactly one: the manifest, at its revision, with the
///   SHA-256 of its envelope;
/// * `pk_a` and `pk_r` are valid Ed25519 public keys;
/// * the OPAQUE record is well formed and the profile is one the rules accept
///   for a new account.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3) and § 8.6.
pub(crate) fn validate_new_account(
    req: &RegisterFinishReq,
    pending: &Pending,
    rules: &ProfileRules,
) -> Result<ValidatedNewAccount, ApiError> {
    // The wraps: one of each kind, in either order.
    let [first, second] = req.wraps.as_slice() else {
        return Err(ApiError::coded("bad_request"));
    };
    let (password, recovery) = match (first.method_type, second.method_type) {
        (TYPE_PASSWORD, TYPE_RECOVERY) => (first, second),
        (TYPE_RECOVERY, TYPE_PASSWORD) => (second, first),
        _ => return Err(ApiError::coded("bad_request")),
    };
    let password = method_row(password, WRAP_WITH_COMMIT_LEN, pending)?;
    let recovery = method_row(recovery, WRAP_LEN, pending)?;
    if password.method_id == recovery.method_id {
        return Err(ApiError::coded("bad_request"));
    }

    // The manifest.
    if req.manifest.rev != FIRST_MANIFEST_REV {
        return Err(ApiError::coded("bad_request"));
    }
    let envelope = &req.manifest.envelope;
    if envelope.len() > MAX_ENVELOPE_LEN {
        return Err(ApiError::coded("too_large"));
    }
    match parse_envelope(envelope) {
        Ok(view) if view.kind == KIND_MANIFEST => {}
        _ => return Err(ApiError::coded("unsupported_envelope")),
    }

    // The checkpoint: one entry, the manifest.
    let checkpoint = &req.checkpoint;
    if checkpoint.seq != FIRST_SEQ {
        return Err(ApiError::coded("bad_request"));
    }
    let digest: [u8; 32] = Sha256::digest(&checkpoint.entries).into();
    if digest != checkpoint.digest {
        return Err(ApiError::coded("bad_request"));
    }
    let entries = parse_entries(&checkpoint.entries).map_err(|_| ApiError::coded("bad_request"))?;
    let manifest_hash: [u8; 32] = Sha256::digest(envelope).into();
    match entries.as_slice() {
        [entry]
            if entry.item_id == MANIFEST_ITEM_ID
                && entry.rev == req.manifest.rev
                && entry.live_hash == Some(manifest_hash) => {}
        _ => return Err(ApiError::coded("bad_request")),
    }

    // The keys.
    if !is_public_key(&req.pk_a) || !is_public_key(&req.pk_r) {
        return Err(ApiError::coded("bad_request"));
    }

    // The OPAQUE record and its profile. A new account is compared with
    // nothing that is stored.
    let record = register_finish(
        &req.record,
        req.ksf_profile,
        rules,
        RegistrationKind::NewAccount,
    )
    .map_err(auth_error)?;

    Ok(ValidatedNewAccount {
        device: DeviceId(req.device_id),
        device_name: req.device_name.clone().unwrap_or_default(),
        record,
        sk_hint: req.sk_bit,
        pk_a: req.pk_a,
        pk_r: req.pk_r,
        methods: vec![password, recovery],
        manifest: ManifestIn {
            rev: req.manifest.rev,
            envelope: envelope.clone(),
            tag: req.manifest.tag,
        },
        checkpoint: CheckpointIn {
            seq: checkpoint.seq,
            digest: checkpoint.digest.to_vec(),
            mac: checkpoint.mac.to_vec(),
            entries: checkpoint.entries.clone(),
        },
    })
}

/// What the transaction of `finish` came to.
enum Created {
    Done {
        secret: SessionSecret,
        claims: SessionClaims,
    },
    Closed,
}

/// Writes the kit user, the site settings, the account with its vault, and the
/// session, in one transaction. Nothing is written if the server has a user
/// already or if any step fails.
fn write_account(
    conn: &mut Connection,
    pending: &Pending,
    account: ValidatedNewAccount,
    now: i64,
) -> Result<Created, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let Some(user_id) = users::insert_first_admin(&tx, &pending.email, EXTERNAL_HASH, "")? else {
        return Ok(Created::Closed);
    };
    settings::set(&tx, settings::SITE_NAME, SITE_NAME)?;
    settings::set(&tx, settings::TIMEZONE, TIMEZONE)?;
    let version: i64 = tx.query_row(
        "SELECT session_version FROM users WHERE id = ?1",
        params![user_id],
        |r| r.get(0),
    )?;
    create_account(
        &tx,
        &NewAccountRows {
            account_id: AccountId::from_bytes(pending.account_id),
            user_id,
            vault_id: VaultId::from_bytes(pending.vault_id),
            record: account.record,
            sk_hint: account.sk_hint,
            pk_a: account.pk_a,
            pk_r: account.pk_r,
            methods: account.methods,
            manifest: account.manifest,
            checkpoint: account.checkpoint,
            now,
        },
    )?;
    let (secret, session, claims) = new_session(
        &mut OsRng,
        now,
        user_id,
        version,
        Origin::Vault,
        account.device,
        &account.device_name,
        SessionScope::Full,
    );
    insert_session(&tx, &session)?;
    tx.commit()?;
    Ok(Created::Done { secret, claims })
}

/// The answer to `finish`: the cookies of the new session and a `201`.
type Finished = (
    SignedCookieJar,
    (
        StatusCode,
        [(HeaderName, HeaderValue); 1],
        Json<RegisterFinishRes>,
    ),
);

/// `POST /api/auth/opaque/register/finish`.
async fn register_finish_step(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(req): ApiJson<RegisterFinishReq>,
) -> Result<Finished, ApiError> {
    require_transport(&state, &headers, peer)?;
    let (_, signed_now) = now_of(&state)?;

    let registration_id = req.registration_id;
    let pending = state
        .vault_db
        .with_conn(move |conn| take_pending(conn, &registration_id, signed_now))
        .await?
        .ok_or_else(|| ApiError::from(AuthError::Denied(DenyReason::StateMissing)))?;

    let account = validate_new_account(&req, &pending, &RULES)?;
    // The request holds ciphertext and keys; nothing past this point needs it.
    drop(req);

    let ids = (pending.account_id, pending.vault_id);
    let created = state
        .vault_db
        .with_conn(move |conn| write_account(conn, &pending, account, signed_now))
        .await?;
    let Created::Done { secret, claims } = created else {
        return Err(ApiError::coded("registration_closed"));
    };

    let secure = state.origins.vault_is_https();
    let jar = SignedCookieJar::from_headers(&headers, state.core.session_key.clone());
    let jar = session_cookies(jar, &secret, &claims, secure);
    let jar = reauth::grant(jar, &state.core.session_key, secure);
    Ok((
        jar,
        (
            StatusCode::CREATED,
            [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(RegisterFinishRes {
                account_id: ids.0,
                vault_id: ids.1,
            }),
        ),
    ))
}
