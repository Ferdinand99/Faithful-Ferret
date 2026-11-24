//! Recovering an account with the recovery key.
//!
//! Two routes, on the vault listener only:
//!
//! * `GET /api/vault/recovery` hands the recovery wrap to a session whose
//!   scope may read it (a full session, or the reset session a one-time code
//!   opened): the account, the vault, the key epoch, the account's key
//!   stretching profile, the recovery wrap and the manifest row. Nothing else:
//!   no password wrap, no record, no public key.
//! * `POST /api/vault/recover` replaces the OPAQUE record, both wraps and
//!   `pk_r`, and writes a new manifest, in one transaction, through
//!   [`unlock_write`](super::unlock_write). The request is signed with the
//!   recovery key (`sk_r`) the server knows now:
//!
//!   1. a vault session whose scope allows `Recover` (a full one or a reset
//!      one); no re-authentication is asked for, since the user who recovers
//!      has usually forgotten the master password;
//!   2. the nonce and the proof headers and the raw body (`400` for a header
//!      of the wrong shape, which burns no nonce);
//!   3. inside the write transaction, against the account as it is read
//!      there: the asking session is still one (`401`, before the nonce is
//!      used up); then the library uses up the nonce and checks the proof of `recover` by `sk_r` against the
//!      stored `pk_r`, the server's key epoch and the exact body (`401
//!      denied` otherwise, and the nonce is gone); only then is the body
//!      read. The record must be well formed, its profile one the server's
//!      table knows (it is not compared with the stored profile: a recovery
//!      may set a lower one, `422 profile_rejected` otherwise), and the new
//!      `pk_r` must differ from the stored one (`400 malformed_recovery_key`);
//!   4. the manifest envelope (`422`), the manifest's `rev` and both new
//!      generations (`409 write_conflict`), the new `pk_r` as a key (`400
//!      malformed_recovery_key`), then the writes.
//!
//!   Every other session of the user ends, on both origins, and so do the
//!   user's pending sign-in codes. A sign-in of the user that is still
//!   half-way cannot finish: its login state is bound to the old record. A
//!   reset session ends with the recovery, and the answer clears its cookies;
//!   a full session goes on, but the admin session handed over from it ends.
//!   Right after the commit, on the database thread (so a client that went
//!   away cannot stop it), the ended sessions' streams close, the vault's
//!   streams hear of the new `seq`, and a backup is asked for.
//!
//!   The answer is `200 {session_ended, seq}`. Nothing of the request is
//!   logged.
//!
//! Spec: Fase 1 § 6.3 (the recovery flow: the reset session's capabilities,
//! the body and the proof of step 4, the sessions after step 5) and § 4.6
//! (the endpoint table; the proof by `sk_r`; all other sessions end after a
//! recovery).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::CookieJar;
use ferret_core::RecoveryPublicKey;
use ferret_server_auth::{AuthError, Clock, Malformed, ReplaceFields, SessionScope};
use rusqlite::{Connection, OptionalExtension as _, params};
use vole_kit::auth::reauth;

use super::notify::SyncEvents;
use super::unlock_write::{self, Authorized, ChangeKind, UnlockChange, Writer};
use crate::auth::session::removal;
use crate::auth::throttle::caller_from;
use crate::error::{ApiError, StoreError};
use crate::http::extract::{ScopedSession, SessionAuth, SignedBody, caps};
use crate::ids::{AccountId, MANIFEST_ITEM_ID};
use crate::product;
use crate::state::{BackupStatus, Proofs, VaultDb};
use crate::wire::{RecoverReq, RecoverRes, RecoveryRes, SealedRowJson, WrapJson, refusal_code};

/// The path of the read of the recovery wrap.
pub const RECOVERY_PATH: &str = "/api/vault/recovery";

/// The path of the recovery.
pub const RECOVER_PATH: &str = "/api/vault/recover";

/// `method_type` of the recovery wrap.
const TYPE_RECOVERY: u8 = 2;

/// The routes of the recovery.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    Proofs: FromRef<S>,
    Arc<dyn Clock>: FromRef<S>,
    SyncEvents: FromRef<S>,
    BackupStatus: FromRef<S>,
{
    Router::new()
        .route(RECOVERY_PATH, get(recovery_get))
        .route(RECOVER_PATH, post(recover_post))
}

// ------------------------------------------------------------ the wrap read

/// `GET /api/vault/recovery`: what the client needs to open the vault with the
/// recovery key, for the session's own account.
///
/// Spec: Fase 1 § 6.3 steps 1 and 2.
async fn recovery_get(
    State(db): State<VaultDb>,
    scoped: ScopedSession<caps::RecoveryWrapRead>,
) -> Result<Json<RecoveryRes>, ApiError> {
    let facts = scoped.session();
    let (account, user_id) = (facts.account(), facts.user_id());
    let res = db
        .with_conn(move |conn| recovery_view(conn, &account, user_id))
        .await??;
    Ok(Json(res))
}

/// The account columns the wrap read needs: vault, profile, key epoch.
type AccountColumns = (Vec<u8>, i64, i64);

/// The columns of a stored wrap: method id, wrap, generation, credential id,
/// PRF salt.
type WrapColumns = (Vec<u8>, Vec<u8>, i64, Option<Vec<u8>>, Option<Vec<u8>>);

/// The columns of the manifest row: revision, envelope, tag.
type ManifestColumns = (i64, Vec<u8>, Vec<u8>);

/// The recovery wrap, the profile, the key epoch and the manifest row of
/// `account`, read in one transaction. A row the server cannot hand out in
/// the shape of the wire (no recovery wrap or more than one, a manifest that
/// is not live) is a fault of the database: `500`, with nothing in the answer.
fn recovery_view(
    conn: &Connection,
    account: &AccountId,
    user_id: i64,
) -> Result<Result<RecoveryRes, ApiError>, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let row: Option<AccountColumns> = tx
        .query_row(
            "SELECT vault_id, ksf_profile, vk_epoch FROM ferret_accounts
             WHERE account_id = ?1 AND user_id = ?2",
            params![account.as_bytes(), user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    // The extractor found the account a moment ago; without it the session
    // no longer counts.
    let Some((vault_id, ksf_profile, vk_epoch)) = row else {
        return Ok(Err(ApiError::unauthorized()));
    };
    let mut stmt = tx.prepare(
        "SELECT method_id, wrap, kek_generation, credential_id, prf_salt
         FROM ferret_unlock_methods WHERE account_id = ?1 AND method_type = ?2",
    )?;
    let wraps = stmt
        .query_map(params![account.as_bytes(), i64::from(TYPE_RECOVERY)], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })?
        .collect::<Result<Vec<WrapColumns>, _>>()?;
    drop(stmt);
    let manifest: Option<ManifestColumns> = tx
        .query_row(
            "SELECT rev, blob, tag FROM ferret_items
             WHERE vault_id = ?1 AND item_id = ?2 AND deleted = 0
               AND blob IS NOT NULL AND tag IS NOT NULL",
            params![vault_id, MANIFEST_ITEM_ID.as_bytes()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    tx.finish()?;

    let mut wraps = wraps.into_iter();
    let (Some(wrap), None) = (wraps.next(), wraps.next()) else {
        return Ok(Err(inconsistent(
            "an account does not have exactly one recovery wrap",
        )));
    };
    let Some(manifest) = manifest else {
        return Ok(Err(inconsistent("the manifest row is not live")));
    };
    let Some(res) = recovery_res(account, (vault_id, ksf_profile, vk_epoch), wrap, manifest) else {
        return Ok(Err(inconsistent("a stored value does not fit the wire")));
    };
    // The same check a client makes: type 2, the size of a recovery wrap, no
    // passkey fields.
    if res.validate().is_err() {
        return Ok(Err(inconsistent("the stored recovery wrap is not one")));
    }
    Ok(Ok(res))
}

/// The answer from the stored columns, or `None` when one does not fit the
/// wire.
fn recovery_res(
    account: &AccountId,
    (vault_id, ksf_profile, vk_epoch): AccountColumns,
    (method_id, wrap, generation, credential_id, prf_salt): WrapColumns,
    (rev, envelope, tag): ManifestColumns,
) -> Option<RecoveryRes> {
    let prf_salt = match prf_salt {
        Some(salt) => Some(<[u8; 32]>::try_from(salt).ok()?),
        None => None,
    };
    Some(RecoveryRes {
        account_id: *account.as_bytes(),
        vault_id: <[u8; 16]>::try_from(vault_id).ok()?,
        vk_epoch: u64::try_from(vk_epoch).ok()?,
        ksf_profile: u8::try_from(ksf_profile).ok()?,
        wrap: WrapJson {
            method_id: <[u8; 16]>::try_from(method_id).ok()?,
            method_type: TYPE_RECOVERY,
            kek_generation: u64::try_from(generation).ok()?,
            wrap,
            credential_id,
            prf_salt,
            aaguid: None,
            created_at: None,
        },
        manifest: SealedRowJson {
            rev: u64::try_from(rev).ok()?,
            envelope,
            tag: <[u8; 32]>::try_from(tag).ok()?,
        },
    })
}

/// `500 internal`, with the reason in the log only.
fn inconsistent(why: &'static str) -> ApiError {
    ApiError::from(StoreError::Invalid(why))
}

// ---------------------------------------------------------------- recovery

/// The handles the recovery uses.
struct Handles {
    proofs: Proofs,
    db: VaultDb,
    clock: Arc<dyn Clock>,
    events: SyncEvents,
    backup: BackupStatus,
}

/// `POST /api/vault/recover`.
#[allow(clippy::too_many_arguments)] // the handles and the extractors of one route
async fn recover_post(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    State(clock): State<Arc<dyn Clock>>,
    State(events): State<SyncEvents>,
    State(backup): State<BackupStatus>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    scoped: ScopedSession<caps::Recover>,
    body: SignedBody,
) -> Result<(CookieJar, Json<RecoverRes>), ApiError> {
    let handles = Handles {
        proofs,
        db,
        clock,
        events,
        backup,
    };
    let caller = caller_from(&headers, Some(peer));
    let res = recover(handles, scoped, body, caller).await?;
    // A session that ended with the recovery is gone in the browser too. A
    // jar read from the request sends nothing back unless a cookie is
    // removed from it.
    let jar = CookieJar::from_headers(&headers);
    let jar = if res.session_ended { cleared(jar) } else { jar };
    Ok((jar, Json(res)))
}

/// The cookies that end a vault session in the browser: the session id, the
/// kit's session cookie, the pending-second-factor cookie and the re-auth
/// grant, each removed if the request carried it.
fn cleared(jar: CookieJar) -> CookieJar {
    jar.remove(removal(product::SID_COOKIE))
        .remove(removal(product::SESSION_COOKIE))
        .remove(removal(product::PENDING_2FA_COOKIE))
        .remove(removal(reauth::cookie_name()))
}

/// The recovery itself, once the extractors have let the request through.
async fn recover(
    handles: Handles,
    scoped: ScopedSession<caps::Recover>,
    body: SignedBody,
    caller: ferret_server_auth::Caller,
) -> Result<RecoverRes, ApiError> {
    let now = handles.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; no account is recovered");
        return Err(ApiError::internal());
    }
    let now = i64::try_from(now).map_err(|_| ApiError::internal())?;
    let facts = scoped.session();
    let sid = facts.sid();
    let writer = Writer {
        account: facts.account(),
        user_id: facts.user_id(),
        sid,
        session_version: facts.session_version(),
        // Only a full session goes on. A reset session ends with the
        // recovery: the permit says so too (`EndSession`), and either one is
        // enough to end it.
        keep_session: scoped.scope() == SessionScope::Full,
        kind: ChangeKind::Recover,
    };
    let vault = facts.vault();
    let Handles {
        proofs,
        db,
        events,
        backup,
        ..
    } = handles;
    // The announcements run on the database thread right after the commit,
    // so a request whose client went away still sends them and asks for the
    // backup.
    let applied = db
        .with_conn(move |conn| {
            let applied = unlock_write::apply(conn, &writer, now, |state| {
                authorize(&proofs, &scoped, &body, caller, state)
            });
            if let Ok(applied) = &applied {
                unlock_write::after_commit(applied, &events, &backup, &vault);
            }
            Ok(applied)
        })
        .await??;
    Ok(RecoverRes {
        session_ended: applied.ended.contains(&sid),
        seq: applied.seq,
    })
}

/// The library's check of the proof by `sk_r`, the record and the new `pk_r`,
/// against the account as it was just read, and the proven body as a change.
///
/// The body is read only by the library's parser, after the proof has
/// verified, and only from the exact bytes it covers. A body that does not
/// parse is `400` with the code of the field that failed (its nonce is used
/// up by then). The record, its profile and the new `pk_r` written are the
/// ones the permit carries; the wraps, their generations and the manifest
/// come from the same proven bytes.
fn authorize(
    proofs: &Proofs,
    scoped: &ScopedSession<caps::Recover>,
    body: &SignedBody,
    caller: ferret_server_auth::Caller,
    state: &ferret_server_auth::AccountAuthState<'_>,
) -> Result<Authorized, ApiError> {
    let mut parsed: Option<RecoverReq> = None;
    let mut refusal: Option<&'static str> = None;
    let permit = proofs.recover(
        scoped,
        body,
        caller,
        state,
        |bytes| match serde_json::from_slice::<RecoverReq>(bytes) {
            Ok(req) => {
                let fields = ReplaceFields {
                    record: req.registration_record.clone(),
                    ksf_profile: u32::from(req.ksf_profile),
                    pk_r_new: Some(RecoveryPublicKey::new(req.pk_r_new)),
                };
                parsed = Some(req);
                Ok(fields)
            }
            Err(error) => {
                refusal = Some(refusal_code(&error.to_string()));
                Err(AuthError::Malformed(Malformed::RegistrationRecord))
            }
        },
    );
    let permit = match (permit, refusal) {
        (Ok(permit), _) => permit,
        (Err(_), Some(code)) => return Err(ApiError::coded(code)),
        (Err(error), None) => return Err(error),
    };
    let (Some(req), Some(pk_r)) = (parsed, permit.new_pk_r) else {
        tracing::error!("a recovery was permitted without a parsed body or a new key");
        return Err(ApiError::internal());
    };
    let RecoverReq {
        pw_wrap,
        rk_wrap,
        pw_kek_generation,
        rk_kek_generation,
        manifest,
        ..
    } = req;
    Ok(Authorized {
        change: UnlockChange::Recover {
            record: permit.new.record,
            profile: permit.new.ksf_profile,
            pw_wrap,
            pw_generation: pw_kek_generation,
            rk_wrap,
            rk_generation: rk_kek_generation,
            pk_r: *pk_r.as_bytes(),
        },
        manifest,
        session_effect: permit.session_effect,
        basis: permit.basis,
    })
}
