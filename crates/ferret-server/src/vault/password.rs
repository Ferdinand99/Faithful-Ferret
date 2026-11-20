//! Changing the master password.
//!
//! `PUT /api/vault/unlock-methods/password` writes a new OPAQUE record, a new
//! password wrap and a new manifest, in one transaction, through
//! [`unlock_write`](super::unlock_write). The request is a sensitive one:
//!
//! 1. a vault session whose scope allows `PasswordPut` (a full one: a reset
//!    session is `403 forbidden`);
//! 2. that proved the master password again within five minutes, with no
//!    second factor the server would have to ask for (`403 reauth_required`,
//!    `403 second_factor_required`);
//! 3. the nonce and the proof headers and the raw body (`400` for a header
//!    of the wrong shape, which burns no nonce);
//! 4. inside the write transaction, against the account as it is read there:
//!    no other new password or recovery of the account in the last minute
//!    (`429 throttled`, before the nonce is used up); then the library uses up the nonce, checks the proof of
//!    `unlock-method.password.put` by `sk_a` over the exact body (`401
//!    denied` otherwise, and the nonce is gone), and only then is the body
//!    read; the record must be well formed and its profile not below the
//!    stored one (`422 profile_rejected`);
//! 5. the manifest envelope (`422`), the manifest's `rev` and the new
//!    generation (`409 write_conflict`), then the writes.
//!
//! Every other session of the user ends, on both origins (there is no opting
//! out), and so do the user's pending sign-in codes and every sign-in that is
//! still half-way. This session goes on, but the admin session handed over
//! from it ends too (it fails safe). Right after the commit, on the database
//! thread (so a client that went away cannot stop it), the ended sessions'
//! streams close, the vault's streams hear of the new `seq`, and a backup is
//! asked for.
//!
//! The answer is `200 {kek_generation, seq}`. Nothing of the request is
//! logged.
//!
//! Spec: Fase 1 § 4.3 (changing MP), § 4.6 (the endpoint table; all other
//! sessions end after an MP change).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, State};
use axum::http::HeaderMap;
use axum::routing::put;
use axum::{Json, Router};
use ferret_server_auth::{AuthError, Clock, Malformed, ReplaceFields};

use super::notify::SyncEvents;
use super::unlock_write::{self, Authorized, ChangeKind, UnlockChange, Writer};
use crate::auth::throttle::caller_from;
use crate::error::ApiError;
use crate::http::extract::{FreshReauth, ScopedSession, SessionAuth, SignedBody, caps};
use crate::state::{BackupStatus, Proofs, VaultDb};
use crate::wire::{PasswordPutReq, PasswordPutRes, refusal_code};

/// The path of the route.
pub const PATH: &str = "/api/vault/unlock-methods/password";

/// The route of the password change.
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
    Router::new().route(PATH, put(password_put))
}

/// The handles the route uses.
struct Handles {
    proofs: Proofs,
    db: VaultDb,
    clock: Arc<dyn Clock>,
    events: SyncEvents,
    backup: BackupStatus,
}

/// `PUT /api/vault/unlock-methods/password`.
#[allow(clippy::too_many_arguments)] // the handles and the extractors of one route
async fn password_put(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    State(clock): State<Arc<dyn Clock>>,
    State(events): State<SyncEvents>,
    State(backup): State<BackupStatus>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    scoped: ScopedSession<caps::PasswordPut>,
    fresh: FreshReauth,
    body: SignedBody,
) -> Result<Json<PasswordPutRes>, ApiError> {
    let handles = Handles {
        proofs,
        db,
        clock,
        events,
        backup,
    };
    let caller = caller_from(&headers, Some(peer));
    change_password(handles, scoped, fresh, body, caller).await
}

/// The change itself, once the extractors have let the request through.
async fn change_password(
    handles: Handles,
    scoped: ScopedSession<caps::PasswordPut>,
    fresh: FreshReauth,
    body: SignedBody,
    caller: ferret_server_auth::Caller,
) -> Result<Json<PasswordPutRes>, ApiError> {
    let now = handles.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; no password is changed");
        return Err(ApiError::internal());
    }
    let now = i64::try_from(now).map_err(|_| ApiError::internal())?;
    let facts = scoped.session();
    let writer = Writer {
        account: facts.account(),
        user_id: facts.user_id(),
        sid: facts.sid(),
        session_version: facts.session_version(),
        keep_session: true,
        kind: ChangeKind::Password,
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
    // so a request whose client went away (its future dropped) still sends
    // them and asks for the backup.
    let (applied, generation) = db
        .with_conn(move |conn| {
            let mut generation = 0;
            let applied = unlock_write::apply(conn, &writer, now, |state| {
                let (authorized, new_generation) =
                    authorize(&proofs, &scoped, &fresh, &body, caller, state)?;
                generation = new_generation;
                Ok(authorized)
            });
            if let Ok(applied) = &applied {
                unlock_write::after_commit(applied, &events, &backup, &vault);
            }
            Ok(applied.map(|applied| (applied, generation)))
        })
        .await??;
    Ok(Json(PasswordPutRes {
        kek_generation: generation,
        seq: applied.seq,
    }))
}

/// The library's check of the proof and the record, against the account as it
/// was just read, and the proven body as a change. Gives the change and the
/// new generation.
///
/// The body is read only by the library's parser, after the proof has
/// verified, and only from the exact bytes it covers. A body that does not
/// parse is `400` with the code of the field that failed (its nonce is used
/// up by then).
fn authorize(
    proofs: &Proofs,
    scoped: &ScopedSession<caps::PasswordPut>,
    fresh: &FreshReauth,
    body: &SignedBody,
    caller: ferret_server_auth::Caller,
    state: &ferret_server_auth::AccountAuthState<'_>,
) -> Result<(Authorized, u32), ApiError> {
    let mut parsed: Option<PasswordPutReq> = None;
    let mut refusal: Option<&'static str> = None;
    let permit =
        proofs.password_put(
            scoped,
            fresh,
            body,
            caller,
            state,
            |bytes| match serde_json::from_slice::<PasswordPutReq>(bytes) {
                Ok(req) => {
                    let fields = ReplaceFields {
                        record: req.registration_record.clone(),
                        ksf_profile: u32::from(req.ksf_profile),
                        pk_r_new: None,
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
    let Some(req) = parsed else {
        tracing::error!("a password change was permitted without a parsed body");
        return Err(ApiError::internal());
    };
    let PasswordPutReq {
        wrap,
        kek_generation,
        manifest,
        ..
    } = req;
    Ok((
        Authorized {
            change: UnlockChange::Password {
                record: permit.new.record,
                profile: permit.new.ksf_profile,
                wrap,
                generation: kek_generation,
            },
            manifest,
            session_effect: permit.session_effect,
            basis: permit.basis,
        },
        kek_generation,
    ))
}
