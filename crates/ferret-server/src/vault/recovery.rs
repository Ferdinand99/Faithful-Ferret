//! A new recovery key.
//!
//! `PUT /api/vault/unlock-methods/recovery` replaces the recovery wrap and
//! `pk_r` with those of a new recovery key, and writes a new manifest, in one
//! transaction, through [`unlock_write`](super::unlock_write). The request is a
//! sensitive one:
//!
//! 1. a vault session whose scope allows `UnlockMethodsWrite` (a full one: a
//!    reset session is `403 forbidden`);
//! 2. that proved the master password again within five minutes, with no
//!    second factor the server would have to ask for (`403 reauth_required`,
//!    `403 second_factor_required`);
//! 3. the nonce and the proof headers and the raw body (`400` for a header
//!    of the wrong shape, which burns no nonce);
//! 4. inside the write transaction, against the account as it is read there:
//!    the library uses up the nonce and checks the proof of
//!    `unlock-method.recovery.put` by `sk_a` over the exact body and the
//!    stored `vk_epoch` (`401 denied` otherwise, and the nonce is gone); only
//!    then is the body read (`400` with the code of the field that failed);
//! 5. the new `pk_r` must differ from the stored one and be a canonical
//!    Ed25519 key that is not of small order (`400 malformed_recovery_key`);
//!    then the manifest envelope (`422`), the manifest's `rev` and the new
//!    generation (`409 write_conflict`), then the writes.
//!
//! The new generation only has to be above the stored one. The client picks
//! it from its pinned floor, the manifest and the server's wrap, so after a
//! restore of an older backup it may jump well above the server's: that is
//! taken, and nothing here can lower a generation.
//!
//! A new recovery key ends no session and leaves every sign-in alone: it
//! changes nothing about how the user signs in, only which key can recover.
//! There is no wait after an earlier change either. Right after the commit,
//! on the database thread (so a client that went away cannot stop it), the
//! vault's streams hear of the new `seq`, and a backup is asked for, so the
//! newest set holds the new recovery wrap.
//!
//! The answer is `200 {kek_generation, seq}`. Nothing of the request is
//! logged.
//!
//! Spec: Fase 1 § 4.6 (sensitive operations; the endpoint table) and § 6.1
//! (the recovery key).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, State};
use axum::http::HeaderMap;
use axum::routing::put;
use axum::{Json, Router};
use ferret_core::MutationOp;
use ferret_server_auth::Clock;

use super::notify::SyncEvents;
use super::unlock_write::{self, Authorized, ChangeKind, UnlockChange, Writer};
use crate::auth::throttle::caller_from;
use crate::error::ApiError;
use crate::http::extract::{FreshReauth, ScopedSession, SessionAuth, SignedBody, caps};
use crate::state::{BackupStatus, Proofs, VaultDb};
use crate::wire::{RecoveryPutReq, RecoveryPutRes};

/// The path of the route.
pub const PATH: &str = "/api/vault/unlock-methods/recovery";

/// The route of a new recovery key.
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
    Router::new().route(PATH, put(recovery_put))
}

/// The handles the route uses.
struct Handles {
    proofs: Proofs,
    db: VaultDb,
    clock: Arc<dyn Clock>,
    events: SyncEvents,
    backup: BackupStatus,
}

/// `PUT /api/vault/unlock-methods/recovery`.
#[allow(clippy::too_many_arguments)] // the handles and the extractors of one route
async fn recovery_put(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    State(clock): State<Arc<dyn Clock>>,
    State(events): State<SyncEvents>,
    State(backup): State<BackupStatus>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    scoped: ScopedSession<caps::UnlockMethodsWrite>,
    fresh: FreshReauth,
    body: SignedBody,
) -> Result<Json<RecoveryPutRes>, ApiError> {
    let handles = Handles {
        proofs,
        db,
        clock,
        events,
        backup,
    };
    let caller = caller_from(&headers, Some(peer));
    renew(handles, scoped, fresh, body, caller).await
}

/// The renewal itself, once the extractors have let the request through.
async fn renew(
    handles: Handles,
    scoped: ScopedSession<caps::UnlockMethodsWrite>,
    fresh: FreshReauth,
    body: SignedBody,
    caller: ferret_server_auth::Caller,
) -> Result<Json<RecoveryPutRes>, ApiError> {
    let now = handles.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; no recovery key is renewed");
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
        kind: ChangeKind::Recovery,
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
    Ok(Json(RecoveryPutRes {
        kek_generation: generation,
        seq: applied.seq,
    }))
}

/// The library's check of the proof against the account as it was just read,
/// and the proven body as a change. Gives the change and the new generation.
///
/// The body is parsed only after the permit, and only from the exact bytes
/// the proof covers. A body that does not parse is `400` with the code of the
/// field that failed (its nonce is used up by then).
///
/// Spec: Fase 1 § 4.6 (the proof by `sk_a` over the exact body).
fn authorize(
    proofs: &Proofs,
    scoped: &ScopedSession<caps::UnlockMethodsWrite>,
    fresh: &FreshReauth,
    body: &SignedBody,
    caller: ferret_server_auth::Caller,
    state: &ferret_server_auth::AccountAuthState<'_>,
) -> Result<(Authorized, u32), ApiError> {
    let permit = proofs.signed(
        scoped,
        fresh,
        body,
        caller,
        MutationOp::UnlockMethodRecoveryPut,
        &state.account,
    )?;
    let RecoveryPutReq {
        wrap,
        kek_generation,
        pk_r,
        manifest,
    } = body.parse::<RecoveryPutReq>(&permit)?;
    Ok((
        Authorized {
            change: UnlockChange::Recovery {
                wrap,
                generation: kek_generation,
                pk_r,
            },
            manifest,
            session_effect: permit.session_effect,
            basis: permit.basis,
        },
        kek_generation,
    ))
}
