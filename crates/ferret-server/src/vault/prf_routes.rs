//! Adding and removing a passkey (PRF) unlock method.
//!
//! ```text
//! POST   /api/vault/unlock-methods                sensitive, signed by sk_a
//! DELETE /api/vault/unlock-methods/{method_id}    sensitive, signed by sk_a
//! ```
//!
//! Both routes share the path of `GET /api/vault/unlock-methods` (the list) and
//! exist only in a build with the cargo feature `quick-unlock`. A change is a
//! sensitive request, like a new recovery key:
//!
//! 1. a vault session whose scope allows `UnlockMethodsWrite` (a full one; a
//!    device token is refused with `401`, as on every route that is not on the
//!    short list of token routes);
//! 2. that proved the master password again within five minutes, with no
//!    second factor the server would have to ask for (`403 reauth_required`,
//!    `403 second_factor_required`);
//! 3. the nonce and the proof headers and the raw body (`400` for a header of
//!    the wrong shape, which burns no nonce);
//! 4. inside the write transaction, against the account as it is read there:
//!    the library uses up the nonce and checks the proof of
//!    `unlock-method.add` or `unlock-method.remove` by `sk_a` over the exact
//!    body (`401 denied` otherwise, and the nonce is gone); only then is the
//!    body read (`400` with the code of the field that failed).
//!
//! The body is the one `ferret-core` makes, byte for byte, and its binary
//! fields are lower-case hexadecimal:
//!
//! ```text
//! add    {"method_type":3,"method_id":"<hex>","wrap":"<hex>","kek_generation":1,
//!         "credential_id":"<hex>","prf_salt":"<hex>","aaguid":"<hex>",
//!         "manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! remove {"method_id":"<hex>","manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! ```
//!
//! What the server holds of a passkey is the wrap, the credential id, the PRF
//! salt and the AAGUID (display data: all zero is stored, Ferret's own is
//! refused). The name the user gave it and its synced flag are in the sealed
//! manifest only. The rules of an addition: `method_type` is 3, the method id
//! is new, `kek_generation` is 1, the wrap is 72 bytes, the credential id is 1
//! to 1 024 bytes and not one of the account's, the PRF salt is 32 bytes and
//! not all zero, the AAGUID is 16 bytes (or left out), the account has fewer
//! than [`unlock_write::MAX_PRF_METHODS`] passkey methods, and the manifest is the next
//! revision. A removal names the method in the URL and in the body (the proof
//! covers the body, so the id has to be in it, and the two must be the same);
//! only a passkey method goes this way: the password and the recovery wrap are
//! replaced by their own routes.
//!
//! The answers: `400` for a request that is wrong in itself (the body, the
//! id in the URL, an id that is not the body's, the wrong kind of method),
//! `404` for a method the account does not have, `409 conflict` for an id or a
//! credential that is listed already, `413 quota_exceeded` for the eleventh
//! passkey, `409 write_conflict` for a manifest that is not the next revision
//! (the methods changed while the client worked), `422` for a manifest that is
//! not one this server stores. A change ends no session and no device; the
//! streams of the vault hear of the new `seq` and a backup is asked for. The
//! answer is `200 {seq}`. Nothing of the request is logged: the line that the
//! change leaves tells that a passkey method was added or removed and how many
//! the account has now, and nothing that names it.
//!
//! Spec: Fase 1 § 4.3 (adding and removing a method), § 4.6 (the endpoint
//! table and the proofs) and § 7.2.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::rejection::PathRejection;
use axum::extract::{ConnectInfo, FromRef, Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, post};
use axum::{Json, Router};
use ferret_core::MutationOp;
use ferret_core::passkey::AAGUID;
use ferret_server_auth::Clock;
use serde::{Deserialize, Serialize};

use super::notify::SyncEvents;
use super::unlock_write::{self, Authorized, ChangeKind, UnlockChange, Writer};
use crate::auth::throttle::caller_from;
use crate::error::ApiError;
use crate::http::extract::{FreshReauth, ScopedSession, SessionAuth, SignedBody, caps};
use crate::ids::MethodId;
use crate::state::{BackupStatus, Proofs, VaultDb};
use crate::wire::{SealedRowJson, hex16, u53};

/// The path of the list, which is also the path of an addition.
pub const PATH: &str = "/api/vault/unlock-methods";

/// The path of a removal.
const REMOVE_PATH: &str = "/api/vault/unlock-methods/{method_id}";

/// `method_type` of a passkey.
const TYPE_PRF: u8 = 3;

/// The length of the wrap of a passkey in bytes: nonce 24, vault key 32 and
/// tag 16.
const PRF_WRAP_LEN: usize = 72;

/// The longest credential id, in bytes.
const MAX_CREDENTIAL_ID_LEN: usize = 1024;

/// The routes that add and remove a passkey method.
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
        .route(PATH, post(add))
        .route(REMOVE_PATH, delete(remove))
}

/// A sealed row as the core writes it into a body: the revision, and the
/// envelope and the tag as hexadecimal text.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    #[serde(deserialize_with = "u53::deserialize")]
    rev: u64,
    #[serde(with = "hex_bytes")]
    envelope: Vec<u8>,
    #[serde(with = "hex_array")]
    tag: [u8; 32],
}

impl ManifestBody {
    fn row(self) -> SealedRowJson {
        SealedRowJson {
            rev: self.rev,
            envelope: self.envelope,
            tag: self.tag,
        }
    }
}

/// The body of an addition.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddBody {
    /// Must be 3.
    method_type: u8,
    #[serde(with = "crate::wire::serde_hex16")]
    method_id: [u8; 16],
    #[serde(with = "hex_bytes")]
    wrap: Vec<u8>,
    #[serde(deserialize_with = "u53::deserialize")]
    kek_generation: u64,
    #[serde(with = "hex_bytes")]
    credential_id: Vec<u8>,
    #[serde(with = "hex_array")]
    prf_salt: [u8; 32],
    /// The authenticator's AAGUID, or left out (`null` as well).
    #[serde(default, with = "crate::wire::serde_hex16_opt")]
    aaguid: Option<[u8; 16]>,
    manifest: ManifestBody,
}

/// The body of a removal.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveBody {
    #[serde(with = "crate::wire::serde_hex16")]
    method_id: [u8; 16],
    manifest: ManifestBody,
}

/// The `200` answer: the vault's `seq` after the manifest was written.
#[derive(Serialize)]
struct Changed {
    seq: u64,
}

/// What the routes use besides the extractors.
struct Handles {
    proofs: Proofs,
    db: VaultDb,
    clock: Arc<dyn Clock>,
    events: SyncEvents,
    backup: BackupStatus,
}

/// `POST /api/vault/unlock-methods`.
#[allow(clippy::too_many_arguments)] // the handles and the extractors of one route
async fn add(
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
) -> Result<Json<Changed>, ApiError> {
    let handles = Handles {
        proofs,
        db,
        clock,
        events,
        backup,
    };
    let caller = caller_from(&headers, Some(peer));
    change(
        handles,
        scoped,
        fresh,
        body,
        caller,
        ChangeKind::AddMethod,
        |permit, body| {
            let add = body.parse::<AddBody>(permit)?;
            let change = add_change(&add)?;
            Ok((change, add.manifest.row()))
        },
    )
    .await
}

/// `DELETE /api/vault/unlock-methods/{method_id}`.
#[allow(clippy::too_many_arguments)] // the handles and the extractors of one route
async fn remove(
    State(proofs): State<Proofs>,
    State(db): State<VaultDb>,
    State(clock): State<Arc<dyn Clock>>,
    State(events): State<SyncEvents>,
    State(backup): State<BackupStatus>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    scoped: ScopedSession<caps::UnlockMethodsWrite>,
    fresh: FreshReauth,
    id: Result<Path<String>, PathRejection>,
    body: SignedBody,
) -> Result<Json<Changed>, ApiError> {
    // The id in the URL is read before anything is checked against the nonce:
    // an id that is not one burns none.
    let Path(id) = id.map_err(|_| ApiError::coded("bad_request"))?;
    let url_id = hex16::decode(&id).map_err(|_| ApiError::coded("bad_request"))?;
    let handles = Handles {
        proofs,
        db,
        clock,
        events,
        backup,
    };
    let caller = caller_from(&headers, Some(peer));
    change(
        handles,
        scoped,
        fresh,
        body,
        caller,
        ChangeKind::RemoveMethod,
        move |permit, body| {
            let remove = body.parse::<RemoveBody>(permit)?;
            // The proof covers the body, so the body names the method; the URL
            // names it too, and the two are the same one.
            if remove.method_id != url_id {
                return Err(ApiError::coded("bad_request"));
            }
            let change = UnlockChange::RemoveMethod {
                method_id: MethodId::from_bytes(remove.method_id),
            };
            Ok((change, remove.manifest.row()))
        },
    )
    .await
}

/// The change an addition asks for, once its fields are known to be well
/// formed. The content rules that need no database are here, the ones that do
/// are in the write transaction.
fn add_change(add: &AddBody) -> Result<UnlockChange, ApiError> {
    let bad = || ApiError::coded("bad_request");
    if add.method_type != TYPE_PRF
        || add.kek_generation != 1
        || add.wrap.len() != PRF_WRAP_LEN
        || add.method_id == [0u8; 16]
        || add.credential_id.is_empty()
        || add.credential_id.len() > MAX_CREDENTIAL_ID_LEN
        || add.prf_salt.iter().all(|byte| *byte == 0)
        // Display data, but Ferret's own AAGUID is refused as an extra guard:
        // such a passkey would live in the vault it has to open (Fase 1 § 9.4).
        || add.aaguid == Some(AAGUID)
    {
        return Err(bad());
    }
    Ok(UnlockChange::AddMethod {
        method_id: MethodId::from_bytes(add.method_id),
        wrap: add.wrap.clone(),
        credential_id: add.credential_id.clone(),
        prf_salt: add.prf_salt,
        aaguid: add.aaguid,
    })
}

/// The change itself, once the extractors have let the request through.
/// `parse` reads the proven body into the change and the new manifest.
async fn change<P>(
    handles: Handles,
    scoped: ScopedSession<caps::UnlockMethodsWrite>,
    fresh: FreshReauth,
    body: SignedBody,
    caller: ferret_server_auth::Caller,
    kind: ChangeKind,
    parse: P,
) -> Result<Json<Changed>, ApiError>
where
    P: FnOnce(
            &ferret_server_auth::SignedPermit,
            &SignedBody,
        ) -> Result<(UnlockChange, SealedRowJson), ApiError>
        + Send
        + 'static,
{
    let now = handles.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; no unlock method is changed");
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
        kind,
    };
    let vault = facts.vault();
    let account = facts.account();
    let op = match kind {
        ChangeKind::RemoveMethod => MutationOp::UnlockMethodRemove,
        _ => MutationOp::UnlockMethodAdd,
    };
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
    let applied = db
        .with_conn(move |conn| {
            let applied = unlock_write::apply(conn, &writer, now, |state| {
                let permit = proofs.signed(&scoped, &fresh, &body, caller, op, &state.account)?;
                let (change, manifest) = parse(&permit, &body)?;
                Ok(Authorized {
                    change,
                    manifest,
                    session_effect: permit.session_effect,
                    basis: permit.basis,
                })
            });
            if let Ok(applied) = &applied {
                unlock_write::after_commit(applied, &events, &backup, &vault);
                audit(conn, &account, kind);
            }
            Ok(applied)
        })
        .await??;
    Ok(Json(Changed { seq: applied.seq }))
}

/// The line a change leaves in the log: what happened and how many passkey
/// methods the account has now. Nothing that names the method or the account.
fn audit(conn: &rusqlite::Connection, account: &crate::ids::AccountId, kind: ChangeKind) {
    let count: Result<i64, _> = conn.query_row(
        "SELECT COUNT(*) FROM ferret_unlock_methods WHERE account_id = ?1 AND method_type = 3",
        [account.as_bytes().as_slice()],
        |row| row.get(0),
    );
    let what = match kind {
        ChangeKind::RemoveMethod => "a passkey unlock method was removed",
        _ => "a passkey unlock method was added",
    };
    match count {
        Ok(passkeys) => tracing::info!(passkeys, "{what}"),
        Err(_) => tracing::info!("{what}"),
    }
}

/// `#[serde(with = "hex_bytes")]` for `Vec<u8>`: lower-case hexadecimal.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, de};

    use crate::wire::hex_text;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex_text::decode(&text).map_err(de::Error::custom)
    }
}

/// `#[serde(with = "hex_array")]` for `[u8; 32]`: 64 lower-case hexadecimal
/// characters.
mod hex_array {
    use serde::{Deserialize, Deserializer, de};

    use crate::wire::hex_text;

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = hex_text::decode(&text).map_err(de::Error::custom)?;
        <[u8; 32]>::try_from(bytes).map_err(|_| de::Error::custom("not 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::hex_text;

    #[test]
    fn hexadecimal_is_strict() {
        assert_eq!(hex_text::decode("00ff7a").expect("hex"), [0x00, 0xff, 0x7a]);
        assert_eq!(hex_text::decode("").expect("hex"), Vec::<u8>::new());
        for refused in ["0", "0G", "FF", "0x00", " 00", "00 ", "é0"] {
            assert!(hex_text::decode(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn the_sizes_are_those_the_core_makes() {
        assert_eq!(PRF_WRAP_LEN, ferret_core::wrap::WRAP_LEN);
        assert_eq!(
            MAX_CREDENTIAL_ID_LEN,
            ferret_core::pinning::MAX_CREDENTIAL_ID_LEN
        );
    }
}
