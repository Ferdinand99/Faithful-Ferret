//! `PUT /api/sync/items/{id}`: one item write, live or tombstone.
//! Spec: Fase 1 § 8.1, § 8.3.
//!
//! The request is checked in this order, and nothing reads or writes the
//! database before the last step (after the session, which the extractor
//! checks first):
//!
//! 1. the session;
//! 2. the size of the body, at most 128 KiB;
//! 3. the JSON (unknown, repeated and mistyped fields are refused), and that
//!    the request has exactly one form: a live row or a tombstone, where only
//!    a live row may carry `resurrect: true`;
//! 4. the item id (32 lower-case hexadecimal characters), which is not the
//!    manifest id;
//! 5. the content: for a live row, an envelope of at most 64 KiB whose version,
//!    suite and kind are the ones this server stores (an item, with its key
//!    wrap); for a tombstone, 40 bytes;
//! 6. the rate limit of the device (`429 throttled`), counting one operation
//!    and the bytes of the body;
//! 7. a turn at the write gate (`503 busy`);
//! 8. the write ([`store::put_item`]), with `SHA-256(item_id || raw body)` as
//!    the request hash of the idempotency record. A write that is stored (not
//!    a replay) tells the event streams the new `seq`.
//!
//! Steps 6 and 7 come after the content checks, so a request that is wrong in
//! itself costs the device nothing from its bucket and takes no turn.
//!
//! The server never opens an envelope or checks a tag or a tombstone: it has no
//! key. It stores what a signed-in client sends, under the compare-and-set of
//! the store.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, PathRejection};
use axum::extract::{DefaultBodyLimit, FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::put;
use axum::{Json, Router};
use ferret_core::ItemId;
use sha2::{Digest as _, Sha256};

use super::events::EventStreams;
use super::notify::SyncEvents;
use super::quota::Limits;
use super::rate::{SyncLimits, WriteGate, busy, throttled};
use super::store::{self, PutBody, PutOutcome, PutRequest};
use super::validate::check_envelope;
use crate::error::{ApiError, StoreError, status_of};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::ids::MANIFEST_ITEM_ID;
use crate::state::VaultDb;
use crate::wire::{ConflictRes, PutItemForm, PutItemReq, PutItemRes, hex16, refusal_code};

/// The most bytes of a request body. An envelope of 64 KiB is about 87 400
/// characters of base64url, so a full envelope fits with room for the rest.
pub const BODY_LIMIT: usize = 128 * 1024;

/// The item routes.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    SyncEvents: FromRef<S>,
    Arc<SyncLimits>: FromRef<S>,
    WriteGate: FromRef<S>,
    Arc<EventStreams>: FromRef<S>,
{
    Router::new().route(
        "/api/sync/items/{id}",
        put(put_item).layer(DefaultBodyLimit::max(BODY_LIMIT)),
    )
}

/// A request that passed every check that needs no database.
///
/// No `Debug`: the request holds ciphertext.
struct Prepared {
    item_id: ItemId,
    request: PutItemReq,
    request_hash: [u8; 32],
}

/// Steps 3 to 5 of the module order, on the raw body. No database, no clock,
/// no session: a request this refuses can never have touched storage.
fn prepare(id: &str, raw: &[u8]) -> Result<Prepared, ApiError> {
    let request: PutItemReq =
        serde_json::from_slice(raw).map_err(|e| ApiError::coded(refusal_code(&e.to_string())))?;
    let form = request
        .validate()
        .map_err(|_| ApiError::coded("bad_request"))?;

    let item_id =
        ItemId::from_bytes(hex16::decode(id).map_err(|_| ApiError::coded("bad_request"))?);
    if item_id == MANIFEST_ITEM_ID {
        return Err(ApiError::coded("manifest_not_writable"));
    }

    // A tombstone is 40 bytes by the time it has parsed (`tombstone_invalid`).
    if let PutItemForm::Live { blob, .. } = form {
        check_envelope(blob)?;
    }

    let mut hasher = Sha256::new();
    hasher.update(item_id.as_bytes());
    hasher.update(raw);
    let digest = hasher.finalize();
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&digest);
    Ok(Prepared {
        item_id,
        request,
        request_hash,
    })
}

/// Writes one item of the session vault.
async fn put_item(
    session: VaultSession,
    State(db): State<VaultDb>,
    State(limits): State<Arc<SyncLimits>>,
    State(gate): State<WriteGate>,
    State(events): State<SyncEvents>,
    id: Result<Path<String>, PathRejection>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let raw = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::coded("too_large")
        } else {
            ApiError::coded("bad_request")
        }
    })?;
    let Path(id) = id.map_err(|_| ApiError::coded("bad_request"))?;
    let prepared = prepare(&id, &raw).inspect_err(|e| {
        tracing::info!(
            status = e.status.as_u16(),
            code = e.code,
            "item write refused"
        );
    })?;
    let item_hex = hex16::encode(prepared.item_id.as_bytes());

    let vault = session.vault;
    let device = session.device;
    let now = session.now;
    let resurrect = prepared.request.resurrect_requested();
    limits
        .admit(
            &vault,
            &device,
            1,
            u64::try_from(raw.len()).unwrap_or(u64::MAX),
        )
        .map_err(throttled)
        .inspect_err(|e| {
            tracing::info!(
                item_id = %item_hex,
                status = e.status.as_u16(),
                code = e.code,
                "item write refused"
            );
        })?;
    let permit = gate.enter().await.map_err(busy).inspect_err(|e| {
        tracing::info!(
            item_id = %item_hex,
            status = e.status.as_u16(),
            code = e.code,
            "item write refused"
        );
    })?;
    let outcome = db
        .with_conn(move |conn| {
            // The turn moves into the closure: it is held until the write has
            // committed, even if this handler is dropped while it waits.
            let _turn = permit;
            let Prepared {
                item_id,
                request,
                request_hash,
            } = prepared;
            let body = match request.validate() {
                Ok(PutItemForm::Live { blob, tag }) => PutBody::Live { blob, tag: *tag },
                Ok(PutItemForm::Deleted { tomb }) => PutBody::Deleted { tomb },
                // `prepare` validated this very request.
                Err(_) => return Err(StoreError::Invalid("request form")),
            };
            let put = PutRequest {
                item_id,
                base_rev: request.base_rev,
                body,
                idem: request.idem,
                request_hash,
                resurrect,
            };
            store::put_item(conn, &vault, &device, &put, &Limits::DEFAULT, now)
        })
        .await
        .map_err(ApiError::from)
        .inspect_err(|e| {
            tracing::info!(
                item_id = %item_hex,
                status = e.status.as_u16(),
                code = e.code,
                "item write failed"
            );
        })?;

    let (status, code) = match &outcome {
        PutOutcome::Stored { .. } => (StatusCode::OK, "stored"),
        PutOutcome::Conflict(_) => (status_of("conflict"), "conflict"),
        PutOutcome::IdemMismatch => (status_of("idem_reuse"), "idem_reuse"),
        PutOutcome::QuotaExceeded => (status_of("quota_exceeded"), "quota_exceeded"),
        PutOutcome::ManifestNotWritable => {
            (status_of("manifest_not_writable"), "manifest_not_writable")
        }
    };
    tracing::info!(item_id = %item_hex, status = status.as_u16(), code, "item write");

    match outcome {
        PutOutcome::Stored { rev, seq, replayed } => {
            // A replay changed nothing, so there is nothing to tell.
            if !replayed {
                events.notify(vault, seq);
            }
            Ok(Json(PutItemRes { rev, seq, replayed }).into_response())
        }
        PutOutcome::Conflict(conflict) => Ok((
            status,
            Json(ConflictRes {
                current_rev: conflict.current_rev,
                blob: conflict.blob,
                tag: conflict.tag,
                deleted: conflict.deleted,
            }),
        )
            .into_response()),
        PutOutcome::IdemMismatch | PutOutcome::QuotaExceeded | PutOutcome::ManifestNotWritable => {
            Err(ApiError::coded(code))
        }
    }
}
