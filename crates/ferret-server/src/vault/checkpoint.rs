//! `PUT` and `GET /api/sync/checkpoint`: the signed checkpoint that a client
//! uploads and another one fetches to check the rows the server shows.
//! Spec: Fase 1 § 8.2, § 8.6.
//!
//! The server **checks the structure and never the MAC**: it has no key, so
//! it cannot tell a checkpoint that a client signed from one that somebody
//! made up, and it does not pretend to. It stores the one with the highest
//! `seq` (and its `entries`), and clients verify what they fetch.
//!
//! `PUT` is checked in this order, and nothing reads or writes the database
//! before the write itself (after the session, which the extractor checks
//! first):
//!
//! 1. the size of the body, at most 4 MiB (`413 too_large`);
//! 2. the JSON (unknown, repeated and mistyped fields are refused, `400`);
//! 3. the structure ([`check_structure`]): `422 checkpoint_invalid`, and more
//!    than 50 000 entries `413 too_large`;
//! 4. the rate limit of the device (`429 throttled`): one operation and the
//!    bytes of the body from its bucket, like an item write, so uploads that
//!    the store refuses (stale, above the vault) are limited too;
//! 5. the pace of the device: one stored upload per ten minutes (`429
//!    throttled`). A refused or failed upload does not use up the turn;
//! 6. a turn at the write gate (`503 busy`);
//! 7. the write ([`store::put_checkpoint`]): a `seq` above the vault's is
//!    `422 checkpoint_invalid`, a lower one (or the same `seq` with other
//!    bytes) is `409 checkpoint_stale` with the stored `seq`, and the same
//!    bytes again are `200`;
//! 8. after a stored checkpoint, the turn of the device is used up.
//!
//! The answers carry `no-store` through the vault layer, and nothing of the
//! body reaches the log: the log line holds the `seq` and a count.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::put;
use axum::{Json, Router};
use ferret_core::integrity::checkpoint::parse_entries;
use sha2::{Digest as _, Sha256};

use super::events::EventStreams;
use super::items::{busy, throttled};
use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use super::store::{self, CheckpointOutcome, StoredCheckpoint};
use crate::error::ApiError;
use crate::http::extract::{SessionAuth, VaultSession};
use crate::state::VaultDb;
use crate::wire::{
    CHECKPOINT_ENTRY_LEN, CheckpointJson, CheckpointPutRes, CheckpointStaleRes,
    MAX_CHECKPOINT_ENTRIES, refusal_code,
};

/// The most bytes of a request body: 50 000 entries are 2 800 000 bytes, about
/// 3 733 400 characters of base64url, so a full checkpoint fits.
pub const BODY_LIMIT: usize = 4 * 1024 * 1024;

/// The checkpoint routes.
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
        "/api/sync/checkpoint",
        put(put_checkpoint)
            .get(get_checkpoint)
            .layer(DefaultBodyLimit::max(BODY_LIMIT)),
    )
}

/// What the server can check of a checkpoint without a key: the shape of
/// `entries` and that `digest` is their SHA-256. Never the MAC.
///
/// Spec: Fase 1 § 8.6. The error is the code of the answer: `too_large` for
/// more than 50 000 entries, `checkpoint_invalid` for the rest:
///
/// * `entries` is a whole number of 56-byte entries;
/// * the `item_id`s are strictly ascending (sorted, no repeats);
/// * every `rev` is at least 1;
/// * `digest` is the SHA-256 of `entries`.
///
/// Whether `seq` is at most the `seq` of the vault is for the store, in the
/// transaction that writes.
pub(crate) fn check_structure(cp: &CheckpointJson) -> Result<(), &'static str> {
    let max_bytes = MAX_CHECKPOINT_ENTRIES.saturating_mul(CHECKPOINT_ENTRY_LEN);
    if cp.entries.len() > max_bytes {
        return Err("too_large");
    }
    let entries = parse_entries(&cp.entries).map_err(|_| "checkpoint_invalid")?;
    if entries.iter().any(|entry| entry.rev == 0) {
        return Err("checkpoint_invalid");
    }
    let digest: [u8; 32] = Sha256::digest(&cp.entries).into();
    if digest != cp.digest {
        return Err("checkpoint_invalid");
    }
    Ok(())
}

/// Stores the checkpoint of the session vault, if it is newer than the stored one.
async fn put_checkpoint(
    session: VaultSession,
    State(db): State<VaultDb>,
    State(limits): State<Arc<SyncLimits>>,
    State(gate): State<WriteGate>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let raw = body
        .map_err(|rejection| {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                ApiError::coded("too_large")
            } else {
                ApiError::coded("bad_request")
            }
        })
        .inspect_err(refused)?;
    let cp: CheckpointJson = serde_json::from_slice(&raw)
        .map_err(|e| ApiError::coded(refusal_code(&e.to_string())))
        .inspect_err(refused)?;
    check_structure(&cp)
        .map_err(ApiError::coded)
        .inspect_err(refused)?;

    let vault = session.vault;
    let device = session.device;
    // An upload that the store will refuse costs the device its bucket too.
    limits
        .admit(
            &vault,
            &device,
            1,
            u64::try_from(raw.len()).unwrap_or(u64::MAX),
        )
        .map_err(throttled)
        .inspect_err(refused)?;
    limits
        .checkpoint_allowed(&vault, &device)
        .map_err(throttled)
        .inspect_err(refused)?;
    let permit = gate.enter().await.map_err(busy).inspect_err(refused)?;
    let seq = cp.seq;
    let stored = StoredCheckpoint {
        seq: cp.seq,
        digest: cp.digest,
        mac: cp.mac,
        entries: cp.entries,
    };
    let outcome = db
        .with_conn(move |conn| {
            // The turn moves into the closure: it is held until the write has
            // committed, even if this handler is dropped while it waits.
            let _turn = permit;
            store::put_checkpoint(conn, &vault, &stored)
        })
        .await
        .map_err(ApiError::from)
        .inspect_err(|e| {
            tracing::info!(
                seq,
                status = e.status.as_u16(),
                code = e.code,
                "checkpoint write failed"
            );
        })?;

    match outcome {
        CheckpointOutcome::Stored { seq } => {
            limits.checkpoint_stored(&vault, &device);
            tracing::info!(seq, "checkpoint stored");
            Ok(Json(CheckpointPutRes { seq }).into_response())
        }
        CheckpointOutcome::Unchanged { seq } => {
            tracing::info!(seq, "checkpoint unchanged");
            Ok(Json(CheckpointPutRes { seq }).into_response())
        }
        CheckpointOutcome::Stale { stored_seq } => {
            tracing::info!(seq, stored_seq, "checkpoint stale");
            Ok((
                StatusCode::CONFLICT,
                Json(CheckpointStaleRes::new(stored_seq)),
            )
                .into_response())
        }
        CheckpointOutcome::AboveVault => {
            tracing::info!(seq, "checkpoint above the vault");
            Err(ApiError::coded("checkpoint_invalid"))
        }
    }
}

/// Logs a refused upload: the status and the code, nothing of the body.
fn refused(error: &ApiError) {
    tracing::info!(
        status = error.status.as_u16(),
        code = error.code,
        "checkpoint upload refused"
    );
}

/// The stored checkpoint of the session vault, with its entries.
async fn get_checkpoint(
    session: VaultSession,
    State(db): State<VaultDb>,
) -> Result<Response, ApiError> {
    let vault = session.vault;
    let stored = db
        .with_conn(move |conn| store::get_checkpoint(conn, &vault))
        .await?;
    Ok(Json(CheckpointJson {
        seq: stored.seq,
        digest: stored.digest,
        mac: stored.mac,
        entries: stored.entries,
    })
    .into_response())
}
