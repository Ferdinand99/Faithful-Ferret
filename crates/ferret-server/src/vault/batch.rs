//! `POST /api/sync/batch`: up to 100 item writes in one request.
//! Spec: Fase 1 § 8.2, § 8.3.
//!
//! The request is checked in this order, and nothing reads or writes the
//! database before the write gate lets it in (after the session, which the
//! extractor checks first):
//!
//! 1. the session;
//! 2. the size of the body, at most 6 MiB (`413`);
//! 3. the JSON, with the same strictness as a single write (`400`);
//! 4. one to 100 operations, and no item id twice (`400`, nothing is written);
//! 5. the rate limits, which count the batch as one operation per item and its
//!    body in bytes (`429` with `Retry-After`);
//! 6. one place in the write queue for the whole batch (`503 busy` with
//!    `Retry-After` when the queue is full);
//! 7. each operation in turn, in its own transaction: the manifest id is
//!    `403`, an envelope or tombstone that is not stored here is `422` (or
//!    `413`), anything else goes to [`store::put_item`]. A refusal or a
//!    conflict of one operation does not stop the others;
//! 8. one notification for the batch, with the highest `seq` it wrote, sent
//!    after the last operation has committed.
//!
//! The answer is `200` with one result for each operation, in the order of
//! the request. The server never opens an envelope or checks a tag or a
//! tombstone: it has no key.
//!
//! A failure of the store inside one operation (not a conflict or a quota,
//! but a database error) is `internal` (500) in that operation's place of the
//! `200` answer, and the batch goes on. The operations that did commit are
//! recorded with their `idem`, so a retry of the whole batch answers them with
//! `replayed: true` and tries the rest again.
//!
//! The write turn is held for the whole run of the writes, also when the
//! request is dropped half way (see the comment in the handler).

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, FromRef, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use ferret_core::ItemId;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};

use super::events::EventStreams;
use super::notify::SyncEvents;
use super::quota::Limits;
use super::rate::{SyncLimits, WriteGate};
use super::store::{self, PutBody, PutOutcome, PutRequest};
use super::validate::check_envelope;
use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::ids::{DeviceId, MANIFEST_ITEM_ID, VaultId};
use crate::state::VaultDb;
use crate::wire::{
    BatchOpForm, BatchOpJson, BatchReq, BatchRes, BatchResultJson, ConflictRes, MAX_BATCH_BYTES,
    MAX_BATCH_OPS, refusal_code,
};

/// The seconds a client is told to wait when the write queue is full.
const BUSY_RETRY_SECS: u32 = 2;

/// Domain separator of the request hash of one operation.
const OP_HASH_LABEL: &[u8] = b"ferret/v1/batch-op";

/// The batch route.
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
        "/api/sync/batch",
        post(post_batch).layer(DefaultBodyLimit::max(MAX_BATCH_BYTES)),
    )
}

/// The content of an operation, owned.
///
/// No `Debug`: it holds ciphertext.
pub(crate) enum OwnedForm {
    /// A live row.
    Live {
        /// The envelope.
        blob: Vec<u8>,
        /// Its tag.
        tag: [u8; 32],
    },
    /// A tombstone.
    Deleted {
        /// The sealed tombstone.
        tomb: Vec<u8>,
    },
}

/// An operation that passed every check that needs no database.
///
/// No `Debug`: the form holds ciphertext.
pub(crate) struct PreparedOp {
    pub(crate) item_id: ItemId,
    pub(crate) form: OwnedForm,
    pub(crate) base_rev: u64,
    pub(crate) idem: [u8; 16],
    pub(crate) resurrect: bool,
    /// `SHA-256("ferret/v1/batch-op" || item_id || JSON of the operation)`.
    /// A single write hashes the item id and its raw body instead, so the same
    /// `idem` in a batch and in a single write is `idem_reuse`.
    pub(crate) request_hash: [u8; 32],
}

/// The operations of a request body, and which of them had a tombstone of the
/// wrong size (such an operation is a blank with only its id).
struct Parsed {
    ops: Vec<BatchOpJson>,
    bad_tomb: Vec<bool>,
}

/// An operation with only an id, in the place of one that did not parse. It
/// has no form, so [`prepare_ops`] refuses it.
fn blank(id: [u8; 16]) -> BatchOpJson {
    BatchOpJson {
        id,
        base_rev: 0,
        blob: None,
        tag: None,
        deleted: None,
        tomb: None,
        idem: [0; 16],
        resurrect: None,
    }
}

/// The batch in the raw body: one to 100 operations. An operation that does
/// not parse refuses the whole request, with the code of the failure, as a
/// single write does; except a tombstone of the wrong size, which is only that
/// operation's own `422`.
fn parse_body(raw: &[u8]) -> Result<Parsed, ApiError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        ops: Vec<Box<RawValue>>,
    }
    #[derive(Deserialize)]
    struct IdOnly {
        #[serde(with = "crate::wire::serde_hex16")]
        id: [u8; 16],
    }

    let envelope: Envelope =
        serde_json::from_slice(raw).map_err(|e| ApiError::coded(refusal_code(&e.to_string())))?;
    if envelope.ops.is_empty() || envelope.ops.len() > MAX_BATCH_OPS {
        return Err(ApiError::coded("bad_request"));
    }
    let mut ops = Vec::with_capacity(envelope.ops.len());
    let mut bad_tomb = Vec::with_capacity(envelope.ops.len());
    for item in &envelope.ops {
        match serde_json::from_str::<BatchOpJson>(item.get()) {
            Ok(op) => {
                ops.push(op);
                bad_tomb.push(false);
            }
            Err(e) if refusal_code(&e.to_string()) == "tombstone_invalid" => {
                // Its own refusal, but it needs an id to be one of the batch.
                let id = serde_json::from_str::<IdOnly>(item.get())
                    .map_err(|_| ApiError::coded("bad_request"))?
                    .id;
                ops.push(blank(id));
                bad_tomb.push(true);
            }
            Err(e) => return Err(ApiError::coded(refusal_code(&e.to_string()))),
        }
    }
    Ok(Parsed { ops, bad_tomb })
}

/// Checks the batch and each of its operations.
///
/// The batch as a whole is refused (`bad_request`) when it has no operation,
/// more than [`MAX_BATCH_OPS`], or one item id twice: two writes to one item in
/// one request would race their own `base_rev`, so none is written. Every
/// other failure stays in the place of its operation, as the code of the
/// answer that operation would get alone: `manifest_not_writable`,
/// `bad_request` (no single form), `unsupported_envelope` or `too_large`.
pub(crate) fn prepare_ops(
    req: &BatchReq,
) -> Result<Vec<Result<PreparedOp, &'static str>>, ApiError> {
    req.validate().map_err(|_| ApiError::coded("bad_request"))?;
    let mut seen = HashSet::with_capacity(req.ops.len());
    if !req.ops.iter().all(|op| seen.insert(op.id)) {
        return Err(ApiError::coded("bad_request"));
    }
    Ok(req.ops.iter().map(prepare_op).collect())
}

fn prepare_op(op: &BatchOpJson) -> Result<PreparedOp, &'static str> {
    let item_id = ItemId::from_bytes(op.id);
    if item_id == MANIFEST_ITEM_ID {
        return Err("manifest_not_writable");
    }
    let (form, resurrect) = match op.validate().map_err(|_| "bad_request")? {
        BatchOpForm::Live {
            blob,
            tag,
            resurrect,
        } => {
            check_envelope(blob).map_err(|e| e.code)?;
            (
                OwnedForm::Live {
                    blob: blob.to_vec(),
                    tag: *tag,
                },
                resurrect,
            )
        }
        // A tombstone is 40 bytes by the time it has parsed.
        BatchOpForm::Deleted { tomb } => (
            OwnedForm::Deleted {
                tomb: tomb.to_vec(),
            },
            false,
        ),
    };
    let json = serde_json::to_vec(op).map_err(|_| "internal")?;
    let mut hasher = Sha256::new();
    hasher.update(OP_HASH_LABEL);
    hasher.update(item_id.as_bytes());
    hasher.update(&json);
    let digest = hasher.finalize();
    let mut request_hash = [0u8; 32];
    request_hash.copy_from_slice(&digest);
    Ok(PreparedOp {
        item_id,
        form,
        base_rev: op.base_rev,
        idem: op.idem,
        resurrect,
        request_hash,
    })
}

/// The body of the request, checked: [`parse_body`] and [`prepare_ops`], with
/// the `422` of an operation with a tombstone of the wrong size in its place.
fn prepare_body(raw: &[u8]) -> Result<Vec<Result<PreparedOp, &'static str>>, ApiError> {
    let Parsed { ops, bad_tomb } = parse_body(raw)?;
    let mut prepared = prepare_ops(&BatchReq { ops })?;
    for (slot, bad) in prepared.iter_mut().zip(bad_tomb) {
        // A blank is refused as `bad_request` (or as the manifest, which comes
        // first): that is the place of the tombstone's own code.
        if bad && matches!(slot, Err("bad_request")) {
            *slot = Err("tombstone_invalid");
        }
    }
    Ok(prepared)
}

/// Runs the operations in order, each in its own transaction, and returns one
/// result for each. An operation that came in refused gets its code in its
/// place; nothing in one operation stops the next.
pub(crate) fn run_batch(
    conn: &mut Connection,
    vault: &VaultId,
    device: &DeviceId,
    ops: &[Result<PreparedOp, &'static str>],
    limits: &Limits,
    now: i64,
) -> Vec<BatchResultJson> {
    ops.iter()
        .map(|op| match op {
            Err(code) => BatchResultJson::refused(code),
            Ok(op) => run_op(conn, vault, device, op, limits, now),
        })
        .collect()
}

fn run_op(
    conn: &mut Connection,
    vault: &VaultId,
    device: &DeviceId,
    op: &PreparedOp,
    limits: &Limits,
    now: i64,
) -> BatchResultJson {
    let body = match &op.form {
        OwnedForm::Live { blob, tag } => PutBody::Live { blob, tag: *tag },
        OwnedForm::Deleted { tomb } => PutBody::Deleted { tomb },
    };
    let put = PutRequest {
        item_id: op.item_id,
        base_rev: op.base_rev,
        body,
        idem: op.idem,
        request_hash: op.request_hash,
        resurrect: op.resurrect,
    };
    match store::put_item(conn, vault, device, &put, limits, now) {
        Ok(PutOutcome::Stored { rev, seq, replayed }) => {
            BatchResultJson::stored(rev, seq, replayed)
        }
        Ok(PutOutcome::Conflict(c)) => BatchResultJson::conflict(ConflictRes {
            current_rev: c.current_rev,
            blob: c.blob,
            tag: c.tag,
            deleted: c.deleted,
        }),
        Ok(PutOutcome::IdemMismatch) => BatchResultJson::refused("idem_reuse"),
        Ok(PutOutcome::QuotaExceeded) => BatchResultJson::refused("quota_exceeded"),
        Ok(PutOutcome::ManifestNotWritable) => BatchResultJson::refused("manifest_not_writable"),
        Err(StoreError::NotFound) => BatchResultJson::refused("not_found"),
        Err(e) => {
            tracing::error!(error = %e, "batch operation failed");
            BatchResultJson::refused("internal")
        }
    }
}

/// Writes up to 100 items of the session vault.
async fn post_batch(
    session: VaultSession,
    State(db): State<VaultDb>,
    State(limits): State<Arc<SyncLimits>>,
    State(gate): State<WriteGate>,
    State(events): State<SyncEvents>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<BatchRes>, ApiError> {
    let raw = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::coded("too_large")
        } else {
            ApiError::coded("bad_request")
        }
    })?;
    let body_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
    let ops = prepare_body(&raw).inspect_err(|e| {
        tracing::info!(
            status = e.status.as_u16(),
            code = e.code,
            "batch write refused"
        );
    })?;
    drop(raw);

    let count = u32::try_from(ops.len()).unwrap_or(u32::MAX);
    limits
        .admit(&session.vault, &session.device, count, body_len)
        .map_err(|refused| {
            tracing::info!(ops = count, "batch write throttled");
            ApiError::throttled(refused.retry_after_secs)
        })?;
    let permit = gate.enter().await.map_err(|_| {
        tracing::info!(ops = count, "batch write turned away, queue full");
        ApiError {
            retry_after: Some(BUSY_RETRY_SECS),
            ..ApiError::coded("busy")
        }
    })?;

    let vault = session.vault;
    let device = session.device;
    let now = session.now;
    // The turn, the writes and the wake-up all live in the closure that runs on
    // the blocking thread. A request that is dropped (the client went away)
    // does not stop that closure, so the turn must not be freed with the
    // request: it is freed when the writes are done. The wake-up is sent there
    // too, after the last transaction of the batch has committed, so a dropped
    // request cannot lose it.
    let results = db
        .with_conn(move |conn| {
            let _turn = permit;
            let results = run_batch(conn, &vault, &device, &ops, &Limits::DEFAULT, now);
            // One wake-up for the batch: the highest `seq` it wrote. A batch
            // that only repeated earlier writes changed nothing.
            let highest = results
                .iter()
                .filter(|r| r.replayed == Some(false))
                .filter_map(|r| r.seq)
                .max();
            if let Some(seq) = highest {
                events.notify(vault, seq);
            }
            Ok(results)
        })
        .await
        .map_err(ApiError::from)
        .inspect_err(|e| {
            tracing::info!(
                status = e.status.as_u16(),
                code = e.code,
                "batch write failed"
            );
        })?;
    let stored = results.iter().filter(|r| r.status == 200).count();
    let conflicts = results.iter().filter(|r| r.status == 409).count();
    tracing::info!(
        ops = count,
        stored,
        conflicts,
        refused = results
            .len()
            .saturating_sub(stored)
            .saturating_sub(conflicts),
        "batch write"
    );
    Ok(Json(BatchRes { results }))
}
