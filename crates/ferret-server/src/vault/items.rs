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
//!    the request has exactly one form: a live row or a tombstone, without
//!    `resurrect: true`;
//! 4. the item id (32 lower-case hexadecimal characters), which is not the
//!    manifest id;
//! 5. the content: for a live row, an envelope of at most 64 KiB whose version,
//!    suite and kind are the ones this server stores (an item, with its key
//!    wrap); for a tombstone, 40 bytes;
//! 6. the write ([`store::put_item`]), with `SHA-256(item_id || raw body)` as
//!    the request hash of the idempotency record.
//!
//! The server never opens an envelope or checks a tag or a tombstone: it has no
//! key. It stores what a signed-in client sends, under the compare-and-set of
//! the store.

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, FromRef, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse as _, Response};
use axum::routing::put;
use axum::{Json, Router};
use ferret_core::envelope::{KIND_ITEM, parse_envelope};
use ferret_core::{Error as CoreError, ItemId};
use sha2::{Digest as _, Sha256};

use super::quota::Limits;
use super::store::{self, PutBody, PutOutcome, PutRequest};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::ids::MANIFEST_ITEM_ID;
use crate::state::VaultDb;
use crate::wire::{ConflictRes, PutItemForm, PutItemReq, PutItemRes, hex16, refusal_code};

/// The most bytes of a request body. An envelope of 64 KiB is about 87 400
/// characters of base64url, so a full envelope fits with room for the rest.
pub const BODY_LIMIT: usize = 128 * 1024;

/// The length of a tombstone in bytes: nonce, tag and an empty plaintext.
const TOMB_LEN: usize = 40;

/// The item routes.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
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
    let request: PutItemReq = serde_json::from_slice(raw).map_err(|e| {
        let code = refusal_code(&e.to_string());
        // A tombstone that is not 40 bytes is the one fixed-size refusal that
        // is a well-formed request about content the server cannot take.
        if code == "tombstone_invalid" {
            ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, code)
        } else {
            ApiError::bad_request(code)
        }
    })?;
    let form = request
        .validate()
        .map_err(|_| ApiError::bad_request("bad_request"))?;

    let item_id =
        ItemId::from_bytes(hex16::decode(id).map_err(|_| ApiError::bad_request("bad_request"))?);
    if item_id == MANIFEST_ITEM_ID {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "manifest_not_writable",
        ));
    }

    match form {
        PutItemForm::Live { blob, .. } => check_envelope(blob)?,
        PutItemForm::Deleted { tomb } => {
            if tomb.len() != TOMB_LEN {
                return Err(ApiError::new(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "tombstone_invalid",
                ));
            }
        }
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

/// An envelope of an item, in a version and suite this server stores. The
/// structure is checked without any key; whether it opens is for the client.
fn check_envelope(blob: &[u8]) -> Result<(), ApiError> {
    match parse_envelope(blob) {
        Ok(view) if view.kind == KIND_ITEM && view.ik_wrap.is_some() => Ok(()),
        Err(CoreError::TooLarge) => Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large")),
        // A version, suite or kind that is not an item, or a structure that is
        // no envelope: one answer, so the server tells nothing about which.
        _ => Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported_envelope",
        )),
    }
}

/// Writes one item of the session vault.
async fn put_item(
    session: VaultSession,
    State(db): State<VaultDb>,
    Path(id): Path<String>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Response, ApiError> {
    let raw = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "too_large")
        } else {
            ApiError::bad_request("bad_request")
        }
    })?;
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
    let outcome = db
        .with_conn(move |conn| {
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
            };
            store::put_item(conn, &vault, &device, &put, &Limits::DEFAULT, now)
        })
        .await
        .inspect_err(|_| tracing::info!(item_id = %item_hex, status = 500, "item write failed"))?;

    let (status, code) = match &outcome {
        PutOutcome::Stored { .. } => (StatusCode::OK, "stored"),
        PutOutcome::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        PutOutcome::IdemMismatch => (StatusCode::UNPROCESSABLE_ENTITY, "idem_reuse"),
        PutOutcome::QuotaExceeded => (StatusCode::PAYLOAD_TOO_LARGE, "quota_exceeded"),
        PutOutcome::ManifestNotWritable => (StatusCode::FORBIDDEN, "manifest_not_writable"),
    };
    tracing::info!(item_id = %item_hex, status = status.as_u16(), code, "item write");

    match outcome {
        PutOutcome::Stored { rev, seq, replayed } => {
            Ok(Json(PutItemRes { rev, seq, replayed }).into_response())
        }
        PutOutcome::Conflict(conflict) => Ok((
            StatusCode::CONFLICT,
            Json(ConflictRes {
                current_rev: conflict.current_rev,
                blob: conflict.blob,
                tag: conflict.tag,
                deleted: conflict.deleted,
            }),
        )
            .into_response()),
        PutOutcome::IdemMismatch | PutOutcome::QuotaExceeded | PutOutcome::ManifestNotWritable => {
            Err(ApiError::new(status, code))
        }
    }
}
