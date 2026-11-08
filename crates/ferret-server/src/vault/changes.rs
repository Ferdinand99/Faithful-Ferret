//! `GET /api/sync/changes?since&limit`: the rows that changed after a sequence
//! number, in sequence order. Spec: Fase 1 § 8.1, § 8.2.
//!
//! `since` is exclusive: the answer holds the rows with `seq > since`. A page
//! holds at most [`MAX_LIMIT`] rows and stays below 4 MiB of JSON; `has_more`
//! says that rows are left, and the client asks again from the last `seq` it
//! got. A `since` below the feed floor (`min_valid_since`, raised when old
//! tombstones are purged) is `410 Gone`: the client may have missed deletions
//! and must list the vault again. `since=0` is never refused: a client with no
//! state has nothing to miss.
//!
//! The answer carries `restore_epoch` and `restore_seq` (the `seq` of the vault
//! at its last restore bump, 0 if it never was restored), read in the same
//! transaction as the page.
//!
//! The answer carries the head of the stored checkpoint (`seq`, digest and
//! MAC), never its entries: those are fetched with `GET /api/sync/checkpoint`
//! when a client needs them. Spec: Fase 1 § 8.2, § 8.6.

use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRef, Query, State};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use super::store::{self, Change, Changes, CheckpointHead};
use crate::error::{ApiError, status_of};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::state::VaultDb;
use crate::wire::{ChangeJson, ChangesRes, CheckpointHeadJson, MAX_JSON_INT};

/// The most rows in one answer (spec § 8.2).
pub const MAX_LIMIT: u32 = 500;

/// The rows in an answer when `limit` is left out.
const DEFAULT_LIMIT: u32 = MAX_LIMIT;

/// The most ciphertext bytes (envelopes and tombstones, as stored) in one page.
///
/// The answer is JSON: envelopes are base64url (4 bytes for 3), and every row
/// adds its id, numbers and a 43-character tag (about 250 bytes with the
/// names). With at most 500 rows, 3 000 000 bytes of ciphertext stay below the
/// 4 MiB (4 194 304 bytes) of spec § 8.2 with room to spare:
/// 3 000 000 * 4 / 3 + 500 * 250 + 400 is about 4 125 000. A page always holds
/// one row, whatever its size (an envelope is at most 64 KiB).
pub const PAGE_BYTES: usize = 3_000_000;

/// The query of the changes call.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesQuery {
    /// Rows after this sequence number; left out means from the start.
    since: Option<u64>,
    /// At most this many rows, 1 to 500 (a larger number is read as 500, 0 as 1).
    limit: Option<u32>,
}

/// The changes route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
{
    Router::new().route("/api/sync/changes", get(get_changes))
}

/// The rows of the session's vault after `since`.
async fn get_changes(
    session: VaultSession,
    query: Result<Query<ChangesQuery>, QueryRejection>,
    State(db): State<VaultDb>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::coded("bad_request"))?;
    let since = query.since.unwrap_or(0);
    if since > MAX_JSON_INT {
        return Err(ApiError::coded("bad_request"));
    }
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let vault = session.vault;
    // The page and the head come out of one read transaction: one snapshot, so
    // the head is never above `latest_seq` (a client reads that as a server
    // that lies about its top).
    let (page, head) = db
        .with_conn(move |conn| store::changes_with_head(conn, &vault, since, limit, PAGE_BYTES))
        .await?;
    // Tombstones at or below the floor may be gone: a cursor below it cannot be
    // trusted, and the client must list the vault again (spec 8.4). `since = 0`
    // is the exception: a device with no state has no deletion to miss, and a
    // listing from 0 holds every live row.
    if since != 0 && since < page.min_valid_since {
        return Ok(gone(page.min_valid_since));
    }
    Ok(Json(changes_res(page, head)).into_response())
}

/// `410 Gone {"error":"gone","min_valid_since":n}`: the cursor is below the floor
/// of the feed.
fn gone(min_valid_since: u64) -> Response {
    (
        status_of("gone"),
        Json(serde_json::json!({ "error": "gone", "min_valid_since": min_valid_since })),
    )
        .into_response()
}

/// The wire shape of a page, with the head of the stored checkpoint.
fn changes_res(page: Changes, head: Option<CheckpointHead>) -> ChangesRes {
    ChangesRes {
        changes: page.changes.into_iter().map(change_json).collect(),
        latest_seq: page.latest_seq,
        vk_epoch: page.vk_epoch,
        restore_epoch: page.restore_epoch,
        restore_seq: page.restore_seq,
        checkpoint: head.map(|(seq, digest, mac)| CheckpointHeadJson { seq, digest, mac }),
        has_more: page.has_more,
    }
}

fn change_json(change: Change) -> ChangeJson {
    ChangeJson {
        id: *change.id.as_bytes(),
        rev: change.rev,
        seq: change.seq,
        deleted: change.deleted,
        blob: change.blob,
        tag: change.tag,
        tomb: change.tomb,
    }
}
