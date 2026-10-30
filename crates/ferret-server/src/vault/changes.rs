//! `GET /api/sync/changes?since&limit`: the rows that changed after a sequence
//! number, in sequence order. Spec: Fase 1 § 8.1, § 8.2.
//!
//! `since` is exclusive: the answer holds the rows with `seq > since`. A page
//! holds at most [`MAX_LIMIT`] rows and stays below 4 MiB of JSON; `has_more`
//! says that rows are left, and the client asks again from the last `seq` it
//! got. A `since` below the feed floor (`min_valid_since`, raised when old
//! tombstones are purged) is `410 Gone`: the client may have missed deletions
//! and must list the vault again.

use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRef, Query, State};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;

use super::store::{self, Change, Changes};
use crate::error::{ApiError, status_of};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::state::VaultDb;
use crate::wire::{ChangeJson, ChangesRes, MAX_JSON_INT};

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
    let page = db
        .with_conn(move |conn| store::changes_since(conn, &vault, since, limit, PAGE_BYTES))
        .await?;
    if since < page.min_valid_since {
        // Tombstones at or below the floor may be gone: the cursor cannot be
        // trusted, and the client must list the vault again (spec 8.4).
        return Ok(gone(page.min_valid_since));
    }
    Ok(Json(changes_res(page)).into_response())
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

/// The wire shape of a page. The checkpoint head is left out: this version
/// does not store checkpoints that a client uploads.
fn changes_res(page: Changes) -> ChangesRes {
    ChangesRes {
        changes: page.changes.into_iter().map(change_json).collect(),
        latest_seq: page.latest_seq,
        vk_epoch: page.vk_epoch,
        restore_epoch: page.restore_epoch,
        checkpoint: None,
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
