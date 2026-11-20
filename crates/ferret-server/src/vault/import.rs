//! The import window.
//!
//! `POST /api/sync/import`: a session that has proved the master password again
//! opens one window per vault, in which the operations of an import are counted
//! apart from the ordinary per-device limit. The batches of the import name the
//! window (`import_window`, see `batch.rs`), and each stored operation is taken
//! from it. Spec: Fase 1 § 8.2.
//!
//! The request is checked in this order:
//!
//! 1. the session, which must allow writes (`401`, `403`);
//! 2. a fresh re-authentication of this session (`403 reauth_required`, and
//!    `403 second_factor_required` for an account with a second factor);
//! 3. the size and the JSON of the body (`413`, `400`), and `ops` of at least 1
//!    (`400`);
//! 4. the room of the vault: `ops` may not be more than the live rows and the
//!    bytes the vault may still hold allow (`413 quota_exceeded`);
//! 5. the window: a vault that has an open one answers `409 import_window_open`.
//!
//! The answer is `200` with the id of the window, its size and the seconds it
//! lasts. The window belongs to the device of the session. It is kept in memory
//! only (see [`ImportWindows`]).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, FromRef, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use ferret_server_auth::Clock;
use rusqlite::{Connection, OptionalExtension as _};

use super::quota::Limits;
use super::rate::{IMPORT_WINDOW_SECS, ImportRefused};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{FreshReauth, ScopedSession, SessionAuth, caps};
use crate::ids::VaultId;
use crate::state::{ImportWindows, VaultDb};
use crate::wire::{ImportWindowReq, ImportWindowRes, refusal_code};

/// The most bytes of the request body: `{"ops":<number>}` is a few bytes.
const BODY_LIMIT: usize = 1024;

/// The routes of the import window.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    ImportWindows: FromRef<S>,
    Arc<dyn Clock>: FromRef<S>,
{
    Router::new().route(
        "/api/sync/import",
        post(post_import).layer(DefaultBodyLimit::max(BODY_LIMIT)),
    )
}

/// The answer for a refusal of the window table.
pub(crate) fn refused(why: ImportRefused) -> ApiError {
    ApiError::coded(match why {
        ImportRefused::Open => "import_window_open",
        ImportRefused::Invalid => "import_window_invalid",
    })
}

/// How many more operations the vault can take: the live rows it may still
/// hold, or none when its bytes are used up. A vault that is not there has no
/// room.
fn room(conn: &Connection, vault: &VaultId, limits: &Limits) -> Result<u64, StoreError> {
    let used: Option<(i64, i64)> = conn
        .query_row(
            "SELECT item_count, bytes_used FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((items, bytes)) = used else {
        return Ok(0);
    };
    let items = u64::try_from(items).unwrap_or(u64::MAX);
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    if bytes >= limits.max_bytes {
        return Ok(0);
    }
    Ok(u64::from(limits.max_items).saturating_sub(items))
}

/// Opens an import window for the device of the session.
async fn post_import(
    session: ScopedSession<caps::SyncWrite>,
    _fresh: FreshReauth,
    State(db): State<VaultDb>,
    State(windows): State<ImportWindows>,
    body: Result<Bytes, BytesRejection>,
) -> Result<Json<ImportWindowRes>, ApiError> {
    let raw = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::coded("too_large")
        } else {
            ApiError::coded("bad_request")
        }
    })?;
    let req: ImportWindowReq =
        serde_json::from_slice(&raw).map_err(|e| ApiError::coded(refusal_code(&e.to_string())))?;
    if req.ops == 0 {
        return Err(ApiError::coded("bad_request"));
    }

    let facts = session.session();
    let (vault, device, now) = (facts.vault(), facts.device(), facts.now());
    let free = db
        .with_conn(move |conn| room(conn, &vault, &Limits::DEFAULT))
        .await
        .map_err(ApiError::from)?;
    if u64::from(req.ops) > free {
        tracing::info!(ops = req.ops, "import window refused, over the room");
        return Err(ApiError::coded("quota_exceeded"));
    }
    let window_id = windows.open(&vault, &device, req.ops, now).map_err(|why| {
        tracing::info!(ops = req.ops, "import window refused, one is open");
        refused(why)
    })?;
    tracing::info!(ops = req.ops, "import window opened");
    Ok(Json(ImportWindowRes {
        window_id,
        ops: req.ops,
        expires_in: IMPORT_WINDOW_SECS,
    }))
}
