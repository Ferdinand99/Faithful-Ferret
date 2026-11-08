//! `GET /api/sync/items?after=<id>&limit=<n>`: every row of the vault, page by
//! page in `item_id` order, tombstones and the manifest row included. Spec:
//! Fase 1 § 8.4 (full reconciliation), § 8.6.
//!
//! This is what a client does when its place in the feed is gone (a cursor below
//! `min_valid_since`, a new vault key, a restored server) and on its first
//! start. It is never `410`: it is the way out of one. Tombstones are listed
//! because the checkpoint check (`verify_checkpoint`) needs them: a live row
//! without an entry, or an entry without a row, is told apart from a deletion
//! only by the tombstone itself.
//!
//! Every page is read in one read transaction, and `as_of_seq` is the vault's
//! counter in that same transaction. A client keeps the `as_of_seq` of the
//! first page and goes on with the changes feed from there: a row written while
//! it pages is on a later page, or has a `seq` above `as_of_seq` and comes with
//! the feed.
//!
//! The server does not promise that the pages of one listing are one snapshot;
//! a client that gets ids that do not rise, or epochs that change between pages,
//! treats the listing as a lie.
//!
//! Also here: `restore_epoch`, the counter that tells clients the server was
//! restored from an older copy (spec § 8.6, "Legitimate rollbacks"). Only the
//! command `ferret restore-epoch bump` raises it.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
use axum::extract::{FromRef, Query, State};
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::types::Type;
use rusqlite::{Connection, Row, TransactionBehavior, params};
use serde::Deserialize;

use super::changes::{MAX_LIMIT, PAGE_BYTES};
use super::events::EventStreams;
use super::notify::SyncEvents;
use super::rate::{SyncLimits, WriteGate};
use super::store::{Change, column_u64};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::ids::{ItemId, VaultId};
use crate::state::VaultDb;
use crate::wire::{ChangeJson, ItemsRes, MAX_JSON_INT, hex16};

/// The rows in an answer when `limit` is left out.
const DEFAULT_LIMIT: u32 = MAX_LIMIT;

/// A page of the listing.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemsPage {
    /// The rows after `after`, in `item_id` order.
    pub items: Vec<Change>,
    /// The vault's `seq` in the transaction that read the page.
    pub as_of_seq: u64,
    /// The epoch of the vault key.
    pub vk_epoch: u64,
    /// How many times the vault was restored.
    pub restore_epoch: u64,
    /// The id of the last row of the page, when more rows follow.
    pub next_after: Option<ItemId>,
    /// Whether there are more rows after this page.
    pub has_more: bool,
}

impl std::fmt::Debug for ItemsPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ItemsPage")
            .field("rows", &self.items.len())
            .field("as_of_seq", &self.as_of_seq)
            .field("vk_epoch", &self.vk_epoch)
            .field("restore_epoch", &self.restore_epoch)
            .field("has_more", &self.has_more)
            .finish_non_exhaustive()
    }
}

/// The rows of a vault with an id above `after` (from the start when `None`),
/// in id order.
///
/// At most `limit` rows (0 is read as 1, so a client that pages on `has_more`
/// always advances), and the page stops before the stored sizes would pass
/// `max_bytes`, but always holds one row if there is one. The page, the counter
/// and the epochs are read in one transaction. An unknown vault is
/// [`StoreError::NotFound`].
///
/// Spec: Fase 1 § 8.4: "the reconciliation returns an `as_of_seq` snapshot
/// value, and the client continues incrementally from there".
pub fn list_items(
    conn: &Connection,
    vault: &VaultId,
    after: Option<&ItemId>,
    limit: u32,
    max_bytes: usize,
) -> Result<ItemsPage, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let (as_of_seq, restore_epoch, vk_epoch) = tx
        .query_row(
            "SELECT v.seq, v.restore_epoch, a.vk_epoch \
             FROM ferret_vaults v JOIN ferret_accounts a ON a.account_id = v.account_id \
             WHERE v.vault_id = ?1",
            [vault.as_bytes()],
            |row| {
                Ok((
                    column_u64(row, 0)?,
                    column_u64(row, 1)?,
                    column_u64(row, 2)?,
                ))
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
            other => StoreError::Sql(other),
        })?;

    // An empty blob sorts before every id: no `after` starts at the first row.
    let start: Vec<u8> = after.map(|id| id.as_bytes().to_vec()).unwrap_or_default();
    let mut stmt = tx.prepare(
        "SELECT item_id, rev, seq, deleted, blob, tag, tomb, size FROM ferret_items \
         WHERE vault_id = ?1 AND item_id > ?2 ORDER BY item_id",
    )?;
    let mut rows = stmt.query(params![vault.as_bytes(), start])?;
    let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
    let mut items: Vec<Change> = Vec::new();
    let mut bytes: usize = 0;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        let size = usize::try_from(column_u64(row, 7)?).unwrap_or(usize::MAX);
        let next_bytes = bytes.saturating_add(size);
        if items.len() >= limit || (!items.is_empty() && next_bytes > max_bytes) {
            has_more = true;
            break;
        }
        bytes = next_bytes;
        items.push(read_change(row)?);
    }
    drop(rows);
    drop(stmt);
    tx.finish()?;
    let next_after = if has_more {
        items.last().map(|last| last.id)
    } else {
        None
    };
    Ok(ItemsPage {
        items,
        as_of_seq,
        vk_epoch,
        restore_epoch,
        next_after,
        has_more,
    })
}

fn read_change(row: &Row<'_>) -> rusqlite::Result<Change> {
    Ok(Change {
        id: ItemId::from_bytes(fixed::<16>(row, 0)?),
        rev: column_u64(row, 1)?,
        seq: column_u64(row, 2)?,
        deleted: row.get::<_, i64>(3)? != 0,
        blob: row.get(4)?,
        tag: row
            .get::<_, Option<Vec<u8>>>(5)?
            .map(|bytes| array_of::<32>(&bytes, 5))
            .transpose()?,
        tomb: row.get(6)?,
    })
}

fn fixed<const N: usize>(row: &Row<'_>, idx: usize) -> rusqlite::Result<[u8; N]> {
    let bytes: Vec<u8> = row.get(idx)?;
    array_of::<N>(&bytes, idx)
}

fn array_of<const N: usize>(bytes: &[u8], idx: usize) -> rusqlite::Result<[u8; N]> {
    <[u8; N]>::try_from(bytes)
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, Type::Blob, Box::new(e)))
}

/// What a bump did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bumped {
    /// How many vaults were raised.
    pub vaults: u64,
    /// The highest `restore_epoch` of any vault after the bump (0 without
    /// vaults).
    pub restore_epoch: u64,
}

/// Raises the restore epoch of every vault by one, in one transaction, and
/// says how many vaults it was and what the highest epoch is now.
///
/// A vault that already holds the largest number a JSON integer can carry
/// refuses the whole bump (nothing changes).
///
/// Spec: Fase 1 § 8.6, "Legitimate rollbacks": after a restore the
/// administrator sets `restore_epoch` higher, and clients that remember a lower
/// one say that the server was restored.
pub fn bump_all_vaults(conn: &mut Connection) -> Result<Bumped, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let max_json = i64::try_from(MAX_JSON_INT).unwrap_or(i64::MAX);
    let at_the_limit: i64 = tx.query_row(
        "SELECT COUNT(*) FROM ferret_vaults WHERE restore_epoch >= ?1",
        [max_json],
        |row| row.get(0),
    )?;
    if at_the_limit != 0 {
        return Err(StoreError::Invalid("restore_epoch is at its largest value"));
    }
    let vaults = tx.execute(
        "UPDATE ferret_vaults SET restore_epoch = restore_epoch + 1",
        [],
    )?;
    let highest: i64 = tx.query_row(
        "SELECT COALESCE(MAX(restore_epoch), 0) FROM ferret_vaults",
        [],
        |row| row.get(0),
    )?;
    tx.commit()?;
    Ok(Bumped {
        vaults: u64::try_from(vaults).unwrap_or(u64::MAX),
        restore_epoch: u64::try_from(highest)
            .map_err(|_| StoreError::Invalid("restore_epoch is negative"))?,
    })
}

/// Raises the restore epoch (the counter that tells clients the server was
/// restored) of every vault by one in one transaction and returns the highest
/// value now. See [`bump_all_vaults`].
pub fn bump_restore_epoch(conn: &mut Connection) -> Result<u64, StoreError> {
    Ok(bump_all_vaults(conn)?.restore_epoch)
}

/// The query of the listing call.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemsQuery {
    /// Rows with an id above this one: 32 lower-case hexadecimal characters.
    after: Option<String>,
    /// At most this many rows, 1 to 500 (a larger number is read as 500, 0 as 1).
    limit: Option<u32>,
}

/// The listing routes.
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
    Router::new().route("/api/sync/items", get(get_items))
}

/// A page of the listing of the session's vault.
async fn get_items(
    session: VaultSession,
    query: Result<Query<ItemsQuery>, QueryRejection>,
    State(db): State<VaultDb>,
) -> Result<Response, ApiError> {
    let Query(query) = query.map_err(|_| ApiError::coded("bad_request"))?;
    let after = query
        .after
        .as_deref()
        .map(|text| hex16::decode(text).map(ItemId::from_bytes))
        .transpose()
        .map_err(|_| ApiError::coded("bad_request"))?;
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let vault = session.vault;
    let page = db
        .with_conn(move |conn| list_items(conn, &vault, after.as_ref(), limit, PAGE_BYTES))
        .await?;
    // Counts only: the rows are ciphertext and never reach the log.
    tracing::info!(
        rows = page.items.len(),
        has_more = page.has_more,
        "listing page"
    );
    let res = items_res(page);
    debug_assert!(res.validate().is_ok());
    Ok(Json(res).into_response())
}

/// The wire shape of a page.
fn items_res(page: ItemsPage) -> ItemsRes {
    ItemsRes {
        items: page.items.into_iter().map(change_json).collect(),
        as_of_seq: page.as_of_seq,
        vk_epoch: page.vk_epoch,
        restore_epoch: page.restore_epoch,
        next_after: page.next_after.map(|id| *id.as_bytes()),
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
