//! The vault store: one write transaction per call, on a `&mut Connection`, with
//! no HTTP and no kit in sight. Spec: Fase 1 § 8.1, § 8.3.
//!
//! # Conditional writes
//!
//! A write names the revision it was made against (`base_rev`). The store
//! accepts it only if that is still the revision of the row, and it says so in
//! the database as well as in the code:
//!
//! * the write runs in a `BEGIN IMMEDIATE` transaction, so a second writer waits
//!   for the first one and then sees its result;
//! * an update is `UPDATE ... WHERE rev = <the revision that was read>`, and an
//!   insert is `INSERT ... ON CONFLICT DO NOTHING`; zero changed rows is a
//!   conflict, never a silent success;
//! * the vault's counters move in one statement whose `WHERE` holds the quota
//!   checks; zero changed rows there means the quota or a missing vault.
//!
//! `seq` comes from the counter on the vault row, so it is never reused, also
//! after rows have been purged. Every number a client sends is checked before
//! it is used in arithmetic.

use ferret_server_auth::{StoredRecord, ValidatedRecord};
use rusqlite::{
    Connection, OptionalExtension as _, Row, Transaction, TransactionBehavior, params, types::Type,
};

use super::idem::{self, Lookup};
use super::quota::{self, Limits, sql_int};
use crate::error::StoreError;
use crate::ids::{AccountId, DeviceId, ItemId, MANIFEST_ITEM_ID, MethodId, VaultId};

/// What a write puts in the row.
pub enum PutBody<'a> {
    /// A live item: the envelope and its tag.
    Live {
        /// The sealed item.
        blob: &'a [u8],
        /// The tag of the envelope.
        tag: [u8; 32],
    },
    /// A deletion: the tombstone replaces the envelope.
    Deleted {
        /// The sealed tombstone.
        tomb: &'a [u8],
    },
}

impl PutBody<'_> {
    fn len(&self) -> usize {
        match self {
            PutBody::Live { blob, .. } => blob.len(),
            PutBody::Deleted { tomb } => tomb.len(),
        }
    }
}

impl std::fmt::Debug for PutBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutBody::Live { blob, .. } => f
                .debug_struct("Live")
                .field("blob", &format_args!("[redacted; {} bytes]", blob.len()))
                .finish_non_exhaustive(),
            PutBody::Deleted { tomb } => f
                .debug_struct("Deleted")
                .field("tomb", &format_args!("[redacted; {} bytes]", tomb.len()))
                .finish(),
        }
    }
}

/// A write of one item.
pub struct PutRequest<'a> {
    /// The item. [`MANIFEST_ITEM_ID`] is the manifest row.
    pub item_id: ItemId,
    /// The revision the client wrote against: 0 for a new item.
    pub base_rev: u64,
    /// The new content.
    pub body: PutBody<'a>,
    /// The idempotency key of the write.
    pub idem: [u8; 16],
    /// A hash of the request, so the same `idem` with another request is seen.
    /// The store cannot tell what it covers: the caller makes it
    /// `SHA-256(item_id || raw body)`, so a replay can never return the `rev`
    /// and `seq` of another item.
    pub request_hash: [u8; 32],
    /// Whether the write asks to replace a tombstone. Read only for a live
    /// body against a tombstone whose revision is `base_rev`; against a live
    /// row (or a missing one) it changes nothing, and a tombstone body never
    /// resurrects anything.
    pub resurrect: bool,
}

impl std::fmt::Debug for PutRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PutRequest")
            .field("item_id", &self.item_id)
            .field("base_rev", &self.base_rev)
            .field("body", &self.body)
            .finish_non_exhaustive()
    }
}

/// What the row holds now, for a client whose `base_rev` was wrong.
#[derive(Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The revision of the row: 0 if there is no row.
    pub current_rev: u64,
    /// The envelope, if the row is live.
    pub blob: Option<Vec<u8>>,
    /// The tag, if the row is live.
    pub tag: Option<[u8; 32]>,
    /// Whether the row is a tombstone.
    pub deleted: bool,
}

impl Conflict {
    /// The conflict of a write against a row that is not there.
    fn absent() -> Self {
        Self {
            current_rev: 0,
            blob: None,
            tag: None,
            deleted: false,
        }
    }
}

impl std::fmt::Debug for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conflict")
            .field("current_rev", &self.current_rev)
            .field("deleted", &self.deleted)
            .field("blob", &format_args!("[redacted]"))
            .field("tag", &format_args!("[redacted]"))
            .finish()
    }
}

/// How a write ended.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PutOutcome {
    /// The write is in. `replayed` is true when the answer is that of an
    /// earlier, identical write.
    Stored {
        /// The new revision of the row.
        rev: u64,
        /// The vault sequence number of the write.
        seq: u64,
        /// Whether this is the answer of an earlier write.
        replayed: bool,
    },
    /// `base_rev` is not the revision of the row. Nothing was written.
    Conflict(Conflict),
    /// The `idem` was used for another request.
    IdemMismatch,
    /// The write would break a limit of the vault, or the envelope is too big.
    QuotaExceeded,
    /// The item is the manifest, which this function never writes (neither a
    /// live body nor a tombstone). Nothing was written.
    ManifestNotWritable,
}

/// The row of an item as the store reads it before a write.
struct Current {
    rev: u64,
    size: u64,
    deleted: bool,
    blob: Option<Vec<u8>>,
    tag: Option<Vec<u8>>,
}

impl Current {
    fn into_conflict(self) -> Result<Conflict, StoreError> {
        let tag = self.tag.map(|t| array32(&t, 3)).transpose()?;
        Ok(Conflict {
            current_rev: self.rev,
            blob: self.blob,
            tag,
            deleted: self.deleted,
        })
    }
}

/// Writes one item against `req.base_rev`.
///
/// Spec: Fase 1 § 8.1, § 8.3. One write transaction: the idempotency record is
/// looked up before `base_rev` is compared, then `base_rev`, then the quota;
/// the new `rev` is `base_rev + 1` and `seq` comes from the counter row of the
/// vault. A tombstone is written over only by a resurrection: a live body with
/// `resurrect` and a `base_rev` equal to the revision of the tombstone gives
/// `rev + 1` and counts as a new live row (it must fit `max_items`). Any other
/// put on a deleted item, an old basis or no `resurrect` included, is a
/// conflict with `deleted: true`. Spec: Fase 1 § 8.4. `now` is stored as
/// `changed_at` of the row.
///
/// The manifest row is not written here, in either body form: changes to it
/// need a signature of the account (spec § 4.6) and have a function of their
/// own. The answer is [`PutOutcome::ManifestNotWritable`] before anything is
/// read or written.
///
/// Counters: `item_count` counts live rows (the manifest included), so a
/// deletion frees a slot; tombstones are bounded by `limits.max_tombstones`;
/// `bytes_used` is the sum of the stored sizes of all rows. An unknown vault is
/// [`StoreError::NotFound`].
pub fn put_item(
    conn: &mut Connection,
    vault: &VaultId,
    device: &DeviceId,
    req: &PutRequest<'_>,
    limits: &Limits,
    now: i64,
) -> Result<PutOutcome, StoreError> {
    if req.item_id == MANIFEST_ITEM_ID {
        return Ok(PutOutcome::ManifestNotWritable);
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if !vault_exists(&tx, vault)? {
        return Err(StoreError::NotFound);
    }

    match idem::lookup(&tx, vault, device, &req.idem, &req.request_hash)? {
        Lookup::Replay { rev, seq } => {
            return Ok(PutOutcome::Stored {
                rev,
                seq,
                replayed: true,
            });
        }
        Lookup::Mismatch => return Ok(PutOutcome::IdemMismatch),
        Lookup::Fresh => {}
    }

    let new_len = req.body.len();
    if !quota::envelope_fits(new_len, limits) {
        return Ok(PutOutcome::QuotaExceeded);
    }

    let (is_new, old_size, was_deleted) = match read_item(&tx, vault, &req.item_id)? {
        None => {
            if req.base_rev != 0 {
                // A basis for a row that is not there: ahead of the server.
                return Ok(PutOutcome::Conflict(Conflict::absent()));
            }
            (true, 0, false)
        }
        Some(row) => {
            // A tombstone is written over only by a resurrection (a decision
            // of its own: a live body that asks for it, against the revision
            // of the tombstone). Any other basis than the current revision is
            // stale or ahead.
            let resurrects = row.deleted
                && req.resurrect
                && matches!(req.body, PutBody::Live { .. })
                && row.rev == req.base_rev;
            if (row.deleted && !resurrects) || row.rev != req.base_rev {
                return Ok(PutOutcome::Conflict(row.into_conflict()?));
            }
            (false, row.size, row.deleted)
        }
    };
    let new_rev = req
        .base_rev
        .checked_add(1)
        .ok_or_else(|| int_error(req.base_rev))?;

    // The counter row: seq, the row count and the bytes move together, in one
    // statement that holds the quota checks. Nothing changed means a limit (or
    // a vault that is not there).
    let new_size = sql_int(u64::try_from(new_len).unwrap_or(u64::MAX));
    let old_size_sql = sql_int(old_size);
    let makes_tombstone = matches!(req.body, PutBody::Deleted { .. });
    // Live rows count against `max_items`: a new live row is one more, a
    // resurrected one is one more (its tombstone was not counted), a deletion
    // of a live row is one less, a tombstone that replaces nothing changes
    // nothing.
    let item_delta: i64 = match (is_new, makes_tombstone, was_deleted) {
        (true, false, _) | (false, false, true) => 1,
        (false, true, _) => -1,
        _ => 0,
    };
    if makes_tombstone {
        let tombstones: i64 = tx.query_row(
            "SELECT COUNT(*) FROM ferret_items WHERE vault_id = ?1 AND deleted = 1",
            [vault.as_bytes()],
            |row| row.get(0),
        )?;
        if tombstones >= i64::from(limits.max_tombstones) {
            return Ok(PutOutcome::QuotaExceeded);
        }
    }
    let seq: Option<i64> = tx
        .query_row(
            "UPDATE ferret_vaults \
             SET seq = seq + 1, \
                 item_count = item_count + ?2, \
                 bytes_used = bytes_used - ?3 + ?4 \
             WHERE vault_id = ?1 \
               AND (?2 <= 0 OR item_count + ?2 <= ?5) \
               AND (?4 <= ?3 OR bytes_used - ?3 + ?4 <= ?6) \
             RETURNING seq",
            params![
                vault.as_bytes(),
                item_delta,
                old_size_sql,
                new_size,
                i64::from(limits.max_items),
                sql_int(limits.max_bytes),
            ],
            |row| row.get(0),
        )
        .optional()?;
    // The vault exists (checked above), so no changed row is a limit.
    let Some(seq) = seq else {
        return Ok(PutOutcome::QuotaExceeded);
    };

    let new_rev_sql = i64::try_from(new_rev).map_err(|_| int_error(new_rev))?;
    let deleted = i64::from(makes_tombstone);
    let (blob, tag): (Option<&[u8]>, Option<&[u8]>) = match &req.body {
        PutBody::Live { blob, tag } => (Some(blob), Some(tag.as_slice())),
        PutBody::Deleted { .. } => (None, None),
    };
    let tomb: Option<&[u8]> = match &req.body {
        PutBody::Deleted { tomb } => Some(tomb),
        PutBody::Live { .. } => None,
    };
    let changed = if is_new {
        tx.execute(
            "INSERT INTO ferret_items \
               (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10) \
             ON CONFLICT (vault_id, item_id) DO NOTHING",
            params![
                vault.as_bytes(),
                req.item_id.as_bytes(),
                new_rev_sql,
                seq,
                deleted,
                blob,
                tag,
                tomb,
                new_size,
                now
            ],
        )?
    } else {
        tx.execute(
            "UPDATE ferret_items \
             SET rev = ?3, seq = ?4, deleted = ?5, blob = ?6, tag = ?7, tomb = ?8, \
                 size = ?9, changed_at = ?10 \
             WHERE vault_id = ?1 AND item_id = ?2 AND rev = ?11 AND deleted = ?12",
            params![
                vault.as_bytes(),
                req.item_id.as_bytes(),
                new_rev_sql,
                seq,
                deleted,
                blob,
                tag,
                tomb,
                new_size,
                now,
                i64::try_from(req.base_rev).map_err(|_| int_error(req.base_rev))?,
                i64::from(was_deleted),
            ],
        )?
    };
    if changed != 1 {
        // Somebody else got there first, or the row is not what it was when we
        // read it. Dropping the transaction undoes the counter as well.
        let current = read_item(&tx, vault, &req.item_id)?;
        return Ok(PutOutcome::Conflict(match current {
            Some(row) => row.into_conflict()?,
            None => Conflict::absent(),
        }));
    }

    idem::record(
        &tx,
        vault,
        device,
        &req.idem,
        &req.request_hash,
        (new_rev_sql, seq),
        now,
    )?;
    tx.commit()?;
    Ok(PutOutcome::Stored {
        rev: new_rev,
        seq: u64::try_from(seq).map_err(|_| int_error_signed(seq))?,
        replayed: false,
    })
}

fn vault_exists(conn: &Connection, vault: &VaultId) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM ferret_vaults WHERE vault_id = ?1)",
        [vault.as_bytes()],
        |row| row.get(0),
    )?)
}

/// A query for a row that must be there: no row is [`StoreError::NotFound`].
fn missing(error: rusqlite::Error) -> StoreError {
    match error {
        rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound,
        other => StoreError::Sql(other),
    }
}

/// What a purge of tombstones did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Purged {
    /// How many tombstones were removed.
    pub removed: u64,
    /// The horizon of the vault after the purge: a client that has seen less
    /// than this must reconcile in full.
    pub min_valid_since: u64,
}

/// Removes the tombstones of a vault that were last written before
/// `older_than` (Unix seconds, compared with `changed_at`).
///
/// The purge and the counters move in one transaction: `bytes_used` loses the
/// sizes of the removed rows, and `min_valid_since` rises to the highest `seq`
/// among them (it never falls). `item_count` is not touched, because it counts
/// live rows. `seq` is not touched either: a purge is not a change that clients
/// see in the feed.
///
/// Spec: Fase 1 § 8.4 (retention of 400 days). Meant for the retention job of
/// the sync milestone, which calls it per vault with `now` minus the retention
/// as `older_than`; nothing calls it before that.
pub fn purge_tombstones(
    conn: &mut Connection,
    vault: &VaultId,
    older_than: i64,
) -> Result<Purged, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let (removed, bytes, top_seq): (i64, i64, i64) = tx.query_row(
        "SELECT COUNT(*), COALESCE(SUM(size), 0), COALESCE(MAX(seq), 0) FROM ferret_items WHERE vault_id = ?1 AND deleted = 1 AND changed_at < ?2",
        params![vault.as_bytes(), older_than],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    tx.execute(
        "DELETE FROM ferret_items WHERE vault_id = ?1 AND deleted = 1 AND changed_at < ?2",
        params![vault.as_bytes(), older_than],
    )?;
    let changed = tx.execute(
        "UPDATE ferret_vaults SET bytes_used = bytes_used - ?2, min_valid_since = MAX(min_valid_since, ?3) WHERE vault_id = ?1",
        params![vault.as_bytes(), bytes, top_seq],
    )?;
    if changed != 1 {
        return Err(StoreError::NotFound);
    }
    let horizon: i64 = tx.query_row(
        "SELECT min_valid_since FROM ferret_vaults WHERE vault_id = ?1",
        [vault.as_bytes()],
        |row| row.get(0),
    )?;
    tx.commit()?;
    Ok(Purged {
        removed: u64::try_from(removed).map_err(|_| int_error_signed(removed))?,
        min_valid_since: u64::try_from(horizon).map_err(|_| int_error_signed(horizon))?,
    })
}

/// The checkpoint a vault keeps: the one with the highest `seq` that a client
/// uploaded. The store keeps the bytes as they came; it checks no MAC (it has
/// no key), and the caller checks the structure.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredCheckpoint {
    /// The sequence number it covers.
    pub seq: u64,
    /// The digest of `entries`.
    pub digest: [u8; 32],
    /// The MAC over `seq` and the digest, as the client made it.
    pub mac: [u8; 32],
    /// The entries the digest covers, 56 bytes each.
    pub entries: Vec<u8>,
}

impl std::fmt::Debug for StoredCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredCheckpoint")
            .field("seq", &self.seq)
            .field("entries", &format_args!("[{} bytes]", self.entries.len()))
            .finish_non_exhaustive()
    }
}

/// How an upload of a checkpoint ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// The checkpoint replaced the stored one (its `seq` is higher).
    Stored {
        /// The sequence number now stored.
        seq: u64,
    },
    /// The stored checkpoint is the same, byte for byte. Nothing was written.
    Unchanged {
        /// The sequence number stored.
        seq: u64,
    },
    /// The stored checkpoint is newer, or has the same `seq` with other bytes.
    /// Nothing was written.
    Stale {
        /// The sequence number that is stored.
        stored_seq: u64,
    },
    /// The checkpoint claims a `seq` above the one of the vault. Nothing was
    /// written.
    AboveVault,
}

/// What an upload of a checkpoint needs next, decided from the head (`seq`,
/// digest, MAC) of the stored one and the `seq` of the vault, before the
/// stored `entries` (up to 2.8 MB) are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CheckpointStep {
    /// The upload claims a `seq` above the vault's.
    AboveVault,
    /// The stored checkpoint is newer, or has the same `seq` and another head.
    Stale { stored_seq: u64 },
    /// The same head as the stored one: only the `entries` can tell whether
    /// this is a retry (`Unchanged`) or another upload (`Stale`).
    SameHead,
    /// Newer than the stored one: write it.
    Replace,
}

/// The decision that does not need the stored `entries`: it is a function of
/// the two heads and the vault's `seq` alone, so a stale upload never reads
/// them.
fn decide_checkpoint(
    vault_seq: u64,
    stored: &CheckpointHead,
    incoming: &CheckpointHead,
) -> CheckpointStep {
    if incoming.0 > vault_seq {
        CheckpointStep::AboveVault
    } else if incoming.0 < stored.0 || (incoming.0 == stored.0 && incoming != stored) {
        CheckpointStep::Stale {
            stored_seq: stored.0,
        }
    } else if incoming.0 == stored.0 {
        CheckpointStep::SameHead
    } else {
        CheckpointStep::Replace
    }
}

/// Stores `cp` if it is newer than the checkpoint of the vault.
///
/// Spec: Fase 1 § 8.6: the server keeps the checkpoint with the highest
/// `seq`; a lower one is refused (harmless), and the `seq` cannot be higher
/// than the one of the vault. The same `seq` is accepted only for the same
/// bytes (a client that retries); other bytes under a `seq` that is already
/// stored would let one upload silently replace another. One `IMMEDIATE`
/// transaction, so two uploads cannot both pass the comparison. Under that
/// lock only the head of the stored checkpoint is read, and its `entries`
/// only when the heads are equal. An unknown vault, or one without a
/// checkpoint, is [`StoreError::NotFound`].
pub fn put_checkpoint(
    conn: &mut Connection,
    vault: &VaultId,
    cp: &StoredCheckpoint,
) -> Result<CheckpointOutcome, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let vault_seq: i64 = tx
        .query_row(
            "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes()],
            |row| row.get(0),
        )
        .map_err(missing)?;
    let vault_seq = u64::try_from(vault_seq).map_err(|_| int_error_signed(vault_seq))?;
    let stored = checkpoint_head(&tx, vault)?.ok_or(StoreError::NotFound)?;
    let incoming = (cp.seq, cp.digest, cp.mac);
    match decide_checkpoint(vault_seq, &stored, &incoming) {
        CheckpointStep::AboveVault => Ok(CheckpointOutcome::AboveVault),
        CheckpointStep::Stale { stored_seq } => Ok(CheckpointOutcome::Stale { stored_seq }),
        CheckpointStep::SameHead => {
            let entries: Vec<u8> = tx.query_row(
                "SELECT entries FROM ferret_checkpoints WHERE vault_id = ?1",
                [vault.as_bytes()],
                |row| row.get(0),
            )?;
            Ok(if entries == cp.entries {
                CheckpointOutcome::Unchanged { seq: cp.seq }
            } else {
                CheckpointOutcome::Stale {
                    stored_seq: stored.0,
                }
            })
        }
        CheckpointStep::Replace => {
            let seq_sql = i64::try_from(cp.seq).map_err(|_| int_error(cp.seq))?;
            let changed = tx.execute(
                "UPDATE ferret_checkpoints SET seq = ?2, digest = ?3, mac = ?4, entries = ?5 WHERE vault_id = ?1 AND seq < ?2",
                params![
                    vault.as_bytes(),
                    seq_sql,
                    cp.digest.as_slice(),
                    cp.mac.as_slice(),
                    cp.entries
                ],
            )?;
            if changed != 1 {
                // The transaction is IMMEDIATE and the row was read above, so
                // this is not a race: refuse rather than report a write that
                // did not happen.
                return Err(StoreError::Invalid("the checkpoint row changed"));
            }
            tx.commit()?;
            Ok(CheckpointOutcome::Stored { seq: cp.seq })
        }
    }
}

/// The checkpoint of a vault, with its entries. An unknown vault is
/// [`StoreError::NotFound`].
pub fn get_checkpoint(conn: &Connection, vault: &VaultId) -> Result<StoredCheckpoint, StoreError> {
    read_checkpoint(conn, vault)
}

/// The head of a checkpoint: `seq`, digest and MAC, no entries.
pub type CheckpointHead = (u64, [u8; 32], [u8; 32]);

/// The head of the checkpoint of a vault (`seq`, digest and MAC, no entries):
/// what the changes feed carries. `None` for a vault without a checkpoint.
pub fn checkpoint_head(
    conn: &Connection,
    vault: &VaultId,
) -> Result<Option<CheckpointHead>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT seq, digest, mac FROM ferret_checkpoints WHERE vault_id = ?1",
            [vault.as_bytes()],
            |row| {
                Ok((
                    column_u64(row, 0)?,
                    column_array32(row, 1)?,
                    column_array32(row, 2)?,
                ))
            },
        )
        .optional()?)
}

fn read_checkpoint(conn: &Connection, vault: &VaultId) -> Result<StoredCheckpoint, StoreError> {
    conn.query_row(
        "SELECT seq, digest, mac, entries FROM ferret_checkpoints WHERE vault_id = ?1",
        [vault.as_bytes()],
        |row| {
            Ok(StoredCheckpoint {
                seq: column_u64(row, 0)?,
                digest: column_array32(row, 1)?,
                mac: column_array32(row, 2)?,
                entries: row.get(3)?,
            })
        },
    )
    .map_err(missing)
}

fn read_item(
    conn: &Connection,
    vault: &VaultId,
    item: &ItemId,
) -> Result<Option<Current>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT rev, deleted, blob, tag, size FROM ferret_items \
             WHERE vault_id = ?1 AND item_id = ?2",
            params![vault.as_bytes(), item.as_bytes()],
            |row| {
                Ok(Current {
                    rev: column_u64(row, 0)?,
                    deleted: row.get::<_, i64>(1)? != 0,
                    blob: row.get(2)?,
                    tag: row.get(3)?,
                    size: column_u64(row, 4)?,
                })
            },
        )
        .optional()?)
}

/// One row of the changes feed.
#[derive(Clone, PartialEq, Eq)]
pub struct Change {
    /// The item. The manifest row has [`MANIFEST_ITEM_ID`].
    pub id: ItemId,
    /// The revision of the row.
    pub rev: u64,
    /// The vault sequence number of the last write to the row.
    pub seq: u64,
    /// Whether the row is a tombstone.
    pub deleted: bool,
    /// The envelope, if the row is live.
    pub blob: Option<Vec<u8>>,
    /// The tag of the envelope, if the row is live.
    pub tag: Option<[u8; 32]>,
    /// The tombstone, if the row is deleted.
    pub tomb: Option<Vec<u8>>,
}

impl std::fmt::Debug for Change {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Change")
            .field("id", &self.id)
            .field("rev", &self.rev)
            .field("seq", &self.seq)
            .field("deleted", &self.deleted)
            .finish_non_exhaustive()
    }
}

/// A page of the changes feed.
#[derive(Clone, PartialEq, Eq)]
pub struct Changes {
    /// The rows after `since`, in `seq` order.
    pub changes: Vec<Change>,
    /// The vault's counter now.
    pub latest_seq: u64,
    /// The feed floor: a cursor below it may have missed purged tombstones.
    pub min_valid_since: u64,
    /// The epoch of the vault key.
    pub vk_epoch: u64,
    /// How many times the vault was restored.
    pub restore_epoch: u64,
    /// Whether there are more rows after this page.
    pub has_more: bool,
}

impl std::fmt::Debug for Changes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Changes")
            .field("rows", &self.changes.len())
            .field("latest_seq", &self.latest_seq)
            .field("min_valid_since", &self.min_valid_since)
            .field("vk_epoch", &self.vk_epoch)
            .field("restore_epoch", &self.restore_epoch)
            .field("has_more", &self.has_more)
            .finish()
    }
}

/// The rows of a vault with `seq` above `since`, oldest first.
///
/// At most `limit` rows, and the page stops before the stored sizes would pass
/// `max_bytes` (but always holds one row if there is one). `has_more` says
/// whether rows are left. The page is read in one transaction, so the counters
/// and the rows agree. A `limit` of 0 is read as 1, so a client that pages on
/// `has_more` always advances. An unknown vault is [`StoreError::NotFound`].
pub fn changes_since(
    conn: &Connection,
    vault: &VaultId,
    since: u64,
    limit: u32,
    max_bytes: usize,
) -> Result<Changes, StoreError> {
    Ok(changes_with_head(conn, vault, since, limit, max_bytes)?.0)
}

/// [`changes_since`], and with the page the head of the checkpoint of the
/// vault (`None` if it has none). Both are read in the one transaction, so the
/// head is never above the `latest_seq` of the page: they are one snapshot.
pub fn changes_with_head(
    conn: &Connection,
    vault: &VaultId,
    since: u64,
    limit: u32,
    max_bytes: usize,
) -> Result<(Changes, Option<CheckpointHead>), StoreError> {
    let tx = conn.unchecked_transaction()?;
    let (latest_seq, min_valid_since, restore_epoch, vk_epoch) = tx
        .query_row(
            "SELECT v.seq, v.min_valid_since, v.restore_epoch, a.vk_epoch \
         FROM ferret_vaults v JOIN ferret_accounts a ON a.account_id = v.account_id \
         WHERE v.vault_id = ?1",
            [vault.as_bytes()],
            |row| {
                Ok((
                    column_u64(row, 0)?,
                    column_u64(row, 1)?,
                    column_u64(row, 2)?,
                    column_u64(row, 3)?,
                ))
            },
        )
        .map_err(missing)?;
    let head = checkpoint_head(&tx, vault)?;

    let since_sql = i64::try_from(since).unwrap_or(i64::MAX);
    let mut stmt = tx.prepare(
        "SELECT item_id, rev, seq, deleted, blob, tag, tomb, size FROM ferret_items \
         WHERE vault_id = ?1 AND seq > ?2 ORDER BY seq",
    )?;
    let mut rows = stmt.query(params![vault.as_bytes(), since_sql])?;
    let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
    let mut changes: Vec<Change> = Vec::new();
    let mut bytes: usize = 0;
    let mut has_more = false;
    while let Some(row) = rows.next()? {
        let size = usize::try_from(column_u64(row, 7)?).unwrap_or(usize::MAX);
        let next_bytes = bytes.saturating_add(size);
        if changes.len() >= limit || (!changes.is_empty() && next_bytes > max_bytes) {
            has_more = true;
            break;
        }
        bytes = next_bytes;
        changes.push(Change {
            id: ItemId::from_bytes(column_array16(row, 0)?),
            rev: column_u64(row, 1)?,
            seq: column_u64(row, 2)?,
            deleted: row.get::<_, i64>(3)? != 0,
            blob: row.get(4)?,
            tag: column_tag(row, 5)?,
            tomb: row.get(6)?,
        });
    }
    drop(rows);
    drop(stmt);
    tx.finish()?;
    Ok((
        Changes {
            changes,
            latest_seq,
            min_valid_since,
            vk_epoch,
            restore_epoch,
            has_more,
        },
        head,
    ))
}

/// A method that unlocks the vault key: a wrap and what is needed to use it.
#[derive(Clone, PartialEq, Eq)]
pub struct MethodRow {
    /// The method.
    pub method_id: MethodId,
    /// 1, 2 or 3 (the table rejects anything else).
    pub method_type: u8,
    /// The vault key, wrapped.
    pub wrap: Vec<u8>,
    /// The generation of the key that wraps it.
    pub kek_generation: u32,
    /// The credential, for a passkey.
    pub credential_id: Option<Vec<u8>>,
    /// The PRF salt, for a passkey.
    pub prf_salt: Option<Vec<u8>>,
    /// The authenticator model, for a passkey.
    pub aaguid: Option<Vec<u8>>,
}

impl std::fmt::Debug for MethodRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodRow")
            .field("method_id", &self.method_id)
            .field("method_type", &self.method_type)
            .field("kek_generation", &self.kek_generation)
            .finish_non_exhaustive()
    }
}

/// The manifest as a registration brings it. It becomes the row with
/// [`MANIFEST_ITEM_ID`] and `seq` 1.
#[derive(Clone, PartialEq, Eq)]
pub struct ManifestIn {
    /// Its revision.
    pub rev: u64,
    /// The sealed manifest.
    pub envelope: Vec<u8>,
    /// The tag of the envelope.
    pub tag: [u8; 32],
}

impl std::fmt::Debug for ManifestIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManifestIn")
            .field("rev", &self.rev)
            .finish_non_exhaustive()
    }
}

/// The checkpoint a registration brings.
#[derive(Clone, PartialEq, Eq)]
pub struct CheckpointIn {
    /// The sequence number it covers.
    pub seq: u64,
    /// The digest of the rows.
    pub digest: Vec<u8>,
    /// The MAC over the digest.
    pub mac: Vec<u8>,
    /// The entries the digest covers.
    pub entries: Vec<u8>,
}

impl std::fmt::Debug for CheckpointIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckpointIn")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

/// Everything a new account puts in the database.
pub struct NewAccountRows {
    /// The account.
    pub account_id: AccountId,
    /// The kit user it belongs to.
    pub user_id: i64,
    /// Its vault.
    pub vault_id: VaultId,
    /// The OPAQUE record with its profile.
    pub record: StoredRecord,
    /// Whether the account has a secret key.
    pub sk_hint: bool,
    /// The public key that authorises changes.
    pub pk_a: [u8; 32],
    /// The public key of the recovery key.
    pub pk_r: [u8; 32],
    /// The unlock methods.
    pub methods: Vec<MethodRow>,
    /// The manifest, which becomes the first row.
    pub manifest: ManifestIn,
    /// The first checkpoint.
    pub checkpoint: CheckpointIn,
    /// When (Unix seconds).
    pub now: i64,
}

impl std::fmt::Debug for NewAccountRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewAccountRows")
            .field("account_id", &self.account_id)
            .field("user_id", &self.user_id)
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

/// Writes a new account: the account row, its unlock methods, the vault row
/// (counter at 1), the manifest as the row with `seq` 1, and the checkpoint.
/// The manifest must be at `rev` 1 and the checkpoint at `seq` 1
/// ([`StoreError::Invalid`] otherwise).
///
/// All or nothing: the rows go in under a savepoint, so a failure at any step
/// leaves none of them, whatever the caller does with the transaction after.
pub fn create_account(tx: &Transaction<'_>, rows: &NewAccountRows) -> Result<(), StoreError> {
    // The vault starts at `seq` 1 and the manifest is its first row, at
    // revision 1; a checkpoint cannot cover more than the vault holds.
    if rows.manifest.rev != 1 {
        return Err(StoreError::Invalid(
            "the manifest of a new account is at rev 1",
        ));
    }
    if rows.checkpoint.seq != 1 {
        return Err(StoreError::Invalid(
            "the checkpoint of a new account is at seq 1",
        ));
    }
    tx.execute_batch("SAVEPOINT ferret_create_account")?;
    match insert_account_rows(tx, rows) {
        Ok(()) => {
            tx.execute_batch("RELEASE ferret_create_account")?;
            Ok(())
        }
        Err(e) => {
            // The original error is the one to report.
            let _ = tx
                .execute_batch("ROLLBACK TO ferret_create_account; RELEASE ferret_create_account");
            Err(e)
        }
    }
}

fn insert_account_rows(tx: &Transaction<'_>, rows: &NewAccountRows) -> Result<(), StoreError> {
    tx.execute(
        "INSERT INTO ferret_accounts \
           (account_id, user_id, vault_id, opaque_record, ksf_profile, sk_hint, pk_a, pk_r, \
            vk_epoch, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)",
        params![
            rows.account_id.as_bytes(),
            rows.user_id,
            rows.vault_id.as_bytes(),
            rows.record.record.as_bytes(),
            i64::from(rows.record.ksf_profile),
            i64::from(rows.sk_hint),
            rows.pk_a,
            rows.pk_r,
            rows.now,
        ],
    )?;
    for method in &rows.methods {
        tx.execute(
            "INSERT INTO ferret_unlock_methods \
               (method_id, account_id, method_type, wrap, kek_generation, credential_id, \
                prf_salt, aaguid, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                method.method_id.as_bytes(),
                rows.account_id.as_bytes(),
                i64::from(method.method_type),
                method.wrap,
                i64::from(method.kek_generation),
                method.credential_id,
                method.prf_salt,
                method.aaguid,
                rows.now,
            ],
        )?;
    }
    let manifest_size = sql_int(u64::try_from(rows.manifest.envelope.len()).unwrap_or(u64::MAX));
    // The manifest is the first write of the vault: counter 1, one row.
    tx.execute(
        "INSERT INTO ferret_vaults (vault_id, account_id, seq, item_count, bytes_used) \
         VALUES (?1, ?2, 1, 1, ?3)",
        params![
            rows.vault_id.as_bytes(),
            rows.account_id.as_bytes(),
            manifest_size
        ],
    )?;
    tx.execute(
        "INSERT INTO ferret_items \
           (vault_id, item_id, rev, seq, deleted, blob, tag, tomb, size, changed_at) \
         VALUES (?1, ?2, ?3, 1, 0, ?4, ?5, NULL, ?6, ?7)",
        params![
            rows.vault_id.as_bytes(),
            MANIFEST_ITEM_ID.as_bytes(),
            i64::try_from(rows.manifest.rev).map_err(|_| int_error(rows.manifest.rev))?,
            rows.manifest.envelope,
            rows.manifest.tag,
            manifest_size,
            rows.now,
        ],
    )?;
    tx.execute(
        "INSERT INTO ferret_checkpoints (vault_id, seq, digest, mac, entries) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            rows.vault_id.as_bytes(),
            i64::try_from(rows.checkpoint.seq).map_err(|_| int_error(rows.checkpoint.seq))?,
            rows.checkpoint.digest,
            rows.checkpoint.mac,
            rows.checkpoint.entries,
        ],
    )?;
    Ok(())
}

/// What the unlock-methods call answers with.
#[derive(Clone, PartialEq, Eq)]
pub struct MethodsView {
    /// The unlock methods of the account.
    pub methods: Vec<MethodRow>,
    /// The public key that authorises changes.
    pub pk_a: [u8; 32],
    /// The epoch of the vault key.
    pub vk_epoch: u64,
    /// The manifest row.
    pub manifest: Change,
}

impl std::fmt::Debug for MethodsView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MethodsView")
            .field("methods", &self.methods.len())
            .field("vk_epoch", &self.vk_epoch)
            .finish_non_exhaustive()
    }
}

/// The unlock methods, the key `pk_a`, the key epoch and the manifest row of an
/// account. Read in one transaction. An unknown account is
/// [`StoreError::NotFound`].
pub fn methods_view(conn: &Connection, account: &AccountId) -> Result<MethodsView, StoreError> {
    let tx = conn.unchecked_transaction()?;
    let (vault_id, pk_a, vk_epoch) = tx
        .query_row(
            "SELECT vault_id, pk_a, vk_epoch FROM ferret_accounts WHERE account_id = ?1",
            [account.as_bytes()],
            |row| {
                Ok((
                    column_array16(row, 0)?,
                    column_array32(row, 1)?,
                    column_u64(row, 2)?,
                ))
            },
        )
        .map_err(missing)?;
    let mut stmt = tx.prepare(
        "SELECT method_id, method_type, wrap, kek_generation, credential_id, prf_salt, aaguid \
         FROM ferret_unlock_methods WHERE account_id = ?1 ORDER BY created_at, method_id",
    )?;
    let methods = stmt
        .query_map([account.as_bytes()], |row| {
            Ok(MethodRow {
                method_id: MethodId::from_bytes(column_array16(row, 0)?),
                method_type: u8::try_from(row.get::<_, i64>(1)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, 0))?,
                wrap: row.get(2)?,
                kek_generation: u32::try_from(row.get::<_, i64>(3)?)
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
                credential_id: row.get(4)?,
                prf_salt: row.get(5)?,
                aaguid: row.get(6)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);
    let manifest = tx.query_row(
        "SELECT item_id, rev, seq, deleted, blob, tag, tomb FROM ferret_items \
         WHERE vault_id = ?1 AND item_id = ?2",
        params![vault_id, MANIFEST_ITEM_ID.as_bytes()],
        |row| {
            Ok(Change {
                id: ItemId::from_bytes(column_array16(row, 0)?),
                rev: column_u64(row, 1)?,
                seq: column_u64(row, 2)?,
                deleted: row.get::<_, i64>(3)? != 0,
                blob: row.get(4)?,
                tag: column_tag(row, 5)?,
                tomb: row.get(6)?,
            })
        },
    )?;
    tx.finish()?;
    Ok(MethodsView {
        methods,
        pk_a,
        vk_epoch,
        manifest,
    })
}

/// The account of a kit user.
pub struct AccountRow {
    /// The account.
    pub account_id: AccountId,
    /// The kit user.
    pub user_id: i64,
    /// Its vault.
    pub vault_id: VaultId,
    /// The OPAQUE record with its profile.
    pub record: StoredRecord,
    /// Whether the account has a secret key.
    pub sk_hint: bool,
    /// The public key that authorises changes.
    pub pk_a: [u8; 32],
    /// The public key of the recovery key.
    pub pk_r: [u8; 32],
    /// The epoch of the vault key.
    pub vk_epoch: u64,
    /// When the account was made (Unix seconds).
    pub created_at: i64,
}

impl std::fmt::Debug for AccountRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountRow")
            .field("account_id", &self.account_id)
            .field("user_id", &self.user_id)
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

/// The account of a kit user, if it has one.
pub fn account_by_user(conn: &Connection, user_id: i64) -> Result<Option<AccountRow>, StoreError> {
    Ok(conn
        .query_row(
            "SELECT account_id, vault_id, opaque_record, ksf_profile, sk_hint, pk_a, pk_r, \
                    vk_epoch, created_at \
             FROM ferret_accounts WHERE user_id = ?1",
            [user_id],
            |row| {
                let record_bytes: Vec<u8> = row.get(2)?;
                let validated = ValidatedRecord::parse(&record_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(2, Type::Blob, Box::new(e))
                })?;
                Ok(AccountRow {
                    account_id: AccountId::from_bytes(column_array16(row, 0)?),
                    user_id,
                    vault_id: VaultId::from_bytes(column_array16(row, 1)?),
                    record: StoredRecord {
                        record: validated,
                        ksf_profile: u8::try_from(row.get::<_, i64>(3)?)
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, 0))?,
                    },
                    sk_hint: row.get::<_, i64>(4)? != 0,
                    pk_a: column_array32(row, 5)?,
                    pk_r: column_array32(row, 6)?,
                    vk_epoch: column_u64(row, 7)?,
                    created_at: row.get(8)?,
                })
            },
        )
        .optional()?)
}

/// A non-negative integer column.
pub(crate) fn column_u64(row: &Row<'_>, idx: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(idx)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(idx, value))
}

fn column_array16(row: &Row<'_>, idx: usize) -> rusqlite::Result<[u8; 16]> {
    let bytes: Vec<u8> = row.get(idx)?;
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, Type::Blob, Box::new(e)))
}

/// A tag column: NULL or exactly 32 bytes.
fn column_tag(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<[u8; 32]>> {
    let bytes: Option<Vec<u8>> = row.get(idx)?;
    bytes
        .map(|b| {
            <[u8; 32]>::try_from(b.as_slice()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(idx, Type::Blob, Box::new(e))
            })
        })
        .transpose()
}

fn column_array32(row: &Row<'_>, idx: usize) -> rusqlite::Result<[u8; 32]> {
    let bytes: Vec<u8> = row.get(idx)?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|e| rusqlite::Error::FromSqlConversionFailure(idx, Type::Blob, Box::new(e)))
}

/// 32 bytes from a column that must hold exactly that.
fn array32(bytes: &[u8], idx: usize) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(bytes).map_err(|e| {
        StoreError::Sql(rusqlite::Error::FromSqlConversionFailure(
            idx,
            Type::Blob,
            Box::new(e),
        ))
    })
}

/// A number from a client that does not fit the database's integers.
fn int_error(_value: u64) -> StoreError {
    StoreError::Sql(rusqlite::Error::ToSqlConversionFailure(
        "integer out of range".into(),
    ))
}

fn int_error_signed(value: i64) -> StoreError {
    StoreError::Sql(rusqlite::Error::IntegralValueOutOfRange(0, value))
}

#[cfg(test)]
mod tests {
    use ferret_server_auth::testing::LoginFixture;

    use super::*;

    const NOW: i64 = 1_793_491_200;

    fn id16(kind: u8) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0] = kind;
        bytes
    }

    /// An in-memory database with every migration and one account.
    fn with_account() -> (Connection, VaultId, DeviceId) {
        crate::product::install();
        let mut conn = Connection::open_in_memory().expect("open");
        conn.execute_batch("PRAGMA foreign_keys = ON;")
            .expect("pragma");
        vole_kit::db::migrate::apply_migrations(&mut conn).expect("migrations apply");
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('a@example.com', 'x', 'editor')",
            [],
        )
        .expect("a user");
        let user_id = conn.last_insert_rowid();
        let vault = VaultId::from_bytes(id16(0xb0));
        let rows = NewAccountRows {
            account_id: AccountId::from_bytes(id16(0xa0)),
            user_id,
            vault_id: vault,
            record: LoginFixture::new().record,
            sk_hint: true,
            pk_a: [0x11; 32],
            pk_r: [0x22; 32],
            methods: vec![MethodRow {
                method_id: MethodId::from_bytes(id16(0xc1)),
                method_type: 1,
                wrap: vec![0x31; 60],
                kek_generation: 1,
                credential_id: None,
                prf_salt: None,
                aaguid: None,
            }],
            manifest: ManifestIn {
                rev: 1,
                envelope: vec![0x4d; 40],
                tag: [0x7a; 32],
            },
            checkpoint: CheckpointIn {
                seq: 1,
                digest: vec![0x41; 32],
                mac: vec![0x42; 32],
                entries: vec![0x43; 20],
            },
            now: NOW,
        };
        let tx = conn.transaction().expect("a transaction");
        create_account(&tx, &rows).expect("create_account");
        tx.commit().expect("commit");
        (conn, vault, DeviceId(id16(0xd0)))
    }

    /// A write of item `n` with the given body, `base_rev` and idempotency key.
    fn write(
        n: u8,
        body: PutBody<'static>,
        base_rev: u64,
        key: u8,
        resurrect: bool,
    ) -> PutRequest<'static> {
        PutRequest {
            item_id: ItemId::from_bytes(id16(n)),
            base_rev,
            body,
            idem: [key; 16],
            request_hash: [key; 32],
            resurrect,
        }
    }

    fn live(tag: u8) -> PutBody<'static> {
        PutBody::Live {
            blob: b"envelope",
            tag: [tag; 32],
        }
    }

    fn gone() -> PutBody<'static> {
        PutBody::Deleted { tomb: b"gone" }
    }

    #[test]
    fn only_a_live_body_with_the_tombstones_rev_resurrects_it() {
        let (mut conn, vault, device) = with_account();
        let limits = Limits::DEFAULT;
        let put = |conn: &mut Connection, req: PutRequest<'static>| {
            put_item(conn, &vault, &device, &req, &limits, NOW).expect("a write")
        };
        assert!(matches!(
            put(&mut conn, write(0x10, live(1), 0, 1, false)),
            PutOutcome::Stored { rev: 1, .. }
        ));
        assert!(matches!(
            put(&mut conn, write(0x10, gone(), 1, 2, false)),
            PutOutcome::Stored { rev: 2, .. }
        ));
        // Without the flag, with an older basis, and with a tombstone body that
        // carries the flag: each is the conflict of a deleted row.
        for (n, req) in [
            (3, write(0x10, live(3), 2, 3, false)),
            (4, write(0x10, live(4), 1, 4, true)),
            (5, write(0x10, gone(), 2, 5, true)),
        ] {
            let PutOutcome::Conflict(conflict) = put(&mut conn, req) else {
                panic!("write {n} should conflict");
            };
            assert!(conflict.deleted, "write {n}");
            assert_eq!(conflict.current_rev, 2, "write {n}");
        }
        let PutOutcome::Stored { rev, seq, replayed } =
            put(&mut conn, write(0x10, live(6), 2, 6, true))
        else {
            panic!("the resurrection should be stored");
        };
        assert_eq!((rev, replayed), (3, false));
        assert_eq!(
            seq, 4,
            "a new seq: manifest 1, create 2, delete 3, resurrect 4"
        );
        let (deleted, count): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT deleted FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2), (SELECT item_count FROM ferret_vaults WHERE vault_id = ?1)",
                params![vault.as_bytes(), ItemId::from_bytes(id16(0x10)).as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the row");
        assert_eq!(deleted, 0, "the row is live again");
        assert_eq!(count, 2, "the manifest and the resurrected item");
    }

    #[test]
    fn a_resurrection_needs_room_under_max_items() {
        let (mut conn, vault, device) = with_account();
        // Room for the manifest and one item.
        let limits = Limits {
            max_items: 2,
            ..Limits::DEFAULT
        };
        let put = |conn: &mut Connection, req: PutRequest<'static>| {
            put_item(conn, &vault, &device, &req, &limits, NOW).expect("a write")
        };
        assert!(matches!(
            put(&mut conn, write(0x10, live(1), 0, 1, false)),
            PutOutcome::Stored { .. }
        ));
        assert!(matches!(
            put(&mut conn, write(0x10, gone(), 1, 2, false)),
            PutOutcome::Stored { rev: 2, .. }
        ));
        // The freed slot is used by another item.
        assert!(matches!(
            put(&mut conn, write(0x11, live(3), 0, 3, false)),
            PutOutcome::Stored { .. }
        ));
        assert_eq!(
            put(&mut conn, write(0x10, live(4), 2, 4, true)),
            PutOutcome::QuotaExceeded
        );
        let deleted: i64 = conn
            .query_row(
                "SELECT deleted FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
                params![vault.as_bytes(), ItemId::from_bytes(id16(0x10)).as_bytes()],
                |row| row.get(0),
            )
            .expect("the row");
        assert_eq!(deleted, 1, "the tombstone is still the row");
    }

    fn checkpoint(seq: u64, byte: u8) -> StoredCheckpoint {
        StoredCheckpoint {
            seq,
            digest: [byte; 32],
            mac: [byte.wrapping_add(1); 32],
            entries: vec![byte; 56],
        }
    }

    #[test]
    fn put_checkpoint_keeps_the_highest_seq_and_never_a_seq_above_the_vault() {
        let (mut conn, vault, device) = with_account();
        let limits = Limits::DEFAULT;
        // The registration checkpoint is at seq 1.
        assert_eq!(
            checkpoint_head(&conn, &vault).expect("a head").map(|h| h.0),
            Some(1)
        );
        for n in 1..=3u8 {
            put_item(
                &mut conn,
                &vault,
                &device,
                &write(0x20 + n, live(n), 0, n, false),
                &limits,
                NOW,
            )
            .expect("a write");
        }
        // The vault is at seq 4.
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &checkpoint(5, 0x51)).expect("a result"),
            CheckpointOutcome::AboveVault
        );
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &checkpoint(3, 0x31)).expect("a result"),
            CheckpointOutcome::Stored { seq: 3 }
        );
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &checkpoint(3, 0x31)).expect("a result"),
            CheckpointOutcome::Unchanged { seq: 3 }
        );
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &checkpoint(3, 0x32)).expect("a result"),
            CheckpointOutcome::Stale { stored_seq: 3 }
        );
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &checkpoint(2, 0x21)).expect("a result"),
            CheckpointOutcome::Stale { stored_seq: 3 }
        );
        assert_eq!(
            get_checkpoint(&conn, &vault).expect("a checkpoint"),
            checkpoint(3, 0x31),
            "nothing but the first upload at seq 3 was written"
        );
        assert_eq!(
            checkpoint_head(&conn, &vault).expect("a head"),
            Some((3, [0x31; 32], [0x32; 32]))
        );
    }

    #[test]
    fn a_checkpoint_is_decided_from_the_heads_and_only_a_same_head_needs_the_entries() {
        let head =
            |seq: u64, digest: u8, mac: u8| -> CheckpointHead { (seq, [digest; 32], [mac; 32]) };
        let stored = head(5, 1, 2);
        // Above the vault: refused before the stored checkpoint matters.
        assert_eq!(
            decide_checkpoint(7, &stored, &head(8, 1, 2)),
            CheckpointStep::AboveVault
        );
        // A stale upload is decided from the heads: nothing asks for entries.
        for incoming in [
            head(4, 1, 2),
            head(0, 1, 2),
            head(4, 9, 9),
            head(5, 9, 2),
            head(5, 1, 9),
        ] {
            assert_eq!(
                decide_checkpoint(7, &stored, &incoming),
                CheckpointStep::Stale { stored_seq: 5 },
                "{incoming:?}"
            );
        }
        // Only an equal head can be a retry, and only the entries can tell.
        assert_eq!(
            decide_checkpoint(7, &stored, &head(5, 1, 2)),
            CheckpointStep::SameHead
        );
        // Newer, up to the seq of the vault: written.
        for seq in [6, 7] {
            assert_eq!(
                decide_checkpoint(7, &stored, &head(seq, 9, 9)),
                CheckpointStep::Replace
            );
        }
    }

    #[test]
    fn a_same_head_with_other_entries_is_stale_and_with_the_same_entries_unchanged() {
        let (mut conn, vault, device) = with_account();
        put_item(
            &mut conn,
            &vault,
            &device,
            &write(0x20, live(1), 0, 1, false),
            &Limits::DEFAULT,
            NOW,
        )
        .expect("a write");
        let first = checkpoint(2, 0x31);
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &first).expect("a result"),
            CheckpointOutcome::Stored { seq: 2 }
        );
        let other_entries = StoredCheckpoint {
            entries: vec![0x99; 56],
            ..first.clone()
        };
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &other_entries).expect("a result"),
            CheckpointOutcome::Stale { stored_seq: 2 }
        );
        assert_eq!(
            put_checkpoint(&mut conn, &vault, &first).expect("a result"),
            CheckpointOutcome::Unchanged { seq: 2 }
        );
        assert_eq!(get_checkpoint(&conn, &vault).expect("a checkpoint"), first);
    }

    #[test]
    fn a_vault_that_is_not_there_has_no_checkpoint() {
        let (mut conn, _vault, _device) = with_account();
        let nobody = VaultId::from_bytes([0xee; 16]);
        assert_eq!(checkpoint_head(&conn, &nobody).expect("a head"), None);
        assert!(matches!(
            get_checkpoint(&conn, &nobody),
            Err(StoreError::NotFound)
        ));
        assert!(matches!(
            put_checkpoint(&mut conn, &nobody, &checkpoint(1, 1)),
            Err(StoreError::NotFound)
        ));
    }
}
