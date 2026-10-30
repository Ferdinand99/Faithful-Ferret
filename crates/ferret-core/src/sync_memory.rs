//! What a client remembers about the server's state, so that a server that
//! shows an older state is noticed.
//!
//! Spec: Fase 1 § 8.6 ("Lokalt minne"): every client remembers the highest
//! `rev` it has seen per item, the highest `seq` and the highest verified
//! checkpoint, and refuses lower values.
//!
//! [`SyncMemory`] is the data and the comparisons; **the client stores it**
//! (storage is outside the core). Keep one record per account and server,
//! beside the [`crate::Pinned`] record, load it before every check and store
//! the changed record after a check has succeeded. The record is not secret.
//! It survives logging out and is removed only when the user forgets the
//! server. The `vk_epoch` floor is in [`crate::Pinned`] and is not repeated
//! here.
//!
//! # What is refused
//!
//! * a server whose highest `seq` is below `max_seq`
//!   ([`CheckpointFailure::RememberedTopSeq`]);
//! * a checkpoint whose `seq` is below `checkpoint_seq`
//!   ([`CheckpointFailure::RememberedCheckpointSeq`]);
//! * a row whose `rev` is below the highest `rev` seen for that item
//!   ([`CheckpointFailure::RememberedRev`]).
//!
//! Every `accept_*` call checks first and changes the record only when the
//! whole call has succeeded. [`verify_checkpoint`] takes the memory as an
//! explicit argument ([`RollbackMemory`]); there is no default, and a caller
//! that has no memory says so with [`RollbackMemory::NoMemory`].
//!
//! # Size
//!
//! The record tracks at most [`MAX_TRACKED_ITEMS`] items (50 000: a vault
//! holds at most 10 000 items, and deleted items keep their entry). When a
//! new item would exceed that, the call fails with [`Error::TooLarge`] and
//! the record is unchanged. Nothing is evicted: dropping an entry would
//! silently lower a floor. The serialised record is at most
//! `1 + 8 + 8 + 4 + 24 * 50 000` bytes (about 1.2 MB).
//!
//! # Older state
//!
//! A restore of the server from a backup shows a lower `seq` (with a higher
//! `restore_epoch`, which the sync layer handles). That is never accepted on
//! its own. After the user has confirmed, and only then,
//! [`SyncMemory::accept_older_state`] replaces the record with the state of
//! a checkpoint that verifies on its own.

use crate::error::{CheckpointFailure, Error, MalformedKind};
use crate::integrity::{Checkpoint, ServerRow, verify_checkpoint};
use crate::keys::UnlockedVault;
use std::collections::BTreeMap;

/// The most items the record tracks.
pub const MAX_TRACKED_ITEMS: usize = 50_000;

/// The `version` byte of the serialised record.
pub const SYNC_MEMORY_VERSION: u8 = 1;

/// `version (1) ‖ max_seq (8) ‖ checkpoint_seq (8) ‖ count (4)`.
const HEADER_LEN: usize = 1 + 8 + 8 + 4;
/// `item_id (16) ‖ rev (8)`.
const ENTRY_LEN: usize = 16 + 8;

fn malformed() -> Error {
    Error::Malformed(MalformedKind::PinnedRecord)
}

fn fail(kind: CheckpointFailure) -> Error {
    Error::Checkpoint(kind)
}

/// The rollback memory of one account on one server. See the module
/// documentation.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SyncMemory {
    /// The highest `seq` the server has shown.
    max_seq: u64,
    /// The `seq` of the highest verified checkpoint.
    checkpoint_seq: u64,
    /// The highest `rev` seen per item.
    revs: BTreeMap<[u8; 16], u64>,
}

/// The rollback memory as an explicit argument of [`verify_checkpoint`]: the
/// client's record, or a named statement that there is none.
#[derive(Debug)]
pub enum RollbackMemory<'a> {
    /// The client's record. Checked, and advanced when the checkpoint
    /// verifies.
    Remembered(&'a mut SyncMemory),
    /// No memory: only the checkpoint's own checks run. Use it only where
    /// there is no earlier state to compare with (a first sync of a new
    /// device, a check in a test).
    NoMemory,
}

impl SyncMemory {
    /// An empty record: nothing seen yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The highest `seq` the server has shown.
    pub fn max_seq(&self) -> u64 {
        self.max_seq
    }

    /// The `seq` of the highest verified checkpoint.
    pub fn checkpoint_seq(&self) -> u64 {
        self.checkpoint_seq
    }

    /// The highest `rev` seen for an item.
    pub fn rev_of(&self, item_id: &crate::ids::ItemId) -> Option<u64> {
        self.revs.get(item_id.as_bytes()).copied()
    }

    /// The number of items tracked.
    pub fn tracked(&self) -> usize {
        self.revs.len()
    }

    /// Checks the server's highest `seq` and a set of verified rows against
    /// the record, without changing it.
    pub fn check_rows(&self, rows: &[ServerRow], top_seq: u64) -> Result<(), Error> {
        if top_seq < self.max_seq {
            return Err(fail(CheckpointFailure::RememberedTopSeq));
        }
        for row in rows {
            if let Some(known) = self.revs.get(row.item_id.as_bytes())
                && row.rev < *known
            {
                return Err(fail(CheckpointFailure::RememberedRev));
            }
        }
        Ok(())
    }

    /// Checks the `seq` of a checkpoint against the highest verified one.
    pub fn check_checkpoint_seq(&self, seq: u64) -> Result<(), Error> {
        if seq < self.checkpoint_seq {
            return Err(fail(CheckpointFailure::RememberedCheckpointSeq));
        }
        Ok(())
    }

    /// Checks a set of rows (from `/changes` or a download) and, when they
    /// hold, remembers them: `max_seq` and the `rev` of each item go up,
    /// never down. The rows must come from [`ServerRow::live`] or
    /// [`ServerRow::deleted`], that is, their tags or tombstones have been
    /// verified. On any error the record is unchanged.
    pub fn accept_rows(&mut self, rows: &[ServerRow], top_seq: u64) -> Result<(), Error> {
        self.check_rows(rows, top_seq)?;
        self.record(rows, top_seq, None)
    }

    /// Applies rows that have been checked. Fails with `too_large` before
    /// changing anything when the record would grow past
    /// [`MAX_TRACKED_ITEMS`].
    fn record(
        &mut self,
        rows: &[ServerRow],
        top_seq: u64,
        checkpoint_seq: Option<u64>,
    ) -> Result<(), Error> {
        let mut next: BTreeMap<[u8; 16], u64> = BTreeMap::new();
        let mut added = 0usize;
        for row in rows {
            let key = *row.item_id.as_bytes();
            let seen = next
                .get(&key)
                .copied()
                .or_else(|| self.revs.get(&key).copied());
            if seen.is_none() {
                added = added.checked_add(1).ok_or(Error::TooLarge)?;
            }
            next.insert(key, seen.map_or(row.rev, |s| s.max(row.rev)));
        }
        if self
            .revs
            .len()
            .checked_add(added)
            .is_none_or(|n| n > MAX_TRACKED_ITEMS)
        {
            return Err(Error::TooLarge);
        }
        self.revs.extend(next);
        self.max_seq = self.max_seq.max(top_seq);
        if let Some(seq) = checkpoint_seq {
            self.checkpoint_seq = self.checkpoint_seq.max(seq);
        }
        Ok(())
    }

    /// Replaces the record with the state of an older checkpoint, **after
    /// the user has confirmed** "accept older state" (Fase 1 § 8.6,
    /// "Legitime tilbakerullinger", for example a server restored from a
    /// backup). It is never called on its own: every other call refuses
    /// lower values.
    ///
    /// The older state must verify by itself: the checkpoint is checked
    /// against `rows` and `top_seq` as in [`verify_checkpoint`] without a
    /// memory. The floors then become what that state shows: `max_seq` is
    /// `top_seq`, `checkpoint_seq` is the checkpoint's `seq`, and the `rev`
    /// of each item is the one in `rows`. Local changes the server lacks are
    /// uploaded by the sync layer afterwards.
    pub fn accept_older_state(
        &mut self,
        vault: &UnlockedVault,
        checkpoint: &Checkpoint,
        rows: &[ServerRow],
        top_seq: u64,
    ) -> Result<(), Error> {
        verify_checkpoint(vault, checkpoint, rows, top_seq, RollbackMemory::NoMemory)?;
        let mut fresh = SyncMemory::new();
        fresh.record(rows, top_seq, Some(checkpoint.seq))?;
        *self = fresh;
        Ok(())
    }

    /// The part of [`verify_checkpoint`] that uses the memory: checks, then
    /// advances. Called with a checkpoint that has verified.
    pub(crate) fn accept_verified_checkpoint(
        &mut self,
        checkpoint_seq: u64,
        rows: &[ServerRow],
        top_seq: u64,
    ) -> Result<(), Error> {
        self.check_checkpoint_seq(checkpoint_seq)?;
        self.check_rows(rows, top_seq)?;
        self.record(rows, top_seq, Some(checkpoint_seq))
    }

    /// The record as bytes for storage: `version (1) ‖ max_seq (8) ‖
    /// checkpoint_seq (8) ‖ count (4)` and then `count` entries of
    /// `item_id (16) ‖ rev (8)` in ascending order of `item_id`. All integers
    /// are big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            HEADER_LEN.saturating_add(self.revs.len().saturating_mul(ENTRY_LEN)),
        );
        out.push(SYNC_MEMORY_VERSION);
        out.extend_from_slice(&self.max_seq.to_be_bytes());
        out.extend_from_slice(&self.checkpoint_seq.to_be_bytes());
        // At most MAX_TRACKED_ITEMS, which fits.
        out.extend_from_slice(
            &u32::try_from(self.revs.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for (id, rev) in &self.revs {
            out.extend_from_slice(id);
            out.extend_from_slice(&rev.to_be_bytes());
        }
        out
    }

    /// Reads a stored record. Anything that [`SyncMemory::to_bytes`] would
    /// not have written is `Malformed(PinnedRecord)`: another version, a
    /// length that does not fit the count, a count above
    /// [`MAX_TRACKED_ITEMS`], entries out of order or repeated, or a
    /// `checkpoint_seq` above `max_seq`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (version, rest) = bytes.split_first().ok_or_else(malformed)?;
        if *version != SYNC_MEMORY_VERSION {
            return Err(malformed());
        }
        let (max_seq, rest) = take_u64(rest)?;
        let (checkpoint_seq, rest) = take_u64(rest)?;
        let (count, rest) = rest.split_at_checked(4).ok_or_else(malformed)?;
        let count = usize::try_from(u32::from_be_bytes(
            count.try_into().map_err(|_| malformed())?,
        ))
        .map_err(|_| malformed())?;
        if count > MAX_TRACKED_ITEMS || checkpoint_seq > max_seq {
            return Err(malformed());
        }
        if rest.len() != count.checked_mul(ENTRY_LEN).ok_or_else(malformed)? {
            return Err(malformed());
        }
        let mut revs = BTreeMap::new();
        let mut previous: Option<[u8; 16]> = None;
        let (chunks, _) = rest.as_chunks::<ENTRY_LEN>();
        for chunk in chunks {
            let (id, rev) = chunk.split_at_checked(16).ok_or_else(malformed)?;
            let id: [u8; 16] = id.try_into().map_err(|_| malformed())?;
            let (rev, _) = take_u64(rev)?;
            if previous.is_some_and(|p| p >= id) {
                return Err(malformed());
            }
            previous = Some(id);
            revs.insert(id, rev);
        }
        Ok(Self {
            max_seq,
            checkpoint_seq,
            revs,
        })
    }
}

fn take_u64(bytes: &[u8]) -> Result<(u64, &[u8]), Error> {
    let (head, rest) = bytes.split_at_checked(8).ok_or_else(malformed)?;
    let head: [u8; 8] = head.try_into().map_err(|_| malformed())?;
    Ok((u64::from_be_bytes(head), rest))
}
