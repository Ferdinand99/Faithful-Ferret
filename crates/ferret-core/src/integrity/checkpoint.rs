//! Signed checkpoints: the roll-back protection of Fase 1 § 8.6.
//!
//! ```text
//! entries = for all rows of the client's state at seq = S, ascending by the
//!           raw bytes of item_id:   item_id (16) ‖ u64be(rev) ‖ h (32)
//!           # h = SHA-256(blob), or 32 zero bytes for a tombstone
//! digest  = SHA-256(entries)
//! mac     = HMAC-SHA256(K_head, TLV[label="ferret/v1/checkpoint",
//!                                   seq = S, hash = digest])
//! ```
//!
//! The server stores the checkpoint with the highest `seq` and the
//! `entries` list. A receiver checks, in this order (the numbers are the
//! points of § 8.6):
//!
//! 1. every row: its tag, or its tombstone, is valid. The caller does this
//!    before a [`ServerRow`] exists (see [`ServerRow::live`] and
//!    [`ServerRow::deleted`], which do it);
//! 2. the checkpoint: the MAC ([`CheckpointFailure::BadMac`]) and
//!    `digest = SHA-256(entries)` ([`CheckpointFailure::BadDigest`]);
//! 3. every live entry must be shown by the server with the same or a higher
//!    `rev`; at the same `rev` the hash must be the same; a deleted row must
//!    have a higher `rev`. A missing row is
//!    [`CheckpointFailure::HiddenOrRolledBack`] (at the top, see 5), a lower `rev`
//!    [`CheckpointFailure::LowerRev`], another hash at the same `rev`
//!    [`CheckpointFailure::SameRevDifferentHash`];
//! 4. a tombstone entry may be missing (tombstones are dropped after 400
//!    days), but a live row with a lower `rev` than the tombstone is
//!    [`CheckpointFailure::LiveBehindTombstone`];
//! 5. when the server's top is the checkpoint's `seq`, the rows must be
//!    exactly the entries: every row has an entry with the same `rev` and
//!    hash, and a live entry has its row. Only a tombstone entry may lack
//!    a row (it has been purged). Anything else is
//!    [`CheckpointFailure::TopDigestMismatch`].
//!
//! A live row whose hash is 32 zero bytes cannot be told from a tombstone in
//! `entries`, so it is refused (`Malformed(Entries)`); a SHA-256 output never
//! has that value.
//!
//! A checkpoint whose `seq` is above the server's top is
//! [`CheckpointFailure::SeqAboveTop`].

use crate::error::{CheckpointFailure, Error, MalformedKind};
use crate::ids::ItemId;
use crate::keys::UnlockedVault;
use crate::prim::{ct::ct_eq, mac::hmac_sha256};
use crate::tlv::{Tlv, tag};
use sha2::{Digest, Sha256};

/// Label of the checkpoint MAC. Spec: Fase 1 § 8.6.
const LABEL_CHECKPOINT: &str = "ferret/v1/checkpoint";

/// Length of one entry: `item_id (16) ‖ u64be(rev) ‖ h (32)`.
pub const ENTRY_LEN: usize = 16 + 8 + 32;
/// The most entries one checkpoint holds (56 MB of `entries`). A vault has a
/// few thousand items; the bound keeps a hostile list from using the memory
/// of the worker.
pub const MAX_ENTRIES: usize = 1_000_000;

/// `h` of a tombstone: 32 zero bytes.
const TOMB_HASH: [u8; 32] = [0; 32];

/// `SHA-256` of a blob (an item envelope), the `h` of a live entry.
///
/// Spec: Fase 1 § 8.6.
pub fn blob_hash(envelope: &[u8]) -> [u8; 32] {
    Sha256::digest(envelope).into()
}

/// One row of the client's state, for [`make_checkpoint`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointEntry {
    /// The item.
    pub item_id: ItemId,
    /// Its revision.
    pub rev: u64,
    /// `SHA-256(blob)` of a live row; `None` for a tombstone.
    pub live_hash: Option<[u8; 32]>,
}

impl CheckpointEntry {
    /// A live row: the hash is that of its envelope.
    pub fn live(item_id: ItemId, rev: u64, envelope: &[u8]) -> Self {
        Self {
            item_id,
            rev,
            live_hash: Some(blob_hash(envelope)),
        }
    }

    /// A tombstone.
    pub fn tombstone(item_id: ItemId, rev: u64) -> Self {
        Self {
            item_id,
            rev,
            live_hash: None,
        }
    }
}

/// A checkpoint as the client uploads it and the server keeps it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Checkpoint {
    /// The server `seq` the state is from.
    pub seq: u64,
    /// `SHA-256(entries)`.
    pub digest: [u8; 32],
    /// `HMAC-SHA256(K_head, TLV[label, seq, hash = digest])`.
    pub mac: [u8; 32],
    /// The sorted list, 56 bytes per row.
    pub entries: Vec<u8>,
}

/// What the server shows for a row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowState {
    /// A live row with `SHA-256(blob)`.
    Live {
        /// The hash of the blob.
        blob_sha256: [u8; 32],
    },
    /// A tombstone.
    Deleted,
}

/// A row of the server's state, **after** its tag (or tombstone) has been
/// verified. Make one with [`ServerRow::live`] or [`ServerRow::deleted`],
/// which do the verification, so that a row nobody checked cannot be passed
/// to [`verify_checkpoint`] by mistake.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServerRow {
    /// The item.
    pub item_id: ItemId,
    /// The revision the server shows.
    pub rev: u64,
    /// Live (with its hash) or deleted.
    pub state: RowState,
}

impl ServerRow {
    /// A live row, after `verify_item_tag`. A wrong tag is `Decrypt`.
    pub fn live(
        vault: &UnlockedVault,
        item_id: ItemId,
        rev: u64,
        envelope: &[u8],
        tag: &[u8; 32],
    ) -> Result<Self, Error> {
        crate::envelope::verify_item_tag(vault, item_id, rev, envelope, tag)?;
        Ok(Self {
            item_id,
            rev,
            state: RowState::Live {
                blob_sha256: blob_hash(envelope),
            },
        })
    }

    /// A deleted row, after `verify_tombstone`. A wrong tombstone is
    /// `TombstoneInvalid`.
    pub fn deleted(
        vault: &UnlockedVault,
        item_id: ItemId,
        rev: u64,
        tomb: &[u8],
    ) -> Result<Self, Error> {
        super::tomb::verify_tombstone(vault, item_id, rev, tomb)?;
        Ok(Self {
            item_id,
            rev,
            state: RowState::Deleted,
        })
    }

    fn entry(&self) -> CheckpointEntry {
        CheckpointEntry {
            item_id: self.item_id,
            rev: self.rev,
            live_hash: match self.state {
                RowState::Live { blob_sha256 } => Some(blob_sha256),
                RowState::Deleted => None,
            },
        }
    }
}

fn malformed_entries() -> Error {
    Error::Malformed(MalformedKind::Entries)
}

/// Sorts by the raw bytes of `item_id`, ascending.
fn sort_entries(entries: &mut [CheckpointEntry]) {
    entries.sort_unstable_by(|a, b| a.item_id.as_bytes().cmp(b.item_id.as_bytes()));
}

/// The `entries` bytes of a list of rows: sorted ascending by the raw bytes
/// of `item_id`, 56 bytes each. Two rows with the same `item_id` are
/// `Malformed(Entries)`, and more than [`MAX_ENTRIES`] is `TooLarge`.
///
/// Spec: Fase 1 § 8.6.
pub fn encode_entries(entries: &[CheckpointEntry]) -> Result<Vec<u8>, Error> {
    if entries.len() > MAX_ENTRIES {
        return Err(Error::TooLarge);
    }
    let mut sorted = entries.to_vec();
    sort_entries(&mut sorted);
    if sorted
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.item_id == b.item_id))
    {
        return Err(malformed_entries());
    }
    // A live row whose hash is 32 zero bytes would read back as a tombstone.
    if sorted.iter().any(|e| e.live_hash == Some(TOMB_HASH)) {
        return Err(malformed_entries());
    }
    let mut out = Vec::with_capacity(sorted.len().saturating_mul(ENTRY_LEN));
    for e in &sorted {
        out.extend_from_slice(e.item_id.as_bytes());
        out.extend_from_slice(&e.rev.to_be_bytes());
        out.extend_from_slice(&e.live_hash.unwrap_or(TOMB_HASH));
    }
    Ok(out)
}

/// Reads an `entries` list. The length must be a multiple of 56, and the
/// `item_id`s must be strictly ascending by their raw bytes (so sorted and
/// without repeats): anything else is `Malformed(Entries)`.
///
/// A hash of 32 zero bytes is a tombstone.
pub fn parse_entries(bytes: &[u8]) -> Result<Vec<CheckpointEntry>, Error> {
    let (chunks, rest) = bytes.as_chunks::<ENTRY_LEN>();
    if !rest.is_empty() {
        return Err(malformed_entries());
    }
    if chunks.len() > MAX_ENTRIES {
        return Err(Error::TooLarge);
    }
    let mut out: Vec<CheckpointEntry> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let (id, rest) = chunk.split_at(16);
        let (rev, hash) = rest.split_at(8);
        let item_id = ItemId::from_bytes(id.try_into().map_err(|_| malformed_entries())?);
        let rev = u64::from_be_bytes(rev.try_into().map_err(|_| malformed_entries())?);
        let hash: [u8; 32] = hash.try_into().map_err(|_| malformed_entries())?;
        if let Some(prev) = out.last()
            && prev.item_id.as_bytes() >= item_id.as_bytes()
        {
            return Err(malformed_entries());
        }
        out.push(CheckpointEntry {
            item_id,
            rev,
            live_hash: if hash == TOMB_HASH { None } else { Some(hash) },
        });
    }
    Ok(out)
}

/// `HMAC-SHA256(K_head, TLV[label="ferret/v1/checkpoint", seq, hash =
/// digest])`: the message is built by [`checkpoint_message`].
fn checkpoint_mac(vault: &UnlockedVault, seq: u64, digest: &[u8; 32]) -> Result<[u8; 32], Error> {
    hmac_sha256(vault.k_head().expose(), &checkpoint_message(seq, digest)?)
}

/// `TLV[label="ferret/v1/checkpoint", seq, hash = digest]`.
///
/// Spec: Fase 1 § 8.6.
pub(crate) fn checkpoint_message(seq: u64, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
    Tlv::new()
        .label(LABEL_CHECKPOINT)
        .u64(tag::SEQ, seq)
        .bytes(tag::HASH, digest)?
        .finish()
}

/// Makes the checkpoint of a state: `entries` (sorted here, whatever the
/// order of the input), their digest and the MAC. Two entries for one
/// `item_id` are `Malformed(Entries)`.
///
/// Spec: Fase 1 § 8.6.
pub fn make_checkpoint(
    vault: &UnlockedVault,
    seq: u64,
    entries: Vec<CheckpointEntry>,
) -> Result<Checkpoint, Error> {
    let entries = encode_entries(&entries)?;
    let digest: [u8; 32] = Sha256::digest(&entries).into();
    let mac = checkpoint_mac(vault, seq, &digest)?;
    Ok(Checkpoint {
        seq,
        digest,
        mac,
        entries,
    })
}

fn fail(kind: CheckpointFailure) -> Error {
    Error::Checkpoint(kind)
}

/// Checks a checkpoint against the rows the server shows, as in the module
/// documentation. `rows` are the rows of the full download (or of the
/// reconciliation after `410`), each made with [`ServerRow::live`] or
/// [`ServerRow::deleted`]. `server_top_seq` is the server's highest `seq`.
///
/// The checks run in this order and the first failure is returned: MAC,
/// digest, the entries' shape, `seq` against the top, each entry against its
/// row, and last, when the top is the checkpoint's `seq`, each row against
/// its entry.
///
/// At the top the rows must be exactly the entries, with one exception: a
/// **tombstone** entry without a row is accepted (the server drops
/// tombstones after 400 days). A **live** entry without a row is
/// `TopDigestMismatch`, and so is a row that has no entry, or another `rev`
/// or hash than its entry.
///
/// `rows` with the same `item_id` twice, or a live row whose hash is 32 zero
/// bytes, are `Malformed(Entries)`.
///
/// Spec: Fase 1 § 8.6.
pub fn verify_checkpoint(
    vault: &UnlockedVault,
    cp: &Checkpoint,
    rows: &[ServerRow],
    server_top_seq: u64,
) -> Result<(), Error> {
    // 2. The MAC over (seq, digest), then the digest over the entries.
    let expected_mac = checkpoint_mac(vault, cp.seq, &cp.digest)?;
    if !ct_eq(&expected_mac, &cp.mac) {
        return Err(fail(CheckpointFailure::BadMac));
    }
    let digest: [u8; 32] = Sha256::digest(&cp.entries).into();
    if !ct_eq(&digest, &cp.digest) {
        return Err(fail(CheckpointFailure::BadDigest));
    }
    let entries = parse_entries(&cp.entries)?;
    if cp.seq > server_top_seq {
        return Err(fail(CheckpointFailure::SeqAboveTop));
    }

    let mut sorted: Vec<&ServerRow> = rows.iter().collect();
    sorted.sort_unstable_by(|a, b| a.item_id.as_bytes().cmp(b.item_id.as_bytes()));
    if sorted
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.item_id == b.item_id))
    {
        return Err(malformed_entries());
    }

    if sorted
        .iter()
        .any(|r| matches!(r.state, RowState::Live { blob_sha256 } if blob_sha256 == TOMB_HASH))
    {
        return Err(malformed_entries());
    }
    let at_top = server_top_seq == cp.seq;

    // 3 and 4. Each entry against its row.
    for entry in &entries {
        let row = sorted
            .binary_search_by(|r| r.item_id.as_bytes().cmp(entry.item_id.as_bytes()))
            .ok()
            .and_then(|i| sorted.get(i));
        check_entry(entry, row.copied(), at_top)?;
    }

    // 5. At the top, every row must be an entry, with the same revision and
    // the same hash (or both deleted). An entry without a row was checked
    // above: only a tombstone may be missing.
    if at_top {
        for row in &sorted {
            let found = entries
                .binary_search_by(|e| e.item_id.as_bytes().cmp(row.item_id.as_bytes()))
                .ok()
                .and_then(|i| entries.get(i));
            match found {
                Some(e) if e.rev == row.rev && e.live_hash == row.entry().live_hash => {}
                _ => return Err(fail(CheckpointFailure::TopDigestMismatch)),
            }
        }
    }
    Ok(())
}

/// One entry of the checkpoint against the row the server shows for it.
fn check_entry(
    entry: &CheckpointEntry,
    row: Option<&ServerRow>,
    at_top: bool,
) -> Result<(), Error> {
    match entry.live_hash {
        // 3. A live entry.
        Some(hash) => {
            let Some(row) = row else {
                // At the top nothing may be missing, so the state is simply
                // not the checkpoint's.
                return Err(fail(if at_top {
                    CheckpointFailure::TopDigestMismatch
                } else {
                    CheckpointFailure::HiddenOrRolledBack
                }));
            };
            if row.rev < entry.rev {
                return Err(fail(CheckpointFailure::LowerRev));
            }
            if row.rev == entry.rev {
                return match row.state {
                    RowState::Live { blob_sha256 } if blob_sha256 == hash => Ok(()),
                    // The same revision with another blob, or deleted at
                    // the revision that was live: the server tells two
                    // stories about one revision.
                    _ => Err(fail(CheckpointFailure::SameRevDifferentHash)),
                };
            }
            // A higher revision is fine, live or deleted.
            Ok(())
        }
        // 4. A tombstone entry: a missing row is fine.
        None => {
            let Some(row) = row else {
                return Ok(());
            };
            match row.state {
                RowState::Deleted => {
                    if row.rev < entry.rev {
                        Err(fail(CheckpointFailure::LowerRev))
                    } else {
                        Ok(())
                    }
                }
                RowState::Live { .. } => {
                    if row.rev < entry.rev {
                        Err(fail(CheckpointFailure::LiveBehindTombstone))
                    } else if row.rev == entry.rev {
                        Err(fail(CheckpointFailure::SameRevDifferentHash))
                    } else {
                        // Revived on purpose, with a higher revision.
                        Ok(())
                    }
                }
            }
        }
    }
}
