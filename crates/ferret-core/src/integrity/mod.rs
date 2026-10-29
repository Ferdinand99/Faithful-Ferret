//! Integrity: authenticated tombstones, signed checkpoints, mutation proofs
//! and the full rekey.
//!
//! * [`tomb`]: a deleted item is a tombstone sealed under `K_del`
//!   (Fase 1 § 8.4).
//! * [`checkpoint`]: the signed list of `(item_id, rev, hash)` that lets a
//!   client notice a server that hides or rolls back rows (Fase 1 § 8.6).
//! * [`proof`]: the Ed25519 proof that goes with every sensitive request
//!   (Fase 1 § 4.6), signed by `sk_a`, or by `sk_r` at recovery.
//! * [`rekey`]: a new vault key, new item keys, new wraps and a new recovery
//!   key, made as one plan that the server applies atomically (Fase 1
//!   § 4.7).

pub mod checkpoint;
pub mod proof;
pub mod rekey;
pub mod tomb;

pub use checkpoint::{
    Checkpoint, CheckpointEntry, ENTRY_LEN, MAX_ENTRIES, RowState, ServerRow, blob_hash,
    encode_entries, make_checkpoint, parse_entries, verify_checkpoint,
};
pub use proof::{MutationOp, auth_sign, recovery_sign, verify_mutation_proof};
pub use rekey::{RekeyBundle, RekeyInput, RekeyItem, RekeyTombstone};
pub use tomb::{TOMB_LEN, Tombstone, make_tombstone, verify_tombstone};
