//! Idempotency records of writes: checked before `base_rev`, scoped to a vault and
//! a device. Spec: Fase 1 § 8.3.
//!
//! A client that did not see the answer to a write sends the same write again
//! with the same `idem`. If the first one was accepted, the second must get the
//! original `rev` and `seq` back, even when another write to the item came in
//! between and `base_rev` is stale by now. So the record is looked up first.
//! The record is scoped to `(vault, device)`: the same `idem` bytes from
//! another device or in another vault mean nothing. The same `idem` with a
//! different request is a client bug and is refused.

use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::StoreError;
use crate::ids::{DeviceId, VaultId};

/// What the record of an `idem` says about a write that arrives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// No record: a new write.
    Fresh,
    /// The same write was accepted before, with this `rev` and `seq`.
    Replay {
        /// The `rev` of the accepted write.
        rev: u64,
        /// The `seq` of the accepted write.
        seq: u64,
    },
    /// A record with another request hash: the `idem` was used for another
    /// write.
    Mismatch,
}

/// Looks up the record of `idem` for this vault and device.
pub fn lookup(
    conn: &Connection,
    vault: &VaultId,
    device: &DeviceId,
    idem: &[u8; 16],
    request_hash: &[u8; 32],
) -> Result<Lookup, StoreError> {
    let found = conn
        .query_row(
            "SELECT request_hash, rev, seq FROM ferret_idem \
             WHERE vault_id = ?1 AND device_id = ?2 AND idem = ?3",
            params![vault.as_bytes(), device.0, idem],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    super::store::column_u64(row, 1)?,
                    super::store::column_u64(row, 2)?,
                ))
            },
        )
        .optional()?;
    Ok(match found {
        None => Lookup::Fresh,
        Some((hash, rev, seq)) => {
            if hash.as_slice() == request_hash.as_slice() {
                Lookup::Replay { rev, seq }
            } else {
                Lookup::Mismatch
            }
        }
    })
}

/// Records an accepted write with its `(rev, seq)`. Called in the transaction of the write; a record
/// that exists already is an error (the lookup came first).
pub fn record(
    conn: &Connection,
    vault: &VaultId,
    device: &DeviceId,
    idem: &[u8; 16],
    request_hash: &[u8; 32],
    (rev, seq): (i64, i64),
    now: i64,
) -> Result<(), StoreError> {
    conn.execute(
        "INSERT INTO ferret_idem (vault_id, device_id, idem, request_hash, rev, seq, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            vault.as_bytes(),
            device.0,
            idem,
            request_hash,
            rev,
            seq,
            now
        ],
    )?;
    Ok(())
}

/// Removes the records made before `before` (Unix seconds). Returns how many
/// went. A record only has to outlive the time a client keeps retrying.
pub fn purge_before(conn: &Connection, before: i64) -> Result<usize, StoreError> {
    Ok(conn.execute("DELETE FROM ferret_idem WHERE created_at < ?1", [before])?)
}
