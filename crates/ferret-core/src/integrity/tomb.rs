//! Authenticated tombstones.
//!
//! Spec: Fase 1 § 8.4. A deletion is a new revision with no blob but an
//! authenticated tombstone:
//!
//! ```text
//! tomb = AEAD(K_del, nonce, pt = empty,
//!             aad = TLV[label="ferret/v1/tomb", version, suite,
//!                       vault_id, item_id, rev])
//! ```
//!
//! The plaintext is empty, so a tombstone is `nonce (24) ‖ tag (16)` = 40
//! bytes. `K_del` is used, not the item key, so deleting needs no item key.
//! The server has no `K_del`, so it cannot make a tombstone, and cannot move
//! one to another item, revision or vault.

use crate::envelope::{VERSION, check_item_id};
use crate::error::Error;
use crate::ids::{ItemId, VaultId};
use crate::keys::UnlockedVault;
use crate::prim::aead::{OVERHEAD, aead_open, aead_seal};
use crate::rng::SecureRng;
use crate::tlv::{SUITE, Tlv, tag};

/// Label of the tombstone AAD. Spec: Fase 1 § 8.4.
const LABEL_TOMB: &str = "ferret/v1/tomb";

/// Length of a tombstone in bytes: the nonce and the tag.
pub const TOMB_LEN: usize = OVERHEAD;

/// A tombstone and the revision it was made for (it is in the AAD).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tombstone {
    /// The 40 bytes the server stores.
    pub tomb: Vec<u8>,
    /// The revision of the deletion.
    pub rev: u64,
}

/// `TLV[label="ferret/v1/tomb", version, suite, vault_id, item_id, rev]`.
///
/// Spec: Fase 1 § 8.4.
pub(crate) fn tomb_aad(vault_id: &VaultId, item_id: &ItemId, rev: u64) -> Result<Vec<u8>, Error> {
    Tlv::new()
        .label(LABEL_TOMB)
        .u8(tag::VERSION, VERSION)
        .u8(tag::SUITE, SUITE)
        .bytes(tag::VAULT_ID, vault_id.as_bytes())?
        .bytes(tag::ITEM_ID, item_id.as_bytes())?
        .u64(tag::REV, rev)
        .finish()
}

/// Makes the tombstone of `item_id` at revision `rev` (the revision the
/// deletion gets, `base_rev + 1`). Draws one 24-byte nonce.
///
/// The reserved `item_id` of the manifest cannot be deleted.
///
/// Spec: Fase 1 § 8.4.
pub fn make_tombstone<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
) -> Result<Tombstone, Error> {
    check_item_id(&item_id)?;
    let aad = tomb_aad(&vault.context().vault_id, &item_id, rev)?;
    let tomb = aead_seal(rng, vault.k_del().expose(), &aad, &[])?;
    Ok(Tombstone { tomb, rev })
}

/// Checks a tombstone for `item_id` at `rev`. A wrong length, key, field or
/// changed byte is `TombstoneInvalid`, without a cause.
///
/// A client that gets `TombstoneInvalid` puts the item in quarantine and
/// does not delete its local copy (Fase 1 § 8.4).
///
/// Spec: Fase 1 § 8.4.
pub fn verify_tombstone(
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    tomb: &[u8],
) -> Result<(), Error> {
    let open = || -> Result<(), Error> {
        if tomb.len() != TOMB_LEN {
            return Err(Error::Decrypt);
        }
        check_item_id(&item_id)?;
        let aad = tomb_aad(&vault.context().vault_id, &item_id, rev)?;
        let pt = aead_open(vault.k_del().expose(), &aad, tomb)?;
        if pt.is_empty() {
            Ok(())
        } else {
            Err(Error::Decrypt)
        }
    };
    open().map_err(|_| Error::TombstoneInvalid)
}
