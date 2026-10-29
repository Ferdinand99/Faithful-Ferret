//! Access to the AADs and signed messages of the integrity layer, for tests
//! and vector runners. Behind `test-support`; never part of a release.

use crate::error::Error;
use crate::ids::{AccountId, ItemId, VaultId};
use crate::integrity::MutationOp;
use crate::integrity::checkpoint::checkpoint_message;
use crate::integrity::proof::proof_message;
use crate::integrity::tomb::tomb_aad;
use crate::secret::RecoveryKey;

/// The AAD of a tombstone.
pub fn tombstone_aad(vault_id: &VaultId, item_id: &ItemId, rev: u64) -> Result<Vec<u8>, Error> {
    tomb_aad(vault_id, item_id, rev)
}

/// The message that the checkpoint MAC covers.
pub fn checkpoint_mac_message(seq: u64, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
    checkpoint_message(seq, digest)
}

/// The bytes that a mutation or recovery proof signs.
pub fn mutation_proof_message(
    op: MutationOp,
    account_id: &AccountId,
    nonce: &[u8; 32],
    vk_epoch: u64,
    body: &[u8],
) -> Result<Vec<u8>, Error> {
    proof_message(op, account_id, nonce, vk_epoch, body)
}

/// The 32 bytes of a recovery key.
pub fn recovery_key_bytes(rk: &RecoveryKey) -> [u8; 32] {
    *rk.expose()
}
