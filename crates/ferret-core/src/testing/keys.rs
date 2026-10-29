//! Access to the key bytes and intermediate values of the key hierarchy and
//! the wraps, for tests and vector runners. Behind `test-support`; never
//! part of a release.

use crate::error::Error;
use crate::keys::{self, UnlockedVault, VaultContext};
use crate::secret::{Kek, RecoveryKey, VaultKey};
use crate::wrap::{self, WrapRecord};

/// The 32 bytes of a KEK.
pub fn kek_bytes(kek: &Kek) -> [u8; 32] {
    *kek.expose()
}

/// The 32 bytes of a vault key.
pub fn vault_key_bytes(vk: &VaultKey) -> [u8; 32] {
    *vk.expose()
}

/// The keys derived from a vault key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeyBytes {
    /// `K_head`.
    pub k_head: [u8; 32],
    /// `K_del`.
    pub k_del: [u8; 32],
    /// `K_meta`.
    pub k_meta: [u8; 32],
    /// `seed_a`.
    pub seed_a: [u8; 32],
    /// `pk_a`.
    pub pk_a: [u8; 32],
}

/// `K_head`, `K_del`, `K_meta`, `seed_a` and `pk_a` for `vk` in `ctx`.
pub fn derived_keys(ctx: &VaultContext, vk: &VaultKey) -> Result<DerivedKeyBytes, Error> {
    let [k_head, k_del, k_meta, seed_a] = keys::derived_key_bytes(ctx, vk)?;
    Ok(DerivedKeyBytes {
        k_head,
        k_del,
        k_meta,
        seed_a,
        pk_a: crate::prim::ed25519::ed25519_from_seed(&seed_a).public_key(),
    })
}

/// The bytes of `VK`, `K_head`, `K_del` and `K_meta` held by an unlocked
/// vault, in that order.
pub fn unlocked_vault_keys(vault: &UnlockedVault) -> [[u8; 32]; 4] {
    [
        *vault.vault_key().expose(),
        *vault.k_head().expose(),
        *vault.k_del().expose(),
        *vault.k_meta().expose(),
    ]
}

/// `seed_r` for a recovery key.
pub fn recovery_seed(
    rk: &RecoveryKey,
    account_id: &crate::ids::AccountId,
) -> Result<[u8; 32], Error> {
    keys::recovery_seed_bytes(rk, account_id)
}

/// The AAD of a wrap record in a vault context.
pub fn wrap_aad(ctx: &VaultContext, rec: &WrapRecord) -> Result<Vec<u8>, Error> {
    wrap::wrap_aad(ctx, &rec.method_id, rec.kek_generation, &rec.method)
}

/// The key commitment of a KEK.
pub fn commit_of(kek: &Kek) -> Result<[u8; 32], Error> {
    wrap::commit_of(kek)
}
