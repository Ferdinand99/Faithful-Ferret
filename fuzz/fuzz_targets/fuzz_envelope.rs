//! The envelope parser and the opening functions on arbitrary bytes: never
//! a panic, the length rules hold, and with a fixed vault key an arbitrary
//! envelope never opens (it has no valid tag) (plan section 9.2).
#![no_main]

use ferret_core::{
    AccountId, ItemId, UnlockedVault, VaultContext, VaultId, VaultKey, decrypt_item,
    decrypt_manifest, parse_envelope,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match parse_envelope(data) {
        Ok(view) => {
            assert!(data.len() <= 65_536);
            assert!(view.body.len() >= 24 + 256 + 16);
            assert!(view.ik_wrap.is_none_or(|w| w.len() == 72));
        }
        Err(e) => assert!(matches!(
            e.code(),
            "malformed_envelope" | "decrypt" | "too_large"
        )),
    }
    let vault = UnlockedVault::from_vault_key(
        VaultContext {
            account_id: AccountId::from_bytes([1; 16]),
            vault_id: VaultId::from_bytes([2; 16]),
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([3; 32]),
    )
    .expect("the keys derive");
    // The first 32 bytes double as the tag, the rest is the envelope.
    let (tag, envelope) = data.split_at(data.len().min(32));
    let mut tag32 = [0u8; 32];
    tag32[..tag.len()].copy_from_slice(tag);
    let item = decrypt_item(&vault, ItemId::from_bytes([4; 16]), 1, envelope, &tag32);
    assert!(item.is_err());
    let manifest = decrypt_manifest(&vault, 1, envelope, &tag32);
    assert!(manifest.is_err());
});
