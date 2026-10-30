//! Property tests for the wraps: the round trip, a flipped
//! bit anywhere, and a changed AAD field. No Argon2: the KEK is given
//! directly (the PIN KEKs are covered in `keys.rs`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::TestRng;
use ferret_core::testing::keys::unlocked_vault_keys;
use ferret_core::{
    AccountId, Error, Kek, KsfProfile, Method, MethodId, VaultContext, VaultId, VaultKey,
    WrapRecord, unwrap_vk, wrap_vk,
};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

#[derive(Debug, Clone)]
struct Input {
    account: [u8; 16],
    vault: [u8; 16],
    method_id: [u8; 16],
    epoch: u64,
    generation: u64,
    kek: [u8; 32],
    vk: [u8; 32],
    method: Method,
    seed: [u8; 8],
}

impl Input {
    fn ctx(&self) -> VaultContext {
        VaultContext {
            account_id: AccountId::from_bytes(self.account),
            vault_id: VaultId::from_bytes(self.vault),
            vk_epoch: self.epoch,
        }
    }

    fn seal(&self) -> WrapRecord {
        let mut rng = TestRng::new(&self.seed);
        wrap_vk(
            &mut rng,
            &self.ctx(),
            &VaultKey::from_test_bytes(self.vk),
            &Kek::from_test_bytes(self.kek),
            MethodId::from_bytes(self.method_id),
            self.generation,
            self.method.clone(),
        )
        .unwrap()
    }

    fn open(&self, ctx: &VaultContext, rec: &WrapRecord) -> Result<[u8; 32], Error> {
        unwrap_vk(ctx, &Kek::from_test_bytes(self.kek), rec).map(|v| unlocked_vault_keys(&v)[0])
    }
}

fn method() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Password {
            ksf: KsfProfile::P1
        }),
        Just(Method::Recovery),
        (prop::collection::vec(any::<u8>(), 0..70), any::<[u8; 32]>()).prop_map(
            |(credential_id, prf_salt)| Method::Prf {
                credential_id,
                prf_salt
            }
        ),
        any::<[u8; 16]>().prop_map(|device_salt| Method::Pin { device_salt }),
        Just(Method::Device),
    ]
}

fn input() -> impl Strategy<Value = Input> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<u64>(),
        any::<u64>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        method(),
        any::<[u8; 8]>(),
    )
        .prop_map(
            |(account, vault, method_id, epoch, generation, kek, vk, method, seed)| Input {
                account,
                vault,
                method_id,
                epoch,
                generation,
                kek,
                vk,
                method,
                seed,
            },
        )
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn wrap_roundtrip_all_methods(i in input()) {
        let rec = i.seal();
        prop_assert_eq!(rec.wrap.len(), i.method.wrap_len());
        prop_assert_eq!(i.open(&i.ctx(), &rec), Ok(i.vk));
    }

    #[test]
    fn wrap_any_bit_flip_fails(i in input(), at in any::<prop::sample::Index>(), bit in 0u8..8) {
        let mut rec = i.seal();
        let byte = at.index(rec.wrap.len());
        rec.wrap[byte] ^= 1 << bit;
        prop_assert_eq!(i.open(&i.ctx(), &rec), Err(Error::Decrypt));
    }

    #[test]
    fn wrap_any_length_change_fails(i in input(), cut in 1usize..40, extra in 1usize..40) {
        let rec = i.seal();
        let mut short = rec.clone();
        short.wrap.truncate(rec.wrap.len().saturating_sub(cut));
        prop_assert_eq!(i.open(&i.ctx(), &short), Err(Error::Decrypt));
        let mut long = rec;
        long.wrap.extend(std::iter::repeat_n(0u8, extra));
        prop_assert_eq!(i.open(&i.ctx(), &long), Err(Error::Decrypt));
    }

    #[test]
    fn wrap_any_aad_field_change_fails(
        i in input(),
        field in 0usize..9,
        mask in 1u8..=255,
        at in any::<prop::sample::Index>(),
    ) {
        let rec = i.seal();
        let mut ctx = i.ctx();
        let mut rec2 = rec.clone();
        // Which AAD fields the method binds. The PIN wrap's AAD (Fase 1
        // § 7.2) has no kek_generation.
        let is_pin = matches!(i.method, Method::Pin { .. });
        let flip16 = |b: &[u8; 16]| {
            let mut out = *b;
            out[at.index(16)] ^= mask;
            out
        };
        match (field, &i.method) {
            (0, _) => ctx.account_id = AccountId::from_bytes(flip16(&i.account)),
            (1, _) => ctx.vk_epoch ^= u64::from(mask),
            (2, _) => ctx.vault_id = VaultId::from_bytes(flip16(&i.vault)),
            (3, _) => rec2.method_id = MethodId::from_bytes(flip16(&i.method_id)),
            (4, _) if !is_pin => rec2.kek_generation ^= u64::from(mask),
            (5, Method::Prf { credential_id, prf_salt }) => {
                let mut cred = credential_id.clone();
                if cred.is_empty() {
                    cred.push(mask);
                } else {
                    let n = cred.len();
                    cred[at.index(n)] ^= mask;
                }
                rec2.method = Method::Prf { credential_id: cred, prf_salt: *prf_salt };
            }
            (6, Method::Prf { credential_id, prf_salt }) => {
                let mut salt = *prf_salt;
                salt[at.index(32)] ^= mask;
                rec2.method = Method::Prf { credential_id: credential_id.clone(), prf_salt: salt };
            }
            (7, Method::Pin { device_salt }) => {
                let mut salt = *device_salt;
                salt[at.index(16)] ^= mask;
                rec2.method = Method::Pin { device_salt: salt };
            }
            (8, m) => {
                // Another method type (of the same wrap length, so that the
                // AAD and not the length decides).
                rec2.method = match m {
                    Method::Recovery => Method::Device,
                    Method::Device => Method::Recovery,
                    Method::Prf { .. } => Method::Recovery,
                    Method::Password { .. } => Method::Pin { device_salt: [mask; 16] },
                    Method::Pin { .. } => Method::Password { ksf: KsfProfile::P1 },
                };
            }
            // The field does not exist for this method: nothing to test.
            _ => return Ok(()),
        }
        prop_assert_eq!(i.open(&ctx, &rec2), Err(Error::Decrypt));
    }
}
