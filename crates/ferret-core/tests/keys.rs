//! The key hierarchy: `vk_derive`, the KEK derivations, the recovery signing
//! key, the PIN rules and the wiping of an unlocked vault, plus the vectors
//! in `vectors/internal/kdf.json`.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{account, ctx, he, hex, hexn, label, t, u64s, vault, vectors_dir, vk};
use ferret_core::testing::ReplayRng;
use ferret_core::testing::keys::{derived_keys, kek_bytes, recovery_seed, unlocked_vault_keys};
use ferret_core::testing::prim::{argon2_run_count, ed25519_public_key, hkdf_sha256};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::{
    AccountId, Error, ExportKey, InputError, Kek, KekDevPin, KsfProfile, Pin, PrfOutput,
    RecoveryKey, UnlockedVault, VaultContext, recovery_public_key,
};
use serde_json::json;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::collections::BTreeSet;
use std::mem::{ManuallyDrop, size_of};
use zeroize::ZeroizeOnDrop;

fn pin() -> Pin {
    Pin::new(b"123456").unwrap()
}

fn hk32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_sha256(salt, ikm, info, &mut out).unwrap();
    out
}

// -------------------------------------------------------------- vk_derive

#[test]
fn vk_derive_four_keys_differ_and_are_deterministic() {
    let keys = derived_keys(&ctx(), &vk(7)).unwrap();
    let all = [keys.k_head, keys.k_del, keys.k_meta, keys.seed_a];
    let distinct: BTreeSet<_> = all.iter().collect();
    assert_eq!(distinct.len(), 4, "the four derived keys must differ");
    assert!(all.iter().all(|k| *k != [0u8; 32] && *k != [7u8; 32]));

    // Same VK and context: the same four keys, every time.
    assert_eq!(derived_keys(&ctx(), &vk(7)).unwrap(), keys);

    // The unlocked vault holds exactly these keys and the matching pk_a.
    let unlocked = UnlockedVault::from_vault_key(ctx(), vk(7)).unwrap();
    assert_eq!(
        unlocked_vault_keys(&unlocked),
        [[7u8; 32], keys.k_head, keys.k_del, keys.k_meta]
    );
    assert_eq!(unlocked.auth_public_key(), keys.pk_a);
    assert_eq!(unlocked.auth_public_key(), ed25519_public_key(&keys.seed_a));
    assert_eq!(unlocked.context(), &ctx());

    // Another VK gives other keys.
    let other = derived_keys(&ctx(), &vk(8)).unwrap();
    assert_ne!(other.k_head, keys.k_head);
    assert_ne!(other.pk_a, keys.pk_a);
}

#[test]
fn vk_derive_changes_with_epoch_account_vault() {
    let base = derived_keys(&ctx(), &vk(7)).unwrap();
    let variants = [
        (
            "vk_epoch 1 -> 2",
            VaultContext {
                vk_epoch: 2,
                ..ctx()
            },
        ),
        (
            "account_id",
            VaultContext {
                account_id: account(0x12),
                ..ctx()
            },
        ),
        (
            "vault_id",
            VaultContext {
                vault_id: vault(0x23),
                ..ctx()
            },
        ),
    ];
    for (what, changed) in variants {
        let k = derived_keys(&changed, &vk(7)).unwrap();
        assert_ne!(k.k_head, base.k_head, "K_head must change with {what}");
        assert_ne!(k.k_del, base.k_del, "K_del must change with {what}");
        assert_ne!(k.k_meta, base.k_meta, "K_meta must change with {what}");
        assert_ne!(k.seed_a, base.seed_a, "seed_a must change with {what}");
        assert_ne!(k.pk_a, base.pk_a, "pk_a must change with {what}");
    }
}

#[test]
fn vk_derive_matches_the_hand_built_salt() {
    // Spec: Fase 1 § 4.5. The salt and the four `info` strings written out by
    // hand, with literal tag numbers.
    let c = ctx();
    let salt = [
        label("ferret/v1/vk-derive"),
        t(0x10, &[0x11; 16]),
        t(0x11, &[0x22; 16]),
        t(0x20, &1u64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(salt.len(), 3 + 19 + 3 + 16 + 3 + 16 + 3 + 8, "salt layout");
    assert_eq!(&salt[..3], &[0x01, 0x00, 0x13]);
    let keys = derived_keys(&c, &vk(7)).unwrap();
    assert_eq!(keys.k_head, hk32(&salt, &[7; 32], b"ferret/v1/head"));
    assert_eq!(keys.k_del, hk32(&salt, &[7; 32], b"ferret/v1/tomb"));
    assert_eq!(keys.k_meta, hk32(&salt, &[7; 32], b"ferret/v1/meta"));
    assert_eq!(keys.seed_a, hk32(&salt, &[7; 32], b"ferret/v1/auth-sign"));
}

// ------------------------------------------------------------ KEK_prf

#[test]
fn kek_prf_salt_has_no_account_id() {
    // Spec: Fase 1 § 4.3 and review focus 1: `KEK_prf` has `credential_id`
    // but no `account_id` in its salt. `Kek::from_prf` does not even take an
    // account, so two accounts with the same credential and PRF output get
    // the same KEK.
    let cred: Vec<u8> = (0u8..16).map(|i| 0xa0 + i).collect();
    let out = || PrfOutput::from_test_bytes([0x80; 32]);
    let a = Kek::from_prf(&cred, &out()).unwrap();
    let b = Kek::from_prf(&cred, &out()).unwrap();
    assert_eq!(kek_bytes(&a), kek_bytes(&b));

    // The bytes are HKDF over the salt TLV[label, credential_id] and
    // nothing else.
    let salt = [label("ferret/v1/prf"), t(0x31, &cred)].concat();
    assert_eq!(
        kek_bytes(&a),
        hk32(&salt, &[0x80; 32], b"ferret/v1/kek/prf")
    );
    // An account id in the salt would give other bytes.
    let with_account = [label("ferret/v1/prf"), t(0x10, &[0x11; 16]), t(0x31, &cred)].concat();
    assert_ne!(
        kek_bytes(&a),
        hk32(&with_account, &[0x80; 32], b"ferret/v1/kek/prf")
    );

    // Another credential id gives another KEK.
    let mut other = cred.clone();
    other[0] ^= 1;
    let c = Kek::from_prf(&other, &out()).unwrap();
    assert_ne!(kek_bytes(&a), kek_bytes(&c));
}

#[test]
fn kek_password_and_recovery_depend_on_the_account() {
    let ek = || ExportKey::from_test_bytes([0x20; 64]);
    let rk = || RecoveryKey::from_test_bytes([0x40; 32]);
    let (a, b) = (account(0x10), account(0x11));
    assert_ne!(
        kek_bytes(&Kek::from_export_key(&a, &ek()).unwrap()),
        kek_bytes(&Kek::from_export_key(&b, &ek()).unwrap())
    );
    assert_ne!(
        kek_bytes(&Kek::from_recovery_key(&a, &rk()).unwrap()),
        kek_bytes(&Kek::from_recovery_key(&b, &rk()).unwrap())
    );
    assert_ne!(
        recovery_public_key(&rk(), &a).unwrap(),
        recovery_public_key(&rk(), &b).unwrap()
    );
}

#[test]
fn kek_derivations_are_hand_built_byte_for_byte() {
    // Spec: Fase 1 § 4.3. Salt labels and `info` strings by hand.
    let acct = account(0x10);
    let id = [0x10u8; 16];

    let ek = ExportKey::from_test_bytes([0x20; 64]);
    let want = hk32(
        &[label("ferret/v1/kek/password"), t(0x10, &id)].concat(),
        &[0x20; 64],
        b"ferret/v1/kek/password",
    );
    assert_eq!(kek_bytes(&Kek::from_export_key(&acct, &ek).unwrap()), want);

    let rk = RecoveryKey::from_test_bytes([0x40; 32]);
    let want = hk32(
        &[label("ferret/v1/recovery"), t(0x10, &id)].concat(),
        &[0x40; 32],
        b"ferret/v1/kek/recovery",
    );
    assert_eq!(
        kek_bytes(&Kek::from_recovery_key(&acct, &rk).unwrap()),
        want
    );

    // seed_r and pk_r: Spec Fase 1 § 4.5.
    let want_seed = hk32(
        &[label("ferret/v1/recovery-sign"), t(0x10, &id)].concat(),
        &[0x40; 32],
        b"ferret/v1/recovery-sign",
    );
    assert_eq!(recovery_seed(&rk, &acct).unwrap(), want_seed);
    assert_eq!(
        recovery_public_key(&rk, &acct).unwrap(),
        ed25519_public_key(&want_seed)
    );
}

#[test]
fn kek_domains_are_separated() {
    // The same 32 bytes as recovery key and as PRF output, and the same
    // account bytes as credential id, give three different KEKs and a
    // different seed_r.
    let rk = RecoveryKey::from_test_bytes([0x40; 32]);
    let prf = PrfOutput::from_test_bytes([0x40; 32]);
    let acct = account(0x10);
    let k_rk = kek_bytes(&Kek::from_recovery_key(&acct, &rk).unwrap());
    let k_prf = kek_bytes(&Kek::from_prf(&[0x10; 16], &prf).unwrap());
    assert_ne!(k_rk, k_prf);
    assert_ne!(k_rk, recovery_seed(&rk, &acct).unwrap());
    assert_ne!(k_prf, recovery_seed(&rk, &acct).unwrap());
}

#[test]
fn kek_prf_credential_id_limit() {
    let prf = PrfOutput::from_test_bytes([1; 32]);
    assert!(Kek::from_prf(&vec![0u8; 65_535], &prf).is_ok());
    assert!(Kek::from_prf(&[], &prf).is_ok());
    assert_eq!(
        Kek::from_prf(&vec![0u8; 65_536], &prf).err(),
        Some(Error::TooLarge)
    );
}

// ------------------------------------------------------------------- PIN

#[test]
fn pin_rules_are_checked_when_the_pin_is_built() {
    let before = argon2_run_count();
    let too_short = Error::InvalidInput(InputError::TooShort);
    let forbidden = Error::InvalidInput(InputError::ForbiddenCharacter);
    let too_long = Error::InvalidInput(InputError::TooLong);
    for (pin, want) in [
        (b"".as_slice(), too_short),
        (b"12345", too_short),
        (b"12345a", forbidden),
        (b"12 456", forbidden),
        (b"-12345", forbidden),
        ("١٢٣٤٥٦".as_bytes(), forbidden), // Arabic-Indic digits
        (&[b'1'; 65], too_long),
    ] {
        assert_eq!(Pin::new(pin).err(), Some(want));
    }
    // The longest PIN is accepted.
    assert!(Pin::new(&[b'1'; 64]).is_ok());
    assert_eq!(
        argon2_run_count(),
        before,
        "a rejected PIN must compute nothing"
    );
}

#[test]
fn pin_keks_use_profile_1_and_the_device_salt() {
    let salt = [0xc0u8; 16];
    let before = argon2_run_count();
    let ext = Kek::from_pin_extension(&pin(), &salt).unwrap();
    assert_eq!(argon2_run_count(), before + 1);

    // The extension KEK is Argon2id with profile 1 and nothing else.
    let mut want = [0u8; 32];
    ferret_core::testing::prim::argon2id(b"123456", &salt, KsfProfile::P1.params(), &mut want)
        .unwrap();
    assert_eq!(kek_bytes(&ext), want);

    // The mobile KEK mixes in the hardware secret through HKDF.
    let mobile =
        Kek::from_pin_mobile(&pin(), &salt, &KekDevPin::from_test_bytes([0xd0; 32])).unwrap();
    let ikm = [[0xd0u8; 32].as_slice(), want.as_slice()].concat();
    let want_mobile = hk32(
        &[label("ferret/v1/kek/pin"), t(0x37, &salt)].concat(),
        &ikm,
        b"ferret/v1/kek/pin",
    );
    assert_eq!(kek_bytes(&mobile), want_mobile);
    assert_ne!(kek_bytes(&mobile), kek_bytes(&ext));

    // Another device salt or hardware secret gives another KEK.
    let other_salt = Kek::from_pin_extension(&pin(), &[0xc1; 16]).unwrap();
    assert_ne!(kek_bytes(&other_salt), kek_bytes(&ext));
    let other_dev =
        Kek::from_pin_mobile(&pin(), &salt, &KekDevPin::from_test_bytes([0xd1; 32])).unwrap();
    assert_ne!(kek_bytes(&other_dev), kek_bytes(&mobile));
}

#[test]
fn ksf_profile_table() {
    assert_eq!(KsfProfile::from_wire(1), Ok(KsfProfile::P1));
    for n in [0, 2, 3, 255, 256, u32::MAX] {
        assert_eq!(
            KsfProfile::from_wire(n),
            Err(Error::KdfProfileUnknown),
            "profile {n}"
        );
    }
    assert_eq!(KsfProfile::P1.number(), 1);
    assert_eq!(KsfProfile::P1.params(), ferret_core::KDF_FLOOR);
}

// --------------------------------------------------------------- vectors

fn run_kdf_case(case: &Case) -> Result<Outcome, Error> {
    let i = &case.input;
    let output = match case.op.as_str() {
        "kdf.kek.password" => {
            let ek = ExportKey::from_test_bytes(hexn(&i["export_key"]));
            let acct = AccountId::from_bytes(hexn(&i["account_id"]));
            json!({ "kek": he(&kek_bytes(&Kek::from_export_key(&acct, &ek)?)) })
        }
        "kdf.kek.recovery" => {
            let rk = RecoveryKey::from_test_bytes(hexn(&i["rk"]));
            let acct = AccountId::from_bytes(hexn(&i["account_id"]));
            json!({
                "kek": he(&kek_bytes(&Kek::from_recovery_key(&acct, &rk)?)),
                "seed_r": he(&recovery_seed(&rk, &acct)?),
                "pk_r": he(&recovery_public_key(&rk, &acct)?),
            })
        }
        "kdf.vk_derive" => {
            let c = VaultContext {
                account_id: AccountId::from_bytes(hexn(&i["account_id"])),
                vault_id: ferret_core::VaultId::from_bytes(hexn(&i["vault_id"])),
                vk_epoch: u64s(&i["vk_epoch"]),
            };
            let vk = ferret_core::VaultKey::from_test_bytes(hexn(&i["vk"]));
            let k = derived_keys(&c, &vk)?;
            let unlocked = UnlockedVault::from_vault_key(c, vk)?;
            assert_eq!(unlocked.auth_public_key(), k.pk_a);
            json!({
                "k_head": he(&k.k_head), "k_del": he(&k.k_del), "k_meta": he(&k.k_meta),
                "seed_a": he(&k.seed_a), "pk_a": he(&k.pk_a),
            })
        }
        "kdf.kek.prf" => {
            let out = PrfOutput::from_test_bytes(hexn(&i["prf_output"]));
            json!({ "kek": he(&kek_bytes(&Kek::from_prf(&hex(&i["credential_id"]), &out)?)) })
        }
        "kdf.kek.pin_extension" => {
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            let kek = Kek::from_pin_extension(&pin, &hexn(&i["device_salt"]))?;
            json!({ "kek": he(&kek_bytes(&kek)) })
        }
        "kdf.kek.pin_mobile" => {
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            let kek = Kek::from_pin_mobile(
                &pin,
                &hexn(&i["device_salt"]),
                &KekDevPin::from_test_bytes(hexn(&i["kek_dev_pin"])),
            )?;
            json!({ "kek": he(&kek_bytes(&kek)) })
        }
        other => panic!("unexpected op {other}"),
    };
    Ok(Outcome {
        output,
        intermediate: None,
    })
}

#[test]
fn kdf_vectors_from_file() {
    let mut file = vector::load(&vectors_dir().join("internal/kdf.json")).unwrap();
    // The Argon2id cases of the same file belong to tests/primitives.rs.
    file.cases.retain(|c| c.op != "kdf.argon2id");
    assert!(file.cases.len() >= 20, "{} cases", file.cases.len());
    let ops: BTreeSet<&str> = file.cases.iter().map(|c| c.op.as_str()).collect();
    for op in [
        "kdf.kek.password",
        "kdf.kek.recovery",
        "kdf.vk_derive",
        "kdf.kek.prf",
        "kdf.kek.pin_extension",
        "kdf.kek.pin_mobile",
    ] {
        assert!(ops.contains(op), "no cases for {op}");
    }
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| {
        run_kdf_case(case)
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());
}

// ---------------------------------------------------------------- wiping

assert_not_impl_any!(Pin: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq);
assert_not_impl_any!(
    UnlockedVault: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq,
    serde::Serialize
);
assert_impl_all!(UnlockedVault: ZeroizeOnDrop);

/// Drops a value in place (without freeing the allocation) and reads its
/// bytes before and after.
fn bytes_before_and_after_drop<T>(value: T) -> (Vec<u8>, Vec<u8>) {
    let slot: *mut ManuallyDrop<T> = Box::into_raw(Box::new(ManuallyDrop::new(value)));
    let base = slot.cast::<u8>();
    let read = || -> Vec<u8> {
        (0..size_of::<T>())
            // SAFETY: the allocation behind `slot` lives until `Box::from_raw`
            // below, and every byte of it is initialized (the struct has no
            // padding that was never written: it was built by value).
            .map(|i| unsafe { base.add(i).read_volatile() })
            .collect()
    };
    let before = read();
    // SAFETY: `slot` is a valid, unique pointer; the value is dropped once.
    unsafe { ManuallyDrop::drop(&mut *slot) };
    let after = read();
    // SAFETY: `slot` came from `Box::into_raw`; `ManuallyDrop` never drops again.
    drop(unsafe { Box::from_raw(slot) });
    (before, after)
}

fn contains(haystack: &[u8], needle: &[u8; 32]) -> bool {
    haystack.windows(32).any(|w| w == needle)
}

#[test]
fn unlocked_vault_zeroizes_all_keys() {
    // VK is distinctive; the derived keys come from HKDF and are random-looking.
    let c = ctx();
    let derived = derived_keys(&c, &vk(0x5a)).unwrap();
    let keys = [
        ("VK", [0x5au8; 32]),
        ("K_head", derived.k_head),
        ("K_del", derived.k_del),
        ("K_meta", derived.k_meta),
        ("seed_a", derived.seed_a),
    ];
    let vault = UnlockedVault::from_vault_key(c, vk(0x5a)).unwrap();
    let (before, after) = bytes_before_and_after_drop(vault);
    for (name, key) in &keys {
        assert!(
            contains(&before, key),
            "{name} must be in the vault before the drop (test sanity)"
        );
        assert!(
            !contains(&after, key),
            "{name} must be wiped when the vault is dropped"
        );
    }
}

#[test]
fn same_vault_key_compares_the_vault_key() {
    let a = UnlockedVault::from_vault_key(ctx(), vk(1)).unwrap();
    let b = UnlockedVault::from_vault_key(ctx(), vk(1)).unwrap();
    let c = UnlockedVault::from_vault_key(ctx(), vk(2)).unwrap();
    assert!(a.same_vault_key(&b));
    assert!(!a.same_vault_key(&c));
    // Same VK in another epoch: still the same vault key, other derived keys.
    let e2 = UnlockedVault::from_vault_key(
        VaultContext {
            vk_epoch: 2,
            ..ctx()
        },
        vk(1),
    )
    .unwrap();
    assert!(a.same_vault_key(&e2));
    assert_ne!(a.auth_public_key(), e2.auth_public_key());
}
