//! Property tests for the PIN: what `Pin::new` accepts and gives back, the
//! rule, and the PIN wrap (a round trip, and a change of any byte or field).
//!
//! The wraps use a KEK made from the PIN bytes with HKDF, not Argon2id: a
//! property runs hundreds of cases, and the Argon2id of the PIN profile is
//! covered by `pin.rs` and by the vectors. A few cases with the real KEK are
//! in `real_kek_round_trip`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::TestRng;
use ferret_core::testing::prim::hkdf_sha256;
use ferret_core::text::unicode::nfkd;
use ferret_core::{
    AccountId, Error, InputError, Kek, Method, MethodId, PIN_FLOOR, Pin, PinProfile, PinRule,
    VaultContext, VaultId, VaultKey, WrapRecord, pin_meets_rule, unwrap_vk, wrap_vk,
};
use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

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

/// A KEK that depends on the PIN bytes, for the properties.
fn stand_in_kek(pin: &Pin) -> Kek {
    let mut out = [0u8; 32];
    hkdf_sha256(b"props_pin", pin.test_bytes(), b"stand-in", &mut out).unwrap();
    Kek::from_test_bytes(out)
}

/// Text of 1 to 64 characters of any kind; most of it is refused or accepted
/// by `Pin::new`, which is what is tested.
fn any_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 1..=70).prop_map(|cs| cs.into_iter().collect())
}

/// Text that is certainly a valid PIN: printable ASCII, digits and letters.
fn plain_text() -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop_oneof![
            prop::char::range('0', '9'),
            prop::char::range('a', 'z'),
            prop::char::range('A', 'Z'),
            Just(' '),
            Just('\u{e9}'),
            Just('\u{ff11}'),
        ],
        // At most 32: an accented letter is two scalars after NFKD.
        1..=32,
    )
    .prop_map(|cs| cs.into_iter().collect())
}

fn context(account: [u8; 16], vault: [u8; 16], epoch: u64) -> VaultContext {
    VaultContext {
        account_id: AccountId::from_bytes(account),
        vault_id: VaultId::from_bytes(vault),
        vk_epoch: epoch,
    }
}

fn seal(
    pin: &Pin,
    ctx: &VaultContext,
    id: [u8; 16],
    salt: [u8; 16],
    vk: [u8; 32],
    seed: [u8; 8],
) -> (Kek, WrapRecord) {
    let kek = stand_in_kek(pin);
    let mut rng = TestRng::new(&seed);
    let rec = wrap_vk(
        &mut rng,
        ctx,
        &VaultKey::from_test_bytes(vk),
        &kek,
        MethodId::from_bytes(id),
        1,
        Method::Pin {
            device_salt: salt,
            profile: PinProfile::P1,
        },
    )
    .unwrap();
    (kek, rec)
}

proptest! {
    #![proptest_config(config())]

    /// Never a panic, and only the errors of the input rules.
    #[test]
    fn a_pin_of_any_bytes_is_built_or_refused_with_an_input_error(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        match Pin::new(&bytes) {
            Ok(pin) => {
                let b = pin.test_bytes();
                prop_assert!(!b.is_empty() && b.len() <= 256);
                prop_assert!(core::str::from_utf8(b).is_ok());
            }
            Err(Error::InvalidInput(
                InputError::NotUtf8 | InputError::ForbiddenCharacter | InputError::TooLong | InputError::TooShort,
            )) => {}
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    /// A PIN is its NFKD form, and normalizing again changes nothing.
    #[test]
    fn a_pin_is_its_nfkd_form_and_normalising_twice_changes_nothing(text in any_text()) {
        if let Ok(pin) = Pin::new(text.as_bytes()) {
            let once = pin.test_bytes().to_vec();
            let want = nfkd(&text);
            prop_assert_eq!(&once[..], want.as_bytes());
            let again = Pin::new(&once).unwrap();
            prop_assert_eq!(again.test_bytes(), &once[..]);
        }
    }

    /// The rule: never below the floor, never below its minimum, never
    /// anything when it forbids PINs, and the decision does not depend on
    /// anything but the length.
    #[test]
    fn the_rule_decides_on_length_alone(text in plain_text(), min in any::<u8>(), allowed in any::<bool>(), after in any::<bool>()) {
        let pin = Pin::new(text.as_bytes()).unwrap();
        let normalized = core::str::from_utf8(pin.test_bytes()).unwrap();
        let len = normalized.nfc().count();
        let rule = PinRule { allowed, after_restart: after, min_length: min };
        let got = pin_meets_rule(&pin, &rule);
        if !allowed {
            prop_assert_eq!(got, Err(Error::PinNotAllowed));
        } else if len >= usize::from(min).clamp(usize::from(PIN_FLOOR), 64) {
            prop_assert_eq!(got, Ok(()));
        } else {
            prop_assert_eq!(got, Err(Error::InvalidInput(InputError::TooShort)));
        }
    }

    /// A wrap of the PIN profile opens under the KEK of the PIN it was made
    /// for, and gives back the vault key.
    #[test]
    fn pin_wrap_round_trips_for_any_valid_pin(
        text in any_text(),
        account in any::<[u8; 16]>(),
        vault in any::<[u8; 16]>(),
        id in any::<[u8; 16]>(),
        salt in any::<[u8; 16]>(),
        epoch in any::<u64>(),
        vk in any::<[u8; 32]>(),
        seed in any::<[u8; 8]>(),
    ) {
        if let Ok(pin) = Pin::new(text.as_bytes()) {
            let ctx = context(account, vault, epoch);
            let (kek, rec) = seal(&pin, &ctx, id, salt, vk, seed);
            prop_assert_eq!(rec.wrap.len(), 104);
            let vault = unwrap_vk(&ctx, &kek, &rec).unwrap();
            prop_assert_eq!(ferret_core::testing::keys::unlocked_vault_keys(&vault)[0], vk);
        }
    }

    /// A wrong PIN never opens a wrap, and says only `decrypt`.
    #[test]
    fn a_different_pin_never_opens_a_pin_wrap(a in plain_text(), b in plain_text(), salt in any::<[u8; 16]>(), vk in any::<[u8; 32]>()) {
        let pa = Pin::new(a.as_bytes()).unwrap();
        let pb = Pin::new(b.as_bytes()).unwrap();
        prop_assume!(pa.test_bytes() != pb.test_bytes());
        let ctx = context([1; 16], [2; 16], 1);
        let (_, rec) = seal(&pa, &ctx, [3; 16], salt, vk, [4; 8]);
        prop_assert_eq!(unwrap_vk(&ctx, &stand_in_kek(&pb), &rec).err(), Some(Error::Decrypt));
    }

    /// A change of any byte of a PIN wrap, or of any field it is bound to,
    /// is the single `decrypt`.
    #[test]
    fn any_byte_change_in_a_pin_wrap_fails(
        text in plain_text(),
        at in 0usize..104,
        mask in 1u8..=255,
        field in 0usize..5,
        flip in any::<prop::sample::Index>(),
        salt in any::<[u8; 16]>(),
        vk in any::<[u8; 32]>(),
    ) {
        let pin = Pin::new(text.as_bytes()).unwrap();
        let ctx = context([1; 16], [2; 16], 7);
        let (kek, rec) = seal(&pin, &ctx, [3; 16], salt, vk, [4; 8]);
        // A byte of the wrap itself (nonce, ciphertext, tag, commitment).
        let mut bad = rec.clone();
        bad.wrap[at] ^= mask;
        prop_assert_eq!(unwrap_vk(&ctx, &kek, &bad).err(), Some(Error::Decrypt));
        // A field of the AAD.
        let mut ctx2 = ctx;
        let mut rec2 = rec.clone();
        match field {
            0 => ctx2.account_id = AccountId::from_bytes({ let mut b = [1u8; 16]; b[flip.index(16)] ^= mask; b }),
            1 => ctx2.vault_id = VaultId::from_bytes({ let mut b = [2u8; 16]; b[flip.index(16)] ^= mask; b }),
            2 => ctx2.vk_epoch ^= u64::from(mask),
            3 => rec2.method_id = MethodId::from_bytes({ let mut b = [3u8; 16]; b[flip.index(16)] ^= mask; b }),
            _ => {
                let mut s = salt;
                s[flip.index(16)] ^= mask;
                rec2.method = Method::Pin { device_salt: s, profile: PinProfile::P1 };
            }
        }
        prop_assert_eq!(unwrap_vk(&ctx2, &kek, &rec2).err(), Some(Error::Decrypt));
        // The profile of the sign-in's size is another `kdf`: it never opens.
        rec2 = rec.clone();
        rec2.method = Method::PinMobile { device_salt: salt };
        prop_assert_eq!(unwrap_vk(&ctx, &kek, &rec2).err(), Some(Error::Decrypt));
    }
}

/// With the real KEK of the PIN profile (Argon2id, 256 MiB). A plain test over
/// a few fixed inputs: `PROPTEST_CASES` would turn a property into thousands
/// of runs of a 256 MiB hash.
#[test]
fn real_kek_round_trip() {
    for (text, salt, vk) in [
        ("123456", [1u8; 16], [2u8; 32]),
        ("correct horse battery", [3u8; 16], [4u8; 32]),
        ("caf\u{e9} \u{ff11}\u{ff12}", [5u8; 16], [6u8; 32]),
    ] {
        let pin = Pin::new(text.as_bytes()).unwrap();
        let kek = Kek::from_pin_extension(&pin, &salt, PinProfile::P1).unwrap();
        let ctx = context([1; 16], [2; 16], 1);
        let mut rng = TestRng::new(b"real kek");
        let rec = wrap_vk(
            &mut rng,
            &ctx,
            &VaultKey::from_test_bytes(vk),
            &kek,
            MethodId::from_bytes([3; 16]),
            1,
            Method::Pin {
                device_salt: salt,
                profile: PinProfile::P1,
            },
        )
        .unwrap();
        let again = Kek::from_pin_extension(&pin, &salt, PinProfile::P1).unwrap();
        let vault = unwrap_vk(&ctx, &again, &rec).unwrap();
        assert_eq!(
            ferret_core::testing::keys::unlocked_vault_keys(&vault)[0],
            vk
        );
    }
}
