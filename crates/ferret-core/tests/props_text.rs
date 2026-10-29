//! Property tests for password text and the recovery/secret key codes (plan
//! section 9.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::text::{master_password_bytes, recovery_key_bytes, secret_key_bytes};
use ferret_core::text::unicode::is_allowed;
use ferret_core::{
    Error, InputError, MasterPassword, MpPolicy, RecoveryKey, SecretKey, decode_recovery_key,
    decode_secret_key, encode_recovery_key, encode_secret_key,
};
use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn symbol_value(letter: char) -> u8 {
    u8::try_from(
        ALPHABET
            .iter()
            .position(|&a| char::from(a) == letter)
            .unwrap(),
    )
    .unwrap()
}

/// Position of symbol `index` in a code with the given group size.
fn position(index: usize, group: usize) -> usize {
    5 + index + index / group
}

fn replace_at(code: &str, at: usize, letter: char) -> String {
    code.chars()
        .enumerate()
        .map(|(i, c)| if i == at { letter } else { c })
        .collect()
}

/// Text made of allowed characters only.
fn allowed_char() -> impl Strategy<Value = char> {
    any::<char>().prop_filter("allowed", |c| is_allowed(*c))
}

fn with_min_prefix(rest: &str) -> String {
    format!("abcdefghijkl{rest}")
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn rk_code_roundtrip(bytes in any::<[u8; 32]>()) {
        let key = RecoveryKey::from_test_bytes(bytes);
        let code = encode_recovery_key(&key);
        prop_assert_eq!(code.len(), 74);
        prop_assert!(code.starts_with("FFR1-"));
        let back = decode_recovery_key(&code).unwrap();
        prop_assert_eq!(recovery_key_bytes(&back), bytes);
        // Reading is case-insensitive and ignores the separators.
        let sloppy = code.to_lowercase().replace('-', " ");
        prop_assert_eq!(recovery_key_bytes(&decode_recovery_key(&sloppy).unwrap()), bytes);
    }

    /// One changed symbol is never accepted as a different key. It is a
    /// `checksum` error, or `non_canonical` when only a spare bit changed.
    /// A 20-bit check can collide with probability 2^-20; the test accepts a
    /// result only if the new key's own check is the same four letters (a true
    /// collision), never because of a decoder fault.
    #[test]
    fn rk_code_single_char_error_detected(
        bytes in any::<[u8; 32]>(),
        index in 0usize..56,
        shift in 1u8..32,
    ) {
        let key = RecoveryKey::from_test_bytes(bytes);
        let code = encode_recovery_key(&key).to_string();
        let at = position(index, 4);
        let old = code.chars().nth(at).unwrap();
        let new = char::from(ALPHABET[usize::from((symbol_value(old) + shift) % 32)]);
        let changed = replace_at(&code, at, new);
        match decode_recovery_key(&changed) {
            Err(Error::Checksum | Error::NonCanonical) => {}
            Ok(other) => {
                prop_assert_ne!(recovery_key_bytes(&other), bytes);
                let again = encode_recovery_key(&other);
                prop_assert_eq!(&again[again.len() - 4..], &code[code.len() - 4..],
                    "accepted without a matching check");
            }
            Err(e) => prop_assert!(false, "unexpected error {e:?}"),
        }
    }

    #[test]
    fn sk_code_roundtrip(bytes in any::<[u8; 16]>()) {
        let key = SecretKey::from_test_bytes(bytes);
        let code = encode_secret_key(&key);
        prop_assert_eq!(code.len(), 40);
        prop_assert!(code.starts_with("FFS1-"));
        let back = decode_secret_key(&code).unwrap();
        prop_assert_eq!(secret_key_bytes(&back), bytes);
        let sloppy = code.to_lowercase().replace('-', "");
        prop_assert_eq!(secret_key_bytes(&decode_secret_key(&sloppy).unwrap()), bytes);
    }

    /// The last data symbol carries 3 data bits and 2 spare bits; any
    /// non-zero spare bit with the right check is rejected.
    #[test]
    fn sk_code_noncanonical_rejected(bytes in any::<[u8; 16]>(), spare in 1u8..4) {
        let key = SecretKey::from_test_bytes(bytes);
        let code = encode_secret_key(&key).to_string();
        let at = position(25, 5);
        let old = symbol_value(code.chars().nth(at).unwrap());
        prop_assert_eq!(old & 3, 0, "canonical spare bits are zero");
        let changed = replace_at(&code, at, char::from(ALPHABET[usize::from(old | spare)]));
        prop_assert_eq!(decode_secret_key(&changed).err(), Some(Error::NonCanonical));
    }

    /// The same for the recovery key: 1 data bit and 4 spare bits.
    #[test]
    fn rk_code_noncanonical_rejected(bytes in any::<[u8; 32]>(), spare in 1u8..16) {
        let key = RecoveryKey::from_test_bytes(bytes);
        let code = encode_recovery_key(&key).to_string();
        let at = position(51, 4);
        let old = symbol_value(code.chars().nth(at).unwrap());
        prop_assert_eq!(old & 15, 0);
        let changed = replace_at(&code, at, char::from(ALPHABET[usize::from(old | spare)]));
        prop_assert_eq!(decode_recovery_key(&changed).err(), Some(Error::NonCanonical));
    }

    #[test]
    fn mp_normalization_idempotent(rest in prop::collection::vec(allowed_char(), 0..40)) {
        let text = with_min_prefix(&rest.into_iter().collect::<String>());
        let once = MasterPassword::new(text.as_bytes(), MpPolicy::WithSecretKey).unwrap();
        let once_bytes = master_password_bytes(&once);
        // norm(norm(x)) == norm(x)
        let twice = MasterPassword::new(&once_bytes, MpPolicy::WithSecretKey).unwrap();
        prop_assert_eq!(master_password_bytes(&twice), once_bytes.clone());
        // NFC and NFD of the same text give the same mp.
        let nfc: String = text.nfc().collect();
        let nfd: String = text.nfd().collect();
        for form in [&nfc, &nfd] {
            let mp = MasterPassword::new(form.as_bytes(), MpPolicy::WithSecretKey).unwrap();
            prop_assert_eq!(master_password_bytes(&mp), once_bytes.clone());
        }
        // The result is NFKD.
        let as_text = String::from_utf8(once_bytes.clone()).unwrap();
        prop_assert_eq!(as_text.nfkd().collect::<String>(), as_text);
    }

    #[test]
    fn mp_rejects_forbidden(
        forbidden in any::<char>().prop_filter("forbidden", |c| !is_allowed(*c)),
        before in "[a-z]{0,20}",
        after in "[a-z]{12,20}",
    ) {
        let text = format!("{before}{forbidden}{after}");
        for policy in [MpPolicy::WithSecretKey, MpPolicy::WithoutSecretKey] {
            prop_assert_eq!(
                MasterPassword::new(text.as_bytes(), policy).err(),
                Some(Error::InvalidInput(InputError::ForbiddenCharacter))
            );
        }
    }

    #[test]
    fn mp_rejects_over_length(extra in 1usize..200, c in allowed_char()) {
        // 1 025 or more scalars after NFKD. Every allowed character has at
        // least one scalar in NFKD, so this many copies is always too long.
        let text: String = std::iter::repeat_n(c, 1_024 + extra).collect();
        prop_assert_eq!(
            MasterPassword::new(text.as_bytes(), MpPolicy::WithSecretKey).err(),
            Some(Error::InvalidInput(InputError::TooLong))
        );
    }

    /// The oracle of the `fuzz_mp_input` target: any bytes give `Ok` or an
    /// error code, never a panic, and a success is always within the limits.
    #[test]
    fn mp_new_is_total(bytes in prop::collection::vec(any::<u8>(), 0..6_000)) {
        for policy in [MpPolicy::WithSecretKey, MpPolicy::WithoutSecretKey] {
            if let Ok(mp) = MasterPassword::new(&bytes, policy) {
                let out = master_password_bytes(&mp);
                prop_assert!(out.len() <= 4_096);
                let text = String::from_utf8(out).unwrap();
                prop_assert!(text.chars().count() <= 1_024);
                prop_assert!(text.chars().all(is_allowed));
            }
        }
    }

    /// The oracle of the `fuzz_codes` target: the code readers are total, and
    /// whatever they accept is the canonical code of the key they return.
    #[test]
    fn code_readers_are_total(text in "[0-9A-Za-z -]{0,80}") {
        if let Ok(key) = decode_recovery_key(&text) {
            let again = encode_recovery_key(&key);
            let squeezed: String = text.chars().filter(|c| *c != '-' && *c != ' ').collect();
            prop_assert_eq!(again.replace('-', "").to_uppercase(),
                squeezed.to_uppercase().replace('O', "0").replace(['I', 'L'], "1"));
        }
        if let Ok(key) = decode_secret_key(&text) {
            let again = encode_secret_key(&key);
            let squeezed: String = text.chars().filter(|c| *c != '-' && *c != ' ').collect();
            prop_assert_eq!(again.replace('-', "").to_uppercase(),
                squeezed.to_uppercase().replace('O', "0").replace(['I', 'L'], "1"));
        }
    }
}
