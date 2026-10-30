//! The password and PIN readers on arbitrary bytes:
//! `MasterPassword::new` and `for_unlock`, `ExportPassword::new` and
//! `for_open`, and `Pin::new`. Never a panic and no error but the input
//! errors; what is accepted is NFKD, valid UTF-8, inside the limits, made of
//! allowed characters, and normalizing it again changes nothing. The unlock
//! readers give the bytes of the creation readers, and a password that
//! creation refuses but unlock reads is refused only for being too short.
#![no_main]

use ferret_core::testing::text::{
    export_password_bytes, master_password_bytes, opaque_input_bytes,
};
use ferret_core::text::unicode::{MAX_BYTES, MAX_SCALARS, is_allowed, nfkd};
use ferret_core::{
    Error, ExportPassword, InputError, MasterPassword, MpPolicy, PIN_MAX_DIGITS, PIN_MIN_DIGITS,
    Pin, SecretKey,
};
use libfuzzer_sys::fuzz_target;

fn is_input_error(e: &Error) -> bool {
    matches!(e, Error::InvalidInput(_))
}

/// An accepted password's bytes are what the rules say.
fn check_bytes(bytes: &[u8]) {
    assert!(bytes.len() <= MAX_BYTES);
    let text = std::str::from_utf8(bytes).expect("an accepted password is UTF-8");
    assert!(text.chars().count() <= MAX_SCALARS);
    assert!(text.chars().all(is_allowed));
    assert_eq!(&**nfkd(text), text, "an accepted password is NFKD");
}

fuzz_target!(|data: &[u8]| {
    let unlock = MasterPassword::for_unlock(data);
    let mut accepted = None;
    for policy in [MpPolicy::WithSecretKey, MpPolicy::WithoutSecretKey] {
        match MasterPassword::new(data, policy) {
            Ok(mp) => {
                let bytes = master_password_bytes(&mp);
                check_bytes(&bytes);
                // The unlock reader gives the same bytes.
                let unlock = unlock.as_ref().expect("unlock reads what creation reads");
                assert_eq!(master_password_bytes(unlock), bytes);
                // Normalizing again changes nothing.
                let twice = MasterPassword::for_unlock(&bytes).expect("a normal form reads");
                assert_eq!(master_password_bytes(&twice), bytes);
                // The opaque input, with and without a secret key.
                assert_eq!(opaque_input_bytes(&mp.opaque_input(None)), bytes);
                let sk = SecretKey::from_test_bytes([9; 16]);
                let with = opaque_input_bytes(&mp.opaque_input(Some(&sk)));
                assert_eq!(with.len(), bytes.len() + 1 + 16);
                assert_eq!(&with[..bytes.len()], bytes.as_slice());
                accepted = Some((mp, bytes));
            }
            Err(e) => {
                assert!(is_input_error(&e), "{}", e.code());
                // Only the length floor depends on the policy.
                if let Ok(unlock) = &unlock {
                    assert_eq!(e, Error::InvalidInput(InputError::TooShort));
                    check_bytes(&master_password_bytes(unlock));
                }
            }
        }
    }
    if let Err(e) = &unlock {
        assert!(is_input_error(e), "{}", e.code());
    }

    // The export password.
    match ExportPassword::new(data, None) {
        Ok(pw) => check_bytes(&export_password_bytes(&pw)),
        Err(e) => assert!(is_input_error(&e), "{}", e.code()),
    }
    match ExportPassword::for_open(data) {
        Ok(pw) => {
            let bytes = export_password_bytes(&pw);
            check_bytes(&bytes);
            if let Ok(creation) = ExportPassword::new(data, None) {
                assert_eq!(export_password_bytes(&creation), bytes);
            }
        }
        Err(e) => assert!(is_input_error(&e), "{}", e.code()),
    }
    // An export password equal to the master password is refused, after the
    // checks the export password has on its own.
    if let Some((mp, _)) = &accepted {
        let alone = ExportPassword::new(data, None).err();
        let checked = ExportPassword::new(data, Some(mp)).err();
        match alone {
            None => assert_eq!(
                checked,
                Some(Error::InvalidInput(InputError::SameAsMasterPassword))
            ),
            Some(e) => assert_eq!(checked, Some(e)),
        }
    }

    // The PIN.
    match Pin::new(data) {
        Ok(_) => {
            assert!(data.iter().all(u8::is_ascii_digit));
            assert!((PIN_MIN_DIGITS..=PIN_MAX_DIGITS).contains(&data.len()));
        }
        Err(e) => assert!(is_input_error(&e), "{}", e.code()),
    }
});
