//! The recovery key and secret key readers on arbitrary text: never a panic, only the stable error codes of the code format, and
//! whatever a reader accepts is read from the canonical spelling of the key
//! it returns (separators dropped, case folded, `O` read as `0`, `I` and `L`
//! as `1`). A recovery code is never read as a secret key and the other way
//! round.
#![no_main]

use ferret_core::codes::is_separator;
use ferret_core::testing::text::{recovery_key_bytes, secret_key_bytes};
use ferret_core::{
    decode_recovery_key, decode_secret_key, encode_recovery_key, encode_secret_key,
    verify_secret_key_entry,
};
use libfuzzer_sys::fuzz_target;

const CODES: [&str; 5] = [
    "input_too_short",
    "input_too_long",
    "malformed_code",
    "checksum",
    "non_canonical",
];

/// The letters a code is read as: separators dropped, upper case, look-alikes
/// folded.
fn squeezed(text: &str) -> String {
    text.chars()
        .filter(|c| !is_separator(*c))
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let rk = decode_recovery_key(text);
    let sk = decode_secret_key(text);
    assert!(!(rk.is_ok() && sk.is_ok()), "one code read as both kinds");

    match &rk {
        Ok(key) => {
            let code = encode_recovery_key(key);
            assert_eq!(code.replace('-', ""), squeezed(text));
            let back = decode_recovery_key(&code).expect("a canonical code reads");
            assert_eq!(recovery_key_bytes(&back), recovery_key_bytes(key));
        }
        Err(e) => assert!(CODES.contains(&e.code()), "{}", e.code()),
    }
    match &sk {
        Ok(key) => {
            let code = encode_secret_key(key);
            assert_eq!(code.replace('-', ""), squeezed(text));
            let back = decode_secret_key(&code).expect("a canonical code reads");
            assert_eq!(secret_key_bytes(&back), secret_key_bytes(key));
            // The entry check agrees with the reader.
            assert!(verify_secret_key_entry(text, key).is_ok());
        }
        Err(e) => assert!(CODES.contains(&e.code()), "{}", e.code()),
    }
});
