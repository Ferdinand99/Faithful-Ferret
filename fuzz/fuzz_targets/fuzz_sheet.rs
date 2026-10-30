//! `parse_setup_qr` on arbitrary text: never a panic, only the stable error
//! codes of the format, and whatever it accepts is the canonical spelling of
//! what it read.
#![no_main]

use ferret_core::{parse_setup_qr, setup_qr_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match parse_setup_qr(text) {
        Ok(qr) => {
            assert!(qr.server_url.len() <= 512);
            let again = setup_qr_payload(
                &qr.server_url,
                &qr.account_id,
                qr.ksf_profile,
                qr.sk_bit,
                &qr.server_public_key,
            )
            .expect("what was read can be written");
            assert_eq!(again, text, "the reader accepts one spelling only");
        }
        Err(e) => assert!(
            matches!(
                e.code(),
                "malformed_setup_qr" | "unsupported" | "too_large" | "kdf_profile_unknown"
            ),
            "{}",
            e.code()
        ),
    }
});
