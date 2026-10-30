//! The item body and manifest readers on arbitrary CBOR bytes: never a
//! panic, and what reads writes back and reads again with the same unknown
//! fields in the same order (plan section 9.2).
//!
//! A body of a newer `schema` is read leniently and is read-only: it is never
//! written (`encrypt_item` and the encrypted export refuse it). A known key
//! of the wrong type is kept as an unknown key in that mode, so writing the
//! body out again would put the key twice; `to_cbor` says so with
//! `malformed_cbor_duplicate_key`. That is the only way a read-only body may
//! fail to write (regression input `readonly-lenient-duplicate-key`).
#![no_main]

use ferret_core::{Error, ItemBody, MalformedKind, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = ItemBody::from_cbor(data) {
        // The redacted view never panics.
        let _ = decoded.body.view();
        match decoded.body.to_cbor() {
            Ok(bytes) => {
                let again = ItemBody::from_cbor(&bytes).expect("a body that was written reads");
                if !decoded.read_only {
                    assert_eq!(again.body, decoded.body, "unknown fields survive");
                    assert_eq!(again.read_only, decoded.read_only);
                }
            }
            Err(e) => {
                assert!(decoded.read_only, "a body that was read can be written");
                assert_eq!(e, Error::Malformed(MalformedKind::CborDuplicateKey));
            }
        }
    }
    if let Ok(manifest) = Manifest::from_cbor(data) {
        let bytes = manifest
            .to_cbor()
            .expect("a manifest that was read can be written");
        assert_eq!(
            Manifest::from_cbor(&bytes).expect("and read again"),
            manifest
        );
    }
});
