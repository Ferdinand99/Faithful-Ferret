//! The item body and manifest readers on arbitrary CBOR bytes: never a
//! panic, and what reads writes back and reads again with the same unknown
//! fields in the same order (plan section 9.2).
//!
//! A body of a newer `schema` is read leniently and is read-only: it is never
//! sealed (`encrypt_item` and the encrypted export refuse it), but it can be
//! written back, and it is written from the value that was decoded, never
//! rebuilt from the typed fields. So every body that reads also writes, a
//! read-only body writes the very bytes it was read from, and a known key of
//! the wrong type (kept as an unknown key by the lenient reader) is never
//! written twice (regression input `readonly-lenient-duplicate-key`).
#![no_main]

use ferret_core::{ItemBody, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = ItemBody::from_cbor(data) {
        // The redacted view never panics.
        let _ = decoded.body.view();
        let bytes = decoded
            .body
            .to_cbor()
            .expect("a body that was read can be written");
        if decoded.read_only {
            assert_eq!(
                bytes.as_slice(),
                data,
                "a read-only body is written as it was read"
            );
        }
        let again = ItemBody::from_cbor(&bytes).expect("a body that was written reads");
        assert_eq!(again.body, decoded.body, "unknown fields survive");
        assert_eq!(again.read_only, decoded.read_only);
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
