//! The item body and manifest readers on arbitrary CBOR bytes: never a
//! panic, and what reads writes back and reads again with the same unknown
//! fields in the same order (plan section 9.2).
#![no_main]

use ferret_core::{ItemBody, Manifest};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(decoded) = ItemBody::from_cbor(data) {
        let bytes = decoded
            .body
            .to_cbor()
            .expect("a body that was read can be written");
        let again = ItemBody::from_cbor(&bytes).expect("and read again");
        assert_eq!(again.body, decoded.body, "unknown fields survive");
        assert_eq!(again.read_only, decoded.read_only);
        // The redacted view never panics.
        let _ = decoded.body.view();
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
