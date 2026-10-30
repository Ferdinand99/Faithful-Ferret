//! The item body and manifest readers on arbitrary CBOR bytes: never a
//! panic, and what reads writes back and reads again with the same unknown
//! fields in the same order (plan section 9.2).
//!
//! A body of a newer `schema` is read leniently and is read-only: it is never
//! written (`encrypt_item` and the encrypted export refuse it). A known key
//! of the wrong type is kept as an unknown key in that mode, so writing the
//! body out again would put the key twice; `to_cbor` says so with
//! `malformed_cbor_duplicate_key`. That is the only way a read-only body may
//! fail to write, and only when an unknown key at some level has the name of
//! a key that level always writes (regression input
//! `readonly-lenient-duplicate-key`).
//!
//! TODO(14c): remove this tolerance when 14c changes the write-back of
//! newer-schema bodies, and assert the round trip for read-only bodies too.
#![no_main]

use ferret_core::{Error, ItemBody, MalformedKind, Manifest};
use libfuzzer_sys::fuzz_target;

/// Whether an unknown key of `extra` is named like one of `written`.
fn clashes(extra: &[(String, ferret_core::cbor::Value)], written: &[&str]) -> bool {
    extra.iter().any(|(k, _)| written.contains(&k.as_str()))
}

/// Whether the lenient reader kept, as an unknown key, the name of a key that
/// the writer always writes (so the writer puts the key twice). The optional
/// keys are written only when present, and a mistyped one is not.
fn has_mistyped_known_key(body: &ItemBody) -> bool {
    clashes(
        &body.extra,
        &[
            "type", "name", "fields", "urls", "created", "modified", "favorite",
        ],
    ) || body
        .fields
        .iter()
        .any(|f| clashes(&f.extra, &["id", "label", "kind", "value"]))
        || body
            .urls
            .iter()
            .any(|u| clashes(&u.extra, &["url", "match"]))
        || body
            .totp
            .as_ref()
            .is_some_and(|t| clashes(&t.extra, &["uri"]))
        || body.passkey.as_ref().is_some_and(|p| {
            clashes(
                &p.extra,
                &[
                    "cred_id",
                    "rp_id",
                    "user_handle",
                    "user_name",
                    "priv",
                    "sign_count",
                    "created",
                ],
            )
        })
}

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
                assert!(
                    has_mistyped_known_key(&decoded.body),
                    "a duplicate key that is not a mistyped known key"
                );
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
