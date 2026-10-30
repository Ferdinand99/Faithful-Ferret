//! `cbor::decode` on arbitrary bytes: never a panic, only `malformed_*`
//! errors, and what decodes writes back and reads again as the same value
//! within the limits.
#![no_main]

use ferret_core::cbor::{self, MAX_BYTES, MAX_DEPTH, MAX_ITEMS, Value};
use libfuzzer_sys::fuzz_target;

/// Checks the limits of Fase 1 § 5.2 on a decoded tree; returns its depth.
fn check(v: &Value, depth: usize) {
    assert!(depth <= MAX_DEPTH, "depth over the limit");
    match v {
        Value::Bytes(b) => assert!(b.len() <= MAX_BYTES),
        Value::Text(s) => assert!(s.len() <= MAX_BYTES),
        Value::Array(items) => {
            assert!(items.len() as u64 <= MAX_ITEMS);
            for item in items {
                check(item, depth + 1);
            }
        }
        Value::Map(entries) => {
            assert!(entries.len() as u64 <= MAX_ITEMS);
            let mut keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
            keys.sort_unstable();
            keys.dedup();
            assert_eq!(keys.len(), entries.len(), "duplicate key");
            for (k, item) in entries {
                assert!(k.len() <= MAX_BYTES);
                check(item, depth + 1);
            }
        }
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Float(_)
        | Value::Float16(_)
        | Value::Float32(_) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    match cbor::decode(data) {
        Ok(v) => {
            check(&v, 0);
            let again = cbor::encode(&v).expect("a decoded value encodes");
            assert_eq!(cbor::encoded_len(&v), again.len());
            assert_eq!(cbor::decode(&again).expect("and decodes again"), v);
        }
        Err(e) => assert!(e.code().starts_with("malformed_")),
    }
});
