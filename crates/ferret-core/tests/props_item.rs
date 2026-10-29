//! Property tests for the item layer (plan section 9.1): round trips, a
//! changed byte anywhere, unknown fields, future schemas, padding, and the
//! CBOR decoder on arbitrary bytes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::{self, Value};
use ferret_core::item::pad::{is_padded_len, pad, padded_len, unpad};
use ferret_core::testing::TestRng;
use ferret_core::{
    Error, Field, FieldKind, ItemBody, ItemId, ItemType, Passkey, Totp, UnlockedVault, UrlEntry,
    UrlMatch, VaultContext, VaultId, decrypt_item, encrypt_item,
};
use proptest::prelude::*;

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

// -------------------------------------------------------------- strategies

fn text() -> impl Strategy<Value = String> {
    "\\PC{0,24}"
}

/// A key that is never one of the known keys of any level.
fn unknown_key() -> impl Strategy<Value = String> {
    "x-[a-z]{1,8}"
}

fn leaf() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::uint),
        any::<i64>().prop_map(Value::int),
        any::<u64>().prop_map(Value::Float),
        prop::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        text().prop_map(Value::Text),
    ]
}

/// A map with unique keys, in the order generated.
fn unique(entries: Vec<(String, Value)>) -> Vec<(String, Value)> {
    let mut seen = std::collections::BTreeSet::new();
    entries
        .into_iter()
        .filter(|(k, _)| seen.insert(k.clone()))
        .collect()
}

fn value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(4, 40, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::vec((text(), inner), 0..4).prop_map(|m| Value::Map(unique(m))),
        ]
    })
}

fn extra() -> impl Strategy<Value = Vec<(String, Value)>> {
    prop::collection::vec((unknown_key(), value()), 0..3).prop_map(unique)
}

fn item_type() -> impl Strategy<Value = ItemType> {
    prop_oneof![
        Just(ItemType::Login),
        Just(ItemType::Note),
        Just(ItemType::Card),
        Just(ItemType::Identity),
        "x-[a-z]{0,8}".prop_map(ItemType::Other),
    ]
}

fn field() -> impl Strategy<Value = Field> {
    let kind = prop_oneof![
        Just(FieldKind::Text),
        Just(FieldKind::Password),
        Just(FieldKind::Hidden),
        Just(FieldKind::Url),
        Just(FieldKind::Email),
        Just(FieldKind::Phone),
        "x-[a-z]{0,8}".prop_map(FieldKind::Other),
    ];
    (text(), text(), kind, text(), extra()).prop_map(|(id, label, kind, value, extra)| Field {
        id,
        label,
        kind,
        value,
        extra,
    })
}

fn url_entry() -> impl Strategy<Value = UrlEntry> {
    let matching = prop_oneof![
        Just(UrlMatch::Host),
        Just(UrlMatch::Domain),
        Just(UrlMatch::Exact),
        "x-[a-z]{0,8}".prop_map(UrlMatch::Other),
    ];
    (text(), matching, extra()).prop_map(|(url, matching, extra)| UrlEntry {
        url,
        matching,
        extra,
    })
}

fn passkey() -> impl Strategy<Value = Passkey> {
    (
        prop::collection::vec(any::<u8>(), 0..40),
        text(),
        prop::collection::vec(any::<u8>(), 0..20),
        text(),
        prop::collection::vec(any::<u8>(), 0..150),
        any::<u64>(),
        any::<u64>(),
        prop::option::of(prop::collection::vec(any::<u8>(), 32)),
        prop::option::of(prop::collection::vec(any::<u8>(), 32)),
        extra(),
    )
        .prop_map(
            |(
                cred_id,
                rp_id,
                user_handle,
                user_name,
                private_key,
                sign_count,
                created,
                prf_seed_uv,
                prf_seed_nouv,
                extra,
            )| Passkey {
                cred_id,
                rp_id,
                user_handle,
                user_name,
                private_key,
                sign_count,
                created,
                prf_seed_uv,
                prf_seed_nouv,
                extra,
            },
        )
}

fn body() -> impl Strategy<Value = ItemBody> {
    let head = (
        item_type(),
        text(),
        prop::collection::vec(field(), 0..4),
        prop::collection::vec(url_entry(), 0..3),
        prop::option::of((text(), extra()).prop_map(|(uri, extra)| Totp { uri, extra })),
        prop::option::of(passkey()),
        prop::option::of(text()),
    );
    let tail = (
        any::<u64>(),
        any::<u64>(),
        any::<bool>(),
        prop::option::of(text()),
        extra(),
    );
    (head, tail).prop_map(
        |(
            (item_type, name, fields, urls, totp, passkey, notes),
            (created, modified, favorite, device, extra),
        )| ItemBody {
            schema: 1,
            item_type,
            name,
            fields,
            urls,
            totp,
            passkey,
            notes,
            created,
            modified,
            favorite,
            device,
            extra,
        },
    )
}

fn vault(vk_byte: u8) -> UnlockedVault {
    UnlockedVault::from_vault_key(ctx(), vk(vk_byte)).unwrap()
}

// -------------------------------------------------------------- properties

proptest! {
    #![proptest_config(config())]

    /// `decrypt(encrypt(body)) == body` for any body.
    #[test]
    fn item_roundtrip(body in body(), id in any::<[u8; 16]>(), rev in 1..u64::MAX, seed in any::<[u8; 8]>()) {
        prop_assume!(id != [0u8; 16]);
        let v = vault(0x5a);
        let id = ItemId::from_bytes(id);
        let s = encrypt_item(&mut TestRng::new(&seed), &v, id, rev, &body, None).unwrap();
        let got = decrypt_item(&v, id, rev, &s.envelope, &s.tag).unwrap();
        prop_assert!(!got.read_only);
        prop_assert_eq!(got.body, body);
    }

    /// Changing one byte of the envelope, the item id, the revision, the
    /// vault id or the tag is an error, and below the header it is `Decrypt`.
    #[test]
    fn item_any_bit_flip_fails(
        body in body(),
        seed in any::<[u8; 8]>(),
        at in any::<prop::sample::Index>(),
        bit in 0u8..8,
        which in 0u8..5,
    ) {
        let v = vault(0x5a);
        let id = ItemId::from_bytes([3; 16]);
        let s = encrypt_item(&mut TestRng::new(&seed), &v, id, 7, &body, None).unwrap();
        let r = match which {
            0 => {
                let mut e = s.envelope.clone();
                let i = at.index(e.len());
                e[i] ^= 1 << bit;
                let r = decrypt_item(&v, id, 7, &e, &s.tag);
                if i >= 3 {
                    prop_assert_eq!(r.clone().unwrap_err(), Error::Decrypt);
                }
                r
            }
            1 => decrypt_item(&v, ItemId::from_bytes([4; 16]), 7, &s.envelope, &s.tag),
            2 => decrypt_item(&v, id, 8, &s.envelope, &s.tag),
            3 => {
                let other = UnlockedVault::from_vault_key(
                    VaultContext { vault_id: VaultId::from_bytes([0x99; 16]), ..ctx() },
                    vk(0x5a),
                ).unwrap();
                decrypt_item(&other, id, 7, &s.envelope, &s.tag)
            }
            _ => {
                let mut tag = s.tag;
                let i = at.index(32);
                tag[i] ^= 1 << bit;
                decrypt_item(&v, id, 7, &s.envelope, &tag)
            }
        };
        prop_assert!(r.is_err());
        if which != 0 {
            prop_assert_eq!(r.unwrap_err(), Error::Decrypt);
        }
    }

    /// Unknown keys at every level survive decode, encode, an edit that
    /// keeps the item key, and decryption.
    #[test]
    fn item_unknown_fields_preserved(body in body(), seed in any::<[u8; 8]>()) {
        let v = vault(0x5a);
        let id = ItemId::from_bytes([5; 16]);
        let s1 = encrypt_item(&mut TestRng::new(&seed), &v, id, 1, &body, None).unwrap();
        let mut got = decrypt_item(&v, id, 1, &s1.envelope, &s1.tag).unwrap().body;
        prop_assert_eq!(&got.extra, &body.extra);
        got.name.push('!');
        let s2 = encrypt_item(&mut TestRng::new(&seed), &v, id, 2, &got, Some(&s1.envelope)).unwrap();
        prop_assert_eq!(&s2.envelope[3..75], &s1.envelope[3..75]);
        let back = decrypt_item(&v, id, 2, &s2.envelope, &s2.tag).unwrap().body;
        prop_assert_eq!(&back.extra, &body.extra);
        prop_assert_eq!(&back.fields, &got.fields);
        prop_assert_eq!(&back.urls, &got.urls);
        prop_assert_eq!(&back.totp, &got.totp);
        prop_assert_eq!(&back.passkey, &got.passkey);
    }

    /// A body with `schema` above 1 can be read and never written.
    #[test]
    fn item_future_schema_never_writable(body in body(), schema in 2..=u64::MAX, seed in any::<[u8; 8]>()) {
        let v = vault(0x5a);
        let id = ItemId::from_bytes([6; 16]);
        let mut future = body;
        future.schema = schema;
        let decoded = ItemBody::from_cbor(&future.to_cbor().unwrap()).unwrap();
        prop_assert!(decoded.read_only);
        prop_assert_eq!(decoded.body.schema, schema);
        let r = encrypt_item(&mut TestRng::new(&seed), &v, id, 1, &future, None);
        prop_assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
        let r = encrypt_item(&mut TestRng::new(&seed), &v, id, 1, &decoded.body, None);
        prop_assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
    }

    /// `unpad(pad(x)) == x`, the length is a class, and it is at least
    /// `len + 1`.
    #[test]
    fn pad_roundtrip_and_class(plain in prop::collection::vec(any::<u8>(), 0..9_000)) {
        let padded = pad(&plain).unwrap();
        prop_assert!(is_padded_len(padded.len()));
        prop_assert!(padded.len() > plain.len());
        prop_assert_eq!(padded.len(), padded_len(plain.len()).unwrap());
        let n = unpad(&padded).unwrap();
        prop_assert_eq!(&padded[..n], plain.as_slice());
        // The smallest class that fits.
        if padded.len() > 256 {
            let smaller = if padded.len() <= 4_096 { padded.len() / 2 } else { padded.len() - 4_096 };
            prop_assert!(smaller < plain.len() + 1);
        }
    }

    /// A buffer without the marker, or with a byte other than zero after
    /// it, is refused.
    #[test]
    fn unpad_rejects_malformed(
        head in prop::collection::vec(any::<u8>(), 0..300),
        zeros in 0usize..300,
        bad in 1u8..=255,
        place in any::<prop::sample::Index>(),
    ) {
        // No marker anywhere: bytes other than 0x80 only.
        let no_marker: Vec<u8> = head.iter().map(|b| if *b == 0x80 { 0x7f } else { *b }).collect();
        prop_assert_eq!(unpad(&no_marker), Err(Error::Decrypt));
        // A good padding, then one nonzero byte after the marker.
        if zeros > 0 {
            let mut good = head.clone();
            good.push(0x80);
            good.extend(std::iter::repeat_n(0u8, zeros));
            prop_assert_eq!(unpad(&good), Ok(head.len()));
            let at = head.len() + 1 + place.index(zeros);
            good[at] = bad;
            if bad == 0x80 {
                // It is itself a marker, the last one: the bytes before it
                // are the plaintext.
                prop_assert_eq!(unpad(&good), Ok(at));
            } else {
                prop_assert_eq!(unpad(&good), Err(Error::Decrypt));
            }
        }
    }

    /// Any bytes give a value or a `malformed_*` error, never a panic; a
    /// value writes back and reads again as itself.
    #[test]
    fn cbor_decoder_total(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        match cbor::decode(&bytes) {
            Ok(v) => {
                let again = cbor::encode(&v).unwrap();
                prop_assert_eq!(cbor::decode(&again).unwrap(), v);
            }
            Err(e) => prop_assert!(e.code().starts_with("malformed_"), "{}", e.code()),
        }
    }

    /// The same on bytes that are mostly valid: a valid encoding with some
    /// bytes changed, cut or added.
    #[test]
    fn cbor_decoder_total_on_mutated_encodings(
        v in value(),
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
        cut in prop::option::of(any::<prop::sample::Index>()),
        extra_bytes in prop::collection::vec(any::<u8>(), 0..3),
    ) {
        let mut bytes = cbor::encode(&v).unwrap();
        for (at, b) in edits {
            let i = at.index(bytes.len());
            bytes[i] = b;
        }
        if let Some(c) = cut {
            bytes.truncate(c.index(bytes.len() + 1));
        }
        bytes.extend(extra_bytes);
        match cbor::decode(&bytes) {
            Ok(v) => {
                let again = cbor::encode(&v).unwrap();
                prop_assert_eq!(cbor::decode(&again).unwrap(), v);
            }
            Err(e) => prop_assert!(e.code().starts_with("malformed_"), "{}", e.code()),
        }
    }

    /// `decode(encode(v)) == v` for every value.
    #[test]
    fn cbor_roundtrip_values(v in value()) {
        let bytes = cbor::encode(&v).unwrap();
        prop_assert_eq!(bytes.len(), cbor::encoded_len(&v));
        prop_assert_eq!(cbor::decode(&bytes).unwrap(), v);
    }
}
