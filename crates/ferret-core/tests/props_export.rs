//! Property tests for the export file and the CSV export (plan section 9.1).
//!
//! The Argon2id parameters are far below the floor (through the
//! `test-support` functions) so that hundreds of cases run in seconds.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::Value;
use ferret_core::testing::TestRng;
use ferret_core::testing::export::{export_encrypt_unchecked, import_decrypt_unchecked};
use ferret_core::{
    ExportItem, ExportPassword, Field, FieldKind, ItemBody, ItemId, ItemType, KdfParams,
    PlainExportOptions, Totp, UrlEntry, UrlMatch, export_plain_csv, parse_export_header,
};
use proptest::prelude::*;
use std::collections::BTreeMap;

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

fn pw() -> ExportPassword {
    ExportPassword::for_open(b"a property test password").unwrap()
}

/// Any characters at all, also control characters, quotes, commas, line
/// breaks and the characters that start a formula.
fn text() -> impl Strategy<Value = String> {
    let special = prop::sample::select(vec!['=', '+', '-', '@', '\t', '\r', '\n', ',', '"', '\'']);
    prop::collection::vec(prop_oneof![3 => any::<char>(), 2 => special], 0..16)
        .prop_map(|v| v.into_iter().collect())
}

fn body() -> impl Strategy<Value = ItemBody> {
    (
        text(),
        prop::collection::vec((text(), text(), text()), 0..4),
        prop::option::of(text()),
        prop::option::of(text()),
        prop::collection::vec(text(), 0..3),
        any::<bool>(),
        prop::option::of(text()),
        (0u64..4_000_000_000_000, 0u64..4_000_000_000_000),
    )
        .prop_map(
            |(name, fields, notes, totp, urls, favorite, unknown, (created, modified))| {
                let mut b = ItemBody::new(ItemType::Login, name, created);
                b.modified = modified;
                b.favorite = favorite;
                b.notes = notes;
                b.fields = fields
                    .into_iter()
                    .map(|(label, value, kind)| Field {
                        id: "id".into(),
                        label,
                        kind: FieldKind::from_text(kind),
                        value,
                        extra: vec![],
                    })
                    .collect();
                b.urls = urls
                    .into_iter()
                    .map(|url| UrlEntry {
                        url,
                        matching: UrlMatch::Host,
                        extra: vec![],
                    })
                    .collect();
                b.totp = totp.map(|uri| Totp { uri, extra: vec![] });
                if let Some(u) = unknown {
                    b.extra = vec![("unknown".into(), Value::Text(u))];
                }
                b
            },
        )
}

/// Items with unique, non-zero ids.
fn items() -> impl Strategy<Value = Vec<ExportItem>> {
    prop::collection::btree_map(
        any::<[u8; 16]>().prop_filter("not the manifest id", |b| *b != [0; 16]),
        body(),
        0..5,
    )
    .prop_map(|m: BTreeMap<[u8; 16], ItemBody>| {
        m.into_iter()
            .map(|(id, body)| ExportItem {
                item_id: ItemId::from_bytes(id),
                body,
            })
            .collect()
    })
}

fn kdf() -> impl Strategy<Value = KdfParams> {
    (16u32..=256, 1u32..=2, 1u32..=2).prop_map(|(m_kib, t, p)| KdfParams { m_kib, t, p })
}

proptest! {
    #![proptest_config(config())]

    /// `import(export(x)) == x`, for any items, parameters and seed.
    #[test]
    fn export_roundtrip(items in items(), kdf in kdf(), seed in any::<[u8; 8]>(), at in 0u64..u64::MAX) {
        let mut rng = TestRng::new(&seed);
        let file = export_encrypt_unchecked(&mut rng, &pw(), kdf, at, &items).unwrap();
        let (h, used) = parse_export_header(&file).unwrap();
        prop_assert_eq!(h.kdf, kdf);
        prop_assert_eq!(h.created_at, at);
        prop_assert!(used + 72 + 40 <= file.len());
        let back = import_decrypt_unchecked(&pw(), &file).unwrap();
        prop_assert_eq!(back, items);
    }

    /// A changed bit in the header never opens: the header is in the AAD of
    /// both ciphertexts and in the Argon2id input.
    #[test]
    fn export_header_tamper_fails(
        items in items(),
        seed in any::<[u8; 8]>(),
        which in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut rng = TestRng::new(&seed);
        let kdf = KdfParams { m_kib: 64, t: 1, p: 1 };
        let mut file = export_encrypt_unchecked(&mut rng, &pw(), kdf, 1, &items).unwrap();
        let (_, used) = parse_export_header(&file).unwrap();
        let at = which.index(used);
        file[at] ^= 1 << bit;
        prop_assert!(import_decrypt_unchecked(&pw(), &file).is_err());
    }

    /// A changed bit anywhere after the header never opens either.
    #[test]
    fn export_body_tamper_fails(
        items in items(),
        seed in any::<[u8; 8]>(),
        which in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut rng = TestRng::new(&seed);
        let kdf = KdfParams { m_kib: 64, t: 1, p: 1 };
        let mut file = export_encrypt_unchecked(&mut rng, &pw(), kdf, 1, &items).unwrap();
        let (_, used) = parse_export_header(&file).unwrap();
        let at = used + which.index(file.len() - used);
        file[at] ^= 1 << bit;
        prop_assert_eq!(import_decrypt_unchecked(&pw(), &file), Err(ferret_core::Error::Decrypt));
    }

    /// Every cell of the CSV that starts with a formula character in the
    /// original starts with an apostrophe and then is the original; every
    /// other cell is the original; and no cell starts with a formula
    /// character.
    #[test]
    fn csv_cells_neutralized(items in items(), include in any::<bool>()) {
        let o = PlainExportOptions { include_passkeys: include };
        let text = export_plain_csv(&items, &o).unwrap();
        let rows = parse_csv(&text);
        prop_assert_eq!(rows.len(), items.len() + 1);
        let formula = |s: &str| s.starts_with(['=', '+', '-', '@', '\t', '\r']);
        let neutral = |s: &str| if formula(s) { format!("'{s}") } else { s.to_string() };
        let width = rows[0].len();
        for (item, row) in items.iter().zip(&rows[1..]) {
            prop_assert_eq!(row.len(), width);
            for cell in row {
                prop_assert!(!formula(cell), "formula start in {cell:?}");
            }
            let b = &item.body;
            prop_assert_eq!(&row[2], &neutral(&b.name));
            prop_assert_eq!(&row[3], &neutral(&b.urls.iter().map(|u| u.url.as_str()).collect::<Vec<_>>().join(" ")));
            prop_assert_eq!(&row[4], &neutral(b.notes.as_deref().unwrap_or("")));
            prop_assert_eq!(&row[5], &neutral(b.totp.as_ref().map_or("", |t| t.uri.as_str())));
            for (i, f) in b.fields.iter().enumerate() {
                prop_assert_eq!(&row[11 + 3 * i], &neutral(&f.label));
                prop_assert_eq!(&row[11 + 3 * i + 1], &neutral(f.kind.as_str()));
                prop_assert_eq!(&row[11 + 3 * i + 2], &neutral(&f.value));
            }
        }
    }
}
