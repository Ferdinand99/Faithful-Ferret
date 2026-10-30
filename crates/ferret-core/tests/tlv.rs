//! TLV builder: byte-exact examples, limits and the generated vectors.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, hex_decode, hex_encode};
use ferret_core::tlv::{self, MAX_VALUE_LEN, tag};
use ferret_core::{Error, MalformedKind, Tlv};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

#[test]
fn tlv_matches_spec_examples() {
    // Fase 1 § 3.1: 01 000e "ferret/v1/wrap" 03 0001 01
    let got = Tlv::new()
        .label("ferret/v1/wrap")
        .u8(0x03, 1)
        .finish()
        .unwrap();
    let mut want = vec![0x01, 0x00, 0x0e];
    want.extend_from_slice(b"ferret/v1/wrap");
    want.extend_from_slice(&[0x03, 0x00, 0x01, 0x01]);
    assert_eq!(got, want);
    assert_eq!(
        hex_encode(&got),
        "01000e6665727265742f76312f7772617003000101"
    );

    // The same with the named tag constants.
    let named = Tlv::new()
        .label("ferret/v1/wrap")
        .u8(tag::SUITE, 1)
        .finish()
        .unwrap();
    assert_eq!(named, want);
}

#[test]
fn tlv_tag_table_matches_the_spec() {
    // Fase 1 § 3.1, table of tags.
    let table: [(u8, u8); 22] = [
        (tag::LABEL, 0x01),
        (tag::VERSION, 0x02),
        (tag::SUITE, 0x03),
        (tag::KIND, 0x04),
        (tag::ACCOUNT_ID, 0x10),
        (tag::VAULT_ID, 0x11),
        (tag::ITEM_ID, 0x12),
        (tag::METHOD_ID, 0x13),
        (tag::METHOD_TYPE, 0x14),
        (tag::VK_EPOCH, 0x20),
        (tag::KEK_GENERATION, 0x21),
        (tag::REV, 0x22),
        (tag::SEQ, 0x23),
        (tag::KDF, 0x30),
        (tag::CREDENTIAL_ID, 0x31),
        (tag::PRF_SALT, 0x32),
        (tag::NONCE, 0x33),
        (tag::HASH, 0x35),
        (tag::OP, 0x36),
        (tag::DEVICE_SALT, 0x37),
        (tag::SALT_A, 0x38),
        (tag::HEADER, 0x39),
    ];
    for (constant, number) in table {
        assert_eq!(constant, number);
    }
    // The list in the crate is the table, and every number is used once.
    let listed: Vec<u8> = table.iter().map(|(c, _)| *c).collect();
    assert_eq!(listed, tag::ALL);
    assert_eq!(listed.iter().collect::<BTreeSet<_>>().len(), listed.len());
}

#[test]
fn tlv_rejects_oversize_value() {
    let at_limit = vec![0xab; MAX_VALUE_LEN];
    let ok = Tlv::new().bytes(tag::HEADER, &at_limit).unwrap();
    let encoded = ok.finish().unwrap();
    assert_eq!(encoded.len(), 3 + 65_535);
    assert_eq!(&encoded[..3], &[tag::HEADER, 0xff, 0xff]);

    let too_big = vec![0xab; MAX_VALUE_LEN + 1];
    assert_eq!(
        Tlv::new().bytes(tag::HEADER, &too_big).unwrap_err(),
        Error::TooLarge
    );
    // Also after earlier fields; nothing is truncated or half-written.
    let after_fields = Tlv::new().label("ferret/v1/x").u8(tag::VERSION, 1);
    assert_eq!(
        after_fields.bytes(tag::HEADER, &too_big).unwrap_err(),
        Error::TooLarge
    );
}

#[test]
fn tlv_u64_is_big_endian() {
    let got = Tlv::new()
        .u64(tag::REV, 0x0102_0304_0506_0708)
        .finish()
        .unwrap();
    assert_eq!(
        got,
        [0x22, 0x00, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],
        "tag, length 8, then the value most significant byte first"
    );
    assert_eq!(
        Tlv::new().u64(tag::SEQ, 1).finish().unwrap(),
        [0x23, 0x00, 0x08, 0, 0, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(
        Tlv::new().u64(tag::VK_EPOCH, u64::MAX).finish().unwrap(),
        [0x20, 0x00, 0x08, 255, 255, 255, 255, 255, 255, 255, 255]
    );
}

#[test]
fn tlv_empty_value_allowed() {
    let got = Tlv::new()
        .bytes(tag::CREDENTIAL_ID, &[])
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(got, [tag::CREDENTIAL_ID, 0x00, 0x00]);
    // An empty list of fields is empty bytes.
    assert_eq!(Tlv::new().finish().unwrap(), Vec::<u8>::new());
}

#[test]
fn tlv_label_must_be_ascii() {
    assert_eq!(
        Tlv::new().label("ferret/v1/\u{e5}").finish().unwrap_err(),
        Error::Malformed(MalformedKind::Tlv)
    );
    // The failure sticks, whatever is added afterwards.
    assert_eq!(
        Tlv::new()
            .label("ferret/v1/\u{e5}")
            .u8(tag::VERSION, 1)
            .finish()
            .unwrap_err(),
        Error::Malformed(MalformedKind::Tlv)
    );
}

#[test]
fn tlv_label_requires_the_suite_prefix() {
    assert_eq!(tlv::LABEL_PREFIX, "ferret/v1/");
    for bad in [
        "",
        "wrap",
        "ferret/v1",
        "ferret/v2/wrap",
        "Ferret/v1/wrap",
        " ferret/v1/wrap",
        "xferret/v1/wrap",
    ] {
        assert_eq!(
            Tlv::new().label(bad).finish().unwrap_err(),
            Error::Malformed(MalformedKind::Tlv),
            "{bad:?}"
        );
    }
    // The prefix alone (an empty rest) is a valid label.
    assert_eq!(
        Tlv::new().label("ferret/v1/").finish().unwrap()[..3],
        [tag::LABEL, 0x00, 0x0a]
    );
}

#[test]
fn tlv_lengths_are_u16_big_endian() {
    let v = vec![7u8; 258];
    let got = Tlv::new()
        .bytes(tag::CREDENTIAL_ID, &v)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(&got[..3], &[tag::CREDENTIAL_ID, 0x01, 0x02]);
    assert_eq!(got.len(), 3 + 258);
}

#[test]
fn tlv_is_a_plain_concatenation_of_fields() {
    let a = Tlv::new().u8(tag::VERSION, 1).finish().unwrap();
    let b = Tlv::new().u8(tag::SUITE, 1).finish().unwrap();
    let both = Tlv::new()
        .u8(tag::VERSION, 1)
        .u8(tag::SUITE, 1)
        .finish()
        .unwrap();
    assert_eq!([a, b].concat(), both, "no separator between fields");
}

// ----------------------------------------------------- generated vectors

/// Builds the TLV bytes a vector case describes.
fn build(case: &Case) -> Result<Vec<u8>, Error> {
    let mut tlv = Tlv::new();
    for field in case.input["fields"].as_array().unwrap() {
        let kind = field["type"].as_str().unwrap();
        let tag_byte = || {
            let t = hex_decode(field["tag"].as_str().unwrap()).unwrap();
            assert_eq!(t.len(), 1);
            t[0]
        };
        tlv = match kind {
            "label" => tlv.label(Box::leak(
                field["value"]
                    .as_str()
                    .unwrap()
                    .to_string()
                    .into_boxed_str(),
            )),
            "label_hex" => {
                let bytes = hex_decode(field["value"].as_str().unwrap()).unwrap();
                tlv.label(Box::leak(
                    String::from_utf8(bytes).unwrap().into_boxed_str(),
                ))
            }
            "u8" => tlv.u8(
                tag_byte(),
                u8::try_from(field["value"].as_u64().unwrap()).unwrap(),
            ),
            "u64" => tlv.u64(
                tag_byte(),
                field["value"].as_str().unwrap().parse().unwrap(),
            ),
            "bytes" => {
                let value = if let Some(fill) = field.get("fill") {
                    let byte = hex_decode(fill["byte"].as_str().unwrap()).unwrap()[0];
                    vec![byte; usize::try_from(fill["len"].as_u64().unwrap()).unwrap()]
                } else {
                    hex_decode(field["value"].as_str().unwrap()).unwrap()
                };
                tlv.bytes(tag_byte(), &value)?
            }
            other => panic!("unknown field type {other}"),
        };
    }
    tlv.finish()
}

#[test]
fn tlv_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/tlv.json")).unwrap();
    assert!(file.cases.len() >= 20, "at least 20 cases");
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| {
        assert_eq!(case.op, "tlv.build");
        let bytes = build(case)?;
        Ok(Outcome {
            output: json!({ "tlv": hex_encode(&bytes) }),
            intermediate: None,
        })
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    // Every tag of the table has a case of its own.
    let used: BTreeSet<u8> = file
        .cases
        .iter()
        .filter(|c| c.id.starts_with("tlv/tag/"))
        .flat_map(|c| {
            c.input["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| match f["tag"].as_str() {
                    Some(t) => hex_decode(t).unwrap()[0],
                    None => tag::LABEL,
                })
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(used, tag::ALL.iter().copied().collect::<BTreeSet<u8>>());

    // Two vectors that must differ do differ (order matters, and so does the
    // split into fields).
    let expect = |id: &str| -> Value {
        file.cases
            .iter()
            .find(|c| c.id == id)
            .unwrap()
            .expect
            .clone()
            .unwrap()
    };
    assert_ne!(
        expect("tlv/order/suite_version"),
        expect("tlv/order/version_suite")
    );
    assert_ne!(
        expect("tlv/split/one_field"),
        expect("tlv/split/two_fields")
    );
    let _ = tlv::MAX_VALUE_LEN;
}
