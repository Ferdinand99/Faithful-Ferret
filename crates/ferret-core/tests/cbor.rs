//! The strict CBOR decoder and encoder: every rule of Fase 1 § 5.2 has its
//! own failing input and its own error code, the limits accept exactly their
//! boundary, and `vectors/internal/cbor-limits.json` runs through the same
//! code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::{self, MAX_BYTES, MAX_DEPTH, MAX_ITEMS, Value};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{self, Outcome};
use ferret_core::{Error, MalformedKind};
use serde_json::json;
use sha2::{Digest, Sha256};

fn malformed(kind: MalformedKind) -> Error {
    Error::Malformed(kind)
}

fn dec(bytes: &[u8]) -> Result<Value, Error> {
    cbor::decode(bytes)
}

fn code(bytes: &[u8]) -> &'static str {
    dec(bytes).unwrap_err().code()
}

/// `0x9a` array head for `n` entries, then `n` copies of `0x00`.
fn array_of_zeros(n: usize) -> Vec<u8> {
    let mut out = vec![0x9a];
    out.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
    out.extend(std::iter::repeat_n(0u8, n));
    out
}

fn map_of_n(n: usize) -> Vec<u8> {
    let mut out = vec![0xba];
    out.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
    for i in 0..n {
        // Keys are the three-byte texts "000".."999" and longer, all unique.
        let key = format!("{i:05}");
        out.push(0x65);
        out.extend_from_slice(key.as_bytes());
        out.push(0x00);
    }
    out
}

fn text_of(len: usize) -> Vec<u8> {
    let mut out = vec![0x7a];
    out.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
    out.extend(std::iter::repeat_n(b'a', len));
    out
}

fn nested_arrays(depth: usize) -> Vec<u8> {
    let mut out = vec![0x81; depth];
    out.push(0x00);
    out
}

#[test]
fn cbor_rejects_each_limit() {
    let cases: Vec<(&str, Vec<u8>, MalformedKind)> = vec![
        (
            "duplicate key",
            vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
            MalformedKind::CborDuplicateKey,
        ),
        (
            "indefinite array",
            vec![0x9f, 0xff],
            MalformedKind::CborIndefinite,
        ),
        (
            "indefinite map",
            vec![0xbf, 0xff],
            MalformedKind::CborIndefinite,
        ),
        (
            "indefinite text",
            vec![0x7f, 0x61, b'a', 0xff],
            MalformedKind::CborIndefinite,
        ),
        (
            "indefinite bytes",
            vec![0x5f, 0x41, 0x01, 0xff],
            MalformedKind::CborIndefinite,
        ),
        ("tag 1", vec![0xc1, 0x00], MalformedKind::CborTag),
        ("tag 0 text", vec![0xc0, 0x60], MalformedKind::CborTag),
        ("depth 17", nested_arrays(17), MalformedKind::CborDepth),
        (
            "array of 10 001",
            array_of_zeros(10_001),
            MalformedKind::CborCount,
        ),
        ("map of 10 001", map_of_n(10_001), MalformedKind::CborCount),
        (
            "text of 65 537 bytes",
            text_of(65_537),
            MalformedKind::CborSize,
        ),
        (
            "float32",
            vec![0xfa, 0x3f, 0x80, 0x00, 0x00],
            MalformedKind::CborFloat,
        ),
        ("float16", vec![0xf9, 0x3c, 0x00], MalformedKind::CborFloat),
        ("undefined", vec![0xf7], MalformedKind::CborSimple),
        ("simple 16", vec![0xf0], MalformedKind::CborSimple),
        ("simple 255", vec![0xf8, 0xff], MalformedKind::CborSimple),
        (
            "key is an integer",
            vec![0xa1, 0x01, 0x02],
            MalformedKind::CborKeyType,
        ),
        (
            "key is bytes",
            vec![0xa1, 0x41, 0x61, 0x02],
            MalformedKind::CborKeyType,
        ),
        (
            "key is indefinite text",
            vec![0xa1, 0x7f, 0x61, b'a', 0xff, 0x02],
            MalformedKind::CborIndefinite,
        ),
        (
            "bytes after the item",
            vec![0x00, 0x00],
            MalformedKind::CborTrailing,
        ),
        (
            "integer below -2^63",
            vec![0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
            MalformedKind::CborInt,
        ),
        ("empty input", vec![], MalformedKind::Cbor),
        ("truncated array", vec![0x82, 0x00], MalformedKind::Cbor),
        ("truncated text", vec![0x63, b'a'], MalformedKind::Cbor),
        ("invalid utf-8", vec![0x62, 0xc3, 0x28], MalformedKind::Cbor),
        ("stray break", vec![0xff], MalformedKind::Cbor),
        ("reserved head 0x1c", vec![0x1c], MalformedKind::Cbor),
    ];
    for (name, bytes, kind) in cases {
        assert_eq!(dec(&bytes).unwrap_err(), malformed(kind), "{name}");
    }
}

#[test]
fn every_limit_has_its_own_code() {
    let codes = [
        "malformed_cbor_duplicate_key",
        "malformed_cbor_indefinite",
        "malformed_cbor_tag",
        "malformed_cbor_depth",
        "malformed_cbor_count",
        "malformed_cbor_size",
        "malformed_cbor_float",
        "malformed_cbor_simple",
        "malformed_cbor_key_type",
        "malformed_cbor_trailing",
    ];
    let inputs: [Vec<u8>; 10] = [
        vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
        vec![0x9f, 0xff],
        vec![0xc1, 0x00],
        nested_arrays(17),
        array_of_zeros(10_001),
        text_of(65_537),
        vec![0xfa, 0, 0, 0, 0],
        vec![0xf7],
        vec![0xa1, 0x01, 0x02],
        vec![0x00, 0x00],
    ];
    for (expected, bytes) in codes.iter().zip(&inputs) {
        assert_eq!(code(bytes), *expected);
    }
}

#[test]
fn cbor_limits_accept_exactly_the_boundary() {
    assert_eq!(MAX_DEPTH, 16);
    assert_eq!(MAX_ITEMS, 10_000);
    assert_eq!(MAX_BYTES, 65_536);
    dec(&nested_arrays(16)).unwrap();
    assert_eq!(dec(&array_of_zeros(10_000)).unwrap(), {
        Value::Array((0..10_000).map(|_| Value::uint(0)).collect())
    });
    let map = dec(&map_of_n(10_000)).unwrap();
    let Value::Map(m) = &map else {
        panic!("not a map");
    };
    assert_eq!(m.len(), 10_000);
    let text = dec(&text_of(65_536)).unwrap();
    let Value::Text(t) = &text else {
        panic!("not text");
    };
    assert_eq!(t.len(), 65_536);
    // 65 536 bytes of a byte string, with a four-byte length.
    let mut big = vec![0x5a];
    big.extend_from_slice(&65_536u32.to_be_bytes());
    big.extend(std::iter::repeat_n(7u8, 65_536));
    assert!(matches!(&dec(&big).unwrap(), Value::Bytes(b) if b.len() == 65_536));
    let mut over = vec![0x5a];
    over.extend_from_slice(&65_537u32.to_be_bytes());
    over.extend(std::iter::repeat_n(7u8, 65_537));
    assert_eq!(code(&over), "malformed_cbor_size");
}

#[test]
fn a_declared_length_the_input_cannot_hold_is_a_plain_error() {
    // 10 000 entries declared, none present: no allocation for 10 000.
    assert_eq!(code(&[0x9a, 0x00, 0x00, 0x27, 0x10]), "malformed_cbor");
    assert_eq!(code(&[0xba, 0x00, 0x00, 0x27, 0x10]), "malformed_cbor");
    // A text of 4 GiB declared in a four-byte length.
    assert_eq!(code(&[0x7a, 0xff, 0xff, 0xff, 0xff]), "malformed_cbor");
    assert_eq!(
        code(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        "malformed_cbor"
    );
}

#[test]
fn scalars_decode_to_the_value_model() {
    assert_eq!(dec(&[0xf6]).unwrap(), Value::Null);
    assert_eq!(dec(&[0xf5]).unwrap(), Value::Bool(true));
    assert_eq!(dec(&[0xf4]).unwrap(), Value::Bool(false));
    assert_eq!(dec(&[0x00]).unwrap(), Value::uint(0));
    assert_eq!(dec(&[0x17]).unwrap(), Value::uint(23));
    assert_eq!(dec(&[0x18, 0x18]).unwrap(), Value::uint(24));
    assert_eq!(
        dec(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
        Value::uint(u64::MAX)
    );
    assert_eq!(dec(&[0x20]).unwrap(), Value::int(-1));
    assert_eq!(
        dec(&[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]).unwrap(),
        Value::int(i64::MIN)
    );
    assert_eq!(
        dec(&[0xfb, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0]).unwrap(),
        Value::float(1.5)
    );
    assert_eq!(dec(&[0x40]).unwrap(), Value::Bytes(vec![]));
    assert_eq!(dec(&[0x60]).unwrap(), Value::text(""));
    assert_eq!(dec(&[0x62, 0xc3, 0xa5]).unwrap(), Value::text("å"));
}

#[test]
fn a_non_shortest_head_is_read_and_written_shortest() {
    // 5 written in two bytes: not canonical, still valid (Fase 1 § 5.2).
    let v = dec(&[0x18, 0x05]).unwrap();
    assert_eq!(v, Value::uint(5));
    assert_eq!(cbor::encode(&v).unwrap(), vec![0x05]);
}

#[test]
fn map_order_is_kept() {
    let bytes = [0xa3, 0x61, b'z', 0x01, 0x61, b'a', 0x02, 0x61, b'm', 0x03];
    let v = dec(&bytes).unwrap();
    let Value::Map(entries) = &v else {
        panic!("not a map");
    };
    let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["z", "a", "m"]);
    assert_eq!(cbor::encode(&v).unwrap(), bytes.to_vec());
}

#[test]
fn float_nan_and_infinity_keep_their_bits() {
    for bits in [
        f64::NAN.to_bits(),
        0x7ff0_0000_0000_0001,
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        (-0.0f64).to_bits(),
    ] {
        let v = Value::Float(bits);
        let bytes = cbor::encode(&v).unwrap();
        assert_eq!(bytes.len(), 9);
        assert_eq!(dec(&bytes).unwrap(), v);
    }
}

#[test]
fn encoder_refuses_what_the_decoder_refuses() {
    let deep = (0..17).fold(Value::uint(0), |v, _| Value::Array(vec![v]));
    assert_eq!(
        cbor::encode(&deep).unwrap_err(),
        malformed(MalformedKind::CborDepth)
    );
    let ok_depth = (0..16).fold(Value::uint(0), |v, _| Value::Array(vec![v]));
    cbor::encode(&ok_depth).unwrap();
    let many = Value::Array((0..10_001).map(|_| Value::Null).collect());
    assert_eq!(
        cbor::encode(&many).unwrap_err(),
        malformed(MalformedKind::CborCount)
    );
    assert_eq!(
        cbor::encode(&Value::Text("a".repeat(65_537))).unwrap_err(),
        malformed(MalformedKind::CborSize)
    );
    assert_eq!(
        cbor::encode(&Value::Bytes(vec![0; 65_537])).unwrap_err(),
        malformed(MalformedKind::CborSize)
    );
    let dup = Value::Map(vec![
        ("k".into(), Value::Null),
        ("k".into(), Value::Bool(true)),
    ]);
    assert_eq!(
        cbor::encode(&dup).unwrap_err(),
        malformed(MalformedKind::CborDuplicateKey)
    );
    assert_eq!(
        cbor::encode(&Value::Int(i128::from(u64::MAX) + 1)).unwrap_err(),
        malformed(MalformedKind::CborInt)
    );
    assert_eq!(
        cbor::encode(&Value::Int(i128::from(i64::MIN) - 1)).unwrap_err(),
        malformed(MalformedKind::CborInt)
    );
    for edge in [i128::from(i64::MIN), i128::from(u64::MAX), -1, 0] {
        let bytes = cbor::encode(&Value::Int(edge)).unwrap();
        assert_eq!(dec(&bytes).unwrap(), Value::Int(edge));
    }
}

#[test]
fn encoded_len_is_exact() {
    let v = Value::Map(vec![
        ("a".into(), Value::uint(300)),
        ("b".into(), Value::int(-70_000)),
        ("c".into(), Value::Bytes(vec![1; 300])),
        ("d".into(), Value::text("x".repeat(25))),
        (
            "e".into(),
            Value::Array(vec![Value::Null, Value::Bool(true), Value::float(0.5)]),
        ),
        ("f".into(), Value::uint(u64::MAX)),
        ("g".into(), Value::int(i64::MIN)),
    ]);
    assert_eq!(cbor::encoded_len(&v), cbor::encode(&v).unwrap().len());
}

// -------------------------------------------------------------- vectors

#[test]
fn cbor_limits_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/cbor-limits.json")).unwrap();
    assert!(file.cases.len() >= 25, "{} cases", file.cases.len());
    let report = vector::run_all(&file, |case, _rng| {
        assert_eq!(case.op, "cbor.decode");
        let input = segments(&case.input);
        let value = cbor::decode(&input)?;
        let again = cbor::encode(&value)?;
        Ok(Outcome {
            output: json!({
                "len": again.len(),
                "sha256": hex_encode(&Sha256::digest(&again)),
            }),
            intermediate: None,
        })
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());
}
