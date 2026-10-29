//! The generated vector groups, one function per file under
//! `vectors/internal/`.

use crate::{Error, render};
use ferret_core::KdfParams;
use ferret_core::testing::hex_encode;
use ferret_core::testing::prim::argon2id;
use ferret_core::testing::vector::{Case, Generator, Status, Tag, VectorFile};
use serde_json::{Value, json};

/// Provenance written into every generated file.
///
/// The `commit` field is a fixed marker, not a git hash: a hash would change
/// the file with every commit and break the byte-for-byte `vectorgen check`.
/// Vectors are versioned by `vectors/VERSION` instead.
fn generator() -> Generator {
    Generator {
        tool: "ferret-vectorgen".into(),
        core: env!("CARGO_PKG_VERSION").into(),
        commit: "see-vectors-version".into(),
        unicode: "16.0.0".into(),
        rng: "hmac-sha256-ctr(seed)".into(),
    }
}

fn valid_case(
    id: &str,
    title: &str,
    op: &str,
    tags: Vec<Tag>,
    input: Value,
    expect: Value,
) -> Case {
    Case {
        id: id.into(),
        title: title.into(),
        op: op.into(),
        status: Status::Valid,
        tags,
        synthetic: true,
        skip_reason: None,
        rng: vec![],
        input,
        intermediate: None,
        expect: Some(expect),
        expect_error: None,
    }
}

fn invalid_case(id: &str, title: &str, op: &str, tags: Vec<Tag>, input: Value, code: &str) -> Case {
    Case {
        id: id.into(),
        title: title.into(),
        op: op.into(),
        status: Status::Invalid,
        tags,
        synthetic: true,
        skip_reason: None,
        rng: vec![],
        input,
        intermediate: None,
        expect: None,
        expect_error: Some(code.into()),
    }
}

// ------------------------------------------------------------------- tlv

/// One TLV field as the vectors describe it.
enum Field {
    /// ASCII label, tag 0x01.
    Label(&'static str),
    /// Label given as bytes (for text the file must not carry raw).
    LabelBytes(Vec<u8>),
    /// One-byte value.
    U8(u8, u8),
    /// Big-endian 64-bit value.
    U64(u8, u64),
    /// Byte value.
    Bytes(u8, Vec<u8>),
    /// `len` copies of `byte` (so that the file does not carry 64 KiB of hex).
    Fill(u8, u8, usize),
}

impl Field {
    fn to_json(&self) -> Value {
        match self {
            Field::Label(s) => json!({ "type": "label", "value": s }),
            Field::LabelBytes(b) => json!({ "type": "label_hex", "value": hex_encode(b) }),
            Field::U8(tag, v) => json!({ "type": "u8", "tag": hex_encode(&[*tag]), "value": v }),
            Field::U64(tag, v) => {
                json!({ "type": "u64", "tag": hex_encode(&[*tag]), "value": v.to_string() })
            }
            Field::Bytes(tag, v) => {
                json!({ "type": "bytes", "tag": hex_encode(&[*tag]), "value": hex_encode(v) })
            }
            Field::Fill(tag, byte, len) => json!({
                "type": "bytes",
                "tag": hex_encode(&[*tag]),
                "fill": { "byte": hex_encode(&[*byte]), "len": len },
            }),
        }
    }

    /// The bytes the specification gives for this field, written out by hand
    /// here and independent of the core's builder: `tag ‖ len(u16be) ‖ value`.
    /// `Err` carries the error code for a value that does not fit.
    fn encode(&self) -> Result<Vec<u8>, &'static str> {
        let (tag, value): (u8, Vec<u8>) = match self {
            Field::Label(s) => (0x01, s.as_bytes().to_vec()),
            Field::LabelBytes(b) => {
                if !b.is_ascii() {
                    return Err("malformed_tlv");
                }
                (0x01, b.clone())
            }
            Field::U8(tag, v) => (*tag, vec![*v]),
            Field::U64(tag, v) => (*tag, v.to_be_bytes().to_vec()),
            Field::Bytes(tag, v) => (*tag, v.clone()),
            Field::Fill(tag, byte, len) => (*tag, vec![*byte; *len]),
        };
        if value.len() > 65_535 {
            return Err("too_large");
        }
        let len = u16::try_from(value.len()).map_err(|_| "too_large")?;
        let mut out = vec![tag];
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&value);
        Ok(out)
    }
}

fn tlv_input(fields: &[Field]) -> Value {
    json!({ "fields": fields.iter().map(Field::to_json).collect::<Vec<_>>() })
}

fn tlv_case(id: &str, title: &str, fields: Vec<Field>) -> Case {
    let input = tlv_input(&fields);
    let mut out = Vec::new();
    for field in &fields {
        match field.encode() {
            Ok(bytes) => out.extend_from_slice(&bytes),
            Err(code) => return invalid_case(id, title, "tlv.build", vec![], input, code),
        }
    }
    valid_case(
        id,
        title,
        "tlv.build",
        vec![],
        input,
        json!({ "tlv": hex_encode(&out) }),
    )
}

/// Bytes `start, start+1, ...` (wrapping), a recognisable pattern.
fn pattern(start: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| start.wrapping_add(u8::try_from(i % 256).unwrap_or(0)))
        .collect()
}

pub(crate) fn tlv() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();

    // The example of Fase 1 § 3.1, written out as literal bytes.
    cases.push(valid_case(
        "tlv/spec/001",
        "label ferret/v1/wrap then suite 1 (the example of the plan)",
        "tlv.build",
        vec![],
        tlv_input(&[Field::Label("ferret/v1/wrap"), Field::U8(0x03, 1)]),
        json!({ "tlv": "01000e6665727265742f76312f7772617003000101" }),
    ));

    // One case per tag of the table in § 3.1.
    cases.push(tlv_case(
        "tlv/tag/label",
        "tag 0x01 label",
        vec![Field::Label("ferret/v1/item")],
    ));
    cases.push(tlv_case(
        "tlv/tag/version",
        "tag 0x02 version",
        vec![Field::U8(0x02, 1)],
    ));
    cases.push(tlv_case(
        "tlv/tag/suite",
        "tag 0x03 suite",
        vec![Field::U8(0x03, 1)],
    ));
    cases.push(tlv_case(
        "tlv/tag/kind",
        "tag 0x04 kind (manifest)",
        vec![Field::U8(0x04, 2)],
    ));
    cases.push(tlv_case(
        "tlv/tag/account_id",
        "tag 0x10 account_id",
        vec![Field::Bytes(0x10, pattern(0x00, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/vault_id",
        "tag 0x11 vault_id",
        vec![Field::Bytes(0x11, pattern(0x10, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/item_id",
        "tag 0x12 item_id",
        vec![Field::Bytes(0x12, pattern(0x20, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/method_id",
        "tag 0x13 method_id",
        vec![Field::Bytes(0x13, pattern(0x30, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/method_type",
        "tag 0x14 method_type (device)",
        vec![Field::U8(0x14, 5)],
    ));
    cases.push(tlv_case(
        "tlv/tag/vk_epoch",
        "tag 0x20 vk_epoch",
        vec![Field::U64(0x20, 7)],
    ));
    cases.push(tlv_case(
        "tlv/tag/kek_generation",
        "tag 0x21 kek_generation",
        vec![Field::U64(0x21, 300)],
    ));
    cases.push(tlv_case(
        "tlv/tag/rev",
        "tag 0x22 rev",
        vec![Field::U64(0x22, 65_536)],
    ));
    cases.push(tlv_case(
        "tlv/tag/seq",
        "tag 0x23 seq",
        vec![Field::U64(0x23, 4_294_967_296)],
    ));
    let mut kdf = Vec::new();
    for v in [65_536u32, 3, 1] {
        kdf.extend_from_slice(&v.to_be_bytes());
    }
    cases.push(tlv_case(
        "tlv/tag/kdf",
        "tag 0x30 kdf (m 65536, t 3, p 1; 12 bytes)",
        vec![Field::Bytes(0x30, kdf)],
    ));
    cases.push(tlv_case(
        "tlv/tag/credential_id",
        "tag 0x31 credential_id",
        vec![Field::Bytes(0x31, pattern(0xa0, 20))],
    ));
    cases.push(tlv_case(
        "tlv/tag/prf_salt",
        "tag 0x32 prf_salt",
        vec![Field::Bytes(0x32, pattern(0x40, 32))],
    ));
    cases.push(tlv_case(
        "tlv/tag/nonce",
        "tag 0x33 nonce (server challenge)",
        vec![Field::Bytes(0x33, pattern(0x60, 32))],
    ));
    cases.push(tlv_case(
        "tlv/tag/hash",
        "tag 0x35 hash",
        vec![Field::Bytes(0x35, pattern(0x80, 32))],
    ));
    cases.push(tlv_case(
        "tlv/tag/op",
        "tag 0x36 op",
        vec![Field::Bytes(0x36, b"unlock-method.add".to_vec())],
    ));
    cases.push(tlv_case(
        "tlv/tag/device_salt",
        "tag 0x37 device_salt",
        vec![Field::Bytes(0x37, pattern(0xc0, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/salt_a",
        "tag 0x38 salt_a (appendix A only)",
        vec![Field::Bytes(0x38, pattern(0xd0, 16))],
    ));
    cases.push(tlv_case(
        "tlv/tag/header",
        "tag 0x39 header (stored verbatim)",
        vec![Field::Bytes(0x39, pattern(0xe0, 10))],
    ));

    // Values.
    cases.push(tlv_case(
        "tlv/value/empty",
        "an empty value is allowed",
        vec![Field::Bytes(0x31, vec![])],
    ));
    cases.push(tlv_case(
        "tlv/value/max",
        "a value of 65535 bytes is the largest that fits",
        vec![Field::Fill(0x39, 0xab, 65_535)],
    ));
    cases.push(tlv_case(
        "tlv/value/oversize",
        "a value of 65536 bytes is rejected, not truncated",
        vec![Field::Fill(0x39, 0xab, 65_536)],
    ));
    cases.push(tlv_case(
        "tlv/value/oversize_after_label",
        "an oversize value after other fields is still rejected",
        vec![
            Field::Label("ferret/v1/wrap"),
            Field::U8(0x02, 1),
            Field::Fill(0x31, 0, 70_000),
        ],
    ));
    cases.push(tlv_case(
        "tlv/u64/big_endian",
        "u64 is big-endian",
        vec![Field::U64(0x22, 0x0102_0304_0506_0708)],
    ));
    cases.push(tlv_case(
        "tlv/u64/zero",
        "u64 zero",
        vec![Field::U64(0x23, 0)],
    ));
    cases.push(tlv_case(
        "tlv/u64/max",
        "u64 maximum",
        vec![Field::U64(0x23, u64::MAX)],
    ));
    cases.push(tlv_case(
        "tlv/label/non_ascii",
        "a label must be ASCII",
        vec![Field::LabelBytes("ferret/v1/\u{e5}".as_bytes().to_vec())],
    ));

    // Order and unambiguity: different field lists never give the same bytes.
    cases.push(tlv_case(
        "tlv/order/suite_version",
        "suite then version",
        vec![Field::U8(0x03, 1), Field::U8(0x02, 1)],
    ));
    cases.push(tlv_case(
        "tlv/order/version_suite",
        "version then suite (differs from suite then version)",
        vec![Field::U8(0x02, 1), Field::U8(0x03, 1)],
    ));
    cases.push(tlv_case(
        "tlv/split/one_field",
        "one field of two zero bytes",
        vec![Field::Bytes(0x31, vec![0, 0])],
    ));
    cases.push(tlv_case(
        "tlv/split/two_fields",
        "two fields of one zero byte (differs from one field of two)",
        vec![Field::Bytes(0x31, vec![0]), Field::Bytes(0x31, vec![0])],
    ));
    cases.push(tlv_case(
        "tlv/split/empty_then_value",
        "an empty field then a one-byte field",
        vec![Field::Bytes(0x31, vec![]), Field::Bytes(0x31, vec![0])],
    ));

    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "tlv".into(),
        suite: 1,
        spec: "Fase 1 § 3.1".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}

// ------------------------------------------------------------------- kdf

fn kdf_input(pwd: &[u8], salt: &[u8], p: KdfParams, out_len: usize) -> Value {
    json!({
        "password": hex_encode(pwd),
        "salt": hex_encode(salt),
        "m_kib": p.m_kib,
        "t": p.t,
        "p": p.p,
        "out_len": out_len,
    })
}

pub(crate) fn kdf() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    let salt = pattern(0x00, 16);
    let profile1 = KdfParams {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };

    // Known answers at the floor (profile 1). The expected values come from
    // the core; the tests cross-check them against argon2 0.5.
    for (n, title, pwd, p, out_len) in [
        (
            1,
            "profile 1, 32 bytes",
            b"ferret test password".as_slice(),
            profile1,
            32usize,
        ),
        (
            2,
            "floor memory and passes with four lanes",
            b"another synthetic password".as_slice(),
            KdfParams { p: 4, ..profile1 },
            32,
        ),
        (
            3,
            "profile 1, 64 bytes of output",
            b"ferret test password".as_slice(),
            profile1,
            64,
        ),
    ] {
        let mut out = vec![0u8; out_len];
        argon2id(pwd, &salt, p, &mut out).map_err(|e| format!("argon2id failed: {e}"))?;
        cases.push(valid_case(
            &format!("kdf/argon2id/valid/{n:03}"),
            title,
            "kdf.argon2id",
            vec![Tag::Slow],
            kdf_input(pwd, &salt, p, out_len),
            json!({ "hash": hex_encode(&out) }),
        ));
    }

    // Parameters outside the floor and ceiling: rejected without computing.
    let pwd = b"ferret test password";
    for (n, title, p) in [
        (
            1,
            "memory one KiB below the floor",
            KdfParams {
                m_kib: 65_535,
                ..profile1
            },
        ),
        (
            2,
            "one pass below the floor",
            KdfParams { t: 2, ..profile1 },
        ),
        (3, "zero lanes", KdfParams { p: 0, ..profile1 }),
        (4, "five lanes", KdfParams { p: 5, ..profile1 }),
        (
            5,
            "memory one KiB above 1 GiB",
            KdfParams {
                m_kib: 1_048_577,
                ..profile1
            },
        ),
        (
            6,
            "memory one KiB above the 512 MiB ceiling",
            KdfParams {
                m_kib: 524_289,
                ..profile1
            },
        ),
        (7, "seventeen passes", KdfParams { t: 17, ..profile1 }),
        (
            8,
            "all zero",
            KdfParams {
                m_kib: 0,
                t: 0,
                p: 0,
            },
        ),
        (
            9,
            "all maximum",
            KdfParams {
                m_kib: u32::MAX,
                t: u32::MAX,
                p: u32::MAX,
            },
        ),
    ] {
        cases.push(invalid_case(
            &format!("kdf/argon2id/invalid/{n:03}"),
            title,
            "kdf.argon2id",
            vec![],
            kdf_input(pwd, &salt, p, 32),
            "kdf_out_of_range",
        ));
    }
    cases.push(invalid_case(
        "kdf/argon2id/invalid/010",
        "salt of seven bytes is too short",
        "kdf.argon2id",
        vec![],
        kdf_input(pwd, &salt[..7], profile1, 32),
        "input_too_short",
    ));

    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "kdf".into(),
        suite: 1,
        spec: "Fase 1 § 4.1".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
