//! The vector groups for the item layer: the CBOR limits (`cbor-limits.json`),
//! padding (`padding.json`) and items and the manifest (`item.json`).
//!
//! Every expected value is made here without calling the core's CBOR,
//! padding or envelope code: the CBOR is written head by head, the padding
//! classes are worked out again, the TLV bytes are written out by hand, and
//! the AEAD and HMAC calls go to the primitive wrappers (which have their own
//! RFC and Wycheproof vectors). The layout follows Fase 1 § 4.4, § 5.1,
//! § 5.2 and § 8.6 directly. The tests of the core then
//! run its own functions against these files.

use crate::groups::{generator, invalid_case, valid_case};
use crate::key_groups::{VkKeys, arr, cat, draw, h, label, t, vk_derive};
use crate::{Error, render};
use ferret_core::testing::prim::{aead_seal, hmac_sha256};
use ferret_core::testing::vector::{Case, FORMAT, VectorFile};
use ferret_core::testing::{ReplayRng, hex_encode};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) mod export;
pub(crate) mod integrity;

// ------------------------------------------------------------ hand-made CBOR

/// CBOR written head by head: the shortest form, definite lengths.
mod cb {
    /// A head of major type `major` with argument `n`.
    pub fn head(major: u8, n: u64) -> Vec<u8> {
        let m = major << 5;
        if let Ok(small) = u8::try_from(n) {
            if small < 24 {
                return vec![m | small];
            }
            return vec![m | 24, small];
        }
        if let Ok(v) = u16::try_from(n) {
            let mut out = vec![m | 25];
            out.extend_from_slice(&v.to_be_bytes());
            return out;
        }
        if let Ok(v) = u32::try_from(n) {
            let mut out = vec![m | 26];
            out.extend_from_slice(&v.to_be_bytes());
            return out;
        }
        let mut out = vec![m | 27];
        out.extend_from_slice(&n.to_be_bytes());
        out
    }

    pub fn uint(n: u64) -> Vec<u8> {
        head(0, n)
    }

    /// A negative integer `n` (below zero): the argument is `-1 - n`.
    pub fn nint(n: i64) -> Vec<u8> {
        head(1, u64::try_from(-1 - i128::from(n)).unwrap_or(0))
    }

    pub fn bytes(b: &[u8]) -> Vec<u8> {
        let mut out = head(2, b.len() as u64);
        out.extend_from_slice(b);
        out
    }

    pub fn text(s: &str) -> Vec<u8> {
        let mut out = head(3, s.len() as u64);
        out.extend_from_slice(s.as_bytes());
        out
    }

    pub fn array(items: &[Vec<u8>]) -> Vec<u8> {
        let mut out = head(4, items.len() as u64);
        for item in items {
            out.extend_from_slice(item);
        }
        out
    }

    pub fn map(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut out = head(5, entries.len() as u64);
        for (k, v) in entries {
            out.extend_from_slice(&text(k));
            out.extend_from_slice(v);
        }
        out
    }

    pub fn boolean(b: bool) -> Vec<u8> {
        vec![if b { 0xf5 } else { 0xf4 }]
    }

    pub fn null() -> Vec<u8> {
        vec![0xf6]
    }

    pub fn float(x: f64) -> Vec<u8> {
        let mut out = vec![0xfb];
        out.extend_from_slice(&x.to_bits().to_be_bytes());
        out
    }
}

/// Runs of at least this many equal bytes become their own segment.
const RUN: usize = 64;

/// `{"segments": [...]}`: the bytes as `hex` units with a repeat count, with
/// long runs of one byte folded so that a 60 KB body stays a few lines.
fn segments(bytes: &[u8]) -> Value {
    let mut segs: Vec<Value> = Vec::new();
    let mut literal: Vec<u8> = Vec::new();
    let mut i = 0;
    let flush = |literal: &mut Vec<u8>, segs: &mut Vec<Value>| {
        if !literal.is_empty() {
            segs.push(json!({ "hex": hex_encode(literal), "repeat": 1 }));
            literal.clear();
        }
    };
    while i < bytes.len() {
        let b = bytes[i];
        let run = bytes[i..].iter().take_while(|x| **x == b).count();
        if run >= RUN {
            flush(&mut literal, &mut segs);
            segs.push(json!({ "hex": hex_encode(&[b]), "repeat": run }));
            i += run;
        } else {
            literal.push(b);
            i += 1;
        }
    }
    flush(&mut literal, &mut segs);
    json!({ "segments": segs })
}

fn sha(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn file(group: &str, spec: &str, cases: Vec<Case>) -> Result<Vec<u8>, Error> {
    render(&VectorFile {
        format: FORMAT.into(),
        group: group.into(),
        suite: 1,
        spec: spec.into(),
        generator: generator(),
        cases,
    })
}

// ------------------------------------------------------------- cbor-limits

fn cbor_case(id: &str, title: &str, bytes: &[u8], expect: Result<Option<Vec<u8>>, &str>) -> Case {
    let input = segments(bytes);
    match expect {
        Ok(reencoded) => {
            let again = reencoded.unwrap_or_else(|| bytes.to_vec());
            valid_case(
                id,
                title,
                "cbor.decode",
                vec![],
                input,
                json!({ "len": again.len(), "sha256": sha(&again) }),
            )
        }
        Err(code) => invalid_case(id, title, "cbor.decode", vec![], input, code),
    }
}

/// An input made of `parts` joined, written as segments by the caller.
fn cat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// A map of `count` entries with the keys "00000", "00001", ... and the
/// value 0, written as a long head plus a `keys` segment.
fn map_case(name: &str, title: &str, count: u64, expect: Result<(), &str>) -> Case {
    let id = format!("cbor-limits/{name}/001");
    let mut long_head = vec![0xba];
    long_head.extend_from_slice(&u32::try_from(count).unwrap_or(0).to_be_bytes());
    let input = json!({ "segments": [
        { "hex": hex_encode(&long_head), "repeat": 1 },
        { "keys": { "count": count, "value_hex": "00" } },
    ] });
    match expect {
        Ok(()) => {
            // Written back with the shortest head.
            let mut bytes = cb::head(5, count);
            for i in 0..count {
                bytes.extend_from_slice(&cb::text(&format!("{i:05}")));
                bytes.push(0);
            }
            valid_case(
                &id,
                title,
                "cbor.decode",
                vec![],
                input,
                json!({ "len": bytes.len(), "sha256": sha(&bytes) }),
            )
        }
        Err(code) => invalid_case(&id, title, "cbor.decode", vec![], input, code),
    }
}

pub(crate) fn cbor_limits() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    let mut maps = Vec::new();
    let mut ok = |name: &str, title: &str, bytes: Vec<u8>, again: Option<Vec<u8>>| {
        cases.push(cbor_case(
            &format!("cbor-limits/{name}/001"),
            title,
            &bytes,
            Ok(again),
        ));
    };

    // Valid values.
    ok("null", "null", cb::null(), None);
    ok("true", "true", cb::boolean(true), None);
    ok("false", "false", cb::boolean(false), None);
    ok("uint_zero", "unsigned 0", cb::uint(0), None);
    ok("uint_23", "unsigned 23, one byte", cb::uint(23), None);
    ok("uint_24", "unsigned 24, two bytes", cb::uint(24), None);
    ok("uint_max", "unsigned 2^64 - 1", cb::uint(u64::MAX), None);
    ok("nint_minus_1", "negative -1", cb::nint(-1), None);
    ok("nint_min", "negative -2^63", cb::nint(i64::MIN), None);
    ok("float_1_5", "float64 1.5", cb::float(1.5), None);
    ok(
        "float32",
        "a single precision float is read and written back as it was",
        vec![0xfa, 0x3f, 0x80, 0x00, 0x00],
        None,
    );
    ok(
        "float16",
        "a half precision float is read and written back as it was",
        vec![0xf9, 0x3c, 0x00],
        None,
    );
    ok(
        "float32_nan_payload",
        "a single precision NaN keeps its bits",
        vec![0xfa, 0x7f, 0xc0, 0x00, 0x01],
        None,
    );
    ok("bytes_empty", "empty byte string", cb::bytes(&[]), None);
    ok("text_empty", "empty text", cb::text(""), None);
    ok(
        "text_utf8",
        "text with a non-ASCII letter",
        cb::text("å"),
        None,
    );
    ok("array_empty", "empty array", cb::array(&[]), None);
    ok("map_empty", "empty map", cb::map(&[]), None);
    ok(
        "map_order",
        "map keys keep their order",
        cb::map(&[("z", cb::uint(1)), ("a", cb::uint(2)), ("m", cb::uint(3))]),
        None,
    );
    ok(
        "non_shortest_head",
        "5 written in two bytes is read, and written back in one",
        vec![0x18, 0x05],
        Some(cb::uint(5)),
    );
    ok(
        "text_long_head",
        "a one-byte text with a four-byte length head is read, and written back short",
        cat_bytes(&[&[0x7a, 0, 0, 0, 1], b"a"]),
        Some(cb::text("a")),
    );

    // The limits, accepted at the boundary.
    ok(
        "depth_16",
        "16 nested arrays",
        cat_bytes(&[&[0x81; 16], &[0x00]]),
        None,
    );
    let mut ten_thousand = vec![0x9a, 0x00, 0x00, 0x27, 0x10];
    ten_thousand.extend(std::iter::repeat_n(0u8, 10_000));
    // The head `9a 00 00 27 10` is longer than the shortest form (`99 27 10`).
    ok(
        "array_10000",
        "an array of 10 000 entries",
        ten_thousand,
        Some(cb::array(&vec![cb::uint(0); 10_000])),
    );
    // Maps of 10 000 and 10 001 entries: keys "00000", "00001", ... and the
    // value `00`, written as a `keys` segment.
    maps.push(map_case(
        "map_10000",
        "a map of 10 000 entries",
        10_000,
        Ok(()),
    ));
    let mut text_max = vec![0x7a, 0x00, 0x01, 0x00, 0x00];
    text_max.extend(std::iter::repeat_n(b'a', 65_536));
    ok(
        "text_65536",
        "a text of 65 536 bytes",
        text_max.clone(),
        None,
    );
    let mut bytes_max = vec![0x5a, 0x00, 0x01, 0x00, 0x00];
    bytes_max.extend(std::iter::repeat_n(7u8, 65_536));
    ok(
        "bytes_65536",
        "a byte string of 65 536 bytes",
        bytes_max,
        None,
    );

    maps.push(map_case(
        "map_10001",
        "a map of 10 001 entries",
        10_001,
        Err("malformed_cbor_count"),
    ));
    let mut bad = |name: &str, title: &str, bytes: Vec<u8>, code: &str| {
        cases.push(cbor_case(
            &format!("cbor-limits/{name}/001"),
            title,
            &bytes,
            Err(code),
        ));
    };
    bad(
        "duplicate_key",
        "a map with the same key twice",
        cb::map(&[("a", cb::uint(1)), ("a", cb::uint(2))]),
        "malformed_cbor_duplicate_key",
    );
    bad(
        "duplicate_key_nested",
        "a duplicate key in a nested map",
        cb::array(&[cb::map(&[("k", cb::null()), ("k", cb::null())])]),
        "malformed_cbor_duplicate_key",
    );
    bad(
        "indefinite_array",
        "an indefinite array (0x9f)",
        vec![0x9f, 0xff],
        "malformed_cbor_indefinite",
    );
    bad(
        "indefinite_map",
        "an indefinite map (0xbf)",
        vec![0xbf, 0xff],
        "malformed_cbor_indefinite",
    );
    bad(
        "indefinite_text",
        "an indefinite text (0x7f)",
        vec![0x7f, 0x61, b'a', 0xff],
        "malformed_cbor_indefinite",
    );
    bad(
        "indefinite_bytes",
        "an indefinite byte string (0x5f)",
        vec![0x5f, 0x41, 0x01, 0xff],
        "malformed_cbor_indefinite",
    );
    bad(
        "tag_1",
        "tag 1 (epoch time)",
        vec![0xc1, 0x00],
        "malformed_cbor_tag",
    );
    bad(
        "tag_in_map",
        "a tag inside a map value",
        cat_bytes(&[&[0xa1, 0x61, b'a', 0xc0], &cb::text("x")]),
        "malformed_cbor_tag",
    );
    bad(
        "depth_17",
        "17 nested arrays",
        cat_bytes(&[&[0x81; 17], &[0x00]]),
        "malformed_cbor_depth",
    );
    let mut over = vec![0x9a, 0x00, 0x00, 0x27, 0x11];
    over.extend(std::iter::repeat_n(0u8, 10_001));
    bad(
        "array_10001",
        "an array of 10 001 entries",
        over,
        "malformed_cbor_count",
    );
    let mut text_over = vec![0x7a, 0x00, 0x01, 0x00, 0x01];
    text_over.extend(std::iter::repeat_n(b'a', 65_537));
    bad(
        "text_65537",
        "a text of 65 537 bytes",
        text_over,
        "malformed_cbor_size",
    );
    let mut bytes_over = vec![0x5a, 0x00, 0x01, 0x00, 0x01];
    bytes_over.extend(std::iter::repeat_n(7u8, 65_537));
    bad(
        "bytes_65537",
        "a byte string of 65 537 bytes",
        bytes_over,
        "malformed_cbor_size",
    );
    bad(
        "undefined",
        "undefined",
        vec![0xf7],
        "malformed_cbor_simple",
    );
    bad(
        "simple_16",
        "simple value 16",
        vec![0xf0],
        "malformed_cbor_simple",
    );
    bad(
        "key_integer",
        "a map key that is an integer",
        vec![0xa1, 0x01, 0x02],
        "malformed_cbor_key_type",
    );
    bad(
        "key_bytes",
        "a map key that is a byte string",
        vec![0xa1, 0x41, 0x61, 0x02],
        "malformed_cbor_key_type",
    );
    bad(
        "trailing",
        "a byte after the item",
        vec![0x00, 0x00],
        "malformed_cbor_trailing",
    );
    bad(
        "int_below_i64_min",
        "an integer below -2^63",
        vec![0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
        "malformed_cbor_int",
    );
    bad("empty", "no input", vec![], "malformed_cbor");
    bad(
        "truncated",
        "an array that stops early",
        vec![0x82, 0x00],
        "malformed_cbor",
    );
    bad(
        "bad_utf8",
        "a text that is not UTF-8",
        vec![0x62, 0xc3, 0x28],
        "malformed_cbor",
    );
    bad(
        "declared_count_missing",
        "10 000 entries declared and none present",
        vec![0x9a, 0x00, 0x00, 0x27, 0x10],
        "malformed_cbor",
    );

    cases.extend(maps);
    file("cbor-limits", "Fase 1 § 5.2", cases)
}

// ----------------------------------------------------------------- padding

/// The padded length for `len` bytes of plaintext, worked out again here.
fn padded_len(len: usize) -> Option<usize> {
    let need = len + 1;
    let class = [256, 512, 1_024, 2_048, 4_096]
        .into_iter()
        .find(|c| need <= *c)
        .unwrap_or_else(|| need.div_ceil(4_096) * 4_096);
    (class <= 61_440).then_some(class)
}

/// `plaintext ‖ 0x80 ‖ 0x00 × n`.
fn pad(plain: &[u8]) -> Result<Vec<u8>, Error> {
    let len = padded_len(plain.len()).ok_or("plaintext too large")?;
    let mut out = plain.to_vec();
    out.push(0x80);
    out.resize(len, 0);
    Ok(out)
}

pub(crate) fn padding() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    let lengths = [
        0usize, 1, 254, 255, 256, 257, 510, 511, 512, 513, 1_022, 1_023, 1_024, 1_025, 2_046,
        2_047, 2_048, 2_049, 4_094, 4_095, 4_096, 4_097, 8_190, 8_191, 8_192, 8_193, 12_287,
        12_288, 61_438, 61_439,
    ];
    for len in lengths {
        let plain = vec![b'a'; len];
        let padded = pad(&plain)?;
        cases.push(valid_case(
            &format!("padding/apply/{len:05}"),
            &format!("{len} bytes of plaintext are padded to {}", padded.len()),
            "pad.apply",
            vec![],
            json!({ "plain": segments(&plain) }),
            json!({ "padded_len": padded.len(), "padded_sha256": sha(&padded) }),
        ));
    }
    for len in [61_440usize, 61_441, 65_535, 70_000] {
        cases.push(invalid_case(
            &format!("padding/apply_too_large/{len:05}"),
            &format!("{len} bytes of plaintext do not fit 61 440"),
            "pad.apply",
            vec![],
            json!({ "plain": segments(&vec![b'a'; len]) }),
            "too_large",
        ));
    }

    // Removal: the plaintext may itself end in 0x80 or in zeros.
    let plains: Vec<(&str, Vec<u8>)> = vec![
        ("empty", vec![]),
        ("one_byte", vec![b'a']),
        ("ends_in_marker_byte", vec![b'a', 0x80]),
        ("ends_in_zeros", vec![b'a', 0, 0, 0]),
        ("only_zeros", vec![0; 40]),
        ("fills_the_class_but_one", vec![b'a'; 255]),
        ("long", vec![b'a'; 4_095]),
        ("largest", vec![b'a'; 61_439]),
    ];
    for (name, plain) in plains {
        let padded = pad(&plain)?;
        cases.push(valid_case(
            &format!("padding/remove/{name}"),
            &format!("padding removed from a plaintext that is {name}"),
            "pad.remove",
            vec![],
            json!({ "padded": segments(&padded) }),
            json!({ "plain_len": plain.len(), "plain_sha256": sha(&plain) }),
        ));
    }
    let mut bad = |name: &str, title: &str, padded: Vec<u8>| {
        cases.push(invalid_case(
            &format!("padding/remove_invalid/{name}"),
            title,
            "pad.remove",
            vec![],
            json!({ "padded": segments(&padded) }),
            "decrypt",
        ));
    };
    bad("no_marker_zeros", "256 zero bytes", vec![0; 256]);
    bad("empty", "no bytes at all", vec![]);
    bad("no_marker_data", "data and no marker", vec![1, 2, 3, 4]);
    let mut tail = pad(b"hello")?;
    tail[200] = 1;
    bad(
        "nonzero_in_tail",
        "a one in the zeros after the marker",
        tail,
    );
    let mut last = pad(b"hello")?;
    if let Some(b) = last.last_mut() {
        *b = 1;
    }
    bad("nonzero_last_byte", "the last byte is 1", last);
    bad(
        "marker_then_ff",
        "a marker followed by 0xff",
        vec![0x80, 0xff],
    );

    file("padding", "Fase 1 § 5.2", cases)
}

// ------------------------------------------------------------------- items

/// A vault state: the account, vault, epoch and vault key.
#[derive(Clone, Copy)]
struct Ctx {
    account: [u8; 16],
    vault: [u8; 16],
    epoch: u64,
    vk: [u8; 32],
}

impl Ctx {
    fn keys(&self) -> Result<VkKeys, Error> {
        vk_derive(&self.account, &self.vault, self.epoch, &self.vk)
    }

    fn input(&self) -> Value {
        json!({
            "account_id": h(&self.account),
            "vault_id": h(&self.vault),
            "vk_epoch": self.epoch.to_string(),
            "vk": h(&self.vk),
        })
    }
}

fn ctx1() -> Ctx {
    Ctx {
        account: arr(0x10),
        vault: arr(0x30),
        epoch: 1,
        vk: arr(0x60),
    }
}

fn ctx2() -> Ctx {
    Ctx {
        account: arr(0x11),
        vault: arr(0x31),
        epoch: 0x1_0000_0002,
        vk: arr(0x61),
    }
}

/// The header bytes and the AAD fields that a sealed envelope gets wrong on
/// purpose.
#[derive(Clone, Copy)]
struct Hdr {
    /// `[version, suite, kind]` in the AAD.
    aad: [u8; 3],
    /// The first three bytes of the envelope.
    written: [u8; 3],
    /// The `vk_epoch` in the AAD of `ik_wrap`, if not the context's.
    ik_epoch: Option<u64>,
}

const GOOD_ITEM: Hdr = Hdr {
    aad: [1, 1, 1],
    written: [1, 1, 1],
    ik_epoch: None,
};

fn ik_aad(aad: [u8; 3], vault: &[u8; 16], item: &[u8; 16], epoch: u64) -> Vec<u8> {
    cat(&[
        label("ferret/v1/item-key"),
        t(0x02, &[aad[0]]),
        t(0x03, &[aad[1]]),
        t(0x11, vault),
        t(0x12, item),
        t(0x20, &epoch.to_be_bytes()),
    ])
}

fn body_aad(manifest: bool, aad: [u8; 3], vault: &[u8; 16], item: &[u8; 16], rev: u64) -> Vec<u8> {
    cat(&[
        label(if manifest {
            "ferret/v1/manifest"
        } else {
            "ferret/v1/item"
        }),
        t(0x02, &[aad[0]]),
        t(0x03, &[aad[1]]),
        t(0x04, &[aad[2]]),
        t(0x11, vault),
        t(0x12, item),
        t(0x22, &rev.to_be_bytes()),
    ])
}

fn item_tag(
    k_head: &[u8; 32],
    item: &[u8; 16],
    rev: u64,
    envelope: &[u8],
) -> Result<[u8; 32], Error> {
    let message = cat(&[
        label("ferret/v1/item-tag"),
        t(0x12, item),
        t(0x22, &rev.to_be_bytes()),
        t(0x35, &Sha256::digest(envelope)),
    ]);
    hmac_sha256(k_head, &message).map_err(|e| format!("hmac failed: {e}").into())
}

/// A sealed item with the pieces a vector reports.
#[derive(Clone)]
struct Item {
    ctx: Ctx,
    id: [u8; 16],
    rev: u64,
    envelope: Vec<u8>,
    tag: [u8; 32],
    ik: [u8; 32],
    ik_aad: Vec<u8>,
    body_aad: Vec<u8>,
    padded_len: usize,
    rng: Vec<Vec<u8>>,
    plain: Vec<u8>,
}

fn seal_with(mut rng: ReplayRng, key: &[u8; 32], aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, Error> {
    aead_seal(&mut rng, key, aad, pt).map_err(|e| format!("seal failed: {e}").into())
}

/// Seals `padded` as an item envelope. With `keep`, the item key and its wrap
/// are taken from that envelope and only the body nonce is drawn.
#[allow(clippy::too_many_arguments)]
fn seal_padded(
    seed: &str,
    ctx: &Ctx,
    id: [u8; 16],
    rev: u64,
    plain: &[u8],
    padded: &[u8],
    keep: Option<&Item>,
    hdr: &Hdr,
) -> Result<Item, Error> {
    let n_body: [u8; 24] = draw(&format!("{seed}/nonce-body"));
    let (ik, ik_wrap, mut rng_draws) = match keep {
        Some(prev) => (prev.ik, prev.envelope[3..75].to_vec(), vec![]),
        None => {
            let ik: [u8; 32] = draw(&format!("{seed}/ik"));
            let n_wrap: [u8; 24] = draw(&format!("{seed}/nonce-wrap"));
            let aad = ik_aad(hdr.aad, &ctx.vault, &id, hdr.ik_epoch.unwrap_or(ctx.epoch));
            let wrap = seal_with(ReplayRng::new(vec![n_wrap.to_vec()]), &ctx.vk, &aad, &ik)?;
            (ik, wrap, vec![ik.to_vec(), n_wrap.to_vec()])
        }
    };
    rng_draws.push(n_body.to_vec());
    let aad_body = body_aad(false, hdr.aad, &ctx.vault, &id, rev);
    let body = seal_with(
        ReplayRng::new(vec![n_body.to_vec()]),
        &ik,
        &aad_body,
        padded,
    )?;
    let mut envelope = hdr.written.to_vec();
    envelope.extend_from_slice(&ik_wrap);
    envelope.extend_from_slice(&body);
    let tag = item_tag(&ctx.keys()?.k_head, &id, rev, &envelope)?;
    Ok(Item {
        ctx: *ctx,
        id,
        rev,
        envelope,
        tag,
        ik,
        ik_aad: ik_aad(GOOD_ITEM.aad, &ctx.vault, &id, ctx.epoch),
        body_aad: body_aad(false, GOOD_ITEM.aad, &ctx.vault, &id, rev),
        padded_len: padded.len(),
        rng: rng_draws,
        plain: plain.to_vec(),
    })
}

fn seal_item(
    seed: &str,
    ctx: &Ctx,
    id: [u8; 16],
    rev: u64,
    plain: &[u8],
    keep: Option<&Item>,
    hdr: &Hdr,
) -> Result<Item, Error> {
    seal_padded(seed, ctx, id, rev, plain, &pad(plain)?, keep, hdr)
}

// ------------------------------------------------------------ item bodies

fn field(id: &str, label: &str, kind: &str, value: &str, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![
        ("id", cb::text(id)),
        ("label", cb::text(label)),
        ("kind", cb::text(kind)),
        ("value", cb::text(value)),
    ];
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

fn url(url: &str, matching: &str, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![("url", cb::text(url)), ("match", cb::text(matching))];
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

fn totp(uri: &str, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![("uri", cb::text(uri))];
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

fn passkey_entries(seed_uv: bool, seed_nouv: bool) -> Vec<(&'static str, Vec<u8>)> {
    let mut e = vec![
        ("cred_id", cb::bytes(&[0xc1; 32])),
        ("rp_id", cb::text("example.com")),
        ("user_handle", cb::bytes(&[0xd2; 16])),
        ("user_name", cb::text("alice")),
        ("priv", cb::bytes(&[0xe3; 138])),
        ("sign_count", cb::uint(0)),
        ("created", cb::uint(1_700_000_050_000)),
    ];
    if seed_uv {
        e.push(("prf_seed_uv", cb::bytes(&[0xf4; 32])));
    }
    if seed_nouv {
        e.push(("prf_seed_nouv", cb::bytes(&[0xf5; 32])));
    }
    e
}

fn passkey(seed_uv: bool, seed_nouv: bool, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = passkey_entries(seed_uv, seed_nouv);
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

/// A body in the order of the schema.
#[derive(Clone)]
struct Body {
    schema: u64,
    ty: String,
    name: String,
    fields: Vec<Vec<u8>>,
    urls: Vec<Vec<u8>>,
    totp: Option<Vec<u8>>,
    passkey: Option<Vec<u8>>,
    notes: Option<String>,
    created: u64,
    modified: u64,
    favorite: bool,
    device: Option<String>,
    extra: Vec<(String, Vec<u8>)>,
}

impl Body {
    fn new(ty: &str, name: &str) -> Self {
        Self {
            schema: 1,
            ty: ty.into(),
            name: name.into(),
            fields: vec![],
            urls: vec![],
            totp: None,
            passkey: None,
            notes: None,
            created: 1_700_000_000_000,
            modified: 1_700_000_100_000,
            favorite: false,
            device: None,
            extra: vec![],
        }
    }

    fn cbor(&self) -> Vec<u8> {
        cb::map(&self.entries())
    }

    fn entries(&self) -> Vec<(&str, Vec<u8>)> {
        let mut e: Vec<(&str, Vec<u8>)> = vec![
            ("schema", cb::uint(self.schema)),
            ("type", cb::text(&self.ty)),
            ("name", cb::text(&self.name)),
            ("fields", cb::array(&self.fields)),
            ("urls", cb::array(&self.urls)),
        ];
        if let Some(v) = &self.totp {
            e.push(("totp", v.clone()));
        }
        if let Some(v) = &self.passkey {
            e.push(("passkey", v.clone()));
        }
        if let Some(v) = &self.notes {
            e.push(("notes", cb::text(v)));
        }
        e.push(("created", cb::uint(self.created)));
        e.push(("modified", cb::uint(self.modified)));
        e.push(("favorite", cb::boolean(self.favorite)));
        if let Some(v) = &self.device {
            e.push(("device", cb::text(v)));
        }
        for (k, v) in &self.extra {
            e.push((k, v.clone()));
        }
        e
    }

    /// A body whose CBOR is exactly `len` bytes, by the length of the notes.
    fn with_cbor_len(mut self, len: usize) -> Result<Self, Error> {
        self.notes = Some(String::new());
        // With empty notes the text head takes one byte.
        let base = self.cbor().len();
        let notes_len = (0usize..=65_535)
            .find(|l| {
                let head = if *l < 24 {
                    1
                } else if *l < 256 {
                    2
                } else {
                    3
                };
                base - 1 + head + l == len
            })
            .ok_or("no notes length gives that body length")?;
        self.notes = Some("a".repeat(notes_len));
        assert_eq!(self.cbor().len(), len);
        Ok(self)
    }
}

fn id(b: u8) -> [u8; 16] {
    arr(b)
}

// ------------------------------------------------------------ item vectors

fn seal_input(ctx: &Ctx, id: &[u8; 16], rev: u64, plain: &[u8], keep: Option<&Item>) -> Value {
    let mut i = ctx.input();
    i["item_id"] = h(id);
    i["rev"] = json!(rev.to_string());
    i["body"] = segments(plain);
    if let Some(prev) = keep {
        i["existing"] = h(&prev.envelope);
    }
    i
}

/// A `valid` `item.seal` case for an item that was sealed.
fn seal_case(case_id: &str, title: &str, it: &Item, keep: Option<&Item>) -> Case {
    let mut c = valid_case(
        case_id,
        title,
        "item.seal",
        vec![],
        seal_input(&it.ctx, &it.id, it.rev, &it.plain, keep),
        json!({ "envelope": hex_encode(&it.envelope), "tag": hex_encode(&it.tag) }),
    );
    c.rng = it.rng.iter().map(|d| hex_encode(d)).collect();
    c.intermediate = Some(json!({
        "ik": hex_encode(&it.ik),
        "ik_aad": hex_encode(&it.ik_aad),
        "body_aad": hex_encode(&it.body_aad),
        "padded_len": it.padded_len,
    }));
    c
}

/// A `valid` `item.seal.digest` case: the same operation, reporting the length and
/// hash of the envelope instead of the bytes, for the large ones.
fn seal_digest_case(case_id: &str, title: &str, it: &Item) -> Case {
    let mut c = valid_case(
        case_id,
        title,
        "item.seal.digest",
        vec![],
        seal_input(&it.ctx, &it.id, it.rev, &it.plain, None),
        json!({
            "envelope_len": it.envelope.len(),
            "envelope_sha256": sha(&it.envelope),
            "tag": hex_encode(&it.tag),
        }),
    );
    c.rng = it.rng.iter().map(|d| hex_encode(d)).collect();
    c
}

fn open_input(ctx: &Ctx, id: &[u8; 16], rev: u64, envelope: &[u8], tag: &[u8; 32]) -> Value {
    let mut i = ctx.input();
    i["item_id"] = h(id);
    i["rev"] = json!(rev.to_string());
    i["envelope"] = h(envelope);
    i["tag"] = h(tag);
    i
}

fn open_case(case_id: &str, title: &str, it: &Item, read_only: bool) -> Case {
    valid_case(
        case_id,
        title,
        "item.open",
        vec![],
        item_input_with(it),
        json!({ "read_only": read_only, "body": hex_encode(&it.plain) }),
    )
}

/// Name, title, vault state, item id byte, revision and CBOR of a new item.
type NewItem = (&'static str, &'static str, Ctx, u8, u64, Vec<u8>);

/// Name, title, vault state, revision and CBOR of a manifest.
type NewManifest = (&'static str, &'static str, Ctx, u64, Vec<u8>);

fn item_input_with(it: &Item) -> Value {
    open_input(&it.ctx, &it.id, it.rev, &it.envelope, &it.tag)
}

pub(crate) fn item() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let c1 = ctx1();
    let c2 = ctx2();

    // ---- bodies
    let login = Body::new("login", "Example");
    let mut note = Body::new("note", "Shopping");
    note.notes = Some("milk, bread and ål".into());
    note.favorite = true;
    note.device = Some("laptop".into());
    let mut card = Body::new("card", "Visa");
    card.fields = vec![
        field("number", "Card number", "hidden", "4111111111111111", &[]),
        field("holder", "Holder", "text", "A. Example", &[]),
        field("pin", "PIN", "password", "1234", &[]),
    ];
    let mut identity = Body::new("identity", "Me");
    identity.fields = vec![
        field("mail", "E-mail", "email", "me@example.com", &[]),
        field("tel", "Phone", "phone", "+4712345678", &[]),
        field("site", "Site", "url", "https://example.com", &[]),
    ];
    identity.urls = vec![
        url("https://example.com/a", "host", &[]),
        url("https://example.com", "domain", &[]),
        url("https://example.com/b?x=1", "exact", &[]),
    ];
    identity.totp = Some(totp(
        "otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        &[],
    ));
    let mut rich = Body::new("login", "Rich");
    rich.fields = vec![
        field(
            "u",
            "User",
            "text",
            "alice",
            &[("hint", cb::text("login name"))],
        ),
        field("k", "Odd", "pin-code", "9", &[]),
    ];
    rich.urls = vec![url(
        "https://example.org",
        "regex",
        &[("flags", cb::uint(3))],
    )];
    rich.passkey = Some(passkey(
        true,
        true,
        &[(
            "future",
            cb::map(&[
                ("deep", cb::array(&[cb::null(), cb::boolean(false)])),
                ("n", cb::nint(-9)),
            ]),
        )],
    ));
    rich.totp = Some(totp(
        "otpauth://totp/x?secret=ABCDEFGH",
        &[("added", cb::uint(5))],
    ));
    rich.notes = Some("åäö \u{1f980}".into());
    rich.extra = vec![
        ("zeta".into(), cb::bytes(&[1, 2, 3])),
        (
            "alpha".into(),
            cb::map(&[
                ("x", cb::float(2.5)),
                ("a", cb::array(&[cb::uint(1), cb::text("two")])),
            ]),
        ),
        ("mid".into(), cb::null()),
        (
            "floats".into(),
            cb::array(&[
                vec![0xf9, 0x3c, 0x00],
                vec![0xfa, 0x3f, 0x80, 0x00, 0x00],
                cb::float(0.1),
            ]),
        ),
    ];
    let wallet = Body::new("wallet", "Unknown type");
    let mut future = Body::new("login", "From the future");
    future.schema = 2;
    future.extra = vec![("x-new".into(), cb::map(&[("a", cb::uint(1))]))];

    // ---- new items
    let list: Vec<NewItem> = vec![
        ("login", "a minimal login", c1, 0x31, 1, login.cbor()),
        (
            "note",
            "a note with notes, favorite and device",
            c1,
            0x32,
            1,
            note.cbor(),
        ),
        (
            "card",
            "a card with hidden and password fields",
            c1,
            0x33,
            1,
            card.cbor(),
        ),
        (
            "identity",
            "an identity with urls and a totp",
            c1,
            0x34,
            2,
            identity.cbor(),
        ),
        (
            "rich",
            "a login with a passkey and unknown keys at three levels",
            c1,
            0x35,
            5,
            rich.cbor(),
        ),
        (
            "wallet",
            "an item of a type this version does not know",
            c1,
            0x36,
            1,
            wallet.cbor(),
        ),
        (
            "other_vault",
            "another account, vault and epoch, large revision",
            c2,
            0x37,
            0x2_0000_0001,
            login.cbor(),
        ),
    ];
    let mut items: Vec<Item> = Vec::new();
    for (name, title, ctx, idb, rev, plain) in &list {
        let seed = format!("item/seal/{name}");
        let it = seal_item(&seed, ctx, id(*idb), *rev, plain, None, &GOOD_ITEM)?;
        cases.push(seal_case(&format!("item/seal/{name}"), title, &it, None));
        items.push(it);
    }

    // Padding classes: the CBOR length decides the class of the body.
    for (name, cbor_len, class) in [
        ("class_256", 255usize, 256usize),
        ("class_512", 256, 512),
        ("class_4096", 4_095, 4_096),
        ("class_8192", 4_096, 8_192),
    ] {
        let body = Body::new("note", "sized").with_cbor_len(cbor_len)?;
        let plain = body.cbor();
        let it = seal_item(
            &format!("item/seal/{name}"),
            &c1,
            id(0x40),
            1,
            &plain,
            None,
            &GOOD_ITEM,
        )?;
        assert_eq!(it.padded_len, class);
        cases.push(seal_case(
            &format!("item/seal/{name}"),
            &format!("a body of {cbor_len} bytes is padded to {class}"),
            &it,
            None,
        ));
        items.push(it);
    }
    let largest = Body::new("note", "largest").with_cbor_len(61_439)?;
    let largest_it = seal_item(
        "item/seal/largest",
        &c1,
        id(0x41),
        1,
        &largest.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    assert_eq!(largest_it.envelope.len(), 3 + 72 + 24 + 61_440 + 16);
    cases.push(seal_digest_case(
        "item/seal_digest/largest",
        "the largest body, 61 439 bytes, makes a 61 555 byte envelope",
        &largest_it,
    ));

    // ---- edits keep the item key
    let first = items
        .iter()
        .find(|i| i.id == id(0x31))
        .cloned()
        .ok_or("missing login")?;
    let mut edited = login.clone();
    edited.name = "Example (edited)".into();
    edited.modified += 1;
    let edit1 = seal_item(
        "item/seal/edit_login",
        &c1,
        id(0x31),
        2,
        &edited.cbor(),
        Some(&first),
        &GOOD_ITEM,
    )?;
    cases.push(seal_case(
        "item/seal_edit/login",
        "an edit keeps ik_wrap and draws only a body nonce",
        &edit1,
        Some(&first),
    ));
    let rich_it = items
        .iter()
        .find(|i| i.id == id(0x35))
        .cloned()
        .ok_or("missing rich")?;
    let mut rich_edit = rich.clone();
    rich_edit.favorite = true;
    let edit2 = seal_item(
        "item/seal/edit_rich",
        &c1,
        id(0x35),
        6,
        &rich_edit.cbor(),
        Some(&rich_it),
        &GOOD_ITEM,
    )?;
    cases.push(seal_case(
        "item/seal_edit/rich",
        "an edit keeps unknown keys at every level",
        &edit2,
        Some(&rich_it),
    ));
    items.push(edit1);
    items.push(edit2);

    // ---- seals that must fail
    let mut inv = |name: &str, title: &str, plain: Vec<u8>, item_id: [u8; 16], code: &str| {
        cases.push(invalid_case(
            &format!("item/seal_invalid/{name}"),
            title,
            "item.seal",
            vec![],
            seal_input(&c1, &item_id, 1, &plain, None),
            code,
        ));
    };
    inv(
        "schema_2",
        "a body with schema 2 cannot be written",
        future.cbor(),
        id(0x31),
        "read_only_schema",
    );
    let mut future9 = future.clone();
    future9.schema = 9;
    inv(
        "schema_9",
        "a body with schema 9 cannot be written",
        future9.cbor(),
        id(0x31),
        "read_only_schema",
    );
    inv(
        "reserved_item_id",
        "the item id of the manifest is not an item id",
        login.cbor(),
        [0; 16],
        "malformed_envelope",
    );
    inv(
        "missing_name",
        "a schema 1 body without a name",
        cb::map(&[
            ("schema", cb::uint(1)),
            ("type", cb::text("note")),
            ("fields", cb::array(&[])),
            ("urls", cb::array(&[])),
            ("created", cb::uint(1)),
            ("modified", cb::uint(1)),
            ("favorite", cb::boolean(false)),
        ]),
        id(0x31),
        "malformed_item_body",
    );
    inv(
        "float_in_a_known_field",
        "a float where the name must be text",
        cb::map(&[
            ("schema", cb::uint(1)),
            ("type", cb::text("note")),
            ("name", vec![0xfa, 0x3f, 0x80, 0x00, 0x00]),
            ("fields", cb::array(&[])),
            ("urls", cb::array(&[])),
            ("created", cb::uint(1)),
            ("modified", cb::uint(1)),
            ("favorite", cb::boolean(false)),
        ]),
        id(0x31),
        "malformed_item_body",
    );
    inv(
        "cbor_tag",
        "a body that is not CBOR the decoder accepts",
        vec![0xc1, 0x00],
        id(0x31),
        "malformed_cbor_tag",
    );

    // ---- opens that succeed
    let future_it = seal_item(
        "item/open/future",
        &c1,
        id(0x31),
        1,
        &future.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    for (n, it) in items.iter().enumerate() {
        let name = format!("item/open/{n:03}");
        cases.push(open_case(
            &name,
            &format!("opens an item sealed at revision {}", it.rev),
            it,
            false,
        ));
    }
    cases.push(open_case(
        "item/open/schema_2",
        "a body with schema 2 opens read-only",
        &future_it,
        true,
    ));

    // ---- key order: known keys in schema order, then unknown keys as read
    // The reader keeps an unknown key that stands before a known one, and the
    // writer puts it after the known keys, at every level.
    let mut ordered = Body::new("login", "Key order");
    ordered.fields = vec![field("u", "User", "text", "alice", &[("zz", cb::uint(1))])];
    ordered.urls = vec![url("https://example.com", "host", &[("yy", cb::text("b"))])];
    ordered.totp = Some(totp(
        "otpauth://totp/x?secret=ABCDEFGH",
        &[("tt", cb::uint(2))],
    ));
    ordered.passkey = Some(passkey(true, false, &[("pk", cb::text("x"))]));
    ordered.extra = vec![
        ("zzz-first".into(), cb::uint(7)),
        ("mmm-last".into(), cb::text("end")),
    ];
    let foreign = {
        cb::map(&[
            ("zzz-first", cb::uint(7)),
            ("schema", cb::uint(1)),
            ("type", cb::text("login")),
            ("name", cb::text("Key order")),
            (
                "fields",
                cb::array(&[cb::map(&[
                    ("zz", cb::uint(1)),
                    ("id", cb::text("u")),
                    ("label", cb::text("User")),
                    ("kind", cb::text("text")),
                    ("value", cb::text("alice")),
                ])]),
            ),
            (
                "urls",
                cb::array(&[cb::map(&[
                    ("yy", cb::text("b")),
                    ("url", cb::text("https://example.com")),
                    ("match", cb::text("host")),
                ])]),
            ),
            (
                "totp",
                cb::map(&[
                    ("tt", cb::uint(2)),
                    ("uri", cb::text("otpauth://totp/x?secret=ABCDEFGH")),
                ]),
            ),
            ("passkey", {
                let mut e = vec![("pk", cb::text("x"))];
                e.extend(passkey_entries(true, false));
                cb::map(&e)
            }),
            ("created", cb::uint(ordered.created)),
            ("modified", cb::uint(ordered.modified)),
            ("favorite", cb::boolean(false)),
            ("mmm-last", cb::text("end")),
        ])
    };
    let ordered_it = seal_item(
        "item/key_order",
        &c1,
        id(0x36),
        1,
        &ordered.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let mut seal_unordered = seal_case(
        "item/seal/key_order",
        "unknown keys that stand before known keys are written after them, at every level",
        &ordered_it,
        None,
    );
    seal_unordered.input["body"] = segments(&foreign);
    cases.push(seal_unordered);
    let foreign_it = seal_item(
        "item/key_order_foreign",
        &c1,
        id(0x37),
        1,
        &foreign,
        None,
        &GOOD_ITEM,
    )?;
    cases.push(valid_case(
        "item/open/key_order",
        "an authentic body with unknown keys before known ones opens in the order the core writes",
        "item.open",
        vec![],
        item_input_with(&foreign_it),
        json!({ "read_only": false, "body": hex_encode(&ordered.cbor()) }),
    ));

    // ---- a newer schema is written back as it was read
    // `name` and `fields` have the wrong type for schema 1. A reader that
    // keeps them as unknown keys and rebuilds the body would write them
    // twice; the body is returned as it was read instead.
    let mistyped = cb::map(&[
        ("zzz-first", cb::uint(7)),
        ("schema", cb::uint(2)),
        ("type", cb::text("login")),
        ("name", cb::uint(5)),
        ("fields", cb::text("not a list")),
        (
            "urls",
            cb::array(&[cb::map(&[("yy", cb::uint(1)), ("url", cb::boolean(true))])]),
        ),
        ("created", cb::uint(1)),
        ("modified", cb::uint(2)),
        ("favorite", cb::boolean(false)),
    ]);
    let mistyped_it = seal_item(
        "item/open/schema_2_mistyped",
        &c1,
        id(0x38),
        1,
        &mistyped,
        None,
        &GOOD_ITEM,
    )?;
    cases.push(open_case(
        "item/open/schema_2_mistyped",
        "a body with schema 2 and mistyped known keys opens read-only and is returned as it was read",
        &mistyped_it,
        true,
    ));

    // ---- sabotage of one envelope
    let base = seal_item(
        "item/sabotage/base",
        &c1,
        id(0x51),
        3,
        &login.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let other = seal_item(
        "item/sabotage/other",
        &c1,
        id(0x52),
        3,
        &login.cbor(),
        None,
        &GOOD_ITEM,
    )?;
    let k_head = c1.keys()?.k_head;
    let mut bad = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("item/open_invalid/{name}"),
            title,
            "item.open",
            vec![],
            input,
            code,
        ));
    };
    let with_env = |env: &[u8]| open_input(&c1, &base.id, base.rev, env, &base.tag);
    let flip = |at: usize| {
        let mut e = base.envelope.clone();
        e[at] ^= 0x01;
        e
    };
    for (name, at) in [
        ("ik_wrap_nonce", 3usize),
        ("ik_wrap_ciphertext", 40),
        ("ik_wrap_tag", 74),
        ("body_nonce", 75),
        ("body_ciphertext", 150),
        ("body_tag", base.envelope.len() - 1),
    ] {
        bad(
            &format!("flip_{name}"),
            &format!("one bit changed in the {name}"),
            with_env(&flip(at)),
            "decrypt",
        );
    }
    for (name, at) in [("first", 0usize), ("last", 31)] {
        let mut tag = base.tag;
        tag[at] ^= 0x01;
        bad(
            &format!("tag_{name}_byte"),
            &format!("the {name} byte of the tag changed"),
            open_input(&c1, &base.id, base.rev, &base.envelope, &tag),
            "decrypt",
        );
    }
    bad(
        "tag_of_another_item",
        "the tag of another item",
        open_input(&c1, &base.id, base.rev, &base.envelope, &other.tag),
        "decrypt",
    );
    let header = |idx: usize, v: u8, code: &str, name: &str, title: &str| {
        let mut e = base.envelope.clone();
        e[idx] = v;
        (
            name.to_owned(),
            title.to_owned(),
            with_env(&e),
            code.to_owned(),
        )
    };
    for (name, title, input, code) in [
        header(0, 2, "decrypt", "version_2", "version 2"),
        header(0, 0, "decrypt", "version_0", "version 0"),
        header(1, 2, "decrypt", "suite_2", "suite 2"),
        header(2, 3, "decrypt", "kind_3", "kind 3"),
        header(2, 0, "decrypt", "kind_0", "kind 0"),
        header(2, 2, "decrypt", "kind_2", "an item as a manifest"),
    ] {
        bad(&name, &format!("the header says {title}"), input, &code);
    }
    let mut truncated = base.envelope.clone();
    truncated.truncate(74);
    bad(
        "truncated_in_ik_wrap",
        "cut off inside ik_wrap",
        with_env(&truncated),
        "malformed_envelope",
    );
    let mut cut = base.envelope.clone();
    cut.truncate(300);
    bad(
        "truncated_body",
        "cut off inside the body, so the padded length is no class",
        with_env(&cut),
        "malformed_envelope",
    );
    let mut longer = base.envelope.clone();
    longer.push(0);
    bad(
        "one_byte_more",
        "one byte too long",
        with_env(&longer),
        "malformed_envelope",
    );
    bad("empty", "no bytes", with_env(&[]), "malformed_envelope");
    let mut huge = base.envelope.clone();
    huge.resize(65_537, 0);
    bad(
        "one_byte_over_the_limit",
        "65 537 bytes: over the largest envelope, refused before anything else",
        with_env(&huge),
        "too_large",
    );

    // Other values than the ones the envelope was sealed for.
    let mut other_id = [0x52u8; 16];
    other_id[15] = 0x53;
    bad(
        "wrong_item_id_old_tag",
        "another item id, the old tag",
        open_input(&c1, &other_id, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    bad(
        "wrong_item_id_retagged",
        "another item id with a tag made for it: only the ik_wrap AAD refuses",
        open_input(
            &c1,
            &other_id,
            base.rev,
            &base.envelope,
            &item_tag(&k_head, &other_id, base.rev, &base.envelope)?,
        ),
        "decrypt",
    );
    bad(
        "wrong_rev_old_tag",
        "revision 4, the old tag",
        open_input(&c1, &base.id, 4, &base.envelope, &base.tag),
        "decrypt",
    );
    bad(
        "wrong_rev_retagged",
        "revision 4 with a tag made for it: only the body AAD refuses",
        open_input(
            &c1,
            &base.id,
            4,
            &base.envelope,
            &item_tag(&k_head, &base.id, 4, &base.envelope)?,
        ),
        "decrypt",
    );
    let mut ctx = c1;
    ctx.vault[0] ^= 1;
    bad(
        "wrong_vault_id",
        "another vault id",
        open_input(&ctx, &base.id, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    let mut ctx = c1;
    ctx.epoch += 1;
    bad(
        "wrong_epoch",
        "another vk_epoch",
        open_input(&ctx, &base.id, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    let mut ctx = c1;
    ctx.account[0] ^= 1;
    bad(
        "wrong_account",
        "another account id",
        open_input(&ctx, &base.id, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    let mut ctx = c1;
    ctx.vk[0] ^= 1;
    bad(
        "wrong_vault_key",
        "another vault key",
        open_input(&ctx, &base.id, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );

    // Envelopes sealed with one AAD field wrong; the header bytes and the
    // tag are right, so the AEAD is what refuses.
    let plain = login.cbor();
    for (name, hdr, title) in [
        (
            "aad_version",
            Hdr {
                aad: [2, 1, 1],
                ..GOOD_ITEM
            },
            "the AAD says version 2",
        ),
        (
            "aad_suite",
            Hdr {
                aad: [1, 2, 1],
                ..GOOD_ITEM
            },
            "the AAD says suite 2",
        ),
        (
            "aad_kind",
            Hdr {
                aad: [1, 1, 2],
                ..GOOD_ITEM
            },
            "the AAD says kind 2",
        ),
        (
            "ik_wrap_epoch",
            Hdr {
                ik_epoch: Some(2),
                ..GOOD_ITEM
            },
            "the ik_wrap AAD says vk_epoch 2",
        ),
    ] {
        let it = seal_item(
            &format!("item/sabotage/{name}"),
            &c1,
            id(0x51),
            3,
            &plain,
            None,
            &hdr,
        )?;
        bad(name, title, item_input_with(&it), "decrypt");
    }

    // Padding that is wrong inside an envelope that is otherwise right: the
    // AEAD accepts it, and the answer is still the one error.
    for (name, padded, title) in [
        (
            "padding_all_zeros",
            vec![0u8; 256],
            "the padded body is 256 zeros",
        ),
        (
            "padding_nonzero_tail",
            {
                let mut p = pad(&plain)?;
                let last = p.len() - 1;
                p[last] = 1;
                p
            },
            "the padded body ends in 1",
        ),
        (
            "padding_no_marker",
            vec![0x61u8; 256],
            "the padded body has no marker",
        ),
    ] {
        let it = seal_padded(
            &format!("item/sabotage/{name}"),
            &c1,
            id(0x51),
            3,
            &plain,
            &padded,
            None,
            &GOOD_ITEM,
        )?;
        bad(name, title, item_input_with(&it), "decrypt");
    }

    // CBOR that the AEAD accepts and the decoder does not.
    for (name, junk, code, title) in [
        (
            "body_not_cbor",
            vec![0xff, 0xff],
            "malformed_cbor",
            "an authentic body that is not CBOR",
        ),
        (
            "body_duplicate_key",
            cb::map(&[("a", cb::uint(1)), ("a", cb::uint(2))]),
            "malformed_cbor_duplicate_key",
            "an authentic body with a duplicate key",
        ),
        (
            "body_missing_field",
            cb::map(&[("schema", cb::uint(1))]),
            "malformed_item_body",
            "an authentic body without the required fields",
        ),
        (
            "body_not_a_map",
            cb::array(&[]),
            "malformed_item_body",
            "an authentic body that is an array",
        ),
    ] {
        let it = seal_item(
            &format!("item/sabotage/{name}"),
            &c1,
            id(0x51),
            3,
            &junk,
            None,
            &GOOD_ITEM,
        )?;
        bad(name, title, item_input_with(&it), code);
    }

    // ---- the manifest
    manifest_cases(&mut cases)?;

    file("item", "Fase 1 § 4.4, § 5.1, § 5.2, § 8.6", cases)
}

// ---------------------------------------------------------------- manifest

fn method(t_: u64, id_: u8, g: u64, extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![
        ("t", cb::uint(t_)),
        ("id", cb::bytes(&[id_; 16])),
        ("g", cb::uint(g)),
    ];
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

fn manifest_cbor(v: u64, epoch: u64, methods: &[Vec<u8>], extra: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut e = vec![
        ("v", cb::uint(v)),
        ("vk_epoch", cb::uint(epoch)),
        ("methods", cb::array(methods)),
    ];
    e.extend(extra.iter().cloned());
    cb::map(&e)
}

struct Sealed {
    ctx: Ctx,
    rev: u64,
    envelope: Vec<u8>,
    tag: [u8; 32],
    plain: Vec<u8>,
    nonce: [u8; 24],
}

fn seal_manifest(seed: &str, ctx: &Ctx, rev: u64, plain: &[u8]) -> Result<Sealed, Error> {
    let nonce: [u8; 24] = draw(&format!("{seed}/nonce"));
    let keys = ctx.keys()?;
    let aad = body_aad(true, [1, 1, 2], &ctx.vault, &[0; 16], rev);
    let body = seal_with(
        ReplayRng::new(vec![nonce.to_vec()]),
        &keys.k_meta,
        &aad,
        &pad(plain)?,
    )?;
    let mut envelope = vec![1, 1, 2];
    envelope.extend_from_slice(&body);
    let tag = item_tag(&keys.k_head, &[0; 16], rev, &envelope)?;
    Ok(Sealed {
        ctx: *ctx,
        rev,
        envelope,
        tag,
        plain: plain.to_vec(),
        nonce,
    })
}

fn manifest_open_input(ctx: &Ctx, rev: u64, envelope: &[u8], tag: &[u8; 32]) -> Value {
    let mut i = ctx.input();
    i["rev"] = json!(rev.to_string());
    i["envelope"] = h(envelope);
    i["tag"] = h(tag);
    i
}

fn manifest_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    let c1 = ctx1();
    let c2 = ctx2();
    let list: Vec<NewManifest> = vec![
        (
            "one_method",
            "a manifest with the password method",
            c1,
            1,
            manifest_cbor(1, 1, &[method(1, 0x70, 1, &[])], &[]),
        ),
        (
            "three_methods",
            "three methods, a large generation, unknown keys",
            c2,
            4,
            manifest_cbor(
                1,
                0x1_0000_0002,
                &[
                    method(1, 0x70, 3, &[]),
                    method(2, 0x71, 1, &[]),
                    method(3, 0x72, u64::MAX, &[("label", cb::text("YubiKey"))]),
                ],
                &[("future", cb::uint(1))],
            ),
        ),
        (
            "no_methods",
            "an empty list of methods",
            c1,
            2,
            manifest_cbor(1, 1, &[], &[]),
        ),
    ];
    let mut sealed = Vec::new();
    for (name, title, ctx, rev, plain) in &list {
        let s = seal_manifest(&format!("item/manifest/{name}"), ctx, *rev, plain)?;
        let mut input = ctx.input();
        input["rev"] = json!(rev.to_string());
        input["manifest"] = h(plain);
        let mut c = valid_case(
            &format!("item/manifest_seal/{name}"),
            title,
            "item.manifest.seal",
            vec![],
            input,
            json!({ "envelope": hex_encode(&s.envelope), "tag": hex_encode(&s.tag) }),
        );
        c.rng = vec![hex_encode(&s.nonce)];
        cases.push(c);
        cases.push(valid_case(
            &format!("item/manifest_open/{name}"),
            &format!("opens: {title}"),
            "item.manifest.open",
            vec![],
            manifest_open_input(&s.ctx, s.rev, &s.envelope, &s.tag),
            json!({ "manifest": hex_encode(&s.plain) }),
        ));
        sealed.push(s);
    }
    // Key order: known keys in schema order, then unknown keys as read, at the
    // top level and in a method entry.
    let unordered = cb::map(&[
        ("zz", cb::uint(1)),
        ("v", cb::uint(1)),
        ("vk_epoch", cb::uint(1)),
        (
            "methods",
            cb::array(&[cb::map(&[
                ("note", cb::text("n")),
                ("t", cb::uint(1)),
                ("id", cb::bytes(&[0x70; 16])),
                ("g", cb::uint(1)),
            ])]),
        ),
        ("aa", cb::text("x")),
    ]);
    let normal = manifest_cbor(
        1,
        1,
        &[method(1, 0x70, 1, &[("note", cb::text("n"))])],
        &[("zz", cb::uint(1)), ("aa", cb::text("x"))],
    );
    let written = seal_manifest("item/manifest/key_order", &c1, 3, &normal)?;
    let mut input = c1.input();
    input["rev"] = json!("3");
    input["manifest"] = h(&unordered);
    let mut c = valid_case(
        "item/manifest_seal/key_order",
        "unknown keys that stand before known keys are written after them, at both levels",
        "item.manifest.seal",
        vec![],
        input,
        json!({ "envelope": hex_encode(&written.envelope), "tag": hex_encode(&written.tag) }),
    );
    c.rng = vec![hex_encode(&written.nonce)];
    cases.push(c);
    let foreign = seal_manifest("item/manifest/key_order_foreign", &c1, 3, &unordered)?;
    cases.push(valid_case(
        "item/manifest_open/key_order",
        "an authentic manifest with unknown keys before known ones opens in the order the core writes",
        "item.manifest.open",
        vec![],
        manifest_open_input(&foreign.ctx, foreign.rev, &foreign.envelope, &foreign.tag),
        json!({ "manifest": hex_encode(&normal) }),
    ));
    // Sealing a manifest for another epoch than the vault's is refused.
    let mut input = c1.input();
    input["rev"] = json!("1");
    input["manifest"] = h(&manifest_cbor(1, 2, &[method(1, 0x70, 1, &[])], &[]));
    cases.push(invalid_case(
        "item/manifest_seal_invalid/epoch_mismatch",
        "the manifest says epoch 2 and the vault is at epoch 1",
        "item.manifest.seal",
        vec![],
        input,
        "malformed_item_body",
    ));
    let base = &sealed[0];
    let k = base.ctx.keys()?;
    let mut bad = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("item/manifest_invalid/{name}"),
            title,
            "item.manifest.open",
            vec![],
            input,
            code,
        ));
    };
    let env_flip = |at: usize| {
        let mut e = base.envelope.clone();
        e[at] ^= 1;
        e
    };
    for (name, at) in [
        ("nonce", 3usize),
        ("ciphertext", 60),
        ("tag", base.envelope.len() - 1),
    ] {
        bad(
            &format!("flip_{name}"),
            &format!("one bit changed in the {name}"),
            manifest_open_input(&base.ctx, base.rev, &env_flip(at), &base.tag),
            "decrypt",
        );
    }
    let mut tag = base.tag;
    tag[0] ^= 1;
    bad(
        "tag",
        "the tag changed",
        manifest_open_input(&base.ctx, base.rev, &base.envelope, &tag),
        "decrypt",
    );
    bad(
        "wrong_rev_old_tag",
        "another revision, the old tag",
        manifest_open_input(&base.ctx, base.rev + 1, &base.envelope, &base.tag),
        "decrypt",
    );
    bad(
        "wrong_rev_retagged",
        "another revision with a tag made for it: only the AAD refuses",
        manifest_open_input(
            &base.ctx,
            base.rev + 1,
            &base.envelope,
            &item_tag(&k.k_head, &[0; 16], base.rev + 1, &base.envelope)?,
        ),
        "decrypt",
    );
    let mut ctx = base.ctx;
    ctx.vk[0] ^= 1;
    bad(
        "wrong_vault_key",
        "another vault key",
        manifest_open_input(&ctx, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    let mut ctx = base.ctx;
    ctx.vault[0] ^= 1;
    bad(
        "wrong_vault_id",
        "another vault id",
        manifest_open_input(&ctx, base.rev, &base.envelope, &base.tag),
        "decrypt",
    );
    let mut as_item = base.envelope.clone();
    as_item[2] = 1;
    bad(
        "kind_item",
        "the header says item: a manifest has no ik_wrap",
        manifest_open_input(&base.ctx, base.rev, &as_item, &base.tag),
        "decrypt",
    );
    bad(
        "version_2",
        "the header says version 2",
        manifest_open_input(
            &base.ctx,
            base.rev,
            &{
                let mut e = base.envelope.clone();
                e[0] = 2;
                e
            },
            &base.tag,
        ),
        "decrypt",
    );
    // A manifest that is authentic and has the wrong shape.
    let v2 = seal_manifest("item/manifest/v2", &c1, 1, &manifest_cbor(2, 1, &[], &[]))?;
    bad(
        "v_2",
        "an authentic manifest with v = 2",
        manifest_open_input(&v2.ctx, v2.rev, &v2.envelope, &v2.tag),
        "unsupported",
    );
    // The manifest says epoch 2, the key that seals it is epoch 1.
    let wrong_epoch = seal_manifest(
        "item/manifest/wrong_epoch",
        &c1,
        1,
        &manifest_cbor(1, 2, &[method(1, 0x70, 1, &[])], &[]),
    )?;
    bad(
        "epoch_mismatch",
        "an authentic manifest for another epoch than its key",
        manifest_open_input(
            &wrong_epoch.ctx,
            wrong_epoch.rev,
            &wrong_epoch.envelope,
            &wrong_epoch.tag,
        ),
        "decrypt",
    );
    let short_id = seal_manifest(
        "item/manifest/short_id",
        &c1,
        1,
        &manifest_cbor(
            1,
            1,
            &[cb::map(&[
                ("t", cb::uint(1)),
                ("id", cb::bytes(&[1; 15])),
                ("g", cb::uint(1)),
            ])],
            &[],
        ),
    )?;
    bad(
        "id_15_bytes",
        "an authentic manifest with a 15-byte method id",
        manifest_open_input(
            &short_id.ctx,
            short_id.rev,
            &short_id.envelope,
            &short_id.tag,
        ),
        "malformed_item_body",
    );
    let big_t = seal_manifest(
        "item/manifest/big_type",
        &c1,
        1,
        &manifest_cbor(
            1,
            1,
            &[cb::map(&[
                ("t", cb::uint(300)),
                ("id", cb::bytes(&[1; 16])),
                ("g", cb::uint(1)),
            ])],
            &[],
        ),
    )?;
    bad(
        "type_300",
        "an authentic manifest with method type 300",
        manifest_open_input(&big_t.ctx, big_t.rev, &big_t.envelope, &big_t.tag),
        "malformed_item_body",
    );
    Ok(())
}
