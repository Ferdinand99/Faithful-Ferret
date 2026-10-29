//! The encrypted export file (Fase 1 § 6.4, F-27) and the plaintext JSON and
//! CSV exports, and `vectors/internal/export.json`.
//!
//! Most tests use Argon2id parameters far below the floor through the
//! `test-support` functions; the ones that name the floor, the ceiling or the
//! production parameters use the production functions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::{self, Value};
use ferret_core::testing::export::{
    export_encrypt_unchecked, import_decrypt_unchecked, intermediate_unchecked,
};
use ferret_core::testing::prim::{
    aead_open, aead_seal, argon2_run_count, argon2id_unchecked, hkdf_sha256,
};
use ferret_core::testing::text::export_password_bytes;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    EXPORT_KDF, Error, ExportItem, ExportPassword, Field, FieldKind, InputError, ItemBody, ItemId,
    ItemType, KDF_CEIL, KDF_FLOOR, KdfParams, MalformedKind, MasterPassword, MpPolicy, Passkey,
    PlainExportOptions, Totp, UrlEntry, UrlMatch, check_kdf_params, export_encrypt,
    export_plain_csv, export_plain_json, import_decrypt, parse_export_header,
};
use serde_json::json;

const PASSWORD: &str = "correct horse battery";
/// A few KiB: far below the floor, so that tests run in milliseconds.
const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const NOW: u64 = 1_700_000_000_000;

fn pw() -> ExportPassword {
    ExportPassword::for_open(PASSWORD.as_bytes()).unwrap()
}

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn login(name: &str) -> ItemBody {
    let mut b = ItemBody::new(ItemType::Login, name, NOW);
    b.fields = vec![
        Field {
            id: "user".into(),
            label: "Username".into(),
            kind: FieldKind::Text,
            value: "alice".into(),
            extra: vec![("future_field".into(), Value::uint(7))],
        },
        Field {
            id: "pass".into(),
            label: "Password".into(),
            kind: FieldKind::Password,
            value: "hunter2,\"x\"".into(),
            extra: vec![],
        },
    ];
    b.urls = vec![UrlEntry {
        url: "https://example.com".into(),
        matching: UrlMatch::Domain,
        extra: vec![],
    }];
    b.totp = Some(Totp {
        uri: "otpauth://totp/x?secret=ABC".into(),
        extra: vec![],
    });
    b.notes = Some("line 1\nline 2".into());
    b.extra = vec![
        ("zeta".into(), Value::text("unknown, kept")),
        (
            "alpha".into(),
            Value::Array(vec![Value::Float(1.5f64.to_bits()), Value::Null]),
        ),
    ];
    b
}

fn passkey_body() -> ItemBody {
    let mut b = ItemBody::new(ItemType::Login, "Passkey site", NOW);
    b.passkey = Some(Passkey {
        cred_id: vec![0xc1; 32],
        rp_id: "example.com".into(),
        user_handle: vec![0xd2; 16],
        user_name: "alice".into(),
        private_key: vec![0xe3; 40],
        sign_count: 0,
        created: NOW,
        prf_seed_uv: Some(vec![0xf4; 32]),
        prf_seed_nouv: Some(vec![0xf5; 32]),
        extra: vec![("aaguid".into(), Value::Bytes(vec![1, 2, 3]))],
    });
    b
}

fn items() -> Vec<ExportItem> {
    vec![
        ExportItem {
            item_id: item_id(0x01),
            body: login("Example"),
        },
        ExportItem {
            item_id: item_id(0x02),
            body: passkey_body(),
        },
        ExportItem {
            item_id: item_id(0x03),
            body: ItemBody::new(ItemType::Note, "Empty note", NOW),
        },
    ]
}

fn small_file() -> Vec<u8> {
    export_encrypt_unchecked(&mut rng("export"), &pw(), SMALL, NOW, &items()).unwrap()
}

fn header_len(file: &[u8]) -> usize {
    parse_export_header(file).unwrap().1
}

/// A file whose header is replaced by `header` (the rest unchanged).
fn with_header(file: &[u8], header: &[u8]) -> Vec<u8> {
    let mut out = header.to_vec();
    out.extend_from_slice(&file[header_len(file)..]);
    out
}

/// A header made by hand with literal key names, in the given order.
fn header_value(m: Value, t: Value, p: Value, salt: &[u8]) -> Value {
    Value::Map(vec![
        ("v".into(), Value::uint(1)),
        ("suite".into(), Value::uint(1)),
        (
            "kdf".into(),
            Value::Map(vec![
                ("salt".into(), Value::Bytes(salt.to_vec())),
                ("m".into(), m),
                ("t".into(), t),
                ("p".into(), p),
            ]),
        ),
        ("created_at".into(), Value::uint(NOW)),
    ])
}

fn header_with_params(file: &[u8], m: u64, t: u64, p: u64) -> Vec<u8> {
    let (h, _) = parse_export_header(file).unwrap();
    let v = header_value(Value::uint(m), Value::uint(t), Value::uint(p), &h.salt);
    with_header(file, &cbor::encode(&v).unwrap())
}

/// Opens `file` with the key chain of the test password, and seals `plain`
/// as the body instead, under the same header: an authentic body with
/// whatever contents a test needs.
fn reseal_body(file: &[u8], plain: &[u8]) -> Vec<u8> {
    let used = header_len(file);
    let im = intermediate_unchecked(&pw(), file).unwrap();
    let ek_wrap = &file[used..used + 72];
    let ek: [u8; 32] = aead_open(&im.k_exp, &im.aad_ek, ek_wrap)
        .unwrap()
        .try_into()
        .unwrap();
    let body = aead_seal(&mut rng("reseal"), &ek, &im.aad_body, plain).unwrap();
    let mut out = file[..used + 72].to_vec();
    out.extend_from_slice(&body);
    out
}

fn text_map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(entries.into_iter().map(|(k, v)| (k.into(), v)).collect())
}

fn body_cbor(id: Vec<u8>, body: &ItemBody) -> Vec<u8> {
    cbor::encode(&text_map(vec![
        ("v", Value::uint(1)),
        (
            "items",
            Value::Array(vec![text_map(vec![
                ("id", Value::Bytes(id)),
                ("body", body.to_value()),
            ])]),
        ),
    ]))
    .unwrap()
}

// ---------------------------------------------------------------- roundtrip

#[test]
fn export_roundtrip() {
    let items = items();
    let file = small_file();
    let back = import_decrypt_unchecked(&pw(), &file).unwrap();
    assert_eq!(back, items);
    // The unknown fields (at three levels) and the passkey survived.
    assert_eq!(back[0].body.extra[0].0, "zeta");
    assert_eq!(back[0].body.fields[0].extra[0].0, "future_field");
    assert_eq!(back[1].body.passkey.as_ref().unwrap().private_key.len(), 40);
    assert_eq!(back[1].body.passkey.as_ref().unwrap().extra[0].0, "aaguid");
    // Layout: header ‖ ek_wrap (72) ‖ body (nonce, ciphertext, tag).
    let used = header_len(&file);
    assert!(file.len() > used + 72 + 40);
}

#[test]
fn export_roundtrip_at_the_floor_with_production_functions() {
    // The production functions, at the lowest parameters they accept.
    let items = items();
    let file = export_encrypt(&mut rng("floor"), &pw(), KDF_FLOOR, NOW, &items).unwrap();
    assert_eq!(import_decrypt(&pw(), &file).unwrap(), items);
    // The test-support path computes the same Argon2id (no secret, no data).
    let same = export_encrypt_unchecked(&mut rng("floor"), &pw(), KDF_FLOOR, NOW, &items).unwrap();
    assert_eq!(file, same);
}

#[test]
fn export_empty_list_roundtrips() {
    let file = export_encrypt_unchecked(&mut rng("e"), &pw(), SMALL, NOW, &[]).unwrap();
    assert!(import_decrypt_unchecked(&pw(), &file).unwrap().is_empty());
}

#[test]
fn export_draws_salt_ek_and_two_nonces_in_that_order() {
    let draws = vec![vec![1u8; 16], vec![2u8; 32], vec![3u8; 24], vec![4u8; 24]];
    let mut replay = ReplayRng::new(draws);
    let file = export_encrypt_unchecked(&mut replay, &pw(), SMALL, NOW, &items()).unwrap();
    replay.finish().unwrap();
    let (h, used) = parse_export_header(&file).unwrap();
    assert_eq!(h.salt, [1u8; 16]);
    assert_eq!(&file[used..used + 24], &[3u8; 24]);
    let body_nonce_at = used + 72;
    assert_eq!(&file[body_nonce_at..body_nonce_at + 24], &[4u8; 24]);
}

#[test]
fn export_default_params_are_256mib_t3_p1() {
    assert_eq!(
        EXPORT_KDF,
        KdfParams {
            m_kib: 256 * 1024,
            t: 3,
            p: 1
        }
    );
    assert_eq!(check_kdf_params(EXPORT_KDF), Ok(EXPORT_KDF));
    // Above the login floor and below the import ceiling (512 MiB).
    assert_eq!(
        EXPORT_KDF.m_kib.cmp(&KDF_FLOOR.m_kib),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        EXPORT_KDF.m_kib.cmp(&KDF_CEIL.m_kib),
        std::cmp::Ordering::Less
    );
    assert_eq!(KDF_CEIL.m_kib, 512 * 1024);
}

#[test]
fn export_password_equal_to_master_is_refused() {
    let mp = MasterPassword::new(PASSWORD.as_bytes(), MpPolicy::WithSecretKey).unwrap();
    assert_eq!(
        ExportPassword::new(PASSWORD.as_bytes(), Some(&mp)).err(),
        Some(Error::InvalidInput(InputError::SameAsMasterPassword))
    );
    // Another password is fine, and a short one is refused when creating.
    assert!(ExportPassword::new(b"another password!", Some(&mp)).is_ok());
    assert_eq!(
        ExportPassword::new(b"short", None).err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
    // ... but not when opening a file.
    assert!(ExportPassword::for_open(b"short").is_ok());
}

#[test]
fn export_password_is_normalized() {
    // "é" composed and decomposed give the same key.
    let a = ExportPassword::new("caf\u{e9} au lait ok".as_bytes(), None).unwrap();
    let b = ExportPassword::for_open("cafe\u{301} au lait ok".as_bytes()).unwrap();
    let file = export_encrypt_unchecked(&mut rng("n"), &a, SMALL, NOW, &items()).unwrap();
    assert_eq!(import_decrypt_unchecked(&b, &file).unwrap(), items());
}

// ------------------------------------------------------------------ header

#[test]
fn export_header_parse_reports_consumed_length() {
    let file = small_file();
    let (h, used) = parse_export_header(&file).unwrap();
    assert_eq!(h.kdf, SMALL);
    assert_eq!(h.created_at, NOW);
    // The decoder stops at the end of the header element: whatever follows
    // does not matter.
    let mut longer = file.clone();
    longer.extend_from_slice(&[0xff; 100]);
    assert_eq!(parse_export_header(&longer).unwrap(), (h, used));
    assert_eq!(parse_export_header(&file[..used]).unwrap(), (h, used));
    // The header as written: v, suite, kdf { salt m t p }, created_at.
    let mut expect = vec![0xa4, 0x61, b'v', 0x01, 0x65];
    expect.extend_from_slice(b"suite");
    expect.push(0x01);
    expect.extend_from_slice(&[0x63, b'k', b'd', b'f', 0xa4, 0x64]);
    expect.extend_from_slice(b"salt");
    expect.extend_from_slice(&[0x50]);
    assert_eq!(&file[..expect.len()], &expect[..]);
    let after_salt = expect.len() + 16;
    assert_eq!(
        &file[after_salt..after_salt + 11],
        &[
            0x61, b'm', 0x18, 0x40, 0x61, b't', 0x01, 0x61, b'p', 0x01, 0x6a
        ]
    );
}

#[test]
fn export_header_bytes_are_aad_verbatim() {
    let file = small_file();
    let (h, used) = parse_export_header(&file).unwrap();
    // The same header, the map entries in another order: the same meaning
    // and the same length, but other bytes.
    let reordered = text_map(vec![
        ("created_at", Value::uint(NOW)),
        ("v", Value::uint(1)),
        (
            "kdf",
            text_map(vec![
                ("p", Value::uint(1)),
                ("t", Value::uint(1)),
                ("m", Value::uint(64)),
                ("salt", Value::Bytes(h.salt.to_vec())),
            ]),
        ),
        ("suite", Value::uint(1)),
    ]);
    let other = cbor::encode(&reordered).unwrap();
    assert_eq!(other.len(), used);
    assert_ne!(other, &file[..used]);
    let moved = with_header(&file, &other);
    // It parses to the same header ...
    assert_eq!(parse_export_header(&moved).unwrap(), (h, used));
    // ... and does not open: the AAD is the bytes as they stand.
    assert_eq!(import_decrypt_unchecked(&pw(), &moved), Err(Error::Decrypt));

    // A longer, equally valid integer head for `v` (`18 01` instead of `01`):
    // another encoding of the same value, another length, another AAD.
    let mut longer = file[..3].to_vec();
    longer.extend_from_slice(&[0x18, 0x01]);
    longer.extend_from_slice(&file[4..used]);
    let moved = with_header(&file, &longer);
    assert_eq!(parse_export_header(&moved).unwrap().0, h);
    assert_eq!(import_decrypt_unchecked(&pw(), &moved), Err(Error::Decrypt));
}

#[test]
fn export_header_must_have_exactly_the_known_shape() {
    let file = small_file();
    let (h, _) = parse_export_header(&file).unwrap();
    let ok = |v: &Value| {
        let f = with_header(&file, &cbor::encode(v).unwrap());
        parse_export_header(&f).map(|(h, _)| h)
    };
    let bad = Err(Error::Malformed(MalformedKind::ExportHeader));
    let good = |m: u64| header_value(Value::uint(m), Value::uint(1), Value::uint(1), &h.salt);
    assert!(ok(&good(64)).is_ok());

    // An unknown key at the top or in `kdf`.
    let mut v = good(64);
    if let Value::Map(e) = &mut v {
        e.push(("extra".into(), Value::Null));
    }
    assert_eq!(ok(&v), bad);
    let mut v = good(64);
    if let Value::Map(e) = &mut v
        && let Value::Map(k) = &mut e[2].1
    {
        k.push(("x".into(), Value::Null));
    }
    assert_eq!(ok(&v), bad);
    // A missing key.
    let mut v = good(64);
    if let Value::Map(e) = &mut v {
        e.pop();
    }
    assert_eq!(ok(&v), bad);
    // A salt of the wrong length, a text for m, not a map.
    for salt_len in [0usize, 8, 15, 17, 32] {
        let v = header_value(
            Value::uint(64),
            Value::uint(1),
            Value::uint(1),
            &vec![7; salt_len],
        );
        assert_eq!(ok(&v), bad, "salt of {salt_len} bytes");
    }
    let v = header_value(Value::text("64"), Value::uint(1), Value::uint(1), &h.salt);
    assert_eq!(ok(&v), bad);
    assert_eq!(ok(&Value::Array(vec![])), bad);
    // Not CBOR at all, and empty.
    assert_eq!(parse_export_header(&[]).map(|(h, _)| h), bad);
    assert_eq!(parse_export_header(&[0xff, 0xff]).map(|(h, _)| h), bad);
    // Another version or suite is unsupported, not malformed.
    for (v, suite) in [(2u64, 1u64), (0, 1), (1, 2), (1, 0)] {
        let mut value = good(64);
        if let Value::Map(e) = &mut value {
            e[0].1 = Value::uint(v);
            e[1].1 = Value::uint(suite);
        }
        assert_eq!(ok(&value), Err(Error::Unsupported));
    }
}

// ------------------------------------------------------------ KDF bounds

#[test]
fn export_rejects_params_below_floor_before_argon() {
    let file = small_file();
    for (m, t, p) in [
        (32_768u64, 3u64, 1u64),
        (65_535, 3, 1),
        (65_536, 2, 1),
        (65_536, 0, 1),
        (65_536, 3, 0),
        (0, 0, 0),
    ] {
        let f = header_with_params(&file, m, t, p);
        let before = argon2_run_count();
        assert_eq!(
            import_decrypt(&pw(), &f),
            Err(Error::KdfOutOfRange),
            "{m} {t} {p}"
        );
        assert_eq!(argon2_run_count(), before, "no Argon2 run for {m} {t} {p}");
    }
    // The same on the way out: nothing is drawn and nothing is computed.
    let before = argon2_run_count();
    let mut none = ReplayRng::new(vec![]);
    assert_eq!(
        export_encrypt(
            &mut none,
            &pw(),
            KdfParams {
                m_kib: 32_768,
                t: 3,
                p: 1
            },
            NOW,
            &items()
        ),
        Err(Error::KdfOutOfRange)
    );
    none.finish().unwrap();
    assert_eq!(argon2_run_count(), before);
}

#[test]
fn export_rejects_params_above_ceil() {
    let file = small_file();
    for (m, t, p) in [
        (524_289u64, 3u64, 1u64),
        (1_048_576, 3, 1),
        (65_536, 17, 1),
        (65_536, 3, 5),
        (u64::from(u32::MAX), 3, 1),
        (u64::from(u32::MAX) + 1, 3, 1),
        (u64::MAX, u64::MAX, u64::MAX),
    ] {
        let f = header_with_params(&file, m, t, p);
        let before = argon2_run_count();
        assert_eq!(
            import_decrypt(&pw(), &f),
            Err(Error::KdfOutOfRange),
            "{m} {t} {p}"
        );
        assert_eq!(argon2_run_count(), before, "no Argon2 run for {m} {t} {p}");
    }
    // A negative integer is not a size either.
    let (h, _) = parse_export_header(&file).unwrap();
    let v = header_value(Value::int(-1), Value::uint(1), Value::uint(1), &h.salt);
    let f = with_header(&file, &cbor::encode(&v).unwrap());
    assert_eq!(import_decrypt(&pw(), &f), Err(Error::KdfOutOfRange));
    // Exactly the ceiling passes the check (and then fails to open: the file
    // was not made with it). The run is not started here: a 512 MiB x 16
    // pass x 4 lane Argon2 would only prove the same slowly. The bounds are
    // checked on their own.
    assert_eq!(check_kdf_params(KDF_CEIL), Ok(KDF_CEIL));
}

#[test]
fn export_checks_size_of_body_before_argon() {
    let file = small_file();
    // The floor parameters pass the check; the body is one byte too long.
    let mut f = header_with_params(&file, 65_536, 3, 1);
    f.truncate(header_len(&f) + 72);
    f.resize(f.len() + 128 * 1024 * 1024 + 1, 0);
    let before = argon2_run_count();
    assert_eq!(import_decrypt(&pw(), &f), Err(Error::TooLarge));
    assert_eq!(argon2_run_count(), before);
}

// ------------------------------------------------------------- tampering

#[test]
fn export_tamper_each_region() {
    let file = small_file();
    let used = header_len(&file);
    let (h, _) = parse_export_header(&file).unwrap();
    let flip = |at: usize| {
        let mut f = file.clone();
        f[at] ^= 0x01;
        f
    };

    // Every byte of the file: no change opens.
    for at in 0..file.len() {
        assert!(
            import_decrypt_unchecked(&pw(), &flip(at)).is_err(),
            "byte {at} changed but the file opened"
        );
    }
    // The values in the header (salt, parameters, date) are authenticated
    // and read as valid: a change is `Decrypt`.
    let salt_at = file
        .windows(16)
        .position(|w| w == h.salt)
        .expect("salt in the header");
    for at in [salt_at, salt_at + 15, used - 1, used - 3] {
        assert_eq!(
            import_decrypt_unchecked(&pw(), &flip(at)),
            Err(Error::Decrypt),
            "header byte {at}"
        );
    }
    // Every byte of ek_wrap and of the body is `Decrypt`.
    for at in used..file.len() {
        assert_eq!(
            import_decrypt_unchecked(&pw(), &flip(at)),
            Err(Error::Decrypt),
            "byte {at}"
        );
    }
    // A byte added or removed at the end is authenticated too.
    let mut longer = file.clone();
    longer.push(0);
    assert_eq!(
        import_decrypt_unchecked(&pw(), &longer),
        Err(Error::Decrypt)
    );
    assert_eq!(
        import_decrypt_unchecked(&pw(), &file[..file.len() - 1]),
        Err(Error::Decrypt)
    );
}

#[test]
fn export_truncated_file_is_malformed() {
    let file = small_file();
    let used = header_len(&file);
    let malformed = Err(Error::Malformed(MalformedKind::ExportHeader));
    // Inside the header, at its end, inside ek_wrap, with no body, and with
    // a body too short to hold a nonce and a tag.
    for len in [
        0,
        1,
        used / 2,
        used - 1,
        used,
        used + 1,
        used + 71,
        used + 72,
    ] {
        assert_eq!(
            import_decrypt_unchecked(&pw(), &file[..len]),
            malformed,
            "length {len}"
        );
    }
    for len in [used + 72 + 1, used + 72 + 39] {
        assert_eq!(
            import_decrypt_unchecked(&pw(), &file[..len]),
            malformed,
            "length {len}"
        );
    }
    // 40 bytes of body is the shortest that reaches the AEAD.
    assert_eq!(
        import_decrypt_unchecked(&pw(), &file[..used + 72 + 40]),
        Err(Error::Decrypt)
    );
}

#[test]
fn export_wrong_password_is_decrypt_error() {
    let file = small_file();
    for wrong in ["correct horse batterY", "correct horse battery ", "x"] {
        let w = ExportPassword::for_open(wrong.as_bytes()).unwrap();
        assert_eq!(import_decrypt_unchecked(&w, &file), Err(Error::Decrypt));
    }
    // The right password for another file does not open this one.
    let other =
        export_encrypt_unchecked(&mut rng("other"), &pw(), SMALL, NOW + 1, &items()).unwrap();
    let mut swapped = other[..header_len(&other) + 72].to_vec();
    swapped.extend_from_slice(&file[header_len(&file) + 72..]);
    assert_eq!(
        import_decrypt_unchecked(&pw(), &swapped),
        Err(Error::Decrypt)
    );
}

#[test]
fn export_ek_wrap_and_body_are_bound_to_the_header() {
    // Two files with the same password differ in salt and header; moving the
    // header of one onto the rest of the other never opens, even though both
    // are well formed.
    let a = export_encrypt_unchecked(&mut rng("a"), &pw(), SMALL, NOW, &items()).unwrap();
    let b = export_encrypt_unchecked(&mut rng("b"), &pw(), SMALL, NOW, &items()).unwrap();
    let hb = b[..header_len(&b)].to_vec();
    assert_eq!(
        import_decrypt_unchecked(&pw(), &with_header(&a, &hb)),
        Err(Error::Decrypt)
    );
    // A header with other parameters but the same salt: same key chain
    // input except for the parameters, which are in the AAD and in Argon2.
    let f = header_with_params(&a, 65, 1, 1);
    assert_eq!(import_decrypt_unchecked(&pw(), &f), Err(Error::Decrypt));
}

// ------------------------------------------------ formulas against the spec

#[test]
fn export_key_chain_matches_the_specification() {
    let file = small_file();
    let used = header_len(&file);
    let header = &file[..used];
    let (h, _) = parse_export_header(&file).unwrap();
    let im = intermediate_unchecked(&pw(), &file).unwrap();

    // aad = TLV[label, header] written out by hand.
    let aad_ek = [t(0x01, b"ferret/v1/export/ek"), t(0x39, header)].concat();
    let aad_body = [t(0x01, b"ferret/v1/export/body"), t(0x39, header)].concat();
    assert_eq!(im.aad_ek, aad_ek);
    assert_eq!(im.aad_body, aad_body);
    assert_eq!(im.header, header);

    // K_exp = HKDF(salt = TLV[label], ikm = Argon2id(pw, salt, m, t, p, 32),
    //              info = "ferret/v1/export/key")
    let mut stretched = [0u8; 32];
    argon2id_unchecked(
        &export_password_bytes(&pw()),
        &h.salt,
        &[],
        &[],
        h.kdf,
        &mut stretched,
    )
    .unwrap();
    let mut k_exp = [0u8; 32];
    hkdf_sha256(
        &label("ferret/v1/export"),
        &stretched,
        b"ferret/v1/export/key",
        &mut k_exp,
    )
    .unwrap();
    assert_eq!(im.k_exp, k_exp);

    // ek_wrap = AEAD(K_exp, nonce, EK, aad_ek) is 72 bytes and opens to a
    // 32-byte key that opens the body under aad_body.
    let ek_wrap = &file[used..used + 72];
    let ek = aead_open(&k_exp, &aad_ek, ek_wrap).unwrap();
    assert_eq!(ek.len(), 32);
    let ek: [u8; 32] = ek.try_into().unwrap();
    let body = aead_open(&ek, &aad_body, &file[used + 72..]).unwrap();
    let decoded = cbor::decode(&body).unwrap();
    assert_eq!(decoded.get("v"), Some(&Value::uint(1)));
    match decoded.get("items") {
        Some(Value::Array(a)) => assert_eq!(a.len(), 3),
        other => panic!("items: {other:?}"),
    }
    // Each AAD works only for its own part.
    assert!(aead_open(&k_exp, &aad_body, ek_wrap).is_err());
    assert!(aead_open(&ek, &aad_ek, &file[used + 72..]).is_err());
}

// --------------------------------------------------- authentic but invalid

#[test]
fn import_rejects_authentic_bodies_of_the_wrong_shape() {
    let file = small_file();
    let b = login("x");
    let good_id = vec![9u8; 16];
    let m = |e: Vec<(&str, Value)>| cbor::encode(&text_map(e)).unwrap();
    let one = |id: Vec<u8>| {
        Value::Array(vec![text_map(vec![
            ("id", Value::Bytes(id)),
            ("body", b.to_value()),
        ])])
    };

    // The good one opens.
    let f = reseal_body(&file, &body_cbor(good_id.clone(), &b));
    assert_eq!(import_decrypt_unchecked(&pw(), &f).unwrap().len(), 1);

    let cases: Vec<(&str, Vec<u8>, Error)> = vec![
        (
            "another version",
            m(vec![("v", Value::uint(2)), ("items", Value::Array(vec![]))]),
            Error::Unsupported,
        ),
        (
            "unknown key at the top",
            m(vec![
                ("v", Value::uint(1)),
                ("items", Value::Array(vec![])),
                ("more", Value::Null),
            ]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "no items",
            m(vec![("v", Value::uint(1))]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "items not an array",
            m(vec![("v", Value::uint(1)), ("items", Value::Null)]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "id of 15 bytes",
            m(vec![("v", Value::uint(1)), ("items", one(vec![9; 15]))]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "the reserved manifest id",
            m(vec![("v", Value::uint(1)), ("items", one(vec![0; 16]))]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "unknown key in an item entry",
            m(vec![
                ("v", Value::uint(1)),
                (
                    "items",
                    Value::Array(vec![text_map(vec![
                        ("id", Value::Bytes(vec![9; 16])),
                        ("body", b.to_value()),
                        ("rev", Value::uint(3)),
                    ])]),
                ),
            ]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "body without a name",
            m(vec![
                ("v", Value::uint(1)),
                (
                    "items",
                    Value::Array(vec![text_map(vec![
                        ("id", Value::Bytes(vec![9; 16])),
                        ("body", text_map(vec![("schema", Value::uint(1))])),
                    ])]),
                ),
            ]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "the same id twice",
            m(vec![
                ("v", Value::uint(1)),
                (
                    "items",
                    Value::Array(vec![
                        text_map(vec![
                            ("id", Value::Bytes(vec![9; 16])),
                            ("body", b.to_value()),
                        ]),
                        text_map(vec![
                            ("id", Value::Bytes(vec![9; 16])),
                            ("body", b.to_value()),
                        ]),
                    ]),
                ),
            ]),
            Error::Malformed(MalformedKind::ItemBody),
        ),
        (
            "trailing bytes after the CBOR",
            [body_cbor(good_id.clone(), &b), vec![0]].concat(),
            Error::Malformed(MalformedKind::CborTrailing),
        ),
        (
            "not CBOR",
            vec![0xff],
            Error::Malformed(MalformedKind::Cbor),
        ),
    ];
    for (name, plain, want) in cases {
        let f = reseal_body(&file, &plain);
        assert_eq!(import_decrypt_unchecked(&pw(), &f), Err(want), "{name}");
    }
}

#[test]
fn import_keeps_a_body_with_a_newer_schema_read_only() {
    // A file from a later release may hold a body with schema 2: it is
    // read, flagged read-only, and cannot be exported again.
    let file = small_file();
    let mut v = login("future").to_value();
    if let Value::Map(e) = &mut v {
        e[0].1 = Value::uint(2);
    }
    let plain = cbor::encode(&text_map(vec![
        ("v", Value::uint(1)),
        (
            "items",
            Value::Array(vec![text_map(vec![
                ("id", Value::Bytes(vec![9; 16])),
                ("body", v),
            ])]),
        ),
    ]))
    .unwrap();
    let f = reseal_body(&file, &plain);
    let back = import_decrypt_unchecked(&pw(), &f).unwrap();
    assert!(back[0].body.is_read_only());
    assert_eq!(
        export_encrypt_unchecked(&mut rng("ro"), &pw(), SMALL, NOW, &back),
        Err(Error::ReadOnlySchema)
    );
}

#[test]
fn export_refuses_items_that_cannot_be_written() {
    let mut none = ReplayRng::new(vec![]);
    let run = |items: &[ExportItem], none: &mut ReplayRng| {
        export_encrypt_unchecked(none, &pw(), SMALL, NOW, items)
    };
    // The manifest id, a repeated id.
    let manifest = ExportItem {
        item_id: ItemId::MANIFEST,
        body: login("m"),
    };
    assert_eq!(
        run(&[manifest], &mut none),
        Err(Error::Malformed(MalformedKind::ItemBody))
    );
    let twice = vec![items()[0].clone(), items()[0].clone()];
    assert_eq!(
        run(&twice, &mut none),
        Err(Error::Malformed(MalformedKind::ItemBody))
    );
    // A body that is read-only.
    let decoded = {
        let mut v = login("f").to_value();
        if let Value::Map(e) = &mut v {
            e[0].1 = Value::uint(2);
        }
        ItemBody::from_value(v).unwrap()
    };
    let ro = ExportItem {
        item_id: item_id(5),
        body: decoded.body,
    };
    assert_eq!(run(&[ro], &mut none), Err(Error::ReadOnlySchema));
    // More items than a CBOR array may hold.
    let many: Vec<ExportItem> = (0..10_001u32)
        .map(|i| {
            let mut id = [1u8; 16];
            id[..4].copy_from_slice(&i.to_be_bytes());
            ExportItem {
                item_id: ItemId::from_bytes(id),
                body: ItemBody::new(ItemType::Note, "n", NOW),
            }
        })
        .collect();
    assert_eq!(run(&many, &mut none), Err(Error::TooLarge));
    // Nothing was drawn for any of them.
    none.finish().unwrap();
}

// ----------------------------------------------------------------- plain

fn sample_for_plain() -> Vec<ExportItem> {
    let mut a = ItemBody::new(ItemType::Login, "=1+1", NOW);
    a.fields = vec![Field {
        id: "f".into(),
        label: "Note, with comma".into(),
        kind: FieldKind::Hidden,
        value: "say \"hi\"\nnext".into(),
        extra: vec![],
    }];
    a.urls = vec![
        UrlEntry {
            url: "https://a.example".into(),
            matching: UrlMatch::Host,
            extra: vec![],
        },
        UrlEntry {
            url: "https://b.example".into(),
            matching: UrlMatch::Host,
            extra: vec![],
        },
    ];
    a.favorite = true;
    vec![
        ExportItem {
            item_id: item_id(0xaa),
            body: a,
        },
        ExportItem {
            item_id: item_id(0xbb),
            body: passkey_body(),
        },
    ]
}

fn csv_of_one_name(name: &str) -> Vec<Vec<String>> {
    let item = ExportItem {
        item_id: item_id(1),
        body: ItemBody::new(ItemType::Note, name, NOW),
    };
    parse_csv(&export_plain_csv(&[item], &PlainExportOptions::default()).unwrap())
}

#[test]
fn plain_csv_neutralizes_formulas() {
    for bad in ["=1+1", "+x", "-x", "@x", "\tx", "\rx", "=", "-", "@SUM(A1)"] {
        let rows = csv_of_one_name(bad);
        assert_eq!(rows[1][2], format!("'{bad}"), "{bad:?}");
    }
    // Everything else is unchanged, also text that has these characters
    // elsewhere, a leading space, and an apostrophe.
    for fine in [
        "plain",
        "a=b",
        "x+y",
        "x-y",
        "a@b.c",
        " =x",
        "'x",
        "1+1",
        "",
        "0",
        "\u{ff1d}x",
        "é",
    ] {
        let rows = csv_of_one_name(fine);
        assert_eq!(rows[1][2], fine, "{fine:?}");
    }
}

#[test]
fn plain_csv_neutralizes_every_text_cell() {
    let mut b = ItemBody::new(ItemType::Other("=type".into()), "=name", NOW);
    b.urls = vec![UrlEntry {
        url: "@url".into(),
        matching: UrlMatch::Host,
        extra: vec![],
    }];
    b.notes = Some("+notes".into());
    b.totp = Some(Totp {
        uri: "-totp".into(),
        extra: vec![],
    });
    b.fields = vec![Field {
        id: "i".into(),
        label: "=label".into(),
        kind: FieldKind::Other("=kind".into()),
        value: "\tvalue".into(),
        extra: vec![],
    }];
    b.passkey = Some(Passkey {
        cred_id: vec![],
        rp_id: "=rp".into(),
        user_handle: vec![],
        user_name: "@user".into(),
        private_key: vec![],
        sign_count: 0,
        created: 0,
        prf_seed_uv: None,
        prf_seed_nouv: None,
        extra: vec![],
    });
    let item = ExportItem {
        item_id: item_id(1),
        body: b,
    };
    let rows = parse_csv(&export_plain_csv(&[item], &PlainExportOptions::default()).unwrap());
    assert_eq!(
        rows[1][1..],
        [
            "'=type",
            "'=name",
            "'@url",
            "'+notes",
            "'-totp",
            "false",
            "1700000000000",
            "1700000000000",
            "'=rp",
            "'@user",
            "'=label",
            "'=kind",
            "'\tvalue"
        ]
    );
}

#[test]
fn plain_csv_quotes_commas_quotes_newlines() {
    let items = sample_for_plain();
    let text = export_plain_csv(&items[..1], &PlainExportOptions::default()).unwrap();
    let header = "id,type,name,url,notes,totp,favorite,created,modified,passkey_rp_id,\
passkey_user_name,field_1_label,field_1_kind,field_1_value\r\n";
    let row = format!(
        "{},login,'=1+1,https://a.example https://b.example,,,true,1700000000000,1700000000000,,,\
\"Note, with comma\",hidden,\"say \"\"hi\"\"\nnext\"\r\n",
        "aa".repeat(16)
    );
    assert_eq!(text, format!("{header}{row}"));
    // It reads back as 2 rows of 14 cells.
    let rows = parse_csv(&text);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.len() == 14));
    assert_eq!(rows[1][13], "say \"hi\"\nnext");
}

#[test]
fn plain_csv_rows_have_the_width_of_the_header() {
    let rows =
        parse_csv(&export_plain_csv(&sample_for_plain(), &PlainExportOptions::default()).unwrap());
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|r| r.len() == 14), "{rows:?}");
    assert_eq!(rows[2][1], "login");
    assert_eq!(rows[2][9], "example.com");
    assert_eq!(rows[2][10], "alice");
    // No items: only the header.
    let none = export_plain_csv(&[], &PlainExportOptions::default()).unwrap();
    assert_eq!(parse_csv(&none).len(), 1);
}

#[test]
fn plain_csv_never_has_passkey_secrets() {
    for include in [false, true] {
        let o = PlainExportOptions {
            include_passkeys: include,
        };
        let text = export_plain_csv(&sample_for_plain(), &o).unwrap();
        for secret in [
            "e3".repeat(40),
            "f4".repeat(32),
            "f5".repeat(32),
            "c1".repeat(32),
        ] {
            assert!(!text.contains(&secret), "include={include}");
        }
    }
}

#[test]
fn plain_json_excludes_passkeys_by_default() {
    let text = export_plain_json(&sample_for_plain(), &PlainExportOptions::default()).unwrap();
    for secret in ["e3".repeat(40), "f4".repeat(32), "f5".repeat(32)] {
        assert!(!text.contains(&secret));
    }
    for key in ["\"priv\"", "\"prf_seed_uv\"", "\"prf_seed_nouv\""] {
        assert!(!text.contains(key));
    }
    // The public part of the passkey is there.
    assert!(text.contains("\"rp_id\":\"example.com\""));
    assert!(text.contains(&format!("\"cred_id\":\"{}\"", "c1".repeat(32))));
}

#[test]
fn plain_json_includes_them_only_when_asked() {
    let o = PlainExportOptions {
        include_passkeys: true,
    };
    let text = export_plain_json(&sample_for_plain(), &o).unwrap();
    assert!(text.contains(&format!("\"priv\":\"{}\"", "e3".repeat(40))));
    assert!(text.contains(&format!("\"prf_seed_uv\":\"{}\"", "f4".repeat(32))));
    assert!(text.contains(&format!("\"prf_seed_nouv\":\"{}\"", "f5".repeat(32))));
}

#[test]
fn plain_json_is_valid_json_with_the_export_structure() {
    let o = PlainExportOptions {
        include_passkeys: true,
    };
    let text = export_plain_json(&items(), &o).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["v"], json!(1));
    let list = v["items"].as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0]["id"], json!("01".repeat(16)));
    let body = &list[0]["body"];
    assert_eq!(body["schema"], json!(1));
    assert_eq!(body["type"], json!("login"));
    assert_eq!(body["fields"][1]["value"], json!("hunter2,\"x\""));
    assert_eq!(body["notes"], json!("line 1\nline 2"));
    // Unknown fields come out too, in order, after the known ones.
    assert_eq!(body["zeta"], json!("unknown, kept"));
    assert_eq!(body["alpha"], json!([1.5, null]));
    assert_eq!(body["fields"][0]["future_field"], json!(7));
    assert_eq!(list[1]["body"]["passkey"]["aaguid"], json!("010203"));
    // Compact, known keys in schema order.
    assert!(text.starts_with(&format!(
        "{{\"v\":1,\"items\":[{{\"id\":\"{}\",\"body\":{{\"schema\":1,\"type\":\"login\",\"name\":\"Example\",\"fields\":[",
        "01".repeat(16)
    )));
    // Empty list.
    assert_eq!(
        export_plain_json(&[], &PlainExportOptions::default()).unwrap(),
        "{\"v\":1,\"items\":[]}"
    );
}

#[test]
fn plain_json_escapes_strings_and_handles_floats() {
    let mut b = ItemBody::new(ItemType::Note, "q\"\\\u{1}\u{1f}\t\u{8}\u{c}é\u{2028}", NOW);
    b.extra = vec![
        ("nan".into(), Value::Float(f64::NAN.to_bits())),
        ("inf".into(), Value::Float(f64::INFINITY.to_bits())),
        ("f32".into(), Value::Float32(0.5f32.to_bits())),
        ("f16".into(), Value::Float16(0x3c00)),
        ("f16b".into(), Value::Float16(0xc000)),
        ("f16sub".into(), Value::Float16(0x0001)),
        ("f16inf".into(), Value::Float16(0x7c00)),
        ("neg".into(), Value::int(-5)),
        ("big".into(), Value::uint(u64::MAX)),
        ("flag".into(), Value::Bool(true)),
    ];
    let text = export_plain_json(
        &[ExportItem {
            item_id: item_id(1),
            body: b,
        }],
        &PlainExportOptions::default(),
    )
    .unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let body = &v["items"][0]["body"];
    assert_eq!(body["name"], json!("q\"\\\u{1}\u{1f}\t\u{8}\u{c}é\u{2028}"));
    assert!(text.contains("\\u0001\\u001f\\t\\b\\f"));
    assert_eq!(body["nan"], json!(null));
    assert_eq!(body["inf"], json!(null));
    assert_eq!(body["f32"].as_f64(), Some(0.5));
    assert_eq!(body["f16"].as_f64(), Some(1.0));
    assert_eq!(body["f16b"].as_f64(), Some(-2.0));
    assert!((body["f16sub"].as_f64().unwrap() - 2f64.powi(-24)).abs() < 1e-20);
    assert_eq!(body["f16inf"], json!(null));
    assert_eq!(body["neg"], json!(-5));
    assert_eq!(body["big"], json!(u64::MAX));
    assert_eq!(body["flag"], json!(true));
}

// ---------------------------------------------------------------- vectors

fn password_of(v: &serde_json::Value) -> ExportPassword {
    ExportPassword::for_open(v.as_str().unwrap().as_bytes()).unwrap()
}

fn input_items(v: &serde_json::Value) -> Vec<ExportItem> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|i| ExportItem {
            item_id: ItemId::from_bytes(id16(&i["id"])),
            body: ItemBody::from_cbor(&hex(&i["body"])).unwrap().body,
        })
        .collect()
}

fn output_items(items: &[ExportItem]) -> serde_json::Value {
    json!(
        items
            .iter()
            .map(|i| json!({
                "id": he(i.item_id.as_bytes()),
                "body": he(&i.body.to_cbor().unwrap()),
            }))
            .collect::<Vec<_>>()
    )
}

fn kdf_of(v: &serde_json::Value) -> KdfParams {
    KdfParams {
        m_kib: u32::try_from(v["m_kib"].as_u64().unwrap()).unwrap(),
        t: u32::try_from(v["t"].as_u64().unwrap()).unwrap(),
        p: u32::try_from(v["p"].as_u64().unwrap()).unwrap(),
    }
}

fn run_vectors(bindings_only: bool) -> ferret_core::testing::vector::RunReport {
    use ferret_core::testing::vector::Tag;
    let mut file = load_ops("export.json", |_| true);
    if bindings_only {
        // What a binding without `test-support` runs: no case that needs
        // parameters below the floor.
        file.cases.retain(|c| !c.tags.contains(&Tag::NativeOnly));
    }
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        // A case with `native-only` uses the unchecked functions; the rest
        // use the production ones.
        let unchecked = case.tags.contains(&Tag::NativeOnly);
        let input = &case.input;
        match case.op.as_str() {
            "export.encrypt" => {
                let pw = password_of(&input["password"]);
                let kdf = kdf_of(&input["kdf"]);
                let created = u64s(&input["created_at"]);
                let items = input_items(&input["items"]);
                let file = if unchecked {
                    export_encrypt_unchecked(rng, &pw, kdf, created, &items)?
                } else {
                    export_encrypt(rng, &pw, kdf, created, &items)?
                };
                let intermediate = if case.intermediate.is_some() {
                    let im = intermediate_unchecked(&pw, &file)?;
                    Some(json!({
                        "header": he(&im.header),
                        "k_exp": he(&im.k_exp),
                        "aad_ek": he(&im.aad_ek),
                        "aad_body": he(&im.aad_body),
                    }))
                } else {
                    None
                };
                Ok(Outcome {
                    output: json!({ "file": he(&file) }),
                    intermediate,
                })
            }
            "export.decrypt" => {
                let pw = password_of(&input["password"]);
                let file = hex(&input["file"]);
                let items = if unchecked {
                    import_decrypt_unchecked(&pw, &file)?
                } else {
                    import_decrypt(&pw, &file)?
                };
                let (h, _) = parse_export_header(&file)?;
                Ok(Outcome {
                    output: json!({
                        "created_at": h.created_at.to_string(),
                        "kdf": { "m_kib": h.kdf.m_kib, "t": h.kdf.t, "p": h.kdf.p },
                        "items": output_items(&items),
                    }),
                    intermediate: None,
                })
            }
            "export.header" => {
                let (h, used) = parse_export_header(&hex(&input["file"]))?;
                Ok(Outcome {
                    output: json!({
                        "created_at": h.created_at.to_string(),
                        "kdf": { "m_kib": h.kdf.m_kib, "t": h.kdf.t, "p": h.kdf.p },
                        "salt": he(&h.salt),
                        "header_len": used,
                    }),
                    intermediate: None,
                })
            }
            "export.plain.json" | "export.plain.csv" => {
                let items = input_items(&input["items"]);
                let o = PlainExportOptions {
                    include_passkeys: input["include_passkeys"].as_bool().unwrap(),
                };
                let text = if case.op == "export.plain.json" {
                    export_plain_json(&items, &o)?
                } else {
                    export_plain_csv(&items, &o)?
                };
                Ok(Outcome {
                    output: json!({ "text": text }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    })
}

#[test]
fn export_vectors_from_file() {
    // Every case, as the Rust runner does (the `native-only` ones through
    // the `test-support` functions).
    assert_all_passed(&run_vectors(false), 14);
}

#[test]
fn export_vectors_as_a_binding_runs_them() {
    // Only the cases that the production functions accept.
    assert_all_passed(&run_vectors(true), 8);
}
