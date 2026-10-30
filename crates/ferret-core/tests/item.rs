//! Items and the manifest: the envelope layout, the AADs, the tag, unknown
//! fields, read-only schemas, key reuse on edit, and
//! `vectors/internal/item.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::{self, Value};
use ferret_core::envelope::{IK_WRAP_LEN, KIND_ITEM, KIND_MANIFEST, MAX_ENVELOPE_LEN, VERSION};
use ferret_core::item::pad::MAX_PLAINTEXT;
use ferret_core::testing::item::{
    Sabotage, intermediate, open_plaintext, reseal, seal_manifest_padded_body,
    seal_manifest_plaintext, seal_padded, seal_plaintext, seal_with,
};
use ferret_core::testing::prim::{aead_open_count, hmac_sha256};
use ferret_core::testing::vector::{self, Outcome};
use ferret_core::testing::{ReplayRng, TestRng, hex_encode};
use ferret_core::{
    DecodedItem, Error, Field, FieldKind, ItemBody, ItemId, ItemType, MalformedKind, Manifest,
    ManifestEntry, MethodId, Passkey, SealedItem, Totp, UnlockedVault, UrlEntry, UrlMatch,
    VaultContext, VaultId, decrypt_item, decrypt_manifest, encrypt_item, encrypt_manifest,
    item_tag, parse_envelope, verify_item_tag,
};
use serde_json::{Value as Json, json};

fn item_id(b: u8) -> ItemId {
    ItemId::from_bytes([b; 16])
}

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn txt(s: &str) -> Value {
    Value::text(s)
}

/// A body with every part filled in and unknown keys at every level.
fn full_body() -> ItemBody {
    let mut body = ItemBody::new(ItemType::Login, "Example", 1_700_000_000_000);
    body.modified = 1_700_000_100_000;
    body.favorite = true;
    body.device = Some("laptop".into());
    body.notes = Some("note with åäö and emoji \u{1f980}".into());
    body.fields = vec![
        Field {
            id: "f1".into(),
            label: "Username".into(),
            kind: FieldKind::Text,
            value: "alice".into(),
            extra: vec![("hint".into(), txt("login name"))],
        },
        Field {
            id: "f2".into(),
            label: "Password".into(),
            kind: FieldKind::Password,
            value: "correct horse battery staple".into(),
            extra: vec![],
        },
        Field {
            id: "f3".into(),
            label: "PIN".into(),
            kind: FieldKind::Other("pin-code".into()),
            value: "1234".into(),
            extra: vec![],
        },
    ];
    body.urls = vec![
        UrlEntry {
            url: "https://example.com/login".into(),
            matching: UrlMatch::Domain,
            extra: vec![],
        },
        UrlEntry {
            url: "https://example.org".into(),
            matching: UrlMatch::Other("regex".into()),
            extra: vec![("flags".into(), Value::uint(3))],
        },
    ];
    body.totp = Some(Totp {
        uri: "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example".into(),
        extra: vec![("added".into(), Value::uint(5))],
    });
    body.passkey = Some(Passkey {
        cred_id: vec![0xc1; 32],
        rp_id: "example.com".into(),
        user_handle: vec![0xd2; 16],
        user_name: "alice".into(),
        private_key: vec![0xe3; 138],
        sign_count: 0,
        created: 1_700_000_050_000,
        prf_seed_uv: Some(vec![0xf4; 32]),
        prf_seed_nouv: None,
        extra: vec![(
            "future".into(),
            Value::Map(vec![
                (
                    "deep".into(),
                    Value::Array(vec![Value::Null, Value::Bool(false)]),
                ),
                ("n".into(), Value::int(-9)),
            ]),
        )],
    });
    body.extra = vec![
        ("zeta".into(), Value::Bytes(vec![1, 2, 3])),
        (
            "alpha".into(),
            Value::Map(vec![
                ("x".into(), Value::float(2.5)),
                ("a".into(), Value::Array(vec![Value::uint(1), txt("two")])),
            ]),
        ),
        ("mid".into(), Value::Null),
    ];
    body
}

fn seal(
    vault: &UnlockedVault,
    id: u8,
    rev: u64,
    body: &ItemBody,
    existing: Option<&[u8]>,
    seed: &str,
) -> SealedItem {
    encrypt_item(&mut rng(seed), vault, item_id(id), rev, body, existing).unwrap()
}

fn open(vault: &UnlockedVault, id: u8, s: &SealedItem) -> Result<DecodedItem, Error> {
    decrypt_item(vault, item_id(id), s.rev, &s.envelope, &s.tag)
}

// ---------------------------------------------------------------- layout

#[test]
fn envelope_layout_bytes() {
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 7, 1, &full_body(), None, "layout");
    let e = &sealed.envelope;
    assert_eq!(&e[..3], &[0x01, 0x01, 0x01], "version, suite, kind");
    assert_eq!(IK_WRAP_LEN, 72);
    let view = parse_envelope(e).unwrap();
    assert_eq!(view.kind, KIND_ITEM);
    assert_eq!(view.ik_wrap.unwrap().len(), 72);
    assert_eq!(view.ik_wrap.unwrap(), &e[3..75]);
    assert_eq!(view.body, &e[75..]);
    assert!(view.body.len() >= 24 + 256 + 16);
    // The padded body is a class; the envelope adds 3 + 72 + 24 + 16.
    let padded = view.body.len() - 40;
    assert!([256, 512, 1_024, 2_048, 4_096].contains(&padded) || padded.is_multiple_of(4_096));
    assert_eq!(e.len(), 3 + 72 + 24 + padded + 16);
    assert_eq!(sealed.rev, 1);
}

#[test]
fn a_small_item_is_the_smallest_envelope() {
    let vault = unlocked(0x5a);
    let body = ItemBody::new(ItemType::Note, "n", 1);
    let sealed = seal(&vault, 1, 1, &body, None, "small");
    assert_eq!(sealed.envelope.len(), 3 + 72 + 24 + 256 + 16);
    assert_eq!(sealed.envelope.len(), 371);
}

#[test]
fn encrypt_item_draws_key_then_two_nonces_and_an_edit_draws_one() {
    let vault = unlocked(0x5a);
    let body = ItemBody::new(ItemType::Note, "n", 1);
    let mut r = ReplayRng::new(vec![vec![0x11; 32], vec![0x22; 24], vec![0x33; 24]]);
    let s = encrypt_item(&mut r, &vault, item_id(1), 1, &body, None).unwrap();
    r.finish().unwrap();
    assert_eq!(&s.envelope[3..27], &[0x22; 24], "ik_wrap nonce");
    assert_eq!(&s.envelope[75..99], &[0x33; 24], "body nonce");
    let mut r = ReplayRng::new(vec![vec![0x44; 24]]);
    let e = encrypt_item(&mut r, &vault, item_id(1), 2, &body, Some(&s.envelope)).unwrap();
    r.finish().unwrap();
    assert_eq!(&e.envelope[3..75], &s.envelope[3..75], "ik_wrap kept");
    assert_eq!(&e.envelope[75..99], &[0x44; 24], "new body nonce");
    // Too few draws is a failed case, not silent reuse.
    let r = std::panic::catch_unwind(|| {
        let vault = unlocked(0x5a);
        let mut r = ReplayRng::new(vec![vec![0x11; 32], vec![0x22; 24]]);
        encrypt_item(
            &mut r,
            &vault,
            item_id(1),
            1,
            &ItemBody::new(ItemType::Note, "n", 1),
            None,
        )
    });
    assert!(r.is_err());
}

#[test]
fn every_write_uses_a_new_nonce() {
    let vault = unlocked(0x5a);
    let body = full_body();
    let a = seal(&vault, 1, 1, &body, None, "nonce a");
    let b = seal(&vault, 1, 1, &body, Some(&a.envelope), "nonce b");
    let c = seal(&vault, 1, 1, &body, Some(&a.envelope), "nonce c");
    assert_ne!(&a.envelope[75..99], &b.envelope[75..99]);
    assert_ne!(&b.envelope[75..99], &c.envelope[75..99]);
    assert_ne!(b.envelope, c.envelope);
}

// ------------------------------------------------------------ round trips

#[test]
fn item_roundtrip_all_types() {
    let vault = unlocked(0x5a);
    for (n, ty) in [
        ItemType::Login,
        ItemType::Note,
        ItemType::Card,
        ItemType::Identity,
        ItemType::Other("passkey".into()),
        ItemType::Other("something-new".into()),
    ]
    .into_iter()
    .enumerate()
    {
        let mut body = full_body();
        body.item_type = ty.clone();
        let sealed = seal(&vault, 1, 1, &body, None, &format!("type {n}"));
        let got = open(&vault, 1, &sealed).unwrap();
        assert!(!got.read_only);
        assert_eq!(got.body, body, "{}", ty.as_str());
        assert_eq!(got.body.item_type, ty);
    }
}

#[test]
fn item_roundtrip_minimal_and_empty_strings() {
    let vault = unlocked(0x5a);
    let body = ItemBody::new(ItemType::Note, "", 0);
    let sealed = seal(&vault, 1, 1, &body, None, "empty");
    assert_eq!(open(&vault, 1, &sealed).unwrap().body, body);
}

#[test]
fn the_body_is_sealed_with_the_item_key_and_the_item_aad() {
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 9, 4, &full_body(), None, "aad");
    let i = intermediate(&vault, item_id(9), 4, &sealed.envelope, &sealed.tag).unwrap();
    // The AADs, written out by hand with literal tags.
    let ik_aad = [
        label("ferret/v1/item-key"),
        t(0x02, &[1]),
        t(0x03, &[1]),
        t(0x11, &[0x22; 16]),
        t(0x12, &[9; 16]),
        t(0x20, &1u64.to_be_bytes()),
    ]
    .concat();
    let body_aad = [
        label("ferret/v1/item"),
        t(0x02, &[1]),
        t(0x03, &[1]),
        t(0x04, &[1]),
        t(0x11, &[0x22; 16]),
        t(0x12, &[9; 16]),
        t(0x22, &4u64.to_be_bytes()),
    ]
    .concat();
    assert_eq!(i.ik_aad, ik_aad);
    assert_eq!(i.body_aad, body_aad);
    assert_eq!(i.padded.len() % 256, 0);
}

#[test]
fn the_tag_is_hmac_over_the_hash_of_the_envelope() {
    use sha2::{Digest, Sha256};
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 3, 8, &full_body(), None, "tag");
    let hash = Sha256::digest(&sealed.envelope);
    let message = [
        label("ferret/v1/item-tag"),
        t(0x12, &[3; 16]),
        t(0x22, &8u64.to_be_bytes()),
        t(0x35, &hash),
    ]
    .concat();
    let k_head = ferret_core::testing::keys::unlocked_vault_keys(&vault)[1];
    assert_eq!(sealed.tag, hmac_sha256(&k_head, &message).unwrap());
    assert_eq!(
        item_tag(&vault, item_id(3), 8, &sealed.envelope).unwrap(),
        sealed.tag
    );
    verify_item_tag(&vault, item_id(3), 8, &sealed.envelope, &sealed.tag).unwrap();
}

// --------------------------------------------------------------- sabotage

#[test]
fn item_any_bit_flip_fails() {
    let vault = unlocked(0x5a);
    let body = ItemBody::new(ItemType::Login, "x", 1);
    let sealed = seal(&vault, 1, 1, &body, None, "flip");
    let id = item_id(1);
    for byte in 0..sealed.envelope.len() {
        for bit in 0..8 {
            let mut e = sealed.envelope.clone();
            e[byte] ^= 1 << bit;
            let err = decrypt_item(&vault, id, 1, &e, &sealed.tag).unwrap_err();
            // The header bytes too: a flipped version, suite or kind is the
            // same error as any other change.
            assert_eq!(err, Error::Decrypt, "byte {byte} bit {bit}");
        }
    }
    for byte in 0..32 {
        let mut tag = sealed.tag;
        tag[byte] ^= 0x80;
        assert_eq!(
            decrypt_item(&vault, id, 1, &sealed.envelope, &tag).unwrap_err(),
            Error::Decrypt
        );
    }
}

#[test]
fn item_aad_binds_item_id_rev_vault_epoch() {
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 1, 5, &full_body(), None, "bind");
    let ok = decrypt_item(&vault, item_id(1), 5, &sealed.envelope, &sealed.tag);
    assert!(ok.is_ok());
    // Another item id or rev with the stored tag: the tag already refuses.
    assert_eq!(
        decrypt_item(&vault, item_id(2), 5, &sealed.envelope, &sealed.tag).unwrap_err(),
        Error::Decrypt
    );
    assert_eq!(
        decrypt_item(&vault, item_id(1), 6, &sealed.envelope, &sealed.tag).unwrap_err(),
        Error::Decrypt
    );
    // Another vault id or another epoch: other K_head, other VK derivations.
    for ctx in [
        VaultContext {
            vault_id: VaultId::from_bytes([0x23; 16]),
            ..ctx()
        },
        VaultContext {
            vk_epoch: 2,
            ..ctx()
        },
    ] {
        let other = UnlockedVault::from_vault_key(ctx, vk(0x5a)).unwrap();
        assert_eq!(
            decrypt_item(&other, item_id(1), 5, &sealed.envelope, &sealed.tag).unwrap_err(),
            Error::Decrypt
        );
    }
}

#[test]
fn item_aad_binds_each_field_even_when_the_tag_is_right() {
    // The tag is computed for the claimed values, as a server with the right
    // K_head would, so only the AEAD can refuse: this isolates the AAD.
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 1, 5, &full_body(), None, "isolate");
    let retag = |id: u8, rev: u64| item_tag(&vault, item_id(id), rev, &sealed.envelope).unwrap();
    let before = aead_open_count();
    let err = decrypt_item(&vault, item_id(2), 5, &sealed.envelope, &retag(2, 5)).unwrap_err();
    assert_eq!(err, Error::Decrypt, "item_id is bound by the ik_wrap AAD");
    assert!(aead_open_count() > before, "the AEAD did run");
    let err = decrypt_item(&vault, item_id(1), 6, &sealed.envelope, &retag(1, 6)).unwrap_err();
    assert_eq!(err, Error::Decrypt, "rev is bound by the body AAD");
}

#[test]
fn version_suite_and_kind_are_bound_by_the_aad() {
    let vault = unlocked(0x5a);
    let plain = ItemBody::new(ItemType::Note, "n", 1).to_cbor().unwrap();
    for (name, aad) in [
        ("version", [2, 1, 1]),
        ("suite", [1, 2, 1]),
        ("kind", [1, 1, 2]),
    ] {
        let s = seal_with(
            &mut rng("hdr"),
            &vault,
            item_id(1),
            1,
            &plain,
            None,
            &Sabotage {
                aad_header: Some(aad),
                ..Sabotage::default()
            },
        )
        .unwrap();
        // The envelope parses (the written header is right) ...
        parse_envelope(&s.envelope).unwrap();
        // ... and does not open.
        assert_eq!(open(&vault, 1, &s).unwrap_err(), Error::Decrypt, "{name}");
    }
}

#[test]
fn the_wrap_epoch_is_bound_by_the_ik_wrap_aad() {
    let vault = unlocked(0x5a);
    let plain = ItemBody::new(ItemType::Note, "n", 1).to_cbor().unwrap();
    let s = seal_with(
        &mut rng("epoch"),
        &vault,
        item_id(1),
        1,
        &plain,
        None,
        &Sabotage {
            ik_epoch: Some(2),
            ..Sabotage::default()
        },
    )
    .unwrap();
    assert_eq!(open(&vault, 1, &s).unwrap_err(), Error::Decrypt);
    // An edit of such an envelope cannot take its key either.
    let r = encrypt_item(
        &mut rng("edit"),
        &vault,
        item_id(1),
        2,
        &ItemBody::new(ItemType::Note, "n", 1),
        Some(&s.envelope),
    );
    assert_eq!(r.unwrap_err(), Error::Decrypt);
}

#[test]
fn item_tag_verified_before_decrypt() {
    let vault = unlocked(0x5a);
    let sealed = seal(&vault, 1, 1, &full_body(), None, "tag first");
    let mut bad = sealed.tag;
    bad[31] ^= 1;
    let before = aead_open_count();
    let err = decrypt_item(&vault, item_id(1), 1, &sealed.envelope, &bad).unwrap_err();
    assert_eq!(err, Error::Decrypt);
    assert_eq!(aead_open_count(), before, "no AEAD ran for a wrong tag");
    assert_eq!(
        verify_item_tag(&vault, item_id(1), 1, &sealed.envelope, &bad).unwrap_err(),
        Error::Decrypt
    );
    // With the right tag, both AEADs run.
    decrypt_item(&vault, item_id(1), 1, &sealed.envelope, &sealed.tag).unwrap();
    assert_eq!(aead_open_count(), before + 2);
}

#[test]
fn a_wrong_vault_key_is_decrypt() {
    let sealed = seal(&unlocked(0x5a), 1, 1, &full_body(), None, "wrong key");
    assert_eq!(
        open(&unlocked(0x5b), 1, &sealed).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn unpad_runs_only_after_aead() {
    let vault = unlocked(0x5a);
    // A body whose padding is broken on purpose: the AEAD accepts it (it
    // authenticates what it is given) and only then is the padding looked at.
    let broken = [0u8; 256];
    let s = seal_raw_padded(&vault, item_id(1), 1, &broken);
    let before = aead_open_count();
    let err = decrypt_item(&vault, item_id(1), 1, &s.envelope, &s.tag).unwrap_err();
    assert_eq!(err, Error::Decrypt, "bad padding is the single error");
    assert_eq!(aead_open_count(), before + 2, "the AEADs ran first");
    // Tampering with a good envelope never reports anything about padding.
    let good = seal(
        &vault,
        1,
        1,
        &ItemBody::new(ItemType::Note, "n", 1),
        None,
        "pad",
    );
    for at in [75usize, 100, 200, good.envelope.len() - 1] {
        let mut e = good.envelope.clone();
        e[at] ^= 0xff;
        let tag = item_tag(&vault, item_id(1), 1, &e).unwrap();
        assert_eq!(
            decrypt_item(&vault, item_id(1), 1, &e, &tag).unwrap_err(),
            Error::Decrypt,
            "byte {at}"
        );
    }
}

/// Seals `padded` (which is not padded correctly) as an item body.
fn seal_raw_padded(vault: &UnlockedVault, id: ItemId, rev: u64, padded: &[u8]) -> SealedItem {
    use ferret_core::testing::prim::aead_seal;
    // Make a real envelope first to get a valid ik_wrap and IK, then replace
    // the body by one sealed under the same IK with the wrong padding.
    let first = encrypt_item(
        &mut rng("raw"),
        vault,
        id,
        rev,
        &ItemBody::new(ItemType::Note, "n", 1),
        None,
    )
    .unwrap();
    let i = intermediate(vault, id, rev, &first.envelope, &first.tag).unwrap();
    let body = aead_seal(&mut rng("raw body"), &i.ik, &i.body_aad, padded).unwrap();
    let mut envelope = first.envelope[..75].to_vec();
    envelope.extend_from_slice(&body);
    let tag = item_tag(vault, id, rev, &envelope).unwrap();
    SealedItem { envelope, tag, rev }
}

// ----------------------------------------------------------- structure

#[test]
fn parse_envelope_checks_the_structure_before_any_key() {
    let vault = unlocked(0x5a);
    let s = seal(
        &vault,
        1,
        1,
        &ItemBody::new(ItemType::Note, "n", 1),
        None,
        "parse",
    );
    let e = &s.envelope;
    let with = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut v = e.clone();
        f(&mut v);
        parse_envelope(&v).unwrap_err()
    };
    // An unknown version, suite or kind is the single error of any change.
    assert_eq!(with(&|v| v[0] = 2), Error::Decrypt);
    assert_eq!(with(&|v| v[0] = 0), Error::Decrypt);
    assert_eq!(with(&|v| v[1] = 2), Error::Decrypt);
    assert_eq!(with(&|v| v[2] = 0), Error::Decrypt);
    assert_eq!(with(&|v| v[2] = 3), Error::Decrypt);
    // The size limit comes before the header.
    assert_eq!(
        with(&|v| {
            v[0] = 9;
            v.resize(MAX_ENVELOPE_LEN + 1, 0);
        }),
        Error::TooLarge
    );
    assert_eq!(
        with(&|v| v.truncate(2)),
        Error::Malformed(MalformedKind::Envelope)
    );
    assert_eq!(
        with(&|v| v.truncate(74)),
        Error::Malformed(MalformedKind::Envelope)
    );
    assert_eq!(
        with(&|v| v.truncate(300)),
        Error::Malformed(MalformedKind::Envelope)
    );
    // One byte too many: the body is no padding class.
    assert_eq!(
        with(&|v| v.push(0)),
        Error::Malformed(MalformedKind::Envelope)
    );
    // Over the limit.
    assert_eq!(
        with(&|v| v.resize(MAX_ENVELOPE_LEN + 1, 0)),
        Error::TooLarge
    );
    assert_eq!(
        parse_envelope(&[]).unwrap_err(),
        Error::Malformed(MalformedKind::Envelope)
    );
    // The structure error comes before the tag, so it is the same for any key.
    assert_eq!(
        decrypt_item(&unlocked(0x01), item_id(1), 1, &e[..300], &s.tag).unwrap_err(),
        Error::Malformed(MalformedKind::Envelope)
    );
}

#[test]
fn the_largest_envelope_fits_65536_bytes() {
    let vault = unlocked(0x5a);
    // A note whose CBOR is exactly 61 439 bytes. With a notes text of 256 to
    // 65 535 bytes its head is three bytes, so the length is linear.
    let mut body = ItemBody::new(ItemType::Note, "big", 1);
    body.notes = Some(String::new());
    let base = body.to_cbor().unwrap().len();
    let fill = MAX_PLAINTEXT - base - 2;
    body.notes = Some("a".repeat(fill));
    assert_eq!(body.to_cbor().unwrap().len(), MAX_PLAINTEXT);
    let sealed = seal(&vault, 1, 1, &body, None, "big");
    assert!(sealed.envelope.len() <= MAX_ENVELOPE_LEN);
    assert_eq!(sealed.envelope.len(), 3 + 72 + 24 + 61_440 + 16);
    assert_eq!(open(&vault, 1, &sealed).unwrap().body, body);
    // One byte more is too large.
    body.notes = Some("a".repeat(fill + 1));
    assert_eq!(body.to_cbor().unwrap().len(), MAX_PLAINTEXT + 1);
    let r = encrypt_item(&mut rng("big"), &vault, item_id(1), 1, &body, None);
    assert_eq!(r.unwrap_err(), Error::TooLarge);
}

#[test]
fn the_reserved_manifest_id_is_not_an_item_id() {
    let vault = unlocked(0x5a);
    let body = ItemBody::new(ItemType::Note, "n", 1);
    let r = encrypt_item(&mut rng("res"), &vault, ItemId::MANIFEST, 1, &body, None);
    assert_eq!(r.unwrap_err(), Error::Malformed(MalformedKind::Envelope));
    let s = seal(&vault, 1, 1, &body, None, "res");
    let r = decrypt_item(&vault, ItemId::MANIFEST, 1, &s.envelope, &s.tag);
    assert_eq!(r.unwrap_err(), Error::Malformed(MalformedKind::Envelope));
}

// -------------------------------------------------------- unknown fields

#[test]
fn item_unknown_fields_preserved_byte_exact() {
    let vault = unlocked(0x5a);
    let body = full_body();
    let first = body.to_cbor().unwrap();
    // decode -> encode -> decode
    let decoded = ItemBody::from_cbor(&first).unwrap().body;
    let again = decoded.to_cbor().unwrap();
    assert_eq!(*again, *first, "the bytes are the same");
    let decoded2 = ItemBody::from_cbor(&again).unwrap().body;
    assert_eq!(decoded2.extra, body.extra);
    assert_eq!(
        decoded2
            .extra
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        ["zeta", "alpha", "mid"],
        "in the order they were read"
    );
    assert_eq!(decoded2.fields[0].extra, body.fields[0].extra);
    assert_eq!(decoded2.urls[1].extra, body.urls[1].extra);
    assert_eq!(
        decoded2.totp.as_ref().unwrap().extra,
        body.totp.as_ref().unwrap().extra
    );
    assert_eq!(
        decoded2.passkey.as_ref().unwrap().extra,
        body.passkey.as_ref().unwrap().extra
    );
    // Through encryption, an edit and decryption.
    let s1 = seal(&vault, 1, 1, &body, None, "unk 1");
    let mut edited = open(&vault, 1, &s1).unwrap().body;
    edited.name = "Renamed".into();
    let s2 = seal(&vault, 1, 2, &edited, Some(&s1.envelope), "unk 2");
    let back = open(&vault, 1, &s2).unwrap().body;
    assert_eq!(back.name, "Renamed");
    assert_eq!(back.extra, body.extra);
    assert_eq!(back.passkey, body.passkey);
}

#[test]
fn unknown_keys_in_a_hand_written_body_are_written_back_in_place() {
    // schema 1, with a key before, between and after the known ones, and
    // nested unknown maps: the known keys come out in schema order, the
    // unknown ones after them in the order they were read.
    let input = Value::Map(vec![
        ("x-first".into(), Value::uint(1)),
        ("schema".into(), Value::uint(1)),
        ("name".into(), txt("n")),
        (
            "x-second".into(),
            Value::Map(vec![("k".into(), Value::Null)]),
        ),
        ("type".into(), txt("login")),
        ("fields".into(), Value::Array(vec![])),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(false)),
        ("x-last".into(), Value::Array(vec![Value::uint(7)])),
    ]);
    let bytes = cbor::encode(&input).unwrap();
    let decoded = ItemBody::from_cbor(&bytes).unwrap();
    assert!(!decoded.read_only);
    let keys: Vec<&str> = decoded.body.extra.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(keys, ["x-first", "x-second", "x-last"]);
    let out = decoded.body.to_value();
    let Value::Map(entries) = &out else { panic!() };
    let order: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        order,
        [
            "schema", "type", "name", "fields", "urls", "created", "modified", "favorite",
            "x-first", "x-second", "x-last"
        ]
    );
    // A second pass is stable.
    let again = ItemBody::from_cbor(&decoded.body.to_cbor().unwrap())
        .unwrap()
        .body;
    assert_eq!(again, decoded.body);
}

#[test]
fn an_unknown_key_that_repeats_a_known_one_is_refused_on_write() {
    let vault = unlocked(0x5a);
    let mut body = ItemBody::new(ItemType::Note, "n", 1);
    body.extra = vec![("name".into(), txt("second name"))];
    let r = encrypt_item(&mut rng("dup"), &vault, item_id(1), 1, &body, None);
    assert_eq!(
        r.unwrap_err(),
        Error::Malformed(MalformedKind::CborDuplicateKey)
    );
}

#[test]
fn item_body_schema_errors_are_item_body_errors() {
    let base = |drop: &str| {
        let mut m = vec![
            ("schema".to_owned(), Value::uint(1)),
            ("type".to_owned(), txt("note")),
            ("name".to_owned(), txt("n")),
            ("fields".to_owned(), Value::Array(vec![])),
            ("urls".to_owned(), Value::Array(vec![])),
            ("created".to_owned(), Value::uint(1)),
            ("modified".to_owned(), Value::uint(1)),
            ("favorite".to_owned(), Value::Bool(false)),
        ];
        m.retain(|(k, _)| k != drop);
        cbor::encode(&Value::Map(m)).unwrap()
    };
    ItemBody::from_cbor(&base("none")).unwrap();
    for missing in [
        "schema", "type", "name", "fields", "urls", "created", "modified", "favorite",
    ] {
        let err = ItemBody::from_cbor(&base(missing)).unwrap_err();
        assert_eq!(
            err,
            Error::Malformed(MalformedKind::ItemBody),
            "missing {missing}"
        );
    }
    // Wrong types.
    for (key, value) in [
        ("name", Value::uint(1)),
        ("type", Value::Bool(true)),
        ("fields", Value::Map(vec![])),
        ("urls", Value::Array(vec![Value::uint(1)])),
        ("created", txt("1")),
        ("modified", Value::int(-1)),
        ("favorite", Value::uint(1)),
        ("schema", txt("1")),
        ("schema", Value::uint(0)),
    ] {
        let decoded = cbor::decode(&base("none")).unwrap();
        let Value::Map(entries) = &decoded else {
            unreachable!()
        };
        let mut m = entries.clone();
        for entry in &mut m {
            if entry.0 == key {
                entry.1 = value.clone();
            }
        }
        let bytes = cbor::encode(&Value::Map(m)).unwrap();
        assert_eq!(
            ItemBody::from_cbor(&bytes).unwrap_err(),
            Error::Malformed(MalformedKind::ItemBody),
            "{key}"
        );
    }
    // Not a map at all.
    let err = ItemBody::from_cbor(&[0x80]).unwrap_err();
    assert_eq!(err, Error::Malformed(MalformedKind::ItemBody));
    // A field whose value is not text.
    let bad_field = Value::Map(vec![
        ("schema".into(), Value::uint(1)),
        ("type".into(), txt("note")),
        ("name".into(), txt("n")),
        (
            "fields".into(),
            Value::Array(vec![Value::Map(vec![("id".into(), Value::uint(1))])]),
        ),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(1)),
        ("favorite".into(), Value::Bool(false)),
    ]);
    assert_eq!(
        ItemBody::from_cbor(&cbor::encode(&bad_field).unwrap()).unwrap_err(),
        Error::Malformed(MalformedKind::ItemBody)
    );
    // CBOR errors keep their own code.
    assert_eq!(
        ItemBody::from_cbor(&[0xf7]).unwrap_err(),
        Error::Malformed(MalformedKind::CborSimple)
    );
}

// ------------------------------------------------------- read-only schema

fn schema2_bytes() -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        ("schema".into(), Value::uint(2)),
        ("type".into(), txt("login")),
        ("name".into(), txt("From the future")),
        ("fields".into(), Value::Array(vec![])),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(true)),
        (
            "x-new".into(),
            Value::Map(vec![("a".into(), Value::uint(1))]),
        ),
    ]))
    .unwrap()
}

#[test]
fn item_schema_2_is_read_only() {
    let vault = unlocked(0x5a);
    let s = seal_plaintext(
        &mut rng("s2"),
        &vault,
        item_id(1),
        1,
        &schema2_bytes(),
        None,
    )
    .unwrap();
    let got = open(&vault, 1, &s).unwrap();
    assert!(got.read_only);
    assert!(got.body.is_read_only());
    assert_eq!(got.body.schema, 2);
    assert_eq!(got.body.name, "From the future");
    assert!(got.body.favorite);
    assert_eq!(got.body.extra.len(), 1);
    assert!(got.body.view().read_only);
    // It can never be written, with or without an existing envelope.
    let r = encrypt_item(
        &mut rng("w"),
        &vault,
        item_id(1),
        2,
        &got.body,
        Some(&s.envelope),
    );
    assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
    let r = encrypt_item(&mut rng("w"), &vault, item_id(1), 2, &got.body, None);
    assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
    // Any schema above 1 is refused, whatever the number.
    let mut forced = got.body.clone();
    forced.schema = 99;
    let r = encrypt_item(&mut rng("w"), &vault, item_id(1), 2, &forced, None);
    assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
}

#[test]
fn item_future_schema_never_writable() {
    let vault = unlocked(0x5a);
    for schema in [2u64, 3, 255, u64::MAX] {
        let mut body = ItemBody::new(ItemType::Note, "n", 1);
        body.schema = schema;
        let r = encrypt_item(&mut rng("fs"), &vault, item_id(1), 1, &body, None);
        assert_eq!(r.unwrap_err(), Error::ReadOnlySchema, "schema {schema}");
        // And it still decodes, read-only.
        let decoded = ItemBody::from_cbor(&body.to_cbor().unwrap()).unwrap();
        assert!(decoded.read_only);
    }
}

#[test]
fn a_future_schema_is_read_leniently() {
    // Known keys with the wrong shape go to the unknown part, missing keys
    // get defaults, and nothing is an error.
    let bytes = cbor::encode(&Value::Map(vec![
        ("schema".into(), Value::uint(7)),
        ("name".into(), Value::uint(42)),
        (
            "fields".into(),
            Value::Map(vec![("odd".into(), Value::Null)]),
        ),
        (
            "urls".into(),
            Value::Array(vec![Value::Map(vec![("url".into(), Value::uint(1))])]),
        ),
        ("favorite".into(), txt("maybe")),
        ("brand-new".into(), Value::Bool(true)),
    ]))
    .unwrap();
    let decoded = ItemBody::from_cbor(&bytes).unwrap();
    assert!(decoded.read_only);
    let body = &decoded.body;
    assert_eq!(body.schema, 7);
    assert_eq!(body.name, "");
    assert!(body.fields.is_empty());
    assert!(!body.favorite);
    // An element that does not fit keeps its own unknown part: the url is
    // not text, so it is kept as it was inside the entry.
    assert_eq!(body.urls.len(), 1);
    assert_eq!(body.urls[0].url, "");
    assert_eq!(body.urls[0].extra, vec![("url".to_owned(), Value::uint(1))]);
    let mut kept: Vec<&str> = body.extra.iter().map(|(k, _)| k.as_str()).collect();
    kept.sort_unstable();
    assert_eq!(kept, ["brand-new", "favorite", "fields", "name"]);
    // The schema key itself is still required and must be a positive number.
    for bad in [
        Value::Map(vec![("name".into(), txt("x"))]),
        Value::Map(vec![("schema".into(), txt("2"))]),
        Value::Map(vec![("schema".into(), Value::uint(0))]),
    ] {
        assert_eq!(
            ItemBody::from_cbor(&cbor::encode(&bad).unwrap()).unwrap_err(),
            Error::Malformed(MalformedKind::ItemBody)
        );
    }
}

// ----------------------------------------------------------------- edit

#[test]
fn item_edit_keeps_ik_wrap() {
    let vault = unlocked(0x5a);
    let created = seal(&vault, 1, 1, &full_body(), None, "edit 1");
    let mut body = open(&vault, 1, &created).unwrap().body;
    body.name = "Edited".into();
    body.modified += 1;
    let edited = seal(&vault, 1, 2, &body, Some(&created.envelope), "edit 2");
    assert_eq!(edited.rev, 2);
    assert_eq!(
        &edited.envelope[3..75],
        &created.envelope[3..75],
        "ik_wrap byte for byte"
    );
    assert_ne!(
        &edited.envelope[75..99],
        &created.envelope[75..99],
        "new body nonce"
    );
    assert_ne!(edited.tag, created.tag);
    assert_eq!(open(&vault, 1, &edited).unwrap().body.name, "Edited");
    // The same item key opens both bodies.
    let a = intermediate(&vault, item_id(1), 1, &created.envelope, &created.tag).unwrap();
    let b = intermediate(&vault, item_id(1), 2, &edited.envelope, &edited.tag).unwrap();
    assert_eq!(a.ik, b.ik);
    // A new item gets a new key.
    let other = seal(&vault, 1, 1, &full_body(), None, "edit 3");
    let c = intermediate(&vault, item_id(1), 1, &other.envelope, &other.tag).unwrap();
    assert_ne!(a.ik, c.ik);
}

#[test]
fn an_edit_cannot_take_the_key_of_another_item() {
    let vault = unlocked(0x5a);
    let a = seal(&vault, 1, 1, &full_body(), None, "a");
    let r = encrypt_item(
        &mut rng("b"),
        &vault,
        item_id(2),
        1,
        &full_body(),
        Some(&a.envelope),
    );
    assert_eq!(r.unwrap_err(), Error::Decrypt);
    // Nor of a manifest envelope or of garbage.
    let m = encrypt_manifest(&mut rng("m"), &vault, 1, &Manifest::new(1, vec![])).unwrap();
    let r = encrypt_item(
        &mut rng("b"),
        &vault,
        item_id(2),
        1,
        &full_body(),
        Some(&m.envelope),
    );
    assert_eq!(r.unwrap_err(), Error::Decrypt);
    let r = encrypt_item(
        &mut rng("b"),
        &vault,
        item_id(2),
        1,
        &full_body(),
        Some(&[1, 1]),
    );
    assert_eq!(r.unwrap_err(), Error::Malformed(MalformedKind::Envelope));
}

#[test]
fn item_rekey_path_does_not_parse_cbor() {
    let old = unlocked(0x5a);
    let new_ctx = VaultContext {
        vk_epoch: 2,
        ..ctx()
    };
    let new = UnlockedVault::from_vault_key(new_ctx, vk(0x6b)).unwrap();
    // A body no reader could parse: not even CBOR.
    let junk = b"\xff\xff not cbor at all \x00\x80";
    let s = seal_plaintext(&mut rng("old"), &old, item_id(4), 3, junk, None).unwrap();
    let re = reseal(
        &mut rng("new"),
        &old,
        &new,
        item_id(4),
        3,
        4,
        &s.envelope,
        &s.tag,
    )
    .unwrap();
    assert_eq!(re.rev, 4);
    let (_, plain) = open_plaintext(&new, item_id(4), 4, &re.envelope, &re.tag).unwrap();
    assert_eq!(plain, junk);
    // A schema 2 body can be rekeyed although it can never be edited.
    let s2 = seal_plaintext(
        &mut rng("old2"),
        &old,
        item_id(5),
        1,
        &schema2_bytes(),
        None,
    )
    .unwrap();
    let re2 = reseal(
        &mut rng("new2"),
        &old,
        &new,
        item_id(5),
        1,
        2,
        &s2.envelope,
        &s2.tag,
    )
    .unwrap();
    let got = decrypt_item(&new, item_id(5), 2, &re2.envelope, &re2.tag).unwrap();
    assert!(got.read_only);
    // Fresh key and nonces; the old vault no longer opens it.
    assert_ne!(&re2.envelope[3..75], &s2.envelope[3..75]);
    assert_eq!(
        decrypt_item(&old, item_id(5), 2, &re2.envelope, &re2.tag).unwrap_err(),
        Error::Decrypt
    );
    // A wrong tag on the old envelope stops it before any AEAD.
    let mut bad = s.tag;
    bad[0] ^= 1;
    let before = aead_open_count();
    let r = reseal(
        &mut rng("x"),
        &old,
        &new,
        item_id(4),
        3,
        4,
        &s.envelope,
        &bad,
    );
    assert_eq!(r.unwrap_err(), Error::Decrypt);
    assert_eq!(aead_open_count(), before);
}

// -------------------------------------------------------------- manifest

fn sample_manifest() -> Manifest {
    let mut m = Manifest::new(
        1,
        vec![
            ManifestEntry::new(1, MethodId::from_bytes([0x70; 16]), 3),
            ManifestEntry::new(2, MethodId::from_bytes([0x71; 16]), 1),
            ManifestEntry {
                method_type: 3,
                method_id: MethodId::from_bytes([0x72; 16]),
                kek_generation: u64::MAX,
                credential_id: None,
                extra: vec![("label".into(), txt("YubiKey"))],
            },
        ],
    );
    m.extra = vec![("future".into(), Value::uint(1))];
    m
}

#[test]
fn manifest_roundtrip_and_aad_label() {
    let vault = unlocked(0x5a);
    let m = sample_manifest();
    let s = encrypt_manifest(&mut rng("manifest"), &vault, 6, &m).unwrap();
    assert_eq!(s.rev, 6);
    assert_eq!(&s.envelope[..3], &[0x01, 0x01, 0x02], "kind 2");
    let view = parse_envelope(&s.envelope).unwrap();
    assert_eq!(view.kind, KIND_MANIFEST);
    assert!(view.ik_wrap.is_none());
    assert_eq!(s.envelope.len(), 3 + 24 + 256 + 16);
    assert_eq!(decrypt_manifest(&vault, 6, &s.envelope, &s.tag).unwrap(), m);
    // The body is sealed under K_meta, with the manifest label and the
    // reserved item id, as written out by hand here.
    let k_meta = ferret_core::testing::keys::unlocked_vault_keys(&vault)[3];
    let aad = [
        label("ferret/v1/manifest"),
        t(0x02, &[1]),
        t(0x03, &[1]),
        t(0x04, &[2]),
        t(0x11, &[0x22; 16]),
        t(0x12, &[0; 16]),
        t(0x22, &6u64.to_be_bytes()),
    ]
    .concat();
    let sealed_body = &s.envelope[3..];
    let pt = ferret_core::testing::prim::aead_open(&k_meta, &aad, sealed_body).unwrap();
    assert_eq!(pt.len(), 256);
    let n = ferret_core::item::pad::unpad(&pt).unwrap();
    assert_eq!(Manifest::from_cbor(&pt[..n]).unwrap(), m);
    // The tag uses the reserved item id.
    assert_eq!(
        s.tag,
        item_tag(&vault, ItemId::MANIFEST, 6, &s.envelope).unwrap()
    );
    // The label is the manifest one: the item AAD does not open it.
    let item_aad = [
        label("ferret/v1/item"),
        t(0x02, &[1]),
        t(0x03, &[1]),
        t(0x04, &[2]),
        t(0x11, &[0x22; 16]),
        t(0x12, &[0; 16]),
        t(0x22, &6u64.to_be_bytes()),
    ]
    .concat();
    assert!(ferret_core::testing::prim::aead_open(&k_meta, &item_aad, sealed_body).is_err());
}

#[test]
fn manifest_is_bound_to_rev_vault_kind_and_key() {
    let vault = unlocked(0x5a);
    let s = encrypt_manifest(&mut rng("m"), &vault, 6, &sample_manifest()).unwrap();
    assert_eq!(
        decrypt_manifest(&vault, 7, &s.envelope, &s.tag).unwrap_err(),
        Error::Decrypt
    );
    assert_eq!(
        decrypt_manifest(&unlocked(0x5b), 6, &s.envelope, &s.tag).unwrap_err(),
        Error::Decrypt
    );
    // Retagged for another rev: only the AAD can refuse.
    let tag7 = item_tag(&vault, ItemId::MANIFEST, 7, &s.envelope).unwrap();
    assert_eq!(
        decrypt_manifest(&vault, 7, &s.envelope, &tag7).unwrap_err(),
        Error::Decrypt
    );
    let mut bad = s.tag;
    bad[3] ^= 4;
    let before = aead_open_count();
    assert_eq!(
        decrypt_manifest(&vault, 6, &s.envelope, &bad).unwrap_err(),
        Error::Decrypt
    );
    assert_eq!(aead_open_count(), before, "the tag is checked first");
    // An item envelope is not a manifest and the other way round.
    let item = seal(
        &vault,
        1,
        6,
        &ItemBody::new(ItemType::Note, "n", 1),
        None,
        "i",
    );
    assert_eq!(
        decrypt_manifest(&vault, 6, &item.envelope, &item.tag).unwrap_err(),
        Error::Decrypt
    );
    assert_eq!(
        decrypt_item(&vault, item_id(1), 6, &s.envelope, &s.tag).unwrap_err(),
        Error::Decrypt
    );
    // Every bit of the sealed part.
    for byte in 3..s.envelope.len() {
        let mut e = s.envelope.clone();
        e[byte] ^= 1;
        assert_eq!(
            decrypt_manifest(&vault, 6, &e, &s.tag).unwrap_err(),
            Error::Decrypt,
            "byte {byte}"
        );
    }
}

#[test]
fn manifest_version_other_than_1_is_unsupported_and_shape_errors_are_item_body() {
    let mut v = sample_manifest().to_value();
    let Value::Map(m) = &mut v else { panic!() };
    m[0].1 = Value::uint(2);
    assert_eq!(
        Manifest::from_cbor(&cbor::encode(&v).unwrap()).unwrap_err(),
        Error::Unsupported
    );
    for bad in [
        Value::Map(vec![("v".into(), Value::uint(1))]),
        Value::Array(vec![]),
        Value::Map(vec![
            ("v".into(), Value::uint(1)),
            ("vk_epoch".into(), Value::uint(1)),
            (
                "methods".into(),
                Value::Array(vec![Value::Map(vec![
                    ("t".into(), Value::uint(300)),
                    ("id".into(), Value::Bytes(vec![0; 16])),
                    ("g".into(), Value::uint(1)),
                ])]),
            ),
        ]),
        Value::Map(vec![
            ("v".into(), Value::uint(1)),
            ("vk_epoch".into(), Value::uint(1)),
            (
                "methods".into(),
                Value::Array(vec![Value::Map(vec![
                    ("t".into(), Value::uint(1)),
                    ("id".into(), Value::Bytes(vec![0; 15])),
                    ("g".into(), Value::uint(1)),
                ])]),
            ),
        ]),
    ] {
        assert_eq!(
            Manifest::from_cbor(&cbor::encode(&bad).unwrap()).unwrap_err(),
            Error::Malformed(MalformedKind::ItemBody)
        );
    }
    // The wire form: a hand-written manifest.
    let m = Manifest::new(
        2,
        vec![ManifestEntry::new(4, MethodId::from_bytes([1; 16]), 9)],
    );
    let mut want = vec![0xa3, 0x61, b'v', 0x01, 0x68];
    want.extend_from_slice(b"vk_epoch");
    want.extend_from_slice(&[0x02, 0x67]);
    want.extend_from_slice(b"methods");
    want.extend_from_slice(&[0x81, 0xa3, 0x61, b't', 0x04, 0x62, b'i', b'd', 0x50]);
    want.extend_from_slice(&[1; 16]);
    want.extend_from_slice(&[0x61, b'g', 0x09]);
    assert_eq!(m.to_cbor().unwrap(), want);
}

// ----------------------------------------------------------- redaction

#[test]
fn the_view_holds_no_secret() {
    let body = full_body();
    let view = body.view();
    assert_eq!(view.fields[0].value.as_deref(), Some("alice"));
    assert_eq!(view.fields[1].value, None, "password field");
    assert_eq!(view.fields[2].value, None, "unknown kind is secret");
    assert!(view.has_totp && view.has_notes);
    let p = view.passkey.as_ref().unwrap();
    assert_eq!(
        (p.rp_id.as_str(), p.user_name.as_str()),
        ("example.com", "alice")
    );
    assert!(p.has_prf);
    let text = format!("{view:?}");
    for secret in ["correct horse", "JBSWY3DP", "otpauth", "note with"] {
        assert!(!text.contains(secret), "{secret}");
    }
    // Debug of the body itself shows nothing.
    let dbg = format!("{body:?} {:?}", body.passkey.as_ref().unwrap());
    for secret in ["correct horse", "example.com", "alice", "JBSWY3DP"] {
        assert!(!dbg.contains(secret), "{secret}");
    }
}

#[test]
fn value_wipes_on_zeroize() {
    use zeroize::Zeroize;
    let mut v = Value::Map(vec![
        ("k".into(), Value::text("secret")),
        ("b".into(), Value::Bytes(vec![9; 8])),
        ("a".into(), Value::Array(vec![Value::text("x")])),
    ]);
    v.zeroize();
    assert_eq!(v, Value::Map(vec![]));
}

// -------------------------------------------------------------- vectors

fn id16(v: &Json) -> [u8; 16] {
    hexn(v)
}

fn vault_of(input: &Json) -> UnlockedVault {
    let ctx = VaultContext {
        account_id: ferret_core::AccountId::from_bytes(id16(&input["account_id"])),
        vault_id: VaultId::from_bytes(id16(&input["vault_id"])),
        vk_epoch: u64s(&input["vk_epoch"]),
    };
    UnlockedVault::from_vault_key(
        ctx,
        ferret_core::VaultKey::from_test_bytes(hexn(&input["vk"])),
    )
    .unwrap()
}

fn tag_of(input: &Json) -> [u8; 32] {
    hexn(&input["tag"])
}

#[test]
fn item_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/item.json")).unwrap();
    assert!(file.cases.len() >= 40, "{} cases", file.cases.len());
    let report = vector::run_all(&file, |case, rng| {
        let input = &case.input;
        let vault = vault_of(input);
        match case.op.as_str() {
            "item.seal" | "item.seal.digest" => {
                let body = ItemBody::from_cbor(&segments(&input["body"]))?.body;
                let id = ItemId::from_bytes(id16(&input["item_id"]));
                let existing = input.get("existing").map(hex);
                let s = encrypt_item(
                    rng,
                    &vault,
                    id,
                    u64s(&input["rev"]),
                    &body,
                    existing.as_deref(),
                )?;
                if case.op == "item.seal.digest" {
                    use sha2::{Digest, Sha256};
                    return Ok(Outcome {
                        output: json!({
                            "envelope_len": s.envelope.len(),
                            "envelope_sha256": he(&Sha256::digest(&s.envelope)),
                            "tag": he(&s.tag),
                        }),
                        intermediate: None,
                    });
                }
                let i = intermediate(&vault, id, s.rev, &s.envelope, &s.tag)?;
                Ok(Outcome {
                    output: json!({ "envelope": he(&s.envelope), "tag": he(&s.tag) }),
                    intermediate: Some(json!({
                        "ik": he(&i.ik),
                        "ik_aad": he(&i.ik_aad),
                        "body_aad": he(&i.body_aad),
                        "padded_len": i.padded.len(),
                    })),
                })
            }
            "item.open" => {
                let id = ItemId::from_bytes(id16(&input["item_id"]));
                let got = decrypt_item(
                    &vault,
                    id,
                    u64s(&input["rev"]),
                    &hex(&input["envelope"]),
                    &tag_of(input),
                )?;
                Ok(Outcome {
                    output: json!({
                        "read_only": got.read_only,
                        "body": he(&got.body.to_cbor()?),
                    }),
                    intermediate: None,
                })
            }
            "item.manifest.seal" => {
                let m = Manifest::from_cbor(&hex(&input["manifest"]))?;
                let s = encrypt_manifest(rng, &vault, u64s(&input["rev"]), &m)?;
                Ok(Outcome {
                    output: json!({ "envelope": he(&s.envelope), "tag": he(&s.tag) }),
                    intermediate: None,
                })
            }
            "item.manifest.open" => {
                let m = decrypt_manifest(
                    &vault,
                    u64s(&input["rev"]),
                    &hex(&input["envelope"]),
                    &tag_of(input),
                )?;
                Ok(Outcome {
                    output: json!({ "manifest": he(&m.to_cbor()?) }),
                    intermediate: None,
                })
            }
            other => panic!("unknown op {other}"),
        }
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());
}

#[test]
fn constants_match_the_spec() {
    assert_eq!(VERSION, 1);
    assert_eq!(KIND_ITEM, 1);
    assert_eq!(KIND_MANIFEST, 2);
    assert_eq!(MAX_ENVELOPE_LEN, 65_536);
    assert_eq!(hex_encode(&[VERSION]), "01");
}

// ---------------------------------------------------------- fix round 1

#[test]
fn encrypt_item_requires_schema_1() {
    let vault = unlocked(0x5a);
    // Schema 0 would be written and could never be read again.
    let mut body = ItemBody::new(ItemType::Note, "n", 1);
    body.schema = 0;
    let r = encrypt_item(&mut rng("s0"), &vault, item_id(1), 1, &body, None);
    assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
    // A future item, changed to schema 1 by the caller, is still read-only.
    let s = seal_plaintext(
        &mut rng("s2"),
        &vault,
        item_id(1),
        1,
        &schema2_bytes(),
        None,
    )
    .unwrap();
    let got = open(&vault, 1, &s).unwrap();
    assert!(got.read_only);
    let mut lowered = got.body.clone();
    lowered.schema = 1;
    assert!(lowered.is_read_only(), "the flag outlives the number");
    for existing in [None, Some(s.envelope.as_slice())] {
        let r = encrypt_item(&mut rng("w"), &vault, item_id(1), 2, &lowered, existing);
        assert_eq!(r.unwrap_err(), Error::ReadOnlySchema);
    }
    // A fresh schema 1 body still writes.
    let ok = ItemBody::new(ItemType::Note, "n", 1);
    assert!(!ok.is_read_only());
    seal(&vault, 1, 1, &ok, None, "ok");
}

#[test]
fn the_manifest_must_name_the_epoch_of_its_key() {
    let vault = unlocked(0x5a); // epoch 1
    let wrong = Manifest::new(
        2,
        vec![ManifestEntry::new(1, MethodId::from_bytes([1; 16]), 1)],
    );
    let mut r = ReplayRng::new(vec![]);
    assert_eq!(
        encrypt_manifest(&mut r, &vault, 1, &wrong).unwrap_err(),
        Error::Malformed(MalformedKind::ItemBody)
    );
    r.finish().unwrap();
    // An authentic manifest for another epoch (a writer bug) is not returned.
    let s = seal_manifest_plaintext(&mut rng("m"), &vault, 1, &wrong.to_cbor().unwrap()).unwrap();
    assert_eq!(
        decrypt_manifest(&vault, 1, &s.envelope, &s.tag).unwrap_err(),
        Error::Decrypt
    );
    // The right epoch works.
    let good = Manifest::new(1, wrong.methods.clone());
    let s = encrypt_manifest(&mut rng("m"), &vault, 1, &good).unwrap();
    assert_eq!(
        decrypt_manifest(&vault, 1, &s.envelope, &s.tag).unwrap(),
        good
    );
}

#[test]
fn reseal_keeps_account_vault_and_moves_forward() {
    let old = unlocked(0x5a);
    let s = seal(&old, 4, 3, &full_body(), None, "old");
    let next = |account: u8, vault: u8, epoch: u64| {
        UnlockedVault::from_vault_key(
            VaultContext {
                account_id: ferret_core::AccountId::from_bytes([account; 16]),
                vault_id: VaultId::from_bytes([vault; 16]),
                vk_epoch: epoch,
            },
            vk(0x6b),
        )
        .unwrap()
    };
    let go = |new: &UnlockedVault, new_rev: u64| {
        reseal(
            &mut rng("r"),
            &old,
            new,
            item_id(4),
            3,
            new_rev,
            &s.envelope,
            &s.tag,
        )
    };
    let bad = Error::Malformed(MalformedKind::Envelope);
    assert_eq!(go(&next(0x11, 0x22, 2), 4).unwrap().rev, 4);
    assert_eq!(
        go(&next(0x12, 0x22, 2), 4).unwrap_err(),
        bad,
        "other account"
    );
    assert_eq!(go(&next(0x11, 0x23, 2), 4).unwrap_err(), bad, "other vault");
    assert_eq!(go(&next(0x11, 0x22, 1), 4).unwrap_err(), bad, "same epoch");
    assert_eq!(
        go(&next(0x11, 0x22, 0), 4).unwrap_err(),
        bad,
        "earlier epoch"
    );
    assert_eq!(
        go(&next(0x11, 0x22, 2), 3).unwrap_err(),
        bad,
        "same revision"
    );
    assert_eq!(
        go(&next(0x11, 0x22, 2), 2).unwrap_err(),
        bad,
        "earlier revision"
    );
}

#[test]
fn floats_in_unknown_fields_are_kept_and_in_known_fields_refused() {
    let vault = unlocked(0x5a);
    let mut body = ItemBody::new(ItemType::Note, "n", 1);
    body.extra = vec![
        ("f16".into(), Value::Float16(0x3c00)),
        ("f32".into(), Value::Float32(0x7fc0_0001)),
        ("f64".into(), Value::Float(0x7ff0_0000_0000_0001)),
        ("nested".into(), Value::Array(vec![Value::Float32(1)])),
    ];
    let s = seal(&vault, 1, 1, &body, None, "floats");
    let got = open(&vault, 1, &s).unwrap().body;
    assert_eq!(got.extra, body.extra);
    // The same bits on the wire.
    let plain = got.to_cbor().unwrap();
    assert!(
        plain
            .windows(5)
            .any(|w| w == [0xfa, 0x7f, 0xc0, 0x00, 0x01])
    );
    // In a known field it is not a name, a number or a flag.
    for (key, value) in [
        ("name", Value::Float32(0x3f80_0000)),
        ("created", Value::float(1.0)),
        ("favorite", Value::Float16(0)),
    ] {
        assert_eq!(
            ItemBody::from_cbor(&body_cbor_with(key, value)).unwrap_err(),
            Error::Malformed(MalformedKind::ItemBody),
            "{key}"
        );
    }
}

fn body_cbor_with(key: &str, value: Value) -> Vec<u8> {
    let mut m = vec![
        ("schema".to_owned(), Value::uint(1)),
        ("type".to_owned(), txt("note")),
        ("name".to_owned(), txt("n")),
        ("fields".to_owned(), Value::Array(vec![])),
        ("urls".to_owned(), Value::Array(vec![])),
        ("created".to_owned(), Value::uint(1)),
        ("modified".to_owned(), Value::uint(1)),
        ("favorite".to_owned(), Value::Bool(false)),
    ];
    for entry in &mut m {
        if entry.0 == key {
            entry.1 = value.clone();
        }
    }
    cbor::encode(&Value::Map(m)).unwrap()
}

#[test]
fn debug_of_a_value_and_of_a_manifest_entry_shows_no_contents() {
    let mut entry = ManifestEntry::new(1, MethodId::from_bytes([1; 16]), 1);
    entry.extra = vec![("note".into(), Value::text("secret-note"))];
    assert!(!format!("{entry:?}").contains("secret-note"));
    assert!(!format!("{:?}", Value::text("secret-note")).contains("secret"));
}

// ------------------------------------------- authentic bodies with bad padding

/// A padded buffer of `len` bytes: `plain`, the marker and zeros.
fn padded_of(plain: &[u8], len: usize) -> Vec<u8> {
    let mut padded = plain.to_vec();
    padded.push(0x80);
    padded.resize(len, 0);
    padded
}

#[test]
fn padded_seal_opens_like_the_padding_of_the_core() {
    let vault = unlocked(0x5a);
    let cbor = full_body().to_cbor().unwrap();
    let padded = padded_of(&cbor, 1_024);
    let by_hand = seal_padded(&mut rng("p"), &vault, item_id(1), 1, &padded).unwrap();
    let by_core = seal_plaintext(&mut rng("p"), &vault, item_id(1), 1, &cbor, None).unwrap();
    assert_eq!(by_hand, by_core, "same bytes, same nonces, same envelope");
    assert_eq!(open(&vault, 1, &by_hand).unwrap().body, full_body());
}

#[test]
fn authentic_bad_padding_is_decrypt_and_authentic_bad_cbor_is_malformed() {
    let vault = unlocked(0x5a);
    let cbor = full_body().to_cbor().unwrap();
    // No marker, only zeros after the body: authentic, but the padding is bad.
    let mut no_marker = cbor.clone();
    no_marker.resize(1_024, 0);
    let s = seal_padded(&mut rng("n"), &vault, item_id(1), 1, &no_marker).unwrap();
    assert_eq!(open(&vault, 1, &s).err(), Some(Error::Decrypt));
    // A byte after the marker.
    let mut trailing = padded_of(&cbor, 1_024);
    trailing[1_000] = 1;
    let s = seal_padded(&mut rng("t"), &vault, item_id(1), 1, &trailing).unwrap();
    assert_eq!(open(&vault, 1, &s).err(), Some(Error::Decrypt));
    // Good padding around bytes that are not CBOR.
    let s = seal_padded(
        &mut rng("c"),
        &vault,
        item_id(1),
        1,
        &padded_of(&[0xff, 0xff], 256),
    )
    .unwrap();
    assert!(matches!(open(&vault, 1, &s), Err(Error::Malformed(_))));
    // A length that is not a padding class is not sealed at all.
    assert_eq!(
        seal_padded(&mut rng("l"), &vault, item_id(1), 1, &[0x80; 300]).err(),
        Some(Error::Malformed(MalformedKind::Envelope))
    );
}

#[test]
fn padded_manifest_seal_opens_like_the_padding_of_the_core() {
    let vault = unlocked(0x5a);
    let manifest = sample_manifest();
    let cbor = manifest.to_cbor().unwrap();
    let by_hand =
        seal_manifest_padded_body(&mut rng("m"), &vault, 1, &padded_of(&cbor, 256)).unwrap();
    let by_core = seal_manifest_plaintext(&mut rng("m"), &vault, 1, &cbor).unwrap();
    assert_eq!(by_hand, by_core);
    assert_eq!(
        decrypt_manifest(&vault, 1, &by_hand.envelope, &by_hand.tag).unwrap(),
        manifest
    );
    // Zeros only: authentic, bad padding.
    let s = seal_manifest_padded_body(&mut rng("z"), &vault, 1, &[0u8; 256]).unwrap();
    assert_eq!(
        decrypt_manifest(&vault, 1, &s.envelope, &s.tag).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(
        seal_manifest_padded_body(&mut rng("l"), &vault, 1, &[0x80; 255]).err(),
        Some(Error::Malformed(MalformedKind::Envelope))
    );
}

/// A schema 2 body whose known keys have the wrong type, with an unknown key
/// in front. The lenient reader keeps those keys as unknown keys; writing the
/// body back must not put them twice or move them.
fn schema2_mistyped_bytes() -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        ("aaa-first".into(), Value::uint(7)),
        ("schema".into(), Value::uint(2)),
        ("type".into(), txt("login")),
        ("name".into(), Value::uint(5)),
        ("fields".into(), txt("not a list")),
        (
            "urls".into(),
            Value::Array(vec![Value::Map(vec![
                ("zz".into(), Value::uint(1)),
                ("url".into(), Value::Bool(true)),
            ])]),
        ),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(false)),
    ]))
    .unwrap()
}

#[test]
fn a_newer_schema_body_is_written_back_from_the_decoded_value() {
    let bytes = schema2_mistyped_bytes();
    let decoded = ItemBody::from_cbor(&bytes).unwrap();
    assert!(decoded.read_only);
    assert_eq!(decoded.body.to_cbor().unwrap().as_slice(), bytes.as_slice());
    // Changing the typed fields, or the number, does not change what is
    // written: the body is a view of what was read.
    let mut edited = decoded.body.clone();
    edited.name = "changed".into();
    edited.schema = 1;
    assert_eq!(edited.to_cbor().unwrap().as_slice(), bytes.as_slice());
    // And it opens again to the same body, through a real envelope.
    let vault = unlocked(0x5a);
    let s = seal_plaintext(&mut rng("m"), &vault, item_id(1), 1, &bytes, None).unwrap();
    let got = open(&vault, 1, &s).unwrap();
    assert!(got.read_only);
    assert_eq!(got.body.to_cbor().unwrap().as_slice(), bytes.as_slice());
}

#[test]
fn a_schema_1_body_is_still_rebuilt_in_schema_order() {
    // The original value is kept only for a newer schema.
    let mut v = Value::Map(vec![
        ("aaa-first".into(), Value::uint(7)),
        ("schema".into(), Value::uint(1)),
        ("type".into(), txt("note")),
        ("name".into(), txt("n")),
        ("fields".into(), Value::Array(vec![])),
        ("urls".into(), Value::Array(vec![])),
        ("created".into(), Value::uint(1)),
        ("modified".into(), Value::uint(2)),
        ("favorite".into(), Value::Bool(false)),
    ]);
    let decoded = ItemBody::from_value(v.clone()).unwrap();
    assert!(!decoded.read_only);
    if let Value::Map(e) = &mut v {
        let first = e.remove(0);
        e.push(first);
    }
    assert_eq!(decoded.body.to_value(), v);
}
