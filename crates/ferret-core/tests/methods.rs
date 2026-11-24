//! Adding and removing an unlock method, the comparison of the server's
//! list with the manifest, the PRF salt, and `vectors/internal/methods.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::{self, Value as Cbor};
use ferret_core::passkey::AAGUID;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    AuthOp, CurrentManifest, Error, InputError, MalformedKind, Manifest, ManifestEntry,
    MethodChange, MethodId, MethodListFailure as L, MethodNameError as N, PasskeyMeta, SealedItem,
    ServerMethod, UnlockedVault, WrapRecord, auth_sign, check_server_methods, decrypt_manifest,
    encrypt_manifest, manifest_add_method, manifest_remove_method, normalize_method_name,
    prf_salt_new, verify_auth_proof,
};
use ferret_core::{AuthPublicKey, Method};
use serde_json::{Value, json};

fn mid(b: u8) -> MethodId {
    method_id(b)
}

fn manifest(list: Vec<ManifestEntry>) -> Manifest {
    Manifest::new(1, list)
}

fn password() -> ManifestEntry {
    ManifestEntry::new(1, mid(0x70), 3)
}

fn recovery() -> ManifestEntry {
    ManifestEntry::new(2, mid(0x71), 1)
}

fn passkey(b: u8, credential: u8) -> ManifestEntry {
    ManifestEntry::passkey(mid(b), 1, vec![credential; 20])
}

fn prf_wrap(b: u8, credential: u8) -> WrapRecord {
    WrapRecord {
        method_id: mid(b),
        kek_generation: 2,
        method: Method::Prf {
            credential_id: vec![credential; 20],
            prf_salt: [0x33; 32],
        },
        wrap: vec![0x5a; 72],
    }
}

/// The registration data of an ordinary passkey: a device-bound key from an
/// authenticator that is not Ferret.
fn meta() -> PasskeyMeta<'static> {
    PasskeyMeta {
        aaguid: [0x9d; 16],
        name: "Work laptop",
        be: false,
        bs: false,
    }
}

fn sealed(vault: &UnlockedVault, rev: u64, m: &Manifest) -> SealedItem {
    let mut rng = TestRng::new(b"methods tests");
    encrypt_manifest(&mut rng, vault, rev, m).unwrap()
}

fn row(s: &SealedItem) -> CurrentManifest<'_> {
    CurrentManifest {
        rev: s.rev,
        envelope: &s.envelope,
        tag: &s.tag,
    }
}

// ------------------------------------------------------------- the lists

#[test]
fn with_method_adds_one_passkey_and_keeps_the_rest() {
    let mut m = manifest(vec![password(), recovery()]);
    m.extra
        .push(("future".into(), ferret_core::cbor::Value::uint(1)));
    let next = m.with_method(&prf_wrap(0x72, 1), &meta()).unwrap();
    assert_eq!(next.methods.len(), 3);
    assert_eq!(&next.methods[..2], &m.methods[..]);
    assert_eq!(next.extra, m.extra);
    let added = &next.methods[2];
    assert_eq!(
        (added.method_type, added.method_id, added.kek_generation),
        (3, mid(0x72), 2)
    );
    assert_eq!(added.credential_id.as_deref(), Some(&[1u8; 20][..]));
    assert_eq!(added.name.as_deref(), Some("Work laptop"));
    assert_eq!((added.be, added.bs), (Some(false), Some(false)));
}

#[test]
fn with_method_refuses_what_the_design_does_not_allow() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let malformed = Err(Error::Malformed(MalformedKind::Entries));
    // An id or a credential the manifest lists already.
    assert_eq!(
        m.with_method(&prf_wrap(0x72, 9), &meta()).map(|_| ()),
        malformed
    );
    assert_eq!(
        m.with_method(&prf_wrap(0x73, 1), &meta()).map(|_| ()),
        malformed
    );
    assert_eq!(
        m.with_method(&prf_wrap(0x70, 9), &meta()).map(|_| ()),
        malformed
    );
    // Another kind of wrap.
    let mut recovery_wrap = prf_wrap(0x74, 2);
    recovery_wrap.method = Method::Recovery;
    assert_eq!(
        m.with_method(&recovery_wrap, &meta()).map(|_| ()),
        Err(Error::Unsupported)
    );
    // Length, credential and salt.
    let mut long = prf_wrap(0x74, 2);
    long.wrap = vec![0; 104];
    assert_eq!(
        m.with_method(&long, &meta()).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Envelope))
    );
    let mut empty = prf_wrap(0x74, 2);
    empty.method = Method::Prf {
        credential_id: vec![],
        prf_salt: [1; 32],
    };
    assert_eq!(
        m.with_method(&empty, &meta()).map(|_| ()),
        Err(Error::InvalidInput(InputError::TooShort))
    );
    let mut zero = prf_wrap(0x74, 2);
    zero.method = Method::Prf {
        credential_id: vec![2; 20],
        prf_salt: [0; 32],
    };
    assert_eq!(
        m.with_method(&zero, &meta()).map(|_| ()),
        Err(Error::InvalidInput(InputError::AllZero))
    );
    // A generation past 2^32 - 1.
    let mut high = prf_wrap(0x74, 2);
    high.kek_generation = 1 << 32;
    assert_eq!(m.with_method(&high, &meta()).map(|_| ()), malformed);
    // The most methods a manifest lists.
    let full = manifest(
        (0..64u8)
            .map(|n| ManifestEntry::new(9, mid(n.saturating_add(1)), 1))
            .collect(),
    );
    assert_eq!(
        full.with_method(&prf_wrap(0xee, 2), &meta()).map(|_| ()),
        malformed
    );
}

#[test]
fn without_method_keeps_the_last_password_and_the_last_recovery() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let last = Err(Error::InvalidInput(InputError::LastMethod));
    assert_eq!(m.without_method(&mid(0x70)).map(|_| ()), last);
    assert_eq!(m.without_method(&mid(0x71)).map(|_| ()), last);
    assert_eq!(
        m.without_method(&mid(0x7f)).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Entries))
    );
    let next = m.without_method(&mid(0x72)).unwrap();
    assert_eq!(next.methods, vec![password(), recovery()]);
    // A manifest with two recovery methods (as a hand-made one may) lets
    // one of them go.
    let two = manifest(vec![
        password(),
        recovery(),
        ManifestEntry::new(2, mid(0x76), 1),
    ]);
    assert_eq!(two.without_method(&mid(0x71)).unwrap().methods.len(), 2);
}

#[test]
fn the_server_list_must_match_the_manifest() {
    let m = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let s = |ty: u8, b: u8, g: u64| ServerMethod {
        method_type: ty,
        method_id: mid(b),
        kek_generation: g,
    };
    let same = [s(3, 0x72, 1), s(1, 0x70, 3), s(2, 0x71, 1)];
    check_server_methods(&m, &same).unwrap();
    let fail = |kind: L| Err(Error::MethodList(kind));
    assert_eq!(
        check_server_methods(&m, &[same[0], same[1], same[2], s(3, 0x7e, 1)]),
        fail(L::Unknown)
    );
    assert_eq!(
        check_server_methods(&m, &[same[0], same[1], same[2], same[0]]),
        fail(L::Unknown)
    );
    assert_eq!(
        check_server_methods(&m, &[s(3, 0x72, 2), same[1], same[2]]),
        fail(L::Changed)
    );
    assert_eq!(
        check_server_methods(&m, &[s(4, 0x72, 1), same[1], same[2]]),
        fail(L::Changed)
    );
    assert_eq!(
        check_server_methods(&m, &[same[1], same[2]]),
        fail(L::Missing)
    );
    // Unknown before changed before missing.
    assert_eq!(
        check_server_methods(&m, &[s(1, 0x70, 9), s(3, 0x7e, 1)]),
        fail(L::Unknown)
    );
    assert_eq!(check_server_methods(&m, &[s(1, 0x70, 9)]), fail(L::Changed));
    check_server_methods(&manifest(vec![]), &[]).unwrap();
}

// ------------------------------------------------- name, flags and AAGUID

fn name_of(raw: &str) -> Result<String, Error> {
    normalize_method_name(raw)
}

#[test]
fn the_prf_add_body_carries_aaguid_in_key_order() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut rng = TestRng::new(b"aaguid");
    let m = PasskeyMeta {
        aaguid: [
            0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcf, 0xbc, 0x9b, 0x0e, 0x6b, 0x28, 0x3a,
            0xf1, 0x55,
        ],
        ..meta()
    };
    let add = manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &m).unwrap();
    let text = String::from_utf8(add.body.clone()).unwrap();
    let want = format!(
        "{{\"method_type\":3,\"method_id\":\"{}\",\"wrap\":\"{}\",\"kek_generation\":2,\"credential_id\":\"{}\",\"prf_salt\":\"{}\",\"aaguid\":\"fbfc3007154e4ecfbc9b0e6b283af155\",\"manifest\":{{\"rev\":3,\"envelope\":\"{}\",\"tag\":\"{}\"}}}}",
        "72".repeat(16),
        "5a".repeat(72),
        "01".repeat(20),
        "33".repeat(32),
        he(&add.sealed.envelope),
        he(&add.sealed.tag),
    );
    assert_eq!(text, want);
    // The proof covers the AAGUID: it is part of the signed bytes.
    let nonce = [7u8; 32];
    let proof = add.sign(&vault, &nonce).unwrap();
    let mut changed = add.clone();
    changed.body = text
        .replace(
            "fbfc3007154e4ecfbc9b0e6b283af155",
            "00000000000000000000000000000000",
        )
        .into_bytes();
    assert_ne!(changed.sign(&vault, &nonce).unwrap(), proof);
}

#[test]
fn a_zero_aaguid_is_accepted_and_shown_as_unknown() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut rng = TestRng::new(b"zero");
    let zero = PasskeyMeta {
        aaguid: [0; 16],
        ..meta()
    };
    let add = manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &zero).unwrap();
    let text = String::from_utf8(add.body.clone()).unwrap();
    assert!(text.contains(&format!("\"aaguid\":\"{}\",\"manifest\"", "00".repeat(16))));
    // Nothing is decided from it: the method is listed like any other, and
    // the AAGUID is not in the manifest at all (the server keeps it for
    // display, where all zero is "unknown").
    let listed = add.manifest.prf_methods();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].method_id, mid(0x72));
    assert!(!String::from_utf8_lossy(&add.manifest.to_cbor().unwrap()).contains("aaguid"));
}

#[test]
fn ferrets_own_aaguid_is_refused_in_the_body() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let own = PasskeyMeta {
        aaguid: AAGUID,
        ..meta()
    };
    // Refused before anything is drawn, and by the manifest step too.
    let mut none = ReplayRng::new(vec![]);
    assert_eq!(
        manifest_add_method(&mut none, &vault, &row(&cur), prf_wrap(0x72, 1), &own).map(|_| ()),
        Err(Error::InvalidState)
    );
    none.finish().unwrap();
    assert_eq!(
        manifest(vec![password()])
            .with_method(&prf_wrap(0x72, 1), &own)
            .map(|_| ()),
        Err(Error::InvalidState)
    );
    // One byte different is another authenticator.
    let mut other = AAGUID;
    other[15] ^= 1;
    let ok = PasskeyMeta {
        aaguid: other,
        ..meta()
    };
    let mut rng = TestRng::new(b"other");
    manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &ok).unwrap();
}

#[test]
fn the_name_and_synced_flag_are_inside_the_sealed_manifest() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut rng = TestRng::new(b"sealed");
    let m = PasskeyMeta {
        name: "Touch ID (kitchen)",
        be: true,
        bs: true,
        ..meta()
    };
    let add = manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &m).unwrap();
    // The request body, which the server reads, has neither.
    let body = String::from_utf8(add.body.clone()).unwrap();
    assert!(!body.contains("Touch ID"));
    assert!(!body.contains("\"be\"") && !body.contains("\"bs\"") && !body.contains("synced"));
    // The sealed row does not hold the name in the clear either.
    let name = "Touch ID (kitchen)".as_bytes();
    assert!(!add.sealed.envelope.windows(name.len()).any(|w| w == name));
    // The vault key opens it, and then the entry has both.
    let opened = decrypt_manifest(
        &vault,
        add.sealed.rev,
        &add.sealed.envelope,
        &add.sealed.tag,
    )
    .unwrap();
    let entry = &opened.methods[2];
    assert_eq!(entry.name.as_deref(), Some("Touch ID (kitchen)"));
    assert_eq!((entry.be, entry.bs), (Some(true), Some(true)));
    // Another vault's key does not.
    let other = unlocked(0x5b);
    assert_eq!(
        decrypt_manifest(
            &other,
            add.sealed.rev,
            &add.sealed.envelope,
            &add.sealed.tag
        )
        .map(|_| ()),
        Err(Error::Decrypt)
    );
    // And the entry survives the next change of the list.
    let mut rng = TestRng::new(b"next");
    let next = manifest_add_method(
        &mut rng,
        &vault,
        &row(&add.sealed),
        prf_wrap(0x73, 2),
        &meta(),
    )
    .unwrap();
    assert_eq!(next.manifest.methods[2], *entry);
    let gone = manifest_remove_method(&mut rng, &vault, &row(&next.sealed), &mid(0x73)).unwrap();
    assert_eq!(gone.manifest.methods[2], *entry);
}

#[test]
fn synced_follows_be_not_bs() {
    let vault = unlocked(0x5a);
    let mut current = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut want = vec![];
    // (be, bs, synced): a synced key can have BS 0 at registration and 1
    // later; BE never changes, so only BE decides.
    for (n, (be, bs, synced)) in [
        (true, true, true),
        (true, false, true),
        (false, false, false),
    ]
    .into_iter()
    .enumerate()
    {
        let id = 0x80 + u8::try_from(n).unwrap();
        let m = PasskeyMeta { be, bs, ..meta() };
        let mut rng = TestRng::new(&[id]);
        let wrap = WrapRecord {
            method: Method::Prf {
                credential_id: vec![id; 20],
                prf_salt: [0x33; 32],
            },
            ..prf_wrap(id, 1)
        };
        let add = manifest_add_method(&mut rng, &vault, &row(&current), wrap, &m).unwrap();
        current = add.sealed.clone();
        want.push((mid(id), synced, Some(bs)));
    }
    let opened = decrypt_manifest(&vault, current.rev, &current.envelope, &current.tag).unwrap();
    let got: Vec<_> = opened
        .prf_methods()
        .into_iter()
        .map(|m| (m.method_id, m.synced, m.bs))
        .collect();
    assert_eq!(got, want);
    // BS without BE is not a conformant registration: refused, nothing drawn.
    let mut none = ReplayRng::new(vec![]);
    let odd = PasskeyMeta {
        be: false,
        bs: true,
        ..meta()
    };
    assert_eq!(
        manifest_add_method(&mut none, &vault, &row(&current), prf_wrap(0x90, 1), &odd).map(|_| ()),
        Err(Error::InvalidState)
    );
    none.finish().unwrap();
    // An entry that states no flag (not made by this version) is shown as
    // "this device only", and an entry of another type is not listed.
    let plain = manifest(vec![password(), recovery(), passkey(0x72, 1)]);
    let listed = plain.prf_methods();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].synced);
    assert_eq!((listed[0].name.as_deref(), listed[0].bs), (None, None));
    assert_eq!(listed[0].credential_id, vec![1; 20]);
}

#[test]
fn a_name_is_1_to_64_characters_without_control_characters() {
    // The edges of the length, counted in characters after NFC and trim.
    assert_eq!(name_of("a").unwrap(), "a");
    assert_eq!(name_of(&"a".repeat(64)).unwrap(), "a".repeat(64));
    assert_eq!(name_of(&"a".repeat(65)), Err(Error::MethodName(N::TooLong)));
    // Characters, not bytes: 64 two-byte characters pass.
    assert_eq!(name_of(&"\u{e9}".repeat(64)).unwrap().chars().count(), 64);
    assert_eq!(
        name_of(&"\u{e9}".repeat(65)),
        Err(Error::MethodName(N::TooLong))
    );
    // The length is the NFC form's: 64 letters with a combining accent are
    // 64 characters, 65 are not.
    assert_eq!(
        name_of(&"e\u{301}".repeat(64)).unwrap(),
        "\u{e9}".repeat(64)
    );
    assert_eq!(
        name_of(&"e\u{301}".repeat(65)),
        Err(Error::MethodName(N::TooLong))
    );
    // NFC and trim: what is stored is the normal form.
    assert_eq!(name_of("  Cafe\u{301} \t").unwrap(), "Caf\u{e9}");
    assert_eq!(name_of("\u{212b}").unwrap(), "\u{c5}");
    // Nothing, or only white space.
    assert_eq!(name_of(""), Err(Error::MethodName(N::Empty)));
    assert_eq!(
        name_of(" \t\u{a0}\u{3000}"),
        Err(Error::MethodName(N::Empty))
    );
    // Control characters, separators, bidirectional controls, the zero width
    // space and the byte order mark: refused inside a name.
    for bad in [
        "\0", "\n", "\r", "\t", "\u{7f}", "\u{85}", "\u{9f}", "\u{2028}", "\u{2029}", "\u{61c}",
        "\u{200e}", "\u{200f}", "\u{202a}", "\u{202b}", "\u{202c}", "\u{202d}", "\u{202e}",
        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}", "\u{200b}", "\u{feff}",
    ] {
        assert_eq!(
            name_of(&format!("a{bad}b")),
            Err(Error::MethodName(N::BadCharacter)),
            "{bad:?}"
        );
    }
    // Bad characters are judged before the length, like a folder name.
    assert_eq!(
        name_of(&format!("{}\u{202e}", "a".repeat(70))),
        Err(Error::MethodName(N::BadCharacter))
    );
    // The joiners that scripts and emoji need are allowed.
    assert!(name_of("\u{1f468}\u{200d}\u{1f4bb} desk").is_ok());
    assert!(name_of("\u{200c}a").is_ok());
    // The same rule at the door of the manifest.
    let m = manifest(vec![password(), recovery()]);
    let too_long = "x".repeat(65);
    for (raw, err) in [
        ("", N::Empty),
        ("a\nb", N::BadCharacter),
        (too_long.as_str(), N::TooLong),
    ] {
        let meta = PasskeyMeta {
            name: raw,
            ..meta()
        };
        assert_eq!(
            m.with_method(&prf_wrap(0x72, 1), &meta).map(|_| ()),
            Err(Error::MethodName(err))
        );
    }
    // The codes are stable.
    assert_eq!(Error::MethodName(N::Empty).code(), "method_name_empty");
    assert_eq!(Error::MethodName(N::TooLong).code(), "method_name_too_long");
    assert_eq!(
        Error::MethodName(N::BadCharacter).code(),
        "method_name_bad_character"
    );
    for e in [N::Empty, N::TooLong, N::BadCharacter] {
        assert!(Error::ALL.contains(&Error::MethodName(e)));
    }
}

/// What a reader without `n`, `be` and `bs` does: it takes the keys it knows
/// from each entry and writes them back, with every other key after them in
/// the order it read them.
fn older_reader_roundtrip(bytes: &[u8]) -> Vec<u8> {
    const KNOWN: [&str; 4] = ["t", "id", "g", "c"];
    let top = cbor::decode(bytes).unwrap().into_map().unwrap();
    let rewritten = top
        .into_iter()
        .map(|(k, v)| {
            if k != "methods" {
                return (k, v);
            }
            let entries = v
                .into_array()
                .unwrap()
                .into_iter()
                .map(|entry| {
                    let map = entry.into_map().unwrap();
                    let (known, rest): (Vec<_>, Vec<_>) = map
                        .into_iter()
                        .partition(|(k, _)| KNOWN.contains(&k.as_str()));
                    let mut out: Vec<_> = KNOWN
                        .iter()
                        .filter_map(|n| known.iter().find(|(k, _)| k == n).cloned())
                        .collect();
                    out.extend(rest);
                    Cbor::Map(out)
                })
                .collect();
            (k, Cbor::Array(entries))
        })
        .collect();
    cbor::encode(&Cbor::Map(rewritten)).unwrap()
}

#[test]
fn an_older_reader_keeps_the_new_manifest_keys() {
    let m = PasskeyMeta {
        name: "Phone",
        be: true,
        bs: false,
        ..meta()
    };
    let mut list = manifest(vec![password(), recovery()]);
    list.methods[0].extra = vec![("label".into(), Cbor::text("kept"))];
    let next = list.with_method(&prf_wrap(0x72, 1), &m).unwrap();
    let bytes = next.to_cbor().unwrap();
    // The entry holds the three new keys after the credential id.
    let entry = next.methods[2].clone();
    assert_eq!(
        (entry.name.as_deref(), entry.be, entry.bs),
        (Some("Phone"), Some(true), Some(false))
    );
    // A reader that does not know them writes the same bytes back...
    let back = older_reader_roundtrip(&bytes);
    assert_eq!(back, bytes);
    // ... and this version reads them from what the older reader wrote.
    assert_eq!(Manifest::from_cbor(&back).unwrap(), next);
    // Unknown keys of a later version keep their place after the new ones.
    let mut later = next.clone();
    later.methods[2].extra = vec![("z".into(), Cbor::uint(9))];
    let later_bytes = later.to_cbor().unwrap();
    assert_eq!(older_reader_roundtrip(&later_bytes), later_bytes);
    assert_eq!(Manifest::from_cbor(&later_bytes).unwrap(), later);
    // The three keys are typed: a name that is not text or a flag that is
    // not a boolean is not a manifest.
    for (key, value) in [
        ("n", Cbor::uint(1)),
        ("be", Cbor::uint(1)),
        ("bs", Cbor::text("yes")),
    ] {
        let mut bad = next.to_value();
        let Cbor::Map(top) = &mut bad else { panic!() };
        let Some((_, Cbor::Array(entries))) = top.iter_mut().find(|(k, _)| k == "methods") else {
            panic!()
        };
        let Cbor::Map(fields) = &mut entries[2] else {
            panic!()
        };
        fields.iter_mut().find(|(k, _)| k == key).unwrap().1 = value;
        assert_eq!(
            Manifest::from_cbor(&cbor::encode(&bad).unwrap()),
            Err(Error::Malformed(MalformedKind::ItemBody)),
            "{key}"
        );
    }
}

// -------------------------------------------------------------- requests

#[test]
fn add_and_remove_make_the_next_manifest_and_a_signed_body() {
    let vault = unlocked(0x5a);
    let before = manifest(vec![password(), recovery()]);
    let cur = sealed(&vault, 2, &before);
    let mut rng = TestRng::new(b"add");
    let add =
        manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &meta()).unwrap();

    assert_eq!(add.op, AuthOp::UnlockMethodAdd);
    assert_eq!(
        add.manifest,
        before.with_method(&prf_wrap(0x72, 1), &meta()).unwrap()
    );
    assert_eq!(add.sealed.rev, 3);
    assert_eq!(
        decrypt_manifest(
            &vault,
            add.sealed.rev,
            &add.sealed.envelope,
            &add.sealed.tag
        )
        .unwrap(),
        add.manifest
    );
    let text = String::from_utf8(add.body.clone()).unwrap();
    assert!(text.starts_with("{\"method_type\":3,\"method_id\":\"72727272"));
    assert!(text.contains("\"kek_generation\":2,"));
    assert!(text.ends_with("}}"));
    assert!(text.contains(&format!("\"envelope\":\"{}\"", he(&add.sealed.envelope))));

    // The proof is over exactly this body.
    let nonce = [0xa5u8; 32];
    let proof = add.sign(&vault, &nonce).unwrap();
    verify_auth_proof(
        &AuthPublicKey::new(add.pk_a),
        AuthOp::UnlockMethodAdd,
        &vault.context().account_id,
        &nonce,
        vault.context().vk_epoch,
        &add.body,
        &proof,
    )
    .unwrap();
    assert_eq!(
        proof,
        auth_sign(&vault, AuthOp::UnlockMethodAdd, &nonce, &add.body).unwrap()
    );

    // Remove it again.
    let mut rng = TestRng::new(b"remove");
    let removed = manifest_remove_method(&mut rng, &vault, &row(&add.sealed), &mid(0x72)).unwrap();
    assert_eq!(removed.op, AuthOp::UnlockMethodRemove);
    assert_eq!(removed.manifest, before);
    assert_eq!(removed.sealed.rev, 4);
    let text = String::from_utf8(removed.body.clone()).unwrap();
    assert!(text.starts_with("{\"method_id\":\"72727272"));
    assert!(!text.contains("method_type"));
}

#[test]
fn a_change_is_signed_only_by_the_vault_it_was_made_for() {
    let vault = unlocked(0x5a);
    let other = unlocked(0x5b);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut rng = TestRng::new(b"who");
    let add =
        manifest_add_method(&mut rng, &vault, &row(&cur), prf_wrap(0x72, 1), &meta()).unwrap();
    assert_eq!(
        add.sign(&other, &[1; 32]),
        Err(Error::Pinned(ferret_core::PinnedField::AuthKey))
    );
}

#[test]
fn a_refused_change_draws_nothing() {
    let vault = unlocked(0x5a);
    let cur = sealed(&vault, 2, &manifest(vec![password(), recovery()]));
    let mut none = ReplayRng::new(vec![]);
    assert_eq!(
        manifest_remove_method(&mut none, &vault, &row(&cur), &mid(0x70)).map(|_| ()),
        Err(Error::InvalidInput(InputError::LastMethod))
    );
    assert_eq!(
        manifest_add_method(&mut none, &vault, &row(&cur), prf_wrap(0x70, 1), &meta()).map(|_| ()),
        Err(Error::Malformed(MalformedKind::Entries))
    );
    none.finish().unwrap();
}

#[test]
fn the_current_manifest_must_be_the_vaults_own_and_current() {
    let vault = unlocked(0x5a);
    let m = manifest(vec![password(), recovery()]);
    let cur = sealed(&vault, 2, &m);
    let mut none = ReplayRng::new(vec![]);
    let mut stale = row(&cur);
    stale.rev = 3;
    assert_eq!(
        manifest_add_method(&mut none, &vault, &stale, prf_wrap(0x72, 1), &meta()).map(|_| ()),
        Err(Error::Decrypt)
    );
    let mut tag = cur.tag;
    tag[0] ^= 1;
    let forged = CurrentManifest {
        tag: &tag,
        ..row(&cur)
    };
    assert_eq!(
        manifest_remove_method(&mut none, &vault, &forged, &mid(0x72)).map(|_| ()),
        Err(Error::Decrypt)
    );
}

// ---------------------------------------------------------------- salt

#[test]
fn prf_salt_new_is_one_draw_of_32_bytes() {
    let mut rng = ReplayRng::new(vec![vec![7; 32]]);
    assert_eq!(prf_salt_new(&mut rng), [7; 32]);
    rng.finish().unwrap();
    let mut a = TestRng::new(b"a");
    let mut b = TestRng::new(b"b");
    assert_ne!(prf_salt_new(&mut a), prf_salt_new(&mut b));
}

// ---------------------------------------------------------------- vectors

fn entry_of(v: &Value) -> ManifestEntry {
    let id = MethodId::from_bytes(hexn(&v["id"]));
    let generation = u64s(&v["generation"]);
    match v.get("credential_id") {
        Some(c) => ManifestEntry::passkey(id, generation, hex(c)),
        None => ManifestEntry::new(v["type"].as_u64().unwrap() as u8, id, generation),
    }
}

fn change_output(c: &MethodChange, input: &Value, vault: &UnlockedVault) -> Result<Value, Error> {
    let mut out = json!({
        "manifest": he(&c.manifest.to_cbor()?),
        "sealed": {
            "rev": c.sealed.rev.to_string(),
            "envelope": he(&c.sealed.envelope),
            "tag": he(&c.sealed.tag),
        },
        "body": he(&c.body),
    });
    if let Some(sign) = input.get("sign") {
        out["op"] = json!(c.op.name());
        out["pk_a"] = json!(he(&c.pk_a));
        out["proof"] = json!(he(&c.sign(vault, &hexn(&sign["nonce"]))?));
    }
    Ok(out)
}

fn methods_case(
    c: &ferret_core::testing::vector::Case,
    rng: &mut ReplayRng,
) -> Result<Outcome, Error> {
    let input = &c.input;
    let output = match c.op.as_str() {
        "prf.salt_new" => json!({ "salt": he(&prf_salt_new(rng)) }),
        "methods.check_server" => {
            let m = &input["manifest"];
            let list = manifest(
                m["methods"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(entry_of)
                    .collect(),
            );
            let server: Vec<ServerMethod> = input["server"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| ServerMethod {
                    method_type: s["method_type"].as_u64().unwrap() as u8,
                    method_id: MethodId::from_bytes(hexn(&s["method_id"])),
                    kek_generation: u64s(&s["kek_generation"]),
                })
                .collect();
            check_server_methods(&list, &server)?;
            json!({ "ok": true })
        }
        "methods.add" | "methods.remove" => {
            let vault = vault_of(input);
            let envelope = hex(&input["current"]["envelope"]);
            let tag: [u8; 32] = hexn(&input["current"]["tag"]);
            let current = CurrentManifest {
                rev: u64s(&input["current"]["rev"]),
                envelope: &envelope,
                tag: &tag,
            };
            let change = if c.op == "methods.add" {
                let w = &input["wrap"];
                let method = if w["method_type"].as_u64() == Some(3) {
                    Method::Prf {
                        credential_id: hex(&w["credential_id"]),
                        prf_salt: hexn(&w["prf_salt"]),
                    }
                } else {
                    Method::Recovery
                };
                let wrap = WrapRecord {
                    method_id: MethodId::from_bytes(hexn(&w["method_id"])),
                    kek_generation: u64s(&w["kek_generation"]),
                    method,
                    wrap: hex(&w["wrap"]),
                };
                let p = &input["passkey"];
                let name = String::from_utf8(hex(&p["name_utf8"])).unwrap();
                let meta = PasskeyMeta {
                    aaguid: hexn(&p["aaguid"]),
                    name: &name,
                    be: p["be"].as_bool().unwrap(),
                    bs: p["bs"].as_bool().unwrap(),
                };
                manifest_add_method(rng, &vault, &current, wrap, &meta)?
            } else {
                let id = MethodId::from_bytes(hexn(&input["method_id"]));
                manifest_remove_method(rng, &vault, &current, &id)?
            };
            change_output(&change, input, &vault)?
        }
        other => panic!("unknown op {other}"),
    };
    Ok(Outcome {
        output,
        intermediate: None,
    })
}

#[test]
fn methods_vectors_from_file() {
    let file = load_ops("methods.json", |_| true);
    let report = ferret_core::testing::vector::run_all(&file, methods_case);
    assert_all_passed(&report, 40);
}

#[test]
fn vectors_methods_add_body_pass() {
    let file = load_ops("methods.json", |op| op == "methods.add");
    let report = ferret_core::testing::vector::run_all(&file, methods_case);
    assert_all_passed(&report, 14);
    // Every accepted add carries the AAGUID of its input in the body, after
    // the salt and before the manifest, and neither the name nor the flags.
    let mut accepted = 0;
    for case in &file.cases {
        let Some(expect) = &case.expect else { continue };
        let body = String::from_utf8(hex(&expect["body"])).unwrap();
        let aaguid = case.input["passkey"]["aaguid"].as_str().unwrap();
        let salt = case.input["wrap"]["prf_salt"].as_str().unwrap();
        assert!(
            body.contains(&format!(
                "\"prf_salt\":\"{salt}\",\"aaguid\":\"{aaguid}\",\"manifest\":{{"
            )),
            "{}",
            case.id
        );
        assert!(!body.contains("\"be\""), "{}", case.id);
        accepted += 1;
    }
    assert!(accepted >= 4, "only {accepted} accepted cases");
}
