//! Wrapping the vault key and opening it again: lengths, AAD bytes, key
//! commitment, the single error, and the vectors in
//! `vectors/internal/wrap.json` and `vectors/internal/unlock.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::keys::{commit_of, kek_bytes, unlocked_vault_keys, wrap_aad};
use ferret_core::testing::prim::{aead_open_count, aead_seal, hkdf_sha256};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, TestRng, hex_encode};
use ferret_core::{
    AccountId, Error, ExportKey, Kek, KekDevPin, KsfProfile, Method, MethodId, Pin, PrfOutput,
    RecoveryKey, UnlockedVault, VaultContext, VaultId, VaultKey, WrapRecord, unwrap_vk, wrap_vk,
};
use serde_json::{Value, json};

/// A KEK for the tests: fixed bytes.
fn kek(b: u8) -> Kek {
    Kek::from_test_bytes([b; 32])
}

fn seal(method: Method, c: &VaultContext, k: &Kek) -> WrapRecord {
    let mut rng = TestRng::new(b"wrap tests");
    wrap_vk(&mut rng, c, &vk(0x5a), k, method_id(0x33), 1, method).unwrap()
}

// ------------------------------------------------------------- lengths

#[test]
fn wrap_password_is_104_bytes_others_72() {
    let c = ctx();
    for method in all_methods() {
        let rec = seal(method.clone(), &c, &kek(9));
        let want = match method {
            Method::Password { .. } | Method::Pin { .. } => 104,
            _ => 72,
        };
        assert_eq!(rec.wrap.len(), want, "{method:?}");
        assert_eq!(rec.method, method);
        assert_eq!(rec.method_id, method_id(0x33));
        assert_eq!(rec.kek_generation, 1);
    }
}

#[test]
fn wrap_draws_exactly_one_nonce_of_24_bytes() {
    let mut rng = ReplayRng::new(vec![vec![0x77; 24]]);
    let rec = wrap_vk(
        &mut rng,
        &ctx(),
        &vk(1),
        &kek(9),
        method_id(1),
        1,
        password_method(),
    )
    .unwrap();
    rng.finish().unwrap();
    assert_eq!(&rec.wrap[..24], &[0x77; 24], "the nonce leads the wrap");
}

#[test]
fn wrap_roundtrip_all_methods() {
    let c = ctx();
    for method in all_methods() {
        let k = kek(9);
        let rec = seal(method.clone(), &c, &k);
        let vault = unwrap_vk(&c, &k, &rec).unwrap();
        assert_eq!(unlocked_vault_keys(&vault)[0], [0x5a; 32], "{method:?}");
        assert_eq!(vault.context(), &c);
        let direct = UnlockedVault::from_vault_key(c, vk(0x5a)).unwrap();
        assert_eq!(vault.auth_public_key(), direct.auth_public_key());
    }
}

#[test]
fn wrap_nonces_are_fresh_for_every_wrap() {
    let c = ctx();
    let mut rng = TestRng::new(b"fresh");
    let a = wrap_vk(
        &mut rng,
        &c,
        &vk(1),
        &kek(9),
        method_id(1),
        1,
        Method::Recovery,
    )
    .unwrap();
    let b = wrap_vk(
        &mut rng,
        &c,
        &vk(1),
        &kek(9),
        method_id(1),
        1,
        Method::Recovery,
    )
    .unwrap();
    assert_ne!(a.wrap[..24], b.wrap[..24]);
    assert_ne!(a.wrap, b.wrap);
}

// ---------------------------------------------------------- AAD, by hand

fn kdf_p1() -> Vec<u8> {
    // m = 65 536 KiB, t = 3, p = 1, each u32be.
    [65_536u32, 3, 1]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect()
}

/// The generic part of `aad_wrap`, in the order of Fase 1 § 4.3.
fn generic_aad(method_type: u8, extra: &[Vec<u8>]) -> Vec<u8> {
    let mut parts = vec![
        label("ferret/v1/wrap"),
        t(0x03, &[1]),                // suite
        t(0x10, &[0x11; 16]),         // account_id
        t(0x11, &[0x22; 16]),         // vault_id
        t(0x14, &[method_type]),      // method_type
        t(0x13, &[0x33; 16]),         // method_id
        t(0x20, &1u64.to_be_bytes()), // vk_epoch
        t(0x21, &1u64.to_be_bytes()), // kek_generation
    ];
    parts.extend_from_slice(extra);
    parts.concat()
}

#[test]
fn wrap_aad_exact_bytes() {
    // Spec: Fase 1 § 4.3 (tag order: label, suite, account, vault,
    // method_type, method_id, vk_epoch, kek_generation, then the
    // method-specific fields) and § 7.2 (the shorter PIN AAD).
    let c = ctx();
    let k = kek(9);

    let rec = seal(password_method(), &c, &k);
    assert_eq!(
        wrap_aad(&c, &rec).unwrap(),
        generic_aad(1, &[t(0x30, &kdf_p1())]),
        "password"
    );
    // The first bytes, spelled out: label tag, length 14, "ferret/v1/wrap",
    // then suite 1.
    assert_eq!(
        he(&wrap_aad(&c, &rec).unwrap()[..21]),
        "01000e6665727265742f76312f777261700300 0101".replace(' ', ""),
    );

    let rec = seal(Method::Recovery, &c, &k);
    assert_eq!(wrap_aad(&c, &rec).unwrap(), generic_aad(2, &[]), "recovery");

    let rec = seal(prf_method(), &c, &k);
    let cred: Vec<u8> = (0u8..16).map(|i| 0xa0 + i).collect();
    assert_eq!(
        wrap_aad(&c, &rec).unwrap(),
        generic_aad(3, &[t(0x31, &cred), t(0x32, &[0xb0; 32])]),
        "prf"
    );

    let rec = seal(Method::Device, &c, &k);
    assert_eq!(wrap_aad(&c, &rec).unwrap(), generic_aad(5, &[]), "device");

    // The PIN AAD of § 7.2 in the order of aad_wrap: TLV[label="ferret/v1/pin",
    // suite, account_id, vault_id, method_type=4, method_id, vk_epoch,
    // device_salt]. No kek_generation.
    let rec = seal(pin_method(), &c, &k);
    assert_eq!(
        wrap_aad(&c, &rec).unwrap(),
        [
            label("ferret/v1/pin"),
            t(0x03, &[1]),
            t(0x10, &[0x11; 16]),
            t(0x11, &[0x22; 16]),
            t(0x14, &[4]),
            t(0x13, &[0x33; 16]),
            t(0x20, &1u64.to_be_bytes()),
            t(0x37, &[0xc0; 16]),
        ]
        .concat(),
        "pin"
    );
}

#[test]
fn aad_wrap_has_no_version_field() {
    // `version` is in the item and item-key AADs but NOT in
    // `aad_wrap`. The tags of each AAD, in order.
    let c = ctx();
    let k = kek(9);
    let tags = |method: Method| -> Vec<u8> {
        let rec = seal(method, &c, &k);
        parse_tlv(&wrap_aad(&c, &rec).unwrap())
            .iter()
            .map(|(tag, _)| *tag)
            .collect()
    };
    let generic = [0x01, 0x03, 0x10, 0x11, 0x14, 0x13, 0x20, 0x21];
    assert_eq!(
        tags(password_method()),
        [generic.as_slice(), &[0x30]].concat()
    );
    assert_eq!(tags(Method::Recovery), generic);
    assert_eq!(
        tags(prf_method()),
        [generic.as_slice(), &[0x31, 0x32]].concat()
    );
    assert_eq!(tags(Method::Device), generic);
    assert_eq!(
        tags(pin_method()),
        [0x01, 0x03, 0x10, 0x11, 0x14, 0x13, 0x20, 0x37]
    );
    for method in all_methods() {
        assert!(
            !tags(method.clone()).contains(&0x02),
            "{method:?}: no `version` (0x02) in a wrap AAD"
        );
    }
}

#[test]
fn password_aad_kdf_is_the_profile_1_parameters() {
    // Spec: Fase 1 § 3.1 (kdf = m_kib u32be ‖ t u32be ‖ p u32be, 12 bytes)
    // and § 4.2 (profile 1 = 64 MiB, t = 3, p = 1).
    assert_eq!(he(&kdf_p1()), "00010000000000030000 0001".replace(' ', ""));
    let c = ctx();
    let rec = seal(password_method(), &c, &kek(9));
    let fields = parse_tlv(&wrap_aad(&c, &rec).unwrap());
    assert_eq!(fields.last().unwrap(), &(0x30, kdf_p1()));
}

// ---------------------------------------------------- commit and the AEAD

#[test]
fn commit_is_hkdf_with_empty_salt_over_the_kek() {
    // Spec: Fase 1 § 4.3: commit = HKDF(salt = none, ikm = KEK,
    // info = "ferret/v1/commit"). No salt is 32 zero bytes (RFC 5869).
    let k = kek(9);
    let mut want = [0u8; 32];
    hkdf_sha256(&[0u8; 32], &[9; 32], b"ferret/v1/commit", &mut want).unwrap();
    assert_eq!(commit_of(&k).unwrap(), want);
    let mut with_empty = [0u8; 32];
    hkdf_sha256(&[], &[9; 32], b"ferret/v1/commit", &mut with_empty).unwrap();
    assert_eq!(with_empty, want);

    // It ends the password and PIN wraps; the others have none.
    let c = ctx();
    for method in [password_method(), pin_method()] {
        let rec = seal(method, &c, &k);
        assert_eq!(&rec.wrap[72..], &want, "commit at the end");
    }
    for method in [Method::Recovery, prf_method(), Method::Device] {
        assert_eq!(seal(method, &c, &k).wrap.len(), 72);
    }
    // The commit does not give the KEK away: it differs from it.
    assert_ne!(want, kek_bytes(&k));
}

#[test]
fn unwrap_checks_commit_before_aead() {
    let c = ctx();
    let k = kek(9);
    for method in [password_method(), pin_method()] {
        let rec = seal(method.clone(), &c, &k);

        // A right commit reaches the AEAD (positive control).
        let before = aead_open_count();
        unwrap_vk(&c, &k, &rec).unwrap();
        assert_eq!(aead_open_count(), before + 1, "{method:?}: control");

        // A wrong commit does not: no AEAD runs, and the error is Decrypt.
        let mut bad = rec.clone();
        *bad.wrap.last_mut().unwrap() ^= 1;
        let before = aead_open_count();
        assert_eq!(unwrap_vk(&c, &k, &bad).err(), Some(Error::Decrypt));
        assert_eq!(aead_open_count(), before, "{method:?}: wrong commit");

        // The commit of another KEK: also no AEAD.
        let mut other = rec.clone();
        other.wrap.truncate(72);
        other.wrap.extend_from_slice(&commit_of(&kek(10)).unwrap());
        let before = aead_open_count();
        assert_eq!(unwrap_vk(&c, &k, &other).err(), Some(Error::Decrypt));
        assert_eq!(aead_open_count(), before, "{method:?}: other KEK's commit");

        // A wrong KEK fails the commit check, too (no AEAD).
        let before = aead_open_count();
        assert_eq!(unwrap_vk(&c, &kek(10), &rec).err(), Some(Error::Decrypt));
        assert_eq!(aead_open_count(), before, "{method:?}: wrong KEK");

        // A wrong length never reaches the AEAD.
        let mut short = rec.clone();
        short.wrap.pop();
        let before = aead_open_count();
        assert_eq!(unwrap_vk(&c, &k, &short).err(), Some(Error::Decrypt));
        assert_eq!(aead_open_count(), before, "{method:?}: short");
    }

    // A method without a commit goes straight to the AEAD, and a wrong KEK
    // fails there.
    let rec = seal(Method::Recovery, &c, &k);
    let before = aead_open_count();
    assert_eq!(unwrap_vk(&c, &kek(10), &rec).err(), Some(Error::Decrypt));
    assert_eq!(aead_open_count(), before + 1);
}

#[test]
fn unwrap_commit_compare_is_constant_time_api() {
    // The commit is compared through `subtle` (via `prim::ct::commit_eq`,
    // from `ct/harness/ct_eq.rs`), never with `==` or `!=`. A grep over the
    // source of the wrap module: no comparison operator on a line that
    // mentions the commit, and the comparison is the `commit_eq` call.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wrap.rs");
    let source = std::fs::read_to_string(path).unwrap();
    let code: Vec<&str> = source
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect();
    for line in &code {
        if line.contains("commit") || line.contains("expected") {
            assert!(
                !line.contains("==") && !line.contains("!="),
                "commit compared with an operator: {line}"
            );
        }
    }
    assert!(
        code.iter()
            .any(|l| l.contains("commit_eq(") && l.contains("commit")),
        "the commit comparison must go through commit_eq"
    );
    let ct = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ct/harness/ct_eq.rs"),
    )
    .unwrap();
    assert!(ct.contains("subtle::ConstantTimeEq") && ct.contains("ct_eq(b"));
}

// ------------------------------------------------------------ one error

#[test]
fn unwrap_wrong_kek_same_error_as_tamper() {
    let c = ctx();
    let k = kek(9);
    for method in all_methods() {
        let rec = seal(method.clone(), &c, &k);
        let wrong_kek = unwrap_vk(&c, &kek(10), &rec).err();

        let mut flipped = rec.clone();
        flipped.wrap[30] ^= 1;
        let tampered = unwrap_vk(&c, &k, &flipped).err();

        let mut other_aad = c;
        other_aad.vk_epoch += 1;
        let aad = unwrap_vk(&other_aad, &k, &rec).err();

        let mut cut = rec.clone();
        cut.wrap.truncate(10);
        let short = unwrap_vk(&c, &k, &cut).err();

        let mut empty = rec.clone();
        empty.wrap.clear();
        let nothing = unwrap_vk(&c, &k, &empty).err();

        for got in [wrong_kek, tampered, aad, short, nothing] {
            assert_eq!(got, Some(Error::Decrypt), "{method:?}");
        }
        // The same value, not merely the same code.
        assert_eq!(wrong_kek, tampered);
        assert_eq!(tampered, aad);
        assert_eq!(Error::Decrypt.code(), "decrypt");
    }
}

#[test]
fn unwrap_reports_nothing_but_decrypt_for_a_malformed_record() {
    // A credential id that cannot be encoded in a TLV field would be
    // `too_large` at wrap time. On the way in it is `decrypt`: the record is
    // untrusted and the error must not tell which step failed.
    let c = ctx();
    let rec = WrapRecord {
        method_id: method_id(1),
        kek_generation: 1,
        method: Method::Prf {
            credential_id: vec![0; 70_000],
            prf_salt: [7; 32],
        },
        wrap: vec![0; 72],
    };
    assert_eq!(unwrap_vk(&c, &kek(9), &rec).err(), Some(Error::Decrypt));
    let mut rng = TestRng::new(b"x");
    assert_eq!(
        wrap_vk(
            &mut rng,
            &c,
            &vk(1),
            &kek(9),
            method_id(1),
            1,
            Method::Prf {
                credential_id: vec![0; 70_000],
                prf_salt: [7; 32]
            }
        )
        .err(),
        Some(Error::TooLarge)
    );
}

// ---------------------------------------------------- AAD sabotage, field by field

fn assert_decrypt(c: &VaultContext, k: &Kek, rec: &WrapRecord, what: &str) {
    assert_eq!(
        unwrap_vk(c, k, rec).err(),
        Some(Error::Decrypt),
        "changing {what} must fail with decrypt"
    );
}

#[test]
fn unwrap_fails_on_each_aad_field() {
    let c = ctx();
    let k = kek(9);

    // The password wrap binds: account, vault, method type, method id,
    // epoch, generation and kdf.
    let rec = seal(password_method(), &c, &k);
    unwrap_vk(&c, &k, &rec).unwrap();

    let mut c2 = c;
    c2.account_id = account(0x12);
    assert_decrypt(&c2, &k, &rec, "account_id");

    let mut c2 = c;
    c2.vault_id = VaultId::from_bytes([0x23; 16]);
    assert_decrypt(&c2, &k, &rec, "vault_id");

    let mut r2 = rec.clone();
    r2.method = pin_method(); // the same 104 bytes, another method type
    assert_decrypt(&c, &k, &r2, "method_type");

    let mut r2 = rec.clone();
    r2.method_id = MethodId::from_bytes([0x34; 16]);
    assert_decrypt(&c, &k, &r2, "method_id");

    let mut c2 = c;
    c2.vk_epoch = 2;
    assert_decrypt(&c2, &k, &rec, "vk_epoch");

    let mut r2 = rec.clone();
    r2.kek_generation = 2;
    assert_decrypt(&c, &k, &r2, "kek_generation");

    // kdf: there is only one profile, so the changed field is put into the
    // wrap itself. A wrap made with another `kdf` in its AAD (and a valid
    // commit) does not open.
    let mut other_kdf = [65_536u32 * 2, 3, 1]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<u8>>();
    let aad = generic_aad(1, &[t(0x30, &other_kdf)]);
    let mut rng = ReplayRng::new(vec![vec![5; 24]]);
    let mut wrap = aead_seal(&mut rng, &[9; 32], &aad, &[0x5a; 32]).unwrap();
    wrap.extend_from_slice(&commit_of(&k).unwrap());
    let r2 = WrapRecord {
        wrap: wrap.clone(),
        ..rec.clone()
    };
    assert_decrypt(&c, &k, &r2, "kdf");
    // The control: the same construction with the right kdf opens.
    other_kdf = kdf_p1();
    let aad = generic_aad(1, &[t(0x30, &other_kdf)]);
    let mut rng = ReplayRng::new(vec![vec![5; 24]]);
    let mut wrap = aead_seal(&mut rng, &[9; 32], &aad, &[0x5a; 32]).unwrap();
    wrap.extend_from_slice(&commit_of(&k).unwrap());
    unwrap_vk(
        &c,
        &k,
        &WrapRecord {
            wrap,
            ..rec.clone()
        },
    )
    .unwrap();

    // The passkey wrap also binds credential_id and prf_salt.
    let rec = seal(prf_method(), &c, &k);
    unwrap_vk(&c, &k, &rec).unwrap();
    let Method::Prf {
        credential_id,
        prf_salt,
    } = rec.method.clone()
    else {
        unreachable!()
    };
    let mut cred = credential_id.clone();
    cred[0] ^= 1;
    let r2 = WrapRecord {
        method: Method::Prf {
            credential_id: cred,
            prf_salt,
        },
        ..rec.clone()
    };
    assert_decrypt(&c, &k, &r2, "credential_id");
    let mut salt = prf_salt;
    salt[31] ^= 1;
    let r2 = WrapRecord {
        method: Method::Prf {
            credential_id,
            prf_salt: salt,
        },
        ..rec.clone()
    };
    assert_decrypt(&c, &k, &r2, "prf_salt");

    // The PIN wrap binds account, vault, method id, epoch and device_salt
    // (and its method type, by being the PIN layout), but not the generation.
    let rec = seal(pin_method(), &c, &k);
    unwrap_vk(&c, &k, &rec).unwrap();
    let mut c2 = c;
    c2.account_id = account(0x12);
    assert_decrypt(&c2, &k, &rec, "pin: account_id");
    let mut c2 = c;
    c2.vk_epoch = 2;
    assert_decrypt(&c2, &k, &rec, "pin: vk_epoch");
    let mut c2 = c;
    c2.vault_id = VaultId::from_bytes([0x23; 16]);
    assert_decrypt(&c2, &k, &rec, "pin: vault_id");
    let mut r2 = rec.clone();
    r2.method_id = MethodId::from_bytes([0x34; 16]);
    assert_decrypt(&c, &k, &r2, "pin: method_id");
    let r2 = WrapRecord {
        method: Method::Pin {
            device_salt: [0xc1; 16],
        },
        ..rec.clone()
    };
    assert_decrypt(&c, &k, &r2, "pin: device_salt");
    assert_decrypt(
        &c,
        &k,
        &WrapRecord {
            method: Method::Device,
            ..rec.clone()
        },
        "pin: method type",
    );
}

#[test]
fn pin_wrap_has_no_generation_in_its_aad() {
    // The PIN wrap binds the vault and the method id (see the sabotage test
    // above) but has no `kek_generation`: the wrap is local, replaced and
    // never rolled forward, and its generation is not recorded anywhere.
    let c = ctx();
    let k = kek(9);
    let rec = seal(pin_method(), &c, &k);
    let mut r2 = rec.clone();
    r2.kek_generation = 9;
    assert!(unwrap_vk(&c, &k, &r2).is_ok());
}

#[test]
fn wrap_any_bit_flip_fails() {
    let c = ctx();
    let k = kek(9);
    for method in [password_method(), Method::Recovery, pin_method()] {
        let rec = seal(method.clone(), &c, &k);
        for byte in 0..rec.wrap.len() {
            for bit in 0..8 {
                let mut bad = rec.clone();
                bad.wrap[byte] ^= 1 << bit;
                assert_eq!(
                    unwrap_vk(&c, &k, &bad).err(),
                    Some(Error::Decrypt),
                    "{method:?}: byte {byte} bit {bit}"
                );
            }
        }
    }
}

// --------------------------------------------------------------- vectors

fn ctx_of(i: &Value) -> VaultContext {
    VaultContext {
        account_id: AccountId::from_bytes(hexn(&i["account_id"])),
        vault_id: VaultId::from_bytes(hexn(&i["vault_id"])),
        vk_epoch: u64s(&i["vk_epoch"]),
    }
}

fn method_of(v: &Value) -> Method {
    match v["type"].as_str().unwrap() {
        "password" => Method::Password {
            ksf: KsfProfile::from_wire(u32::try_from(v["ksf_profile"].as_u64().unwrap()).unwrap())
                .unwrap(),
        },
        "recovery" => Method::Recovery,
        "prf" => Method::Prf {
            credential_id: hex(&v["credential_id"]),
            prf_salt: hexn(&v["prf_salt"]),
        },
        "pin" => Method::Pin {
            device_salt: hexn(&v["device_salt"]),
        },
        "device" => Method::Device,
        other => panic!("unknown method type {other}"),
    }
}

fn run_seal(case: &Case, rng: &mut ReplayRng) -> Result<Outcome, Error> {
    let i = &case.input;
    let c = ctx_of(i);
    let vk = VaultKey::from_test_bytes(hexn(&i["vk"]));
    let id = MethodId::from_bytes(hexn(&i["method_id"]));
    let generation = u64s(&i["kek_generation"]);
    let (kek, method) = match case.op.as_str() {
        "wrap.seal.password" => {
            let ek = ExportKey::from_test_bytes(hexn(&i["export_key"]));
            (
                Kek::from_export_key(&c.account_id, &ek)?,
                Method::Password {
                    ksf: KsfProfile::from_wire(
                        u32::try_from(i["ksf_profile"].as_u64().unwrap()).unwrap(),
                    )?,
                },
            )
        }
        "wrap.seal.recovery" => {
            let rk = RecoveryKey::from_test_bytes(hexn(&i["rk"]));
            (
                Kek::from_recovery_key(&c.account_id, &rk)?,
                Method::Recovery,
            )
        }
        "wrap.seal.prf" => {
            let out = PrfOutput::from_test_bytes(hexn(&i["prf_output"]));
            let credential_id = hex(&i["credential_id"]);
            (
                Kek::from_prf(&credential_id, &out)?,
                Method::Prf {
                    credential_id,
                    prf_salt: hexn(&i["prf_salt"]),
                },
            )
        }
        "wrap.seal.pin" => {
            let salt = hexn(&i["device_salt"]);
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            (
                Kek::from_pin_extension(&pin, &salt)?,
                Method::Pin { device_salt: salt },
            )
        }
        "wrap.seal.pin_mobile" => {
            let salt = hexn(&i["device_salt"]);
            let pin = Pin::new(i["pin"].as_str().unwrap().as_bytes())?;
            (
                Kek::from_pin_mobile(
                    &pin,
                    &salt,
                    &KekDevPin::from_test_bytes(hexn(&i["kek_dev_pin"])),
                )?,
                Method::Pin { device_salt: salt },
            )
        }
        "wrap.seal.device" => (Kek::generate(rng), Method::Device),
        other => panic!("unexpected op {other}"),
    };
    let rec = wrap_vk(rng, &c, &vk, &kek, id, generation, method.clone())?;
    let mut intermediate = json!({
        "kek": he(&kek_bytes(&kek)),
        "aad": he(&wrap_aad(&c, &rec)?),
    });
    if matches!(method, Method::Password { .. } | Method::Pin { .. }) {
        intermediate["commit"] = json!(he(&commit_of(&kek)?));
    }
    // Every wrap the vectors seal must also open again.
    unwrap_vk(&c, &kek, &rec).expect("a sealed wrap opens");
    Ok(Outcome {
        output: json!({ "wrap": he(&rec.wrap) }),
        intermediate: Some(intermediate),
    })
}

fn run_open(case: &Case) -> Result<Outcome, Error> {
    assert_eq!(case.op, "wrap.open");
    let i = &case.input;
    let c = ctx_of(i);
    let rec = WrapRecord {
        method_id: MethodId::from_bytes(hexn(&i["method_id"])),
        kek_generation: u64s(&i["kek_generation"]),
        method: method_of(&i["method"]),
        wrap: hex(&i["wrap"]),
    };
    let kek = Kek::from_test_bytes(hexn(&i["kek"]));
    let vault = unwrap_vk(&c, &kek, &rec)?;
    Ok(Outcome {
        output: json!({
            "vk": he(&unlocked_vault_keys(&vault)[0]),
            "pk_a": he(&vault.auth_public_key()),
        }),
        intermediate: None,
    })
}

#[test]
fn wrap_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/wrap.json")).unwrap();
    assert!(file.cases.len() >= 13, "{} cases", file.cases.len());
    let report = vector::run_all(&file, |case: &Case, rng: &mut ReplayRng| {
        run_seal(case, rng)
    });
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    // All five method types, with and without a commit, are covered.
    for op in [
        "wrap.seal.password",
        "wrap.seal.recovery",
        "wrap.seal.prf",
        "wrap.seal.pin",
        "wrap.seal.pin_mobile",
        "wrap.seal.device",
    ] {
        assert!(file.cases.iter().any(|c| c.op == op), "no case for {op}");
    }
}

#[test]
fn unlock_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/unlock.json")).unwrap();
    let valid = file
        .cases
        .iter()
        .filter(|c| c.expect_error.is_none())
        .count();
    let invalid = file.cases.len() - valid;
    assert!(
        valid >= 13 && invalid >= 40,
        "{valid} valid, {invalid} invalid"
    );
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| run_open(case));
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());
    // Every failure in the file is the one error.
    assert!(
        file.cases
            .iter()
            .filter_map(|c| c.expect_error.as_deref())
            .all(|code| code == "decrypt")
    );
}

#[test]
fn wrap_aad_matches_the_vector_intermediate() {
    // The vector's `intermediate.aad` for the password case is byte-equal to
    // the hand-built AAD of this file (same ids as the vector).
    let file = vector::load(&vectors_dir().join("internal/wrap.json")).unwrap();
    let case = file
        .cases
        .iter()
        .find(|c| c.id == "wrap/password/valid/001")
        .unwrap();
    let want = hex(&case.intermediate.as_ref().unwrap()["aad"]);
    let acct = hex(&case.input["account_id"]);
    let vault = hex(&case.input["vault_id"]);
    let method = hex(&case.input["method_id"]);
    let by_hand = [
        label("ferret/v1/wrap"),
        t(0x03, &[1]),
        t(0x10, &acct),
        t(0x11, &vault),
        t(0x14, &[1]),
        t(0x13, &method),
        t(0x20, &1u64.to_be_bytes()),
        t(0x21, &1u64.to_be_bytes()),
        t(0x30, &kdf_p1()),
    ]
    .concat();
    assert_eq!(by_hand, want);
    let _ = hex_encode(&want);
}

// ------------------------------------------------- the vault wraps itself

#[test]
fn the_unlocked_vault_wraps_its_own_key_for_every_method() {
    let c = ctx();
    let vault = UnlockedVault::from_vault_key(c, vk(0x5a)).unwrap();
    let k = kek(9);
    for (i, method) in all_methods().into_iter().enumerate() {
        let mut rng = TestRng::new(b"wrap for method");
        let rec = vault
            .wrap_for_method(&mut rng, &k, method_id(0x40), 2, method.clone())
            .unwrap();
        assert_eq!(rec.method, method);
        assert_eq!(rec.kek_generation, 2);
        assert_eq!(rec.method.type_code(), u8::try_from(i + 1).unwrap());
        // The same record as the free function makes, and it opens.
        let mut rng = TestRng::new(b"wrap for method");
        let by_hand = wrap_vk(&mut rng, &c, &vk(0x5a), &k, method_id(0x40), 2, method).unwrap();
        assert_eq!(rec, by_hand);
        let opened = unwrap_vk(&c, &k, &rec).unwrap();
        assert!(opened.same_vault_key(&vault));
    }
}

// ---------------------------------------------------------- PRF salt

#[test]
fn prf_salt_new_draws_32_random_bytes_once() {
    let mut rng = ReplayRng::new(vec![vec![0x42; 32]]);
    assert_eq!(ferret_core::prf_salt_new(&mut rng), [0x42; 32]);
    rng.finish().unwrap();
}

#[test]
fn an_all_zero_prf_salt_is_refused_at_wrap_and_at_unlock() {
    let c = ctx();
    let k = kek(9);
    let method = |salt: [u8; 32]| Method::Prf {
        credential_id: vec![5; 20],
        prf_salt: salt,
    };
    let mut rng = TestRng::new(b"zero salt");
    assert_eq!(
        wrap_vk(&mut rng, &c, &vk(1), &k, method_id(1), 1, method([0; 32])).err(),
        Some(Error::InvalidInput(ferret_core::InputError::AllZero))
    );
    // A wrap record with the zero salt (from a damaged or hostile server)
    // does not open, whatever it holds.
    let good = seal(method([3; 32]), &c, &k);
    let record = WrapRecord {
        method: method([0; 32]),
        ..good.clone()
    };
    assert_eq!(unwrap_vk(&c, &k, &record).err(), Some(Error::Decrypt));
    unwrap_vk(&c, &k, &good).unwrap();
    // One set bit is enough for the wrap.
    let mut salt = [0u8; 32];
    salt[31] = 1;
    wrap_vk(&mut rng, &c, &vk(1), &k, method_id(1), 1, method(salt)).unwrap();
}
