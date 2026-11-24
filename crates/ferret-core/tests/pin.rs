//! The PIN of the local unlock methods: its normalization and length, the
//! rule of the server, the PIN profile, the AAD with its `kdf` field, the
//! wrap and its commitment, and the vectors in `vectors/internal/pin.json`.

#![allow(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::keys::{commit_of, kek_bytes, wrap_aad};
use ferret_core::testing::prim::{aead_open_count, argon2_run_count, argon2id};
use ferret_core::testing::vector::{self, Outcome};
use ferret_core::testing::{TestRng, hex_decode, hex_encode};
use ferret_core::{
    Error, InputError, Kek, KekDevPin, KsfProfile, Method, MethodId, PIN_FLOOR, PIN_MAX_BYTES,
    PIN_MAX_SCALARS, PIN_OFFLINE_GUESSES_PER_SECOND, PIN_PROFILE_1_PARAMS, PIN_PROFILE_MIN, Pin,
    PinProfile, PinRule, VaultContext, WrapRecord, pin_meets_rule, unwrap_vk, wrap_vk,
};
use serde_json::{Value, json};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use zeroize::{Zeroize, ZeroizeOnDrop};

assert_not_impl_any!(Pin: Clone, Copy, core::fmt::Debug, core::fmt::Display, PartialEq, Eq);
assert_impl_all!(Pin: ZeroizeOnDrop);

fn too_short() -> Error {
    Error::InvalidInput(InputError::TooShort)
}
fn too_long() -> Error {
    Error::InvalidInput(InputError::TooLong)
}
fn forbidden() -> Error {
    Error::InvalidInput(InputError::ForbiddenCharacter)
}

/// The normalized bytes of a PIN.
fn bytes_of(text: &str) -> Result<Vec<u8>, Error> {
    Pin::new(text.as_bytes()).map(|p| p.test_bytes().to_vec())
}

fn rule(min_length: u8) -> PinRule {
    PinRule {
        allowed: true,
        after_restart: true,
        min_length,
    }
}

/// Reads `len` bytes at `ptr`.
///
/// # Safety
/// `ptr` must point to `len` initialized bytes of a live allocation.
unsafe fn read(ptr: *const u8, len: usize) -> Vec<u8> {
    // SAFETY: the caller guarantees the range; volatile so that the read
    // cannot be removed or reordered against the wipe.
    (0..len)
        .map(|i| unsafe { ptr.add(i).read_volatile() })
        .collect()
}

// -------------------------------------------------------------- the PIN

#[test]
fn a_pin_of_digits_and_full_width_digits_normalise_to_the_same_bytes() {
    let ascii = bytes_of("123456").unwrap();
    assert_eq!(ascii, b"123456");
    let wide = bytes_of("\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}").unwrap();
    assert_eq!(wide, ascii);
    // The same PIN, so the same KEK for the same salt (checked at the byte
    // level above; Argon2id of equal bytes is equal).
    // Arabic-Indic digits have no compatibility mapping and stay themselves.
    assert_eq!(
        bytes_of("\u{661}\u{662}\u{663}\u{664}").unwrap(),
        "\u{661}\u{662}\u{663}\u{664}".as_bytes()
    );
}

#[test]
fn a_text_pin_is_nfkd_normalised_like_the_master_password() {
    // Composed and decomposed forms are the same PIN, in NFKD.
    let composed = bytes_of("caf\u{e9}").unwrap();
    assert_eq!(composed, "cafe\u{301}".as_bytes());
    assert_eq!(bytes_of("cafe\u{301}").unwrap(), composed);
    // A compatibility ligature is two letters.
    assert_eq!(bytes_of("\u{fb01}sh").unwrap(), b"fish");
    // The bytes are the ones of the master password's normalizer.
    for text in [
        "caf\u{e9} 42",
        "\u{fb01}sh\u{ff11}",
        "e\u{301}x",
        "correct horse",
    ] {
        let mp = ferret_core::text::unicode::nfkd(text);
        assert_eq!(bytes_of(text).unwrap(), mp.as_bytes(), "{text}");
    }
    // The tables are the locked ones.
    assert_eq!(
        ferret_core::text::unicode::CATEGORY_UNICODE_VERSION,
        (16, 0, 0)
    );
}

#[test]
fn control_and_unassigned_characters_are_refused() {
    let before = argon2_run_count();
    for text in [
        "12\u{0}456",     // NUL
        "12\t456",        // tab
        "12\n456",        // line feed
        "12\u{7f}456",    // DEL
        "12\u{85}456",    // NEL
        "12\u{378}456",   // unassigned in Unicode 16.0
        "12\u{fffe}456",  // a noncharacter
        "12\u{10ffff}56", // a noncharacter
    ] {
        assert_eq!(
            Pin::new(text.as_bytes()).err(),
            Some(forbidden()),
            "{text:?}"
        );
    }
    // Not UTF-8 is its own error, and a forbidden character wins over length.
    assert_eq!(
        Pin::new(&[0xff, 0x31]).err(),
        Some(Error::InvalidInput(InputError::NotUtf8))
    );
    assert_eq!(Pin::new(&[0x07; 80]).err(), Some(forbidden()));
    assert_eq!(argon2_run_count(), before, "a refused PIN computes nothing");
}

#[test]
fn pin_length_counts_scalars_and_caps_at_64_and_256_bytes() {
    assert_eq!(PIN_MAX_SCALARS, 64);
    assert_eq!(PIN_MAX_BYTES, 256);
    // Empty is too short; one scalar is a PIN (the rule asks for more).
    assert_eq!(Pin::new(b"").err(), Some(too_short()));
    assert!(Pin::new(b"1").is_ok());
    // 64 scalars are accepted, 65 are not.
    assert!(Pin::new(&[b'1'; 64]).is_ok());
    assert_eq!(Pin::new(&[b'1'; 65]).err(), Some(too_long()));
    // 64 four-byte scalars are exactly 256 bytes and are accepted; 65 are not.
    let wide = "\u{1f600}".repeat(64);
    assert_eq!(wide.len(), PIN_MAX_BYTES);
    assert_eq!(bytes_of(&wide).unwrap().len(), PIN_MAX_BYTES);
    assert_eq!(bytes_of(&"\u{1f600}".repeat(65)).err(), Some(too_long()));
    // The count is of the scalars after NFKD: four of the ligature U+FDFA
    // expand to 72 scalars, too many although the input has four.
    assert_eq!(bytes_of(&"\u{fdfa}".repeat(4)).err(), Some(too_long()));
    // A scalar is one, whatever its bytes: 64 of the 2-byte ones fit.
    assert_eq!(bytes_of(&"\u{e6}".repeat(64)).unwrap().len(), 128);
    // A huge input is refused before it is normalized (no work, no copy).
    assert_eq!(Pin::new(&vec![b'1'; 1 << 20]).err(), Some(too_long()));
}

#[test]
fn a_pin_buffer_is_reserved_once_and_wiped() {
    let mut pin = Pin::new(b"correct horse").unwrap();
    let (ptr, cap) = pin.test_buffer();
    assert_eq!(cap, PIN_MAX_BYTES, "reserved once, no regrowth");
    // SAFETY: the buffer is alive and the first bytes are initialized.
    assert_eq!(unsafe { read(ptr, 13) }, b"correct horse");
    pin.zeroize();
    // SAFETY: `zeroize` keeps the allocation and writes zeros over all of its
    // capacity, so every byte is initialized; `pin` is still alive.
    let after = unsafe { read(ptr, cap) };
    assert!(after.iter().all(|b| *b == 0), "Pin not wiped");
}

// ------------------------------------------------------------- the rule

#[test]
fn the_rule_refuses_below_its_minimum_and_never_accepts_below_four() {
    let pin = |text: &str| Pin::new(text.as_bytes()).unwrap();
    assert_eq!(PIN_FLOOR, 4);
    // At the minimum, and above it.
    assert_eq!(pin_meets_rule(&pin("123456"), &rule(6)), Ok(()));
    assert_eq!(pin_meets_rule(&pin("1234567"), &rule(6)), Ok(()));
    assert_eq!(pin_meets_rule(&pin("12345"), &rule(6)), Err(too_short()));
    // The floor is 4, whatever the rule says.
    for min in [0u8, 1, 2, 3, 4] {
        assert_eq!(
            pin_meets_rule(&pin("1234"), &rule(min)),
            Ok(()),
            "min {min}"
        );
        assert_eq!(
            pin_meets_rule(&pin("123"), &rule(min)),
            Err(too_short()),
            "min {min}"
        );
        assert_eq!(pin_meets_rule(&pin("1"), &rule(min)), Err(too_short()));
    }
    // A minimum above 64 is the largest PIN there is, not an impossible rule.
    let longest = pin(&"x".repeat(64));
    assert_eq!(pin_meets_rule(&longest, &rule(64)), Ok(()));
    assert_eq!(pin_meets_rule(&longest, &rule(255)), Ok(()));
    assert_eq!(
        pin_meets_rule(&pin(&"x".repeat(63)), &rule(255)),
        Err(too_short())
    );
    // The length is counted in scalars of the NFC form: a letter with a
    // combining accent is one, and a ligature is two.
    assert_eq!(
        pin_meets_rule(&pin("e\u{301}e\u{301}e\u{301}e\u{301}"), &rule(4)),
        Ok(())
    );
    assert_eq!(
        pin_meets_rule(&pin("e\u{301}e\u{301}e\u{301}"), &rule(4)),
        Err(too_short())
    );
    assert_eq!(pin_meets_rule(&pin("\u{fb01}\u{fb01}"), &rule(4)), Ok(()));
    // A rule that allows nothing keeps `after_restart` out of the decision.
    let r = PinRule {
        after_restart: false,
        ..rule(6)
    };
    assert_eq!(pin_meets_rule(&pin("123456"), &r), Ok(()));
}

#[test]
fn a_rule_that_forbids_pins_refuses_every_pin() {
    let forbid = PinRule {
        allowed: false,
        after_restart: true,
        min_length: 4,
    };
    for text in ["1234", "123456", "correct horse battery staple"] {
        let pin = Pin::new(text.as_bytes()).unwrap();
        assert_eq!(pin_meets_rule(&pin, &forbid), Err(Error::PinNotAllowed));
    }
    // It wins over the length: a too-short PIN under a forbidding rule is
    // still "not allowed", so the answer does not depend on the PIN.
    let short = Pin::new(b"1").unwrap();
    assert_eq!(pin_meets_rule(&short, &forbid), Err(Error::PinNotAllowed));
    assert_eq!(Error::PinNotAllowed.code(), "pin_not_allowed");
    assert!(Error::ALL.contains(&Error::PinNotAllowed));
    // Nothing is computed from a PIN by the rule.
    let before = argon2_run_count();
    let _ = pin_meets_rule(&short, &forbid);
    assert_eq!(argon2_run_count(), before);
}

// ------------------------------------------------------------- the profile

#[test]
fn pin_profile_1_has_the_measured_parameters() {
    // 256 MiB, three passes, one lane: the single constant.
    let p = PinProfile::P1.params();
    assert_eq!(p, PIN_PROFILE_1_PARAMS);
    assert_eq!((p.m_kib, p.t, p.p), (262_144, 3, 1));
    assert_eq!(PinProfile::P1.number(), 1);
    assert_eq!(PIN_PROFILE_MIN, PinProfile::P1);
    assert_eq!(PinProfile::from_wire(1), Ok(PinProfile::P1));
    // It is within the ceiling of the core, and much stronger than the
    // sign-in profile (so the cost of a guess is what scales).
    assert!(p.m_kib <= ferret_core::KDF_CEIL.m_kib);
    assert!(p.m_kib >= 4 * KsfProfile::P1.params().m_kib);
    const { assert!(PIN_OFFLINE_GUESSES_PER_SECOND > 0) };
    // The KEK is Argon2id of the normalized bytes with exactly these numbers
    // (an independent run of the primitive).
    let salt = [0xc0u8; 16];
    let pin = Pin::new(b"correct horse").unwrap();
    let mut want = [0u8; 32];
    argon2id(b"correct horse", &salt, p, &mut want).unwrap();
    let kek = Kek::from_pin_extension(&pin, &salt, PinProfile::P1).unwrap();
    assert_eq!(kek_bytes(&kek), want);
}

#[test]
fn an_unknown_or_too_low_pin_profile_is_refused_before_argon2() {
    let before = argon2_run_count();
    for n in [0u32, 2, 3, 255, 256, u32::MAX] {
        assert_eq!(
            PinProfile::from_wire(n),
            Err(Error::KdfProfileUnknown),
            "profile {n}"
        );
    }
    // A known profile is never below the minimum, and the check that a wrap
    // keeps is the same one.
    assert_eq!(PinProfile::P1.at_least_min(), Ok(PinProfile::P1));
    assert_eq!(argon2_run_count(), before, "nothing was computed");
    // The profile of the sign-in is another table: its number does not select
    // a PIN profile, and its parameters (64 MiB) are no PIN profile.
    assert_ne!(PinProfile::P1.params(), KsfProfile::P1.params());
}

#[test]
fn the_mobile_pin_keeps_profile_1_of_the_sign_in() {
    let salt = [0xc0u8; 16];
    let dev = KekDevPin::from_test_bytes([0xd0; 32]);
    let pin = Pin::new(b"123456").unwrap();
    let before = argon2_run_count();
    let kek = Kek::from_pin_mobile(&pin, &salt, &dev).unwrap();
    assert_eq!(argon2_run_count(), before + 1);
    // 64 MiB: the HKDF input is the stretch of profile 1 of the sign-in.
    let mut stretched = [0u8; 32];
    argon2id(b"123456", &salt, KsfProfile::P1.params(), &mut stretched).unwrap();
    let mut ikm = [0xd0u8; 32].to_vec();
    ikm.extend_from_slice(&stretched);
    let mut want = [0u8; 32];
    ferret_core::testing::prim::hkdf_sha256(
        &[label("ferret/v1/kek/pin"), t(0x37, &salt)].concat(),
        &ikm,
        b"ferret/v1/kek/pin",
        &mut want,
    )
    .unwrap();
    assert_eq!(kek_bytes(&kek), want);
    // Its wrap says so in the AAD (64 MiB, 3, 1), and a wrap of the
    // extension (256 MiB) cannot be opened as a mobile one.
    let c = ctx();
    let method = Method::PinMobile { device_salt: salt };
    assert_eq!(method.type_code(), 4);
    let mut rng = TestRng::new(b"mobile pin");
    let rec = wrap_vk(&mut rng, &c, &vk(0x5a), &kek, method_id(0x33), 1, method).unwrap();
    assert_eq!(rec.wrap.len(), 104);
    let aad = wrap_aad(&c, &rec).unwrap();
    assert_eq!(
        aad[aad.len() - 15..],
        t(0x30, &[0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1])[..]
    );
    assert!(unwrap_vk(&c, &kek, &rec).is_ok());
}

// ------------------------------------------------- the wrap and its AAD

/// A PIN wrap under a fixed KEK (no Argon2id: the wrap is what is tested).
fn wrap_of(method: Method, c: &VaultContext) -> (Kek, WrapRecord) {
    let kek = Kek::from_test_bytes([9; 32]);
    let mut rng = TestRng::new(b"pin wrap");
    let rec = wrap_vk(&mut rng, c, &vk(0x5a), &kek, method_id(0x33), 1, method).unwrap();
    (kek, rec)
}

fn pin_method_with(profile: PinProfile, salt: u8) -> Method {
    Method::Pin {
        device_salt: [salt; 16],
        profile,
    }
}

#[test]
fn the_pin_aad_binds_the_kdf_and_the_epoch() {
    let c = ctx();
    let (_, rec) = wrap_of(pin_method_with(PinProfile::P1, 0xc0), &c);
    let aad = wrap_aad(&c, &rec).unwrap();
    // TLV[label="ferret/v1/pin", suite, account_id, vault_id, method_type=4,
    // method_id, vk_epoch, device_salt, kdf], written out by hand.
    let want = [
        label("ferret/v1/pin"),
        t(0x03, &[1]),
        t(0x10, &[0x11; 16]),
        t(0x11, &[0x22; 16]),
        t(0x14, &[4]),
        t(0x13, &[0x33; 16]),
        t(0x20, &1u64.to_be_bytes()),
        t(0x37, &[0xc0; 16]),
        t(0x30, &[0, 4, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1]),
    ]
    .concat();
    assert_eq!(aad, want);
    // The fields are in this order, and `kdf` is the last; no generation.
    let tags: Vec<u8> = parse_tlv(&aad).iter().map(|(tag, _)| *tag).collect();
    assert_eq!(tags, [0x01, 0x03, 0x10, 0x11, 0x14, 0x13, 0x20, 0x37, 0x30]);
    // The epoch is in it, so a wrap of one epoch does not open in another.
    let (kek, rec) = wrap_of(pin_method_with(PinProfile::P1, 0xc0), &c);
    let mut later = c;
    later.vk_epoch = 2;
    assert_eq!(unwrap_vk(&later, &kek, &rec).err(), Some(Error::Decrypt));
    assert!(unwrap_vk(&c, &kek, &rec).is_ok());
    // The kdf is in it: the mobile wrap (64 MiB) has another AAD.
    let (_, mobile) = wrap_of(
        Method::PinMobile {
            device_salt: [0xc0; 16],
        },
        &c,
    );
    assert_ne!(wrap_aad(&c, &mobile).unwrap(), aad);
}

#[test]
fn a_pin_wrap_with_changed_kdf_bytes_does_not_open() {
    let c = ctx();
    let kek = Kek::from_test_bytes([9; 32]);
    let method = pin_method_with(PinProfile::P1, 0xc0);
    let (_, rec) = wrap_of(method.clone(), &c);
    let good_aad = wrap_aad(&c, &rec).unwrap();
    let kdf_at = good_aad.len() - 12;
    assert!(unwrap_vk(&c, &kek, &rec).is_ok());
    // A wrap made with any one bit of the kdf field changed in the AAD does
    // not open under the AAD of its profile.
    for byte in 0..12 {
        for bit in 0..8 {
            let mut aad = good_aad.clone();
            aad[kdf_at + byte] ^= 1 << bit;
            let sealed = ferret_core::testing::prim::aead_seal(
                &mut TestRng::new(b"changed kdf"),
                &kek_bytes(&kek),
                &aad,
                &[0x5a; 32],
            )
            .unwrap();
            let mut forged = rec.clone();
            forged.wrap = [sealed, commit_of(&kek).unwrap().to_vec()].concat();
            assert_eq!(
                unwrap_vk(&c, &kek, &forged).err(),
                Some(Error::Decrypt),
                "kdf byte {byte} bit {bit}"
            );
        }
    }
    // The same wrap as the sign-in's 64 MiB profile is another AAD too.
    let (_, as_mobile) = wrap_of(
        Method::PinMobile {
            device_salt: [0xc0; 16],
        },
        &c,
    );
    let presented = WrapRecord {
        method,
        ..as_mobile
    };
    assert_eq!(unwrap_vk(&c, &kek, &presented).err(), Some(Error::Decrypt));
}

#[test]
fn a_wrong_pin_gives_only_decrypt() {
    let c = ctx();
    let salt = [0xc0u8; 16];
    let right = Pin::new(b"correct horse").unwrap();
    let wrong = Pin::new(b"correct hors3").unwrap();
    let method = pin_method_with(PinProfile::P1, 0xc0);
    let kek = Kek::from_pin_extension(&right, &salt, PinProfile::P1).unwrap();
    let mut rng = TestRng::new(b"wrong pin");
    let rec = wrap_vk(&mut rng, &c, &vk(0x5a), &kek, method_id(0x33), 1, method).unwrap();
    assert!(unwrap_vk(&c, &kek, &rec).is_ok());
    let bad = Kek::from_pin_extension(&wrong, &salt, PinProfile::P1).unwrap();
    assert_eq!(unwrap_vk(&c, &bad, &rec).err(), Some(Error::Decrypt));
    // Every other mistake is the same error, with no cause.
    let mut r = rec.clone();
    r.wrap[3] ^= 1;
    assert_eq!(unwrap_vk(&c, &kek, &r).err(), Some(Error::Decrypt));
    let mut r = rec.clone();
    r.wrap.pop();
    assert_eq!(unwrap_vk(&c, &kek, &r).err(), Some(Error::Decrypt));
    let mut r = rec.clone();
    r.method = pin_method_with(PinProfile::P1, 0xc1);
    assert_eq!(unwrap_vk(&c, &kek, &r).err(), Some(Error::Decrypt));
    let mut r = rec.clone();
    r.method_id = MethodId::from_bytes([0x34; 16]);
    assert_eq!(unwrap_vk(&c, &kek, &r).err(), Some(Error::Decrypt));
}

#[test]
fn the_commitment_is_checked_before_the_aead_in_constant_time() {
    let c = ctx();
    let (kek, rec) = wrap_of(pin_method_with(PinProfile::P1, 0xc0), &c);
    // The right commitment reaches the AEAD (positive control).
    let before = aead_open_count();
    unwrap_vk(&c, &kek, &rec).unwrap();
    assert_eq!(aead_open_count(), before + 1);
    // A wrong commitment, in the first byte or the last, does not.
    for at in [72, 80, 103] {
        let mut bad = rec.clone();
        bad.wrap[at] ^= 1;
        let before = aead_open_count();
        assert_eq!(unwrap_vk(&c, &kek, &bad).err(), Some(Error::Decrypt));
        assert_eq!(aead_open_count(), before, "commit byte {at}");
    }
    // The wrong KEK fails at the commitment too.
    let before = aead_open_count();
    let other = Kek::from_test_bytes([10; 32]);
    assert_eq!(unwrap_vk(&c, &other, &rec).err(), Some(Error::Decrypt));
    assert_eq!(aead_open_count(), before);
    // The commitment is compared through `subtle` and never with an operator.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/wrap.rs");
    let source = std::fs::read_to_string(path).unwrap();
    assert!(source.contains("commit_eq(&expected, got)"));
    for line in source.lines().filter(|l| l.contains("commit")) {
        let code = line.split("//").next().unwrap();
        assert!(
            !code.contains("==") && !code.contains("!="),
            "commitment compared with an operator: {line}"
        );
    }
}

// ----------------------------------------------------------------- vectors

fn json_u32(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

fn pin_bytes(v: &Value) -> Vec<u8> {
    hex_decode(v["utf8"].as_str().unwrap()).unwrap()
}

#[test]
fn vectors_pin_pass() {
    let file = load_ops("pin.json", |op| op.starts_with("pin."));
    let c = |i: &Value| VaultContext {
        account_id: ferret_core::AccountId::from_bytes(hexn(&i["account_id"])),
        vault_id: ferret_core::VaultId::from_bytes(hexn(&i["vault_id"])),
        vk_epoch: u64s(&i["vk_epoch"]),
    };
    let report = vector::run_all(&file, |case, _rng| {
        let i = &case.input;
        let output = match case.op.as_str() {
            "pin.normalize" => {
                let pin = Pin::new(&pin_bytes(i))?;
                json!({ "pin": hex_encode(pin.test_bytes()) })
            }
            "pin.rule" => {
                let pin = Pin::new(&pin_bytes(i))?;
                let r = &i["rule"];
                let rule = PinRule {
                    allowed: r["allowed"].as_bool().unwrap(),
                    after_restart: r["after_restart"].as_bool().unwrap(),
                    min_length: u8::try_from(r["min_length"].as_u64().unwrap().min(255)).unwrap(),
                };
                pin_meets_rule(&pin, &rule)?;
                json!({})
            }
            "pin.profile" => {
                let p = PinProfile::from_wire(json_u32(&i["pin_profile"]))?.params();
                json!({ "m_kib": p.m_kib, "t": p.t, "p": p.p })
            }
            "pin.aad" => {
                let m = &i["method"];
                let method = match m["type"].as_str().unwrap() {
                    "pin" => Method::Pin {
                        device_salt: hexn(&m["device_salt"]),
                        profile: PinProfile::from_wire(json_u32(&m["pin_profile"]))?,
                    },
                    "pin_mobile" => Method::PinMobile {
                        device_salt: hexn(&m["device_salt"]),
                    },
                    other => panic!("unknown method {other}"),
                };
                let rec = WrapRecord {
                    method_id: MethodId::from_bytes(hexn(&i["method_id"])),
                    kek_generation: 1,
                    method,
                    wrap: vec![],
                };
                let aad = wrap_aad(&c(i), &rec)?;
                let kdf = aad[aad.len() - 12..].to_vec();
                json!({ "aad": hex_encode(&aad), "kdf": hex_encode(&kdf) })
            }
            "pin.kek" => {
                // The profile and the PIN are checked before Argon2id runs.
                let profile = PinProfile::from_wire(json_u32(&i["pin_profile"]))?;
                let pin = Pin::new(&pin_bytes(i))?;
                let kek = Kek::from_pin_extension(&pin, &hexn(&i["device_salt"]), profile)?;
                json!({ "kek": hex_encode(&kek_bytes(&kek)) })
            }
            other => panic!("unexpected op {other}"),
        };
        Ok(Outcome {
            output,
            intermediate: None,
        })
    });
    assert_all_passed(&report, 20);
    for op in [
        "pin.normalize",
        "pin.rule",
        "pin.profile",
        "pin.aad",
        "pin.kek",
    ] {
        let n = file.cases.iter().filter(|c| c.op == op).count();
        assert!(n >= 3, "{op} has {n} cases");
    }
    assert!(file.cases.len() >= 20);
    assert!(
        file.cases
            .iter()
            .any(|c| c.status == vector::Status::Invalid)
    );
}

#[test]
fn the_vector_file_is_listed_and_the_version_was_raised() {
    use sha2::{Digest, Sha256};
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(vectors_dir().join("MANIFEST.json")).unwrap())
            .unwrap();
    let listed = manifest["files"]["internal/pin.json"]
        .as_str()
        .expect("MANIFEST.json lists internal/pin.json");
    let bytes = std::fs::read(vectors_dir().join("internal/pin.json")).unwrap();
    assert_eq!(listed, hex_encode(&Sha256::digest(&bytes)));
    let version: u32 = std::fs::read_to_string(vectors_dir().join("VERSION"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(version >= 31, "the vectors version was not raised");
    // The register describes the ops.
    let ops = std::fs::read_to_string(vectors_dir().join("OPS.md")).unwrap();
    for op in [
        "pin.normalize",
        "pin.rule",
        "pin.profile",
        "pin.aad",
        "pin.kek",
    ] {
        assert!(ops.contains(&format!("| `{op}` |")), "{op}");
    }
}
