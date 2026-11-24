//! The vector group for the PIN (`pin.json`): how a PIN is normalized and
//! counted, the rule of the server, the PIN profile, the AAD of a PIN wrap
//! with its `kdf` field, and the KEK of a text PIN.
//!
//! Every expected value is written here apart from the core: the normalized
//! bytes are literals (NFKD of the characters named in the title), the AAD is
//! assembled with the hand-made TLV helpers, and the KEK is Argon2id of the
//! normalized bytes with the numbers of PIN profile 1 written out in
//! `key_groups.rs`.

use crate::groups::{generator, invalid_case, valid_case};
use crate::key_groups::{P1, PIN_P1, arr, cat, h, kdf_field, label, stretch_with, t};
use crate::{Error, render};
use ferret_core::testing::vector::{Case, FORMAT, Tag, VectorFile};
use serde_json::{Value, json};

/// Why a binding does not run this file yet.
const SKIP: &str = "the PIN operations are not exported by the WebAssembly binding yet";

fn native(mut case: Case) -> Case {
    case.tags.push(Tag::NativeOnly);
    case.skip_reason = Some(SKIP.into());
    case
}

fn hx(bytes: &[u8]) -> String {
    ferret_core::testing::hex_encode(bytes)
}

fn input_of(utf8: &[u8]) -> Value {
    json!({ "utf8": hx(utf8) })
}

fn normalize_ok(cases: &mut Vec<Case>, n: u32, title: &str, input: &[u8], want: &[u8]) {
    cases.push(native(valid_case(
        &format!("pin/normalize/valid/{n:03}"),
        title,
        "pin.normalize",
        vec![],
        input_of(input),
        json!({ "pin": hx(want) }),
    )));
}

fn normalize_err(cases: &mut Vec<Case>, n: u32, title: &str, input: &[u8], code: &str) {
    cases.push(native(invalid_case(
        &format!("pin/normalize/invalid/{n:03}"),
        title,
        "pin.normalize",
        vec![],
        input_of(input),
        code,
    )));
}

fn rule_input(pin: &[u8], allowed: bool, min_length: u32) -> Value {
    json!({
        "utf8": hx(pin),
        "rule": { "allowed": allowed, "after_restart": true, "min_length": min_length },
    })
}

fn rule_ok(cases: &mut Vec<Case>, n: u32, title: &str, pin: &[u8], min_length: u32) {
    cases.push(native(valid_case(
        &format!("pin/rule/valid/{n:03}"),
        title,
        "pin.rule",
        vec![],
        rule_input(pin, true, min_length),
        json!({}),
    )));
}

fn rule_err(cases: &mut Vec<Case>, n: u32, title: &str, input: Value, code: &str) {
    cases.push(native(invalid_case(
        &format!("pin/rule/invalid/{n:03}"),
        title,
        "pin.rule",
        vec![],
        input,
        code,
    )));
}

/// The PIN AAD, by hand: `kdf` is the last field.
fn pin_aad(
    account: &[u8; 16],
    vault: &[u8; 16],
    method_id: &[u8; 16],
    epoch: u64,
    salt: &[u8; 16],
    kdf: &[u8; 12],
) -> Vec<u8> {
    cat(&[
        label("ferret/v1/pin"),
        t(0x03, &[1]),
        t(0x10, account),
        t(0x11, vault),
        t(0x14, &[4]),
        t(0x13, method_id),
        t(0x20, &epoch.to_be_bytes()),
        t(0x37, salt),
        t(0x30, kdf),
    ])
}

fn aad_case(
    cases: &mut Vec<Case>,
    n: u32,
    title: &str,
    method: Value,
    epoch: u64,
    salt: &[u8; 16],
    kdf: &[u8; 12],
) {
    let account = arr::<16>(0x10);
    let vault = arr::<16>(0x30);
    let method_id = arr::<16>(0x78);
    let aad = pin_aad(&account, &vault, &method_id, epoch, salt, kdf);
    cases.push(native(valid_case(
        &format!("pin/aad/valid/{n:03}"),
        title,
        "pin.aad",
        vec![],
        json!({
            "account_id": h(&account),
            "vault_id": h(&vault),
            "method_id": h(&method_id),
            "vk_epoch": epoch.to_string(),
            "method": method,
        }),
        json!({ "aad": h(&aad), "kdf": h(kdf) }),
    )));
}

fn kek_case(
    cases: &mut Vec<Case>,
    n: u32,
    title: &str,
    pin: &[u8],
    normalized: &[u8],
    salt: &[u8; 16],
) -> Result<(), Error> {
    cases.push(native(valid_case(
        &format!("pin/kek/valid/{n:03}"),
        title,
        "pin.kek",
        vec![Tag::Slow],
        json!({ "utf8": hx(pin), "device_salt": h(salt), "pin_profile": 1 }),
        json!({ "kek": h(&stretch_with(normalized, salt, PIN_P1)?) }),
    )));
    Ok(())
}

pub(crate) fn pin() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let salt = arr::<16>(0xc0);

    // ---- normalization: digits, text, NFKD pairs
    normalize_ok(&mut cases, 1, "six ASCII digits", b"123456", b"123456");
    normalize_ok(&mut cases, 2, "four ASCII digits", b"0000", b"0000");
    normalize_ok(
        &mut cases,
        3,
        "fullwidth digits are ASCII digits after NFKD",
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}".as_bytes(),
        b"123456",
    );
    normalize_ok(
        &mut cases,
        4,
        "text with a space",
        b"correct horse",
        b"correct horse",
    );
    normalize_ok(
        &mut cases,
        5,
        "NFKD pair, composed: e with an acute accent",
        "caf\u{e9}".as_bytes(),
        "cafe\u{301}".as_bytes(),
    );
    normalize_ok(
        &mut cases,
        6,
        "NFKD pair, decomposed: e and a combining acute accent",
        "cafe\u{301}".as_bytes(),
        "cafe\u{301}".as_bytes(),
    );
    normalize_ok(
        &mut cases,
        7,
        "a compatibility ligature is two letters",
        "\u{fb01}sh".as_bytes(),
        b"fish",
    );
    normalize_ok(
        &mut cases,
        8,
        "Arabic-Indic digits stay as they are (no compatibility mapping)",
        "\u{661}\u{662}\u{663}\u{664}".as_bytes(),
        "\u{661}\u{662}\u{663}\u{664}".as_bytes(),
    );
    normalize_ok(
        &mut cases,
        9,
        "a single scalar is enough for the normalization (the rule decides the minimum)",
        b"7",
        b"7",
    );
    normalize_ok(&mut cases, 10, "64 scalars", &[b'1'; 64], &[b'1'; 64]);
    let wide = "\u{1f600}".repeat(64);
    normalize_ok(
        &mut cases,
        11,
        "64 four-byte scalars are exactly 256 bytes",
        wide.as_bytes(),
        wide.as_bytes(),
    );
    normalize_err(&mut cases, 1, "an empty PIN", b"", "input_too_short");
    normalize_err(
        &mut cases,
        2,
        "bytes that are not UTF-8",
        &[0xff, 0x31, 0x32, 0x33],
        "input_not_utf8",
    );
    normalize_err(
        &mut cases,
        3,
        "a tab is a control character",
        b"12\t456",
        "input_forbidden_character",
    );
    normalize_err(
        &mut cases,
        4,
        "NUL is a control character",
        b"12\x00456",
        "input_forbidden_character",
    );
    normalize_err(
        &mut cases,
        5,
        "an unassigned character (U+0378)",
        "12\u{378}456".as_bytes(),
        "input_forbidden_character",
    );
    normalize_err(
        &mut cases,
        6,
        "65 scalars are too many",
        &[b'1'; 65],
        "input_too_long",
    );
    let wide65 = "\u{1f600}".repeat(65);
    normalize_err(
        &mut cases,
        7,
        "65 four-byte scalars are too many",
        wide65.as_bytes(),
        "input_too_long",
    );
    normalize_err(
        &mut cases,
        8,
        "four ligatures that expand to more than 64 scalars after NFKD",
        "\u{fdfa}".repeat(4).as_bytes(),
        "input_too_long",
    );
    normalize_err(
        &mut cases,
        9,
        "a forbidden character wins over the length",
        &[b'\x07'; 80],
        "input_forbidden_character",
    );

    // ---- the rule of the server
    rule_ok(&mut cases, 1, "six characters, minimum 6", b"123456", 6);
    rule_ok(&mut cases, 2, "four characters, minimum 4", b"abcd", 4);
    rule_ok(
        &mut cases,
        3,
        "a minimum of 0 is raised to the floor of 4",
        b"1234",
        0,
    );
    rule_ok(&mut cases, 4, "64 characters, minimum 64", &[b'x'; 64], 64);
    rule_ok(
        &mut cases,
        5,
        "a minimum above 64 is lowered to 64",
        &[b'x'; 64],
        200,
    );
    rule_ok(
        &mut cases,
        6,
        "a letter with a combining accent counts as one character",
        "e\u{301}e\u{301}e\u{301}e\u{301}".as_bytes(),
        4,
    );
    rule_err(
        &mut cases,
        1,
        "five characters, minimum 6",
        rule_input(b"12345", true, 6),
        "input_too_short",
    );
    rule_err(
        &mut cases,
        2,
        "three characters, minimum 0: never below the floor",
        rule_input(b"123", true, 0),
        "input_too_short",
    );
    rule_err(
        &mut cases,
        3,
        "a rule that forbids PINs refuses every PIN",
        rule_input(b"123456", false, 6),
        "pin_not_allowed",
    );
    rule_err(
        &mut cases,
        4,
        "a rule that forbids PINs refuses a long PIN too",
        rule_input(&[b'9'; 64], false, 4),
        "pin_not_allowed",
    );
    rule_err(
        &mut cases,
        5,
        "three letters with combining accents are three characters",
        rule_input("e\u{301}e\u{301}e\u{301}".as_bytes(), true, 4),
        "input_too_short",
    );

    // ---- the PIN profile
    cases.push(native(valid_case(
        "pin/profile/valid/001",
        "profile 1",
        "pin.profile",
        vec![],
        json!({ "pin_profile": 1 }),
        json!({ "m_kib": PIN_P1.m_kib, "t": PIN_P1.t, "p": PIN_P1.p }),
    )));
    for (n, title, profile) in [
        (1, "profile 0 is unknown", 0u32),
        (2, "profile 2 is unknown", 2),
        (3, "profile 255 is unknown", 255),
        (4, "the largest number is unknown", u32::MAX),
    ] {
        cases.push(native(invalid_case(
            &format!("pin/profile/invalid/{n:03}"),
            title,
            "pin.profile",
            vec![],
            json!({ "pin_profile": profile }),
            "kdf_profile_unknown",
        )));
    }

    // ---- the AAD, with the kdf field
    aad_case(
        &mut cases,
        1,
        "extension PIN wrap, profile 1, epoch 1",
        json!({ "type": "pin", "device_salt": h(&salt), "pin_profile": 1 }),
        1,
        &salt,
        &kdf_field(PIN_P1),
    );
    aad_case(
        &mut cases,
        2,
        "extension PIN wrap, epoch 2: the epoch is in the AAD",
        json!({ "type": "pin", "device_salt": h(&salt), "pin_profile": 1 }),
        2,
        &salt,
        &kdf_field(PIN_P1),
    );
    aad_case(
        &mut cases,
        3,
        "extension PIN wrap, another device salt",
        json!({ "type": "pin", "device_salt": h(&arr::<16>(0xc1)), "pin_profile": 1 }),
        1,
        &arr::<16>(0xc1),
        &kdf_field(PIN_P1),
    );
    aad_case(
        &mut cases,
        4,
        "mobile PIN wrap keeps profile 1 of the sign-in (64 MiB) in its kdf field",
        json!({ "type": "pin_mobile", "device_salt": h(&salt) }),
        1,
        &salt,
        &kdf_field(P1),
    );

    // ---- the KEK of a text PIN
    kek_case(&mut cases, 1, "six digits", b"123456", b"123456", &salt)?;
    kek_case(
        &mut cases,
        2,
        "fullwidth digits give the KEK of the ASCII digits",
        "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}".as_bytes(),
        b"123456",
        &salt,
    )?;
    kek_case(
        &mut cases,
        3,
        "a text PIN",
        b"correct horse",
        b"correct horse",
        &salt,
    )?;
    kek_case(
        &mut cases,
        4,
        "composed and decomposed text give the same KEK",
        "caf\u{e9}".as_bytes(),
        "cafe\u{301}".as_bytes(),
        &salt,
    )?;
    kek_case(
        &mut cases,
        5,
        "the decomposed form, the same KEK as the composed one",
        "cafe\u{301}".as_bytes(),
        "cafe\u{301}".as_bytes(),
        &salt,
    )?;
    cases.push(native(invalid_case(
        "pin/kek/invalid/001",
        "an unknown PIN profile is refused before Argon2id",
        "pin.kek",
        vec![],
        json!({ "utf8": hx(b"123456"), "device_salt": h(&salt), "pin_profile": 2 }),
        "kdf_profile_unknown",
    )));
    cases.push(native(invalid_case(
        "pin/kek/invalid/002",
        "an empty PIN is refused before Argon2id",
        "pin.kek",
        vec![],
        json!({ "utf8": "", "device_salt": h(&salt), "pin_profile": 1 }),
        "input_too_short",
    )));

    render(&VectorFile {
        format: FORMAT.into(),
        group: "pin".into(),
        suite: 1,
        spec: "Fase 1 § 3.1, § 4.3 and § 7.2".into(),
        generator: generator(),
        cases,
    })
}
