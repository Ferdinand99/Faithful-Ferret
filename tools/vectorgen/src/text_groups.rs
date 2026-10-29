//! The vector groups for text handling (`unicode.json`) and for the recovery
//! and secret key codes (`codes.json`).
//!
//! Every expected value is written out here, independently of the core: the
//! NFKD results as code point lists taken from the Unicode data, the codes
//! with a small table-based Crockford implementation and `sha2` directly. The
//! tests of the core then compare its output with these files.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::testing::hex_encode;
use ferret_core::testing::vector::{Case, VectorFile};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// ------------------------------------------------------------------ text

/// A run of characters repeated `n` times. A text is a list of these.
struct Seg(&'static str, usize);

fn text_bytes(segs: &[Seg]) -> Vec<u8> {
    let mut out = String::new();
    for Seg(chars, n) in segs {
        for _ in 0..*n {
            out.push_str(chars);
        }
    }
    out.into_bytes()
}

/// The JSON form of a text: `segments` (escapes, so that no editor can
/// normalize the file's content) and, for short texts, the text itself for
/// reading.
fn text_value(segs: &[Seg]) -> Value {
    let segments: Vec<Value> = segs
        .iter()
        .map(|Seg(chars, n)| {
            let escapes: Vec<String> = chars
                .chars()
                .map(|c| format!("U+{:04X}", u32::from(c)))
                .collect();
            json!({ "escapes": escapes.join(" "), "repeat": n })
        })
        .collect();
    let bytes = text_bytes(segs);
    let mut value = json!({ "segments": segments });
    if bytes.len() <= 64
        && let Ok(text) = String::from_utf8(bytes)
        && !text.chars().any(char::is_control)
    {
        value["text"] = json!(text);
    }
    value
}

fn bytes_value(bytes: &[u8]) -> Value {
    json!({ "utf8": hex_encode(bytes) })
}

fn nfkd_case(n: usize, title: &str, input: &'static str, output: &'static str) -> Case {
    valid_case(
        &format!("unicode/nfkd/{n:03}"),
        title,
        "text.nfkd",
        vec![],
        text_value(&[Seg(input, 1)]),
        json!({ "nfkd": hex_encode(output.as_bytes()) }),
    )
}

const WITH_SK: &str = "with_secret_key";
const WITHOUT_SK: &str = "without_secret_key";

fn mp_input(segs: &[Seg], policy: &str) -> Value {
    let mut v = text_value(segs);
    v["policy"] = json!(policy);
    v
}

fn mp_ok(n: usize, title: &str, segs: &[Seg], policy: &str, mp: &str) -> Case {
    valid_case(
        &format!("unicode/mp/valid/{n:03}"),
        title,
        "text.mp",
        vec![],
        mp_input(segs, policy),
        json!({ "mp": hex_encode(mp.as_bytes()) }),
    )
}

fn mp_ok_bytes(n: usize, title: &str, segs: &[Seg], policy: &str, mp: &[u8]) -> Case {
    valid_case(
        &format!("unicode/mp/valid/{n:03}"),
        title,
        "text.mp",
        vec![],
        mp_input(segs, policy),
        json!({ "mp": hex_encode(mp) }),
    )
}

fn mp_err(n: usize, title: &str, segs: &[Seg], policy: &str, code: &str) -> Case {
    invalid_case(
        &format!("unicode/mp/invalid/{n:03}"),
        title,
        "text.mp",
        vec![],
        mp_input(segs, policy),
        code,
    )
}

fn mp_err_bytes(n: usize, title: &str, bytes: &[u8], policy: &str, code: &str) -> Case {
    let mut input = bytes_value(bytes);
    input["policy"] = json!(policy);
    invalid_case(
        &format!("unicode/mp/invalid/{n:03}"),
        title,
        "text.mp",
        vec![],
        input,
        code,
    )
}

fn nfkd_cases(cases: &mut Vec<Case>) {
    // (title, input, NFKD). Code points from UnicodeData.txt (decomposition
    // mappings) and UAX #15, written as escapes.
    let table: &[(&str, &str, &str)] = &[
        ("ASCII is unchanged", "ferret", "ferret"),
        ("empty text", "", ""),
        ("ligature fi", "\u{FB01}", "fi"),
        ("ligature fl", "\u{FB02}", "fl"),
        ("ligature ffi", "\u{FB03}", "ffi"),
        ("long s t ligature", "\u{FB05}", "st"),
        ("ligature ij", "\u{0133}", "ij"),
        ("fullwidth digits", "\u{FF11}\u{FF12}\u{FF13}", "123"),
        ("fullwidth letters", "\u{FF21}\u{FF42}", "Ab"),
        ("circled digit one", "\u{2460}", "1"),
        ("superscript two", "\u{00B2}", "2"),
        ("roman numeral eight", "\u{2167}", "VIII"),
        ("square kg", "\u{338F}", "kg"),
        ("vulgar fraction one half", "\u{00BD}", "1\u{2044}2"),
        ("apostrophe n", "\u{0149}", "\u{02BC}n"),
        ("dz with caron", "\u{01C6}", "dz\u{030C}"),
        ("degree celsius", "\u{2103}", "\u{00B0}C"),
        ("no-break space becomes a space", "\u{00A0}", " "),
        ("ideographic space becomes a space", "\u{3000}", " "),
        ("mathematical bold capital A", "\u{1D400}", "A"),
        (
            "Arabic ligature of 18 letters",
            "\u{FDFA}",
            "\u{0635}\u{0644}\u{0649} \u{0627}\u{0644}\u{0644}\u{0647} \u{0639}\u{0644}\u{064A}\u{0647} \u{0648}\u{0633}\u{0644}\u{0645}",
        ),
        (
            "halfwidth katakana ka with voiced mark",
            "\u{FF76}\u{FF9E}",
            "\u{30AB}\u{3099}",
        ),
        (
            "Hangul syllable han",
            "\u{D55C}",
            "\u{1112}\u{1161}\u{11AB}",
        ),
        (
            "Hangul syllable ga (no final)",
            "\u{AC00}",
            "\u{1100}\u{1161}",
        ),
        (
            "last Hangul syllable",
            "\u{D7A3}",
            "\u{1112}\u{1175}\u{11C2}",
        ),
        (
            "Hangul jamo are already decomposed",
            "\u{1112}\u{1161}\u{11AB}",
            "\u{1112}\u{1161}\u{11AB}",
        ),
        ("e acute, precomposed", "\u{00E9}", "e\u{0301}"),
        ("e acute, combining", "e\u{0301}", "e\u{0301}"),
        ("n tilde", "\u{00F1}", "n\u{0303}"),
        (
            "e circumflex acute (Vietnamese)",
            "\u{1EBF}",
            "e\u{0302}\u{0301}",
        ),
        ("Greek dialytika tonos", "\u{0344}", "\u{0308}\u{0301}"),
        (
            "combining marks are put in canonical order",
            "a\u{0301}\u{0323}",
            "a\u{0323}\u{0301}",
        ),
        (
            "combining marks already in order",
            "a\u{0323}\u{0301}",
            "a\u{0323}\u{0301}",
        ),
        (
            "long s with dot above and dot below (UAX #15)",
            "\u{1E9B}\u{0323}",
            "s\u{0323}\u{0307}",
        ),
        ("Angstrom sign", "\u{212B}", "A\u{030A}"),
        ("A with ring above", "\u{00C5}", "A\u{030A}"),
        ("Ohm sign", "\u{2126}", "\u{03A9}"),
        (
            "Devanagari qa (composition exclusion)",
            "\u{0958}",
            "\u{0915}\u{093C}",
        ),
        (
            "Norwegian letters in NFC",
            "\u{00E6}\u{00F8}\u{00E5}",
            "\u{00E6}\u{00F8}a\u{030A}",
        ),
        (
            "Norwegian letters in NFD",
            "\u{00E6}\u{00F8}a\u{030A}",
            "\u{00E6}\u{00F8}a\u{030A}",
        ),
        (
            "capital Norwegian letters in NFC",
            "\u{00C6}\u{00D8}\u{00C5}",
            "\u{00C6}\u{00D8}A\u{030A}",
        ),
        ("emoji outside the BMP", "\u{1F600}", "\u{1F600}"),
        ("zero width joiner is kept", "a\u{200D}b", "a\u{200D}b"),
    ];
    for (i, (title, input, output)) in table.iter().enumerate() {
        cases.push(nfkd_case(i + 1, title, input, output));
    }
}

fn mp_cases(cases: &mut Vec<Case>) {
    // Valid passwords: lengths at the minimum, normalization, allowed
    // characters, the maximum.
    cases.push(mp_ok(
        1,
        "twelve characters with a secret key",
        &[Seg("abcdefghijkl", 1)],
        WITH_SK,
        "abcdefghijkl",
    ));
    cases.push(mp_ok(
        2,
        "fifteen characters without a secret key",
        &[Seg("abcdefghijklmno", 1)],
        WITHOUT_SK,
        "abcdefghijklmno",
    ));
    cases.push(mp_ok(
        3,
        "fifteen characters with a secret key",
        &[Seg("abcdefghijklmno", 1)],
        WITH_SK,
        "abcdefghijklmno",
    ));
    cases.push(mp_ok(
        4,
        "twelve a with ring in NFD: 12 NFC characters, 24 scalars",
        &[Seg("a\u{030A}", 12)],
        WITH_SK,
        &"a\u{030A}".repeat(12),
    ));
    cases.push(mp_ok(
        5,
        "twelve a with ring in NFC gives the same bytes as NFD",
        &[Seg("\u{00E5}", 12)],
        WITH_SK,
        &"a\u{030A}".repeat(12),
    ));
    cases.push(mp_ok(
        6,
        "twelve fullwidth digits",
        &[Seg("\u{FF11}", 12)],
        WITH_SK,
        "111111111111",
    ));
    cases.push(mp_ok(
        7,
        "twelve Hangul syllables",
        &[Seg("\u{D55C}", 12)],
        WITH_SK,
        &"\u{1112}\u{1161}\u{11AB}".repeat(12),
    ));
    cases.push(mp_ok(
        8,
        "Norwegian letters, NFC and NFD of the same text",
        &[Seg("\u{00E6}\u{00F8}\u{00E5}", 4)],
        WITH_SK,
        &"\u{00E6}\u{00F8}a\u{030A}".repeat(4),
    ));
    cases.push(mp_ok(
        9,
        "spaces and an emoji with a joiner sequence",
        &[Seg(
            "correct horse \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} battery",
            1,
        )],
        WITH_SK,
        "correct horse \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} battery",
    ));
    cases.push(mp_ok(
        10,
        "private use and soft hyphen are assigned and allowed",
        &[Seg("\u{E000}\u{00AD}abcdefghijkl", 1)],
        WITH_SK,
        "\u{E000}\u{00AD}abcdefghijkl",
    ));
    cases.push(mp_ok(
        11,
        "twelve ligatures count as twelve",
        &[Seg("\u{FB01}", 12)],
        WITH_SK,
        &"fi".repeat(12),
    ));
    cases.push(mp_ok(
        12,
        "512 e acute: 1 024 scalars after NFKD",
        &[Seg("\u{00E9}", 512)],
        WITH_SK,
        &"e\u{0301}".repeat(512),
    ));
    let a1024 = "a".repeat(1_024);
    cases.push(mp_ok(
        13,
        "1 024 scalars",
        &[Seg("a", 1_024)],
        WITH_SK,
        &a1024,
    ));
    let emoji1024 = [0xf0, 0x9f, 0x98, 0x80].repeat(1_024);
    cases.push(mp_ok_bytes(
        14,
        "1 024 four-byte scalars: exactly 4 096 bytes",
        &[Seg("\u{1F600}", 1_024)],
        WITH_SK,
        &emoji1024,
    ));
    cases.push(mp_ok(
        15,
        "1 024 three-byte scalars",
        &[Seg("\u{20AC}", 1_024)],
        WITHOUT_SK,
        &"\u{20AC}".repeat(1_024),
    ));

    // Too short, at the borders and by NFC counting.
    cases.push(mp_err(
        1,
        "eleven characters with a secret key",
        &[Seg("abcdefghijk", 1)],
        WITH_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        2,
        "fourteen characters without a secret key",
        &[Seg("abcdefghijklmn", 1)],
        WITHOUT_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        3,
        "twelve characters without a secret key",
        &[Seg("abcdefghijkl", 1)],
        WITHOUT_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        4,
        "eleven a with ring in NFD: 22 scalars but 11 NFC characters",
        &[Seg("a\u{030A}", 11)],
        WITH_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        5,
        "eleven a with ring in NFC",
        &[Seg("\u{00E5}", 11)],
        WITH_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        6,
        "eleven ligatures: 22 scalars after NFKD but 11 characters",
        &[Seg("\u{FB01}", 11)],
        WITH_SK,
        "input_too_short",
    ));
    cases.push(mp_err(
        7,
        "empty",
        &[Seg("", 1)],
        WITH_SK,
        "input_too_short",
    ));

    // Too long.
    cases.push(mp_err(
        8,
        "1 025 scalars",
        &[Seg("a", 1_025)],
        WITH_SK,
        "input_too_long",
    ));
    cases.push(mp_err(
        9,
        "1 025 four-byte scalars: more than 4 096 bytes",
        &[Seg("\u{1F600}", 1_025)],
        WITH_SK,
        "input_too_long",
    ));
    cases.push(mp_err(
        10,
        "600 ligatures: 600 characters but 1 200 scalars after NFKD",
        &[Seg("\u{FB01}", 600)],
        WITH_SK,
        "input_too_long",
    ));
    cases.push(mp_err(
        11,
        "513 e acute: 1 026 scalars after NFKD",
        &[Seg("\u{00E9}", 513)],
        WITH_SK,
        "input_too_long",
    ));
    cases.push(mp_err(
        12,
        "1 000 e with acute in NFD",
        &[Seg("e\u{0301}", 1_000)],
        WITH_SK,
        "input_too_long",
    ));

    // Forbidden characters. The text around them is long enough.
    for (n, title, ch) in [
        (13, "U+0000", "\u{0000}"),
        (14, "tab U+0009", "\u{0009}"),
        (15, "line feed U+000A", "\u{000A}"),
        (16, "U+001F", "\u{001F}"),
        (17, "delete U+007F", "\u{007F}"),
        (18, "next line U+0085 (Cc)", "\u{0085}"),
        (19, "U+009F (Cc)", "\u{009F}"),
        (20, "unassigned U+0378", "\u{0378}"),
        (21, "noncharacter U+FFFF", "\u{FFFF}"),
        (22, "noncharacter U+FFFE", "\u{FFFE}"),
        (23, "noncharacter U+FDD0", "\u{FDD0}"),
        (24, "noncharacter U+1FFFF", "\u{1FFFF}"),
        (25, "unassigned U+E0080", "\u{E0080}"),
        (26, "last code point U+10FFFF", "\u{10FFFF}"),
        (
            27,
            "first assigned in Unicode 17: Saudi riyal sign U+20C1",
            "\u{20C1}",
        ),
        (
            28,
            "first assigned in Unicode 17: CJK extension J U+323B0",
            "\u{323B0}",
        ),
        (
            29,
            "first assigned in Unicode 17: Sidetic U+10940",
            "\u{10940}",
        ),
    ] {
        let text: &'static str = Box::leak(format!("abcdef{ch}ghijkl").into_boxed_str());
        cases.push(mp_err(
            n,
            title,
            &[Seg(text, 1)],
            WITH_SK,
            "input_forbidden_character",
        ));
    }
    // Precedence: forbidden before length.
    let tabbed: &'static str = Box::leak(format!("\t{}", "a".repeat(1_100)).into_boxed_str());
    cases.push(mp_err(
        30,
        "a tab in a text that is also too long: forbidden character wins",
        &[Seg(tabbed, 1)],
        WITH_SK,
        "input_forbidden_character",
    ));
    cases.push(mp_err(
        31,
        "a tab in a text that is also too short: forbidden character wins",
        &[Seg("a\tb", 1)],
        WITH_SK,
        "input_forbidden_character",
    ));

    // Not UTF-8.
    for (n, title, tail) in [
        (32, "encoded surrogate U+D800", vec![0xed, 0xa0, 0x80]),
        (33, "overlong slash", vec![0xc0, 0xaf]),
        (34, "byte 0xff", vec![0xff]),
        (35, "truncated three-byte sequence", vec![0xe2, 0x82]),
        (36, "above U+10FFFF", vec![0xf4, 0x90, 0x80, 0x80]),
        (37, "continuation byte alone", vec![0x80]),
    ] {
        let mut bytes = b"abcdefghijkl".to_vec();
        bytes.extend_from_slice(&tail);
        cases.push(mp_err_bytes(n, title, &bytes, WITH_SK, "input_not_utf8"));
    }
    let mut bad_and_tab = b"abc\tdef".to_vec();
    bad_and_tab.push(0xff);
    cases.push(mp_err_bytes(
        38,
        "invalid UTF-8 and a tab: invalid UTF-8 wins",
        &bad_and_tab,
        WITH_SK,
        "input_not_utf8",
    ));
}

/// 16 bytes `0x10..0x1f`, the secret key of the OPAQUE input cases.
fn sk_pattern() -> Vec<u8> {
    (0x10..=0x1fu8).collect()
}

fn opaque_cases(cases: &mut Vec<Case>) {
    let sk = sk_pattern();
    for (n, title, segs, policy, with_sk, mp) in [
        (
            1,
            "with a secret key: mp, 0x00, SK",
            vec![Seg("correct horse battery", 1)],
            WITH_SK,
            true,
            "correct horse battery".to_string(),
        ),
        (
            2,
            "without a secret key: mp alone",
            vec![Seg("correct horse battery", 1)],
            WITHOUT_SK,
            false,
            "correct horse battery".to_string(),
        ),
        (
            3,
            "the NFKD form is what goes in",
            vec![Seg("\u{00E5}\u{FB01}\u{FF11}abcdefghi", 1)],
            WITH_SK,
            true,
            "a\u{030A}fi1abcdefghi".to_string(),
        ),
        (
            4,
            "a secret key that contains a zero byte",
            vec![Seg("abcdefghijklmnopqrst", 1)],
            WITH_SK,
            true,
            "abcdefghijklmnopqrst".to_string(),
        ),
    ] {
        let mut input = mp_input(&segs, policy);
        let mut expected = mp.clone().into_bytes();
        if with_sk {
            let key: Vec<u8> = if n == 4 {
                let mut k = sk_pattern();
                k[3] = 0;
                k
            } else {
                sk.clone()
            };
            input["secret_key"] = json!(hex_encode(&key));
            expected.push(0);
            expected.extend_from_slice(&key);
        } else {
            input["secret_key"] = Value::Null;
        }
        cases.push(valid_case(
            &format!("unicode/opaque_input/{n:03}"),
            title,
            "text.opaque_input",
            vec![],
            input,
            json!({ "opaque_input": hex_encode(&expected) }),
        ));
    }
}

fn export_cases(cases: &mut Vec<Case>) {
    fn input(segs: &[Seg], mp: Option<&[Seg]>) -> Value {
        let mut v = text_value(segs);
        v["master_password"] = match mp {
            Some(m) => text_value(m),
            None => Value::Null,
        };
        v
    }
    let ok = |n: usize, title: &str, segs: &[Seg], mp: Option<&[Seg]>, out: &str| {
        valid_case(
            &format!("unicode/export_password/valid/{n:03}"),
            title,
            "text.export_password",
            vec![],
            input(segs, mp),
            json!({ "export_password": hex_encode(out.as_bytes()) }),
        )
    };
    let err = |n: usize, title: &str, segs: &[Seg], mp: Option<&[Seg]>, code: &str| {
        invalid_case(
            &format!("unicode/export_password/invalid/{n:03}"),
            title,
            "text.export_password",
            vec![],
            input(segs, mp),
            code,
        )
    };
    cases.push(ok(
        1,
        "twelve characters, no master password given",
        &[Seg("abcdefghijkl", 1)],
        None,
        "abcdefghijkl",
    ));
    cases.push(ok(
        2,
        "twelve characters, different from the master password",
        &[Seg("abcdefghijkl", 1)],
        Some(&[Seg("correct horse battery", 1)]),
        "abcdefghijkl",
    ));
    cases.push(ok(
        3,
        "NFKD like the master password",
        &[Seg("\u{00E5}\u{FB01}\u{FF11}abcdefghi", 1)],
        None,
        "a\u{030A}fi1abcdefghi",
    ));
    cases.push(ok(
        4,
        "one character different from the master password",
        &[Seg("correct horse battery", 1)],
        Some(&[Seg("correct horse batterz", 1)]),
        "correct horse battery",
    ));
    cases.push(err(
        1,
        "eleven characters",
        &[Seg("abcdefghijk", 1)],
        None,
        "input_too_short",
    ));
    cases.push(err(
        2,
        "equal to the master password",
        &[Seg("correct horse battery", 1)],
        Some(&[Seg("correct horse battery", 1)]),
        "input_same_as_master_password",
    ));
    cases.push(err(
        3,
        "equal to the master password after normalization (NFC and NFD)",
        &[Seg("\u{00E5}", 12)],
        Some(&[Seg("a\u{030A}", 12)]),
        "input_same_as_master_password",
    ));
    cases.push(err(
        4,
        "equal after NFKD (fullwidth digits and plain digits)",
        &[Seg("\u{FF11}", 12)],
        Some(&[Seg("1", 12)]),
        "input_same_as_master_password",
    ));
    cases.push(err(
        5,
        "a tab",
        &[Seg("abcdef\tghijkl", 1)],
        None,
        "input_forbidden_character",
    ));
    cases.push(err(
        6,
        "1 025 scalars",
        &[Seg("a", 1_025)],
        None,
        "input_too_long",
    ));
}

pub(crate) fn unicode() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    nfkd_cases(&mut cases);
    mp_cases(&mut cases);
    opaque_cases(&mut cases);
    export_cases(&mut cases);
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "unicode".into(),
        suite: 1,
        spec: "Fase 1 § 3.1, § 4.1".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}

// ----------------------------------------------------------------- codes

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A kind of code, with everything the reference implementation needs.
#[derive(Clone, Copy)]
struct Kind {
    name: &'static str,
    prefix: &'static str,
    label: &'static str,
    key_len: usize,
    data_symbols: usize,
    group: usize,
}

const RK: Kind = Kind {
    name: "rk",
    prefix: "FFR1",
    label: "ferret/v1/rk-check",
    key_len: 32,
    data_symbols: 52,
    group: 4,
};

const SK: Kind = Kind {
    name: "sk",
    prefix: "FFS1",
    label: "ferret/v1/sk-check",
    key_len: 16,
    data_symbols: 26,
    group: 5,
};

/// Bits of `data`, most significant first, zero-padded to `symbols * 5`, as
/// letters.
fn ref_symbols(data: &[u8], symbols: usize) -> Vec<u8> {
    let mut bits: Vec<u8> = data
        .iter()
        .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
        .collect();
    bits.resize(symbols * 5, 0);
    bits.chunks(5)
        .map(|c| ALPHABET[usize::from(c.iter().fold(0u8, |a, b| (a << 1) | b))])
        .collect()
}

/// The four check letters: the first 20 bits of SHA-256(label || key).
fn ref_check(kind: Kind, key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(kind.label.as_bytes());
    hasher.update(key);
    let digest = hasher.finalize();
    ref_symbols(&digest[..3], 4)
}

fn ref_encode(kind: Kind, key: &[u8]) -> String {
    let mut letters = ref_symbols(key, kind.data_symbols);
    letters.extend(ref_check(kind, key));
    let mut out = String::from(kind.prefix);
    for group in letters.chunks(kind.group) {
        out.push('-');
        out.push_str(std::str::from_utf8(group).unwrap_or(""));
    }
    out
}

/// The reading rules, table-based and with ordinary branches. Returns the key
/// or the error code. The order of the checks is the one documented in
/// `codes.rs`.
fn ref_decode(kind: Kind, text: &str) -> Result<Vec<u8>, &'static str> {
    let is_separator = |c: &char| {
        matches!(
            c,
            '-' | ' ' | '\t' | '\n' | '\r' | '\u{000C}' | '\u{00A0}' | '\u{2013}' | '\u{2014}'
        )
    };
    let letters: Vec<u8> = text
        .chars()
        .filter(|c| !is_separator(c))
        .flat_map(|c| c.to_string().into_bytes())
        .collect();
    if letters.len() > 64 {
        return Err("input_too_long");
    }
    let fold = |b: u8| match b.to_ascii_uppercase() {
        b'O' => b'0',
        b'I' | b'L' => b'1',
        other => other,
    };
    if letters.len() < 4 {
        return Err("input_too_short");
    }
    let folded: Vec<u8> = letters.iter().map(|b| fold(*b)).collect();
    if &folded[..4] != kind.prefix.as_bytes() {
        return Err("malformed_code");
    }
    let total = kind.data_symbols + 4;
    if folded.len() - 4 < total {
        return Err("input_too_short");
    }
    if folded.len() - 4 > total {
        return Err("input_too_long");
    }
    let mut values = Vec::new();
    for b in &folded[4..] {
        match ALPHABET.iter().position(|a| a == b) {
            Some(p) => values.push(u8::try_from(p).unwrap_or(0)),
            None => return Err("malformed_code"),
        }
    }
    let bits: Vec<u8> = values
        .iter()
        .flat_map(|v| (0..5).rev().map(move |i| (v >> i) & 1))
        .collect();
    let data_bits = kind.data_symbols * 5;
    let key_bits = kind.key_len * 8;
    let key: Vec<u8> = bits[..key_bits]
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | b))
        .collect();
    let check_read = &folded[4 + kind.data_symbols..];
    if check_read != ref_check(kind, &key).as_slice() {
        return Err("checksum");
    }
    if bits[key_bits..data_bits].iter().any(|b| *b != 0) {
        return Err("non_canonical");
    }
    Ok(key)
}

fn key_from(label: &str, n: usize, len: usize) -> Vec<u8> {
    let digest = Sha256::digest(format!("ferret test vector {label} {n}").as_bytes());
    digest[..len].to_vec()
}

fn code_op(kind: Kind, what: &str) -> String {
    format!("code.{}.{what}", kind.name)
}

fn encode_case(kind: Kind, n: usize, title: &str, key: &[u8]) -> Case {
    valid_case(
        &format!("codes/{}_encode/{n:03}", kind.name),
        title,
        &code_op(kind, "encode"),
        vec![],
        json!({ "key": hex_encode(key) }),
        json!({ "code": ref_encode(kind, key) }),
    )
}

fn decode_ok(kind: Kind, n: usize, title: &str, text: &str, key: &[u8]) -> Case {
    valid_case(
        &format!("codes/{}_decode/valid/{n:03}", kind.name),
        title,
        &code_op(kind, "decode"),
        vec![],
        json!({ "code": text }),
        json!({ "key": hex_encode(key) }),
    )
}

fn decode_err(kind: Kind, n: usize, title: &str, text: &str, code: &'static str) -> Case {
    invalid_case(
        &format!("codes/{}_decode/invalid/{n:03}", kind.name),
        title,
        &code_op(kind, "decode"),
        vec![],
        json!({ "code": text }),
        code,
    )
}

/// Replaces the letter at `index` (counting letters, not dashes).
fn with_letter(code: &str, index: usize, letter: char) -> String {
    let mut seen = 0usize;
    let mut out = String::new();
    let mut in_prefix = true;
    for (i, c) in code.chars().enumerate() {
        if in_prefix && i < 5 {
            out.push(c);
            continue;
        }
        in_prefix = false;
        if c == '-' {
            out.push(c);
            continue;
        }
        out.push(if seen == index { letter } else { c });
        seen += 1;
    }
    out
}

fn kind_cases(kind: Kind, cases: &mut Vec<Case>) {
    let len = kind.key_len;
    let zero = vec![0u8; len];
    let full = vec![0xffu8; len];
    let counting: Vec<u8> = (0..len).map(|i| u8::try_from(i).unwrap_or(0)).collect();
    let mut keys: Vec<(&str, Vec<u8>)> = vec![
        ("all zero bytes", zero.clone()),
        ("all 0xff bytes", full.clone()),
        ("bytes 0, 1, 2, ...", counting.clone()),
        ("first symbol is 1", {
            let mut k = zero.clone();
            k[0] = 0x08;
            k
        }),
    ];
    for n in 0..4 {
        keys.push(("derived from a label", key_from(kind.name, n, len)));
    }
    for (i, (title, key)) in keys.iter().enumerate() {
        cases.push(encode_case(kind, i + 1, title, key));
    }

    // Reading valid forms.
    let code_zero = ref_encode(kind, &zero);
    let code_count = ref_encode(kind, &counting);
    let code_full = ref_encode(kind, &full);
    let first_one = keys[3].1.clone();
    let code_one = ref_encode(kind, &first_one);
    assert!(code_one[kind.prefix.len() + 1..].starts_with('1'));
    let mut n = 0usize;
    let mut ok = |cases: &mut Vec<Case>, title: &str, text: &str, key: &[u8]| {
        n += 1;
        assert_eq!(ref_decode(kind, text).as_deref(), Ok(key), "{title}");
        cases.push(decode_ok(kind, n, title, text, key));
    };
    ok(cases, "canonical code, all zero", &code_zero, &zero);
    ok(cases, "canonical code, all 0xff", &code_full, &full);
    ok(
        cases,
        "canonical code, bytes 0, 1, 2",
        &code_count,
        &counting,
    );
    ok(
        cases,
        "lower case",
        &code_count.to_ascii_lowercase(),
        &counting,
    );
    ok(
        cases,
        "spaces instead of dashes",
        &code_count.replace('-', " "),
        &counting,
    );
    ok(
        cases,
        "no separators at all",
        &code_count.replace('-', ""),
        &counting,
    );
    ok(
        cases,
        "extra spaces and dashes everywhere",
        &format!(" {} ", code_count.replace('-', " - ")),
        &counting,
    );
    ok(
        cases,
        "tabs between the groups",
        &code_count.replace('-', "\t"),
        &counting,
    );
    ok(
        cases,
        "a line break inside the code, as in a wrapped paste",
        &format!("{}\r\n{}\n", &code_count[..20], &code_count[20..]),
        &counting,
    );
    ok(
        cases,
        "no-break spaces between the groups",
        &code_count.replace('-', "\u{00A0}"),
        &counting,
    );
    ok(
        cases,
        "en dashes instead of hyphens",
        &code_count.replace('-', "\u{2013}"),
        &counting,
    );
    ok(
        cases,
        "em dashes instead of hyphens",
        &code_count.replace('-', "\u{2014}"),
        &counting,
    );
    ok(
        cases,
        "letter O read as zero",
        &code_zero.replace('0', "O"),
        &zero,
    );
    ok(
        cases,
        "lower case o read as zero",
        &code_zero.replace('0', "o"),
        &zero,
    );
    let one_i = format!(
        "{}{}",
        &code_one[..kind.prefix.len() + 1],
        code_one[kind.prefix.len() + 1..].replacen('1', "I", 1)
    );
    ok(cases, "letter I read as one", &one_i, &first_one);
    let one_l = format!(
        "{}{}",
        &code_one[..kind.prefix.len() + 1],
        code_one[kind.prefix.len() + 1..].replacen('1', "l", 1)
    );
    ok(cases, "lower case l read as one", &one_l, &first_one);
    ok(
        cases,
        "prefix with a lower case letter and L for the one",
        &code_count.replacen(
            &format!("{}-", kind.prefix),
            &format!("{}l-", &kind.prefix[..3]).to_lowercase(),
            1,
        ),
        &counting,
    );
    for (i, (title, key)) in keys.iter().enumerate().skip(4) {
        let text = ref_encode(kind, key);
        ok(cases, &format!("{title} ({})", i - 3), &text, key);
    }

    // Rejected input.
    let mut m = 0usize;
    let mut bad = |cases: &mut Vec<Case>, title: &str, text: &str, code: &'static str| {
        m += 1;
        assert_eq!(ref_decode(kind, text), Err(code), "{title}");
        cases.push(decode_err(kind, m, title, text, code));
    };
    let last = kind.data_symbols + 3;
    let flip = |c: char| if c == '0' { '2' } else { '0' };
    let c_last = code_count.chars().last().unwrap_or('0');
    bad(
        cases,
        "last check letter changed",
        &with_letter(&code_count, last, flip(c_last)),
        "checksum",
    );
    let c_first_check = code_count
        .replace('-', "")
        .chars()
        .nth(4 + kind.data_symbols)
        .unwrap_or('0');
    bad(
        cases,
        "first check letter changed",
        &with_letter(&code_count, kind.data_symbols, flip(c_first_check)),
        "checksum",
    );
    bad(
        cases,
        "first data letter changed",
        &with_letter(&code_zero, 0, '2'),
        "checksum",
    );
    bad(
        cases,
        "a data letter in the middle changed",
        &with_letter(&code_zero, kind.data_symbols / 2, 'Z'),
        "checksum",
    );
    // Spare bits: the last data letter holds the final data bits and the
    // spare bits; a non-zero spare bit with a matching check is not canonical.
    bad(
        cases,
        "spare bit set in the last data letter",
        &with_letter(&code_zero, kind.data_symbols - 1, '1'),
        "non_canonical",
    );
    bad(
        cases,
        &format!(
            "all {} spare bits of the last data letter set on an all-ones key",
            kind.data_symbols * 5 - kind.key_len * 8
        ),
        &with_letter(&code_full, kind.data_symbols - 1, 'Z'),
        "non_canonical",
    );
    bad(
        cases,
        "spare bit and a wrong check: the check is reported",
        &with_letter(
            &with_letter(&code_zero, kind.data_symbols - 1, '1'),
            last,
            '2',
        ),
        "checksum",
    );
    bad(cases, "empty", "", "input_too_short");
    bad(cases, "only the prefix", kind.prefix, "input_too_short");
    bad(
        cases,
        "last group missing",
        &code_count[..code_count.rfind('-').unwrap_or(0)],
        "input_too_short",
    );
    bad(
        cases,
        "one letter missing",
        &code_count[..code_count.len() - 1],
        "input_too_short",
    );
    bad(
        cases,
        "one letter too many",
        &format!("{code_count}0"),
        "input_too_long",
    );
    bad(
        cases,
        "more than 64 letters",
        &format!("{code_count}{}", "0".repeat(64)),
        "input_too_long",
    );
    let other = if kind.prefix == "FFR1" { SK } else { RK };
    bad(
        cases,
        "the prefix of the other kind of code",
        &ref_encode(other, &key_from("other", 0, other.key_len)),
        "malformed_code",
    );
    bad(
        cases,
        "no prefix",
        &code_count[kind.prefix.len() + 1..],
        "malformed_code",
    );
    bad(
        cases,
        "prefix version 2",
        &code_count.replacen("1-", "2-", 1),
        "malformed_code",
    );
    bad(
        cases,
        "letter U is not in the alphabet",
        &with_letter(&code_zero, 3, 'U'),
        "malformed_code",
    );
    bad(
        cases,
        "lower case u is not in the alphabet",
        &with_letter(&code_zero, 3, 'u'),
        "malformed_code",
    );
    bad(
        cases,
        "a symbol character is not in the alphabet",
        &with_letter(&code_zero, 3, '!'),
        "malformed_code",
    );
    bad(
        cases,
        "a tab in place of a letter is dropped as a separator: one letter short",
        &with_letter(&code_zero, 3, '\t'),
        "input_too_short",
    );
    bad(
        cases,
        "underscores are not separators",
        &code_count.replace('-', "_"),
        "input_too_long",
    );
    bad(
        cases,
        "a letter outside the alphabet in the check",
        &with_letter(&code_zero, last, 'U'),
        "malformed_code",
    );
}

pub(crate) fn codes() -> Result<Vec<u8>, Error> {
    let mut cases = Vec::new();
    kind_cases(RK, &mut cases);
    kind_cases(SK, &mut cases);
    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "codes".into(),
        suite: 1,
        spec: "Fase 1 § 6.1, § 6.2".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
