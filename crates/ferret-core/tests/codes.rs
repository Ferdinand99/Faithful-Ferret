//! Recovery key and secret key codes: known answers, reading rules, the
//! generated vectors in `vectors/internal/codes.json`, and the constant-time
//! harness file.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::prim::argon2_run_count;
use ferret_core::testing::text::{recovery_key_bytes, secret_key_bytes};
use ferret_core::testing::vector::{self, Case, Outcome};
use ferret_core::testing::{ReplayRng, hex_decode, hex_encode};
use ferret_core::{
    Error, InputError, MalformedKind, RecoveryKey, SecretKey, decode_recovery_key,
    decode_secret_key, encode_recovery_key, encode_secret_key,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vectors")
}

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn rk(bytes: [u8; 32]) -> RecoveryKey {
    RecoveryKey::from_test_bytes(bytes)
}

fn sk(bytes: [u8; 16]) -> SecretKey {
    SecretKey::from_test_bytes(bytes)
}

fn pattern<const N: usize>() -> [u8; N] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn rk_text(bytes: [u8; 32]) -> String {
    encode_recovery_key(&rk(bytes)).to_string()
}

fn sk_text(bytes: [u8; 16]) -> String {
    encode_secret_key(&sk(bytes)).to_string()
}

fn rk_decode(text: &str) -> Result<[u8; 32], Error> {
    decode_recovery_key(text).map(|k| recovery_key_bytes(&k))
}

fn sk_decode(text: &str) -> Result<[u8; 16], Error> {
    decode_secret_key(text).map(|k| secret_key_bytes(&k))
}

// -------------------------------------------------------- known answers

#[test]
fn rk_code_known_answer() {
    // Written out here, apart from the vector file. Zero key: 52 zero
    // symbols, then the first 20 bits of SHA-256("ferret/v1/rk-check" ||
    // 32 zero bytes).
    let zero = rk_text([0; 32]);
    assert_eq!(zero, KNOWN_RK_ZERO);
    assert_eq!(rk_text([0xff; 32]), KNOWN_RK_FF);
    assert_eq!(rk_text(pattern::<32>()), KNOWN_RK_PATTERN);

    for code in [&zero, &rk_text([0xff; 32]), &rk_text(pattern::<32>())] {
        assert_eq!(code.len(), 74, "5 + 56 symbols + 13 dashes");
        assert!(code.starts_with("FFR1-"));
        let groups: Vec<&str> = code["FFR1-".len()..].split('-').collect();
        assert_eq!(groups.len(), 14);
        assert!(groups.iter().all(|g| g.len() == 4));
    }
}

const KNOWN_RK_ZERO: &str =
    "FFR1-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-0000-8NFH";
const KNOWN_RK_FF: &str =
    "FFR1-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZG-CWD7";
const KNOWN_RK_PATTERN: &str =
    "FFR1-000G-40R4-0M30-E209-185G-R38E-1W81-24GK-2GAH-C5RR-34D1-P70X-3RFG-GVX2";

#[test]
fn sk_code_known_answer() {
    let zero = sk_text([0; 16]);
    assert_eq!(zero, KNOWN_SK_ZERO);
    assert_eq!(sk_text([0xff; 16]), KNOWN_SK_FF);
    assert_eq!(sk_text(pattern::<16>()), KNOWN_SK_PATTERN);
    for code in [&zero, &sk_text([0xff; 16]), &sk_text(pattern::<16>())] {
        assert_eq!(code.len(), 40, "5 + 30 symbols + 5 dashes");
        assert!(code.starts_with("FFS1-"));
        let groups: Vec<&str> = code["FFS1-".len()..].split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 5));
    }
}

const KNOWN_SK_ZERO: &str = "FFS1-00000-00000-00000-00000-00000-0N99X";
const KNOWN_SK_FF: &str = "FFS1-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-W61VN";
const KNOWN_SK_PATTERN: &str = "FFS1-000G4-0R40M-30E20-9185G-R38E1-WPPTJ";

fn run_vector(case: &Case) -> Result<Outcome, Error> {
    let key_bytes = |name: &str| hex_decode(case.input[name].as_str().unwrap()).unwrap();
    let output = match case.op.as_str() {
        "code.rk.encode" => {
            let key: [u8; 32] = key_bytes("key").try_into().unwrap();
            json!({ "code": rk_text(key) })
        }
        "code.sk.encode" => {
            let key: [u8; 16] = key_bytes("key").try_into().unwrap();
            json!({ "code": sk_text(key) })
        }
        "code.rk.decode" => {
            let key = rk_decode(case.input["code"].as_str().unwrap())?;
            json!({ "key": hex_encode(&key) })
        }
        "code.sk.decode" => {
            let key = sk_decode(case.input["code"].as_str().unwrap())?;
            json!({ "key": hex_encode(&key) })
        }
        other => panic!("unknown op {other}"),
    };
    Ok(Outcome {
        output,
        intermediate: None,
    })
}

#[test]
fn code_vectors_from_file() {
    let file = vector::load(&vectors_dir().join("internal/codes.json")).unwrap();
    assert!(
        file.cases.len() >= 30,
        "the plan asks for at least 30 cases"
    );
    let report = vector::run_all(&file, |case: &Case, _rng: &mut ReplayRng| run_vector(case));
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.passed, file.cases.len());

    let ops: BTreeSet<&str> = file.cases.iter().map(|c| c.op.as_str()).collect();
    assert_eq!(
        ops,
        BTreeSet::from([
            "code.rk.decode",
            "code.rk.encode",
            "code.sk.decode",
            "code.sk.encode"
        ])
    );
    let errors: BTreeSet<&str> = file
        .cases
        .iter()
        .filter_map(|c| c.expect_error.as_deref())
        .collect();
    assert_eq!(
        errors,
        BTreeSet::from([
            "checksum",
            "input_too_long",
            "input_too_short",
            "malformed_code",
            "non_canonical"
        ])
    );
}

// ---------------------------------------------------------- reading rules

#[test]
fn code_decode_normalizes_input() {
    let key = [0u8; 32];
    let canonical = rk_text(key);
    assert_eq!(rk_decode(&canonical).unwrap(), key);
    // Lower case, O for 0, spaces for dashes, no separators.
    assert_eq!(rk_decode(&canonical.to_lowercase()).unwrap(), key);
    assert_eq!(rk_decode(&canonical.replace('0', "O")).unwrap(), key);
    assert_eq!(rk_decode(&canonical.replace('0', "o")).unwrap(), key);
    assert_eq!(rk_decode(&canonical.replace('-', " ")).unwrap(), key);
    assert_eq!(rk_decode(&canonical.replace('-', "")).unwrap(), key);
    assert_eq!(rk_decode(&canonical.replace('-', " - ")).unwrap(), key);
    assert_eq!(rk_decode(&format!("  {canonical}\u{20}")).unwrap(), key);

    // I and L read as 1, in the symbols and in the prefix.
    let mut ones = [0u8; 32];
    ones[0] = 0x08; // first symbol 00001
    let with_one = rk_text(ones);
    assert!(with_one.starts_with("FFR1-1"));
    for letter in ["I", "i", "L", "l"] {
        let typed = with_one.replacen("FFR1-1", &format!("FFR{letter}-{letter}"), 1);
        assert_eq!(rk_decode(&typed).unwrap(), ones, "{typed}");
    }

    // The same for the secret key.
    let skey = [0x42; 16];
    let sk_canonical = sk_text(skey);
    assert_eq!(sk_decode(&sk_canonical).unwrap(), skey);
    assert_eq!(sk_decode(&sk_canonical.to_lowercase()).unwrap(), skey);
    assert_eq!(sk_decode(&sk_canonical.replace('-', " ")).unwrap(), skey);
    assert_eq!(sk_decode(&sk_canonical.replace('-', "")).unwrap(), skey);
    assert_eq!(
        sk_decode(&sk_text([0; 16]).replace('0', "O")).unwrap(),
        [0; 16]
    );
}

#[test]
fn code_rejects_bad_checksum_before_use() {
    let before = argon2_run_count();
    for key in [[0u8; 32], [0xff; 32], pattern::<32>()] {
        let code = rk_text(key);
        let mut letters: Vec<char> = code.chars().collect();
        let last = letters.len() - 1;
        letters[last] = if letters[last] == '0' { '1' } else { '0' };
        let bad: String = letters.into_iter().collect();
        assert_eq!(rk_decode(&bad).err(), Some(Error::Checksum));
    }
    for key in [[0u8; 16], [0xff; 16], pattern::<16>()] {
        let code = sk_text(key);
        let mut letters: Vec<char> = code.chars().collect();
        let last = letters.len() - 1;
        letters[last] = if letters[last] == '0' { '1' } else { '0' };
        let bad: String = letters.into_iter().collect();
        assert_eq!(sk_decode(&bad).err(), Some(Error::Checksum));
    }
    // Reading never starts a key derivation, valid or not.
    let _ = rk_decode(&rk_text(pattern::<32>())).unwrap();
    assert_eq!(argon2_run_count(), before, "no KDF ran");
}

/// Every single-symbol change of a code is rejected: with `checksum`, or with
/// `non_canonical` when only a spare bit changed. Never accepted.
fn every_single_symbol_change<const N: usize>(
    code: &str,
    decode: impl Fn(&str) -> Result<[u8; N], Error>,
    original: [u8; N],
) -> (usize, usize) {
    let prefix = 5;
    let chars: Vec<char> = code.chars().collect();
    let (mut checksum, mut non_canonical) = (0, 0);
    for index in prefix..chars.len() {
        if chars[index] == '-' {
            continue;
        }
        for &candidate in ALPHABET {
            let candidate = char::from(candidate);
            if candidate == chars[index] {
                continue;
            }
            let mut changed = chars.clone();
            changed[index] = candidate;
            let text: String = changed.into_iter().collect();
            match decode(&text) {
                Err(Error::Checksum) => checksum += 1,
                Err(Error::NonCanonical) => non_canonical += 1,
                other => panic!("{text}: {other:?} (original {original:02x?})"),
            }
        }
    }
    (checksum, non_canonical)
}

#[test]
fn rk_every_single_symbol_change_is_caught() {
    let key = pattern::<32>();
    let (checksum, non_canonical) = every_single_symbol_change(&rk_text(key), rk_decode, key);
    // 56 symbols, 31 other letters each. Only the last data symbol can change
    // a spare bit alone: 15 of its 31 other values have a spare bit set and
    // the same data bit.
    assert_eq!(checksum + non_canonical, 56 * 31);
    assert_eq!(non_canonical, 15);
}

#[test]
fn sk_every_single_symbol_change_is_caught() {
    let key = pattern::<16>();
    let (checksum, non_canonical) = every_single_symbol_change(&sk_text(key), sk_decode, key);
    assert_eq!(checksum + non_canonical, 30 * 31);
    // The last data symbol: 3 data bits and 2 spare bits; 3 of the other 31
    // values keep the data bits and change a spare bit.
    assert_eq!(non_canonical, 3);
}

#[test]
fn code_rejects_noncanonical_spare_bits() {
    // RK: the last data symbol holds one data bit and four spare bits.
    let zero = rk_text([0; 32]);
    for (letter, ok) in [('0', true), ('1', false), ('8', false), ('F', false)] {
        let text = replace_letter(&zero, 51, letter);
        let got = rk_decode(&text);
        if ok {
            assert_eq!(got.unwrap(), [0; 32]);
        } else {
            assert_eq!(got.err(), Some(Error::NonCanonical), "{letter}");
        }
    }
    // The key with that bit set: canonical symbol is G (10000), and the
    // other 15 symbols with the same top bit are not canonical.
    let top = {
        let mut k = [0u8; 32];
        k[31] = 0x01;
        k
    };
    let code = rk_text(top);
    assert_eq!(code.chars().nth(5 + 51 + 12), Some('G'));
    assert_eq!(rk_decode(&code).unwrap(), top);
    assert_eq!(
        rk_decode(&replace_letter(&code, 51, 'H')).err(),
        Some(Error::NonCanonical)
    );

    // SK: the last data symbol holds three data bits and two spare bits.
    let zero = sk_text([0; 16]);
    for (letter, ok) in [
        ('0', true),
        ('1', false),
        ('2', false),
        ('3', false),
        ('4', true),
    ] {
        let text = replace_letter(&zero, 25, letter);
        let got = sk_decode(&text);
        if ok && letter == '0' {
            assert_eq!(got.unwrap(), [0; 16]);
        } else if ok {
            // '4' = 00100 changes a data bit: a different key, so the
            // checksum is what fails.
            assert_eq!(got.err(), Some(Error::Checksum));
        } else {
            assert_eq!(got.err(), Some(Error::NonCanonical), "{letter}");
        }
    }
    // Spare bits and a wrong checksum: the checksum is reported.
    let both = replace_letter(&replace_letter(&zero, 25, '1'), 29, '2');
    assert_eq!(sk_decode(&both).err(), Some(Error::Checksum));
}

/// Replaces the `index`-th symbol letter (not counting the prefix and
/// dashes).
fn replace_letter(code: &str, index: usize, letter: char) -> String {
    let mut out = String::new();
    let mut seen = 0;
    for (i, c) in code.chars().enumerate() {
        if i < 5 || c == '-' {
            out.push(c);
        } else {
            out.push(if seen == index { letter } else { c });
            seen += 1;
        }
    }
    out
}

#[test]
fn code_rejects_wrong_prefix_and_length() {
    let code = rk_text(pattern::<32>());
    let skc = sk_text(pattern::<16>());
    let malformed = Error::Malformed(MalformedKind::Code);
    let short = Error::InvalidInput(InputError::TooShort);
    let long = Error::InvalidInput(InputError::TooLong);

    // Prefix.
    assert_eq!(rk_decode(&skc).err(), Some(malformed));
    assert_eq!(sk_decode(&code).err(), Some(malformed));
    assert_eq!(
        rk_decode(&code.replacen("FFR1", "FFR2", 1)).err(),
        Some(malformed)
    );
    assert_eq!(
        rk_decode(&code.replacen("FFR1", "FFQ1", 1)).err(),
        Some(malformed)
    );
    assert_eq!(rk_decode(&code["FFR1-".len()..]).err(), Some(malformed));
    // Length.
    assert_eq!(rk_decode("").err(), Some(short));
    assert_eq!(rk_decode("FFR").err(), Some(short));
    assert_eq!(rk_decode("FFR1").err(), Some(short));
    assert_eq!(rk_decode(&code[..code.len() - 1]).err(), Some(short));
    assert_eq!(rk_decode(&format!("{code}0")).err(), Some(long));
    assert_eq!(
        rk_decode(&format!("{code}{}", "0".repeat(64))).err(),
        Some(long)
    );
    assert_eq!(sk_decode(&skc[..skc.len() - 1]).err(), Some(short));
    assert_eq!(sk_decode(&format!("{skc}0")).err(), Some(long));
    // Letters outside the alphabet, in data and in the check.
    for bad in ['U', 'u', '!', '\t', '_', 'é'] {
        for index in [0, 25, 51, 52, 55] {
            let text = replace_letter(&code, index, bad);
            let expected = if bad == 'é' { long } else { malformed };
            assert_eq!(rk_decode(&text).err(), Some(expected), "{bad:?} at {index}");
        }
    }
    // Only dashes and spaces are separators.
    assert_eq!(rk_decode(&code.replace('-', "_")).err(), Some(long));
    assert_eq!(rk_decode(&code.replace('-', "\t")).err(), Some(long));
}

#[test]
fn code_roundtrip_many_keys() {
    for seed in 0..200u32 {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = u8::try_from(
                (seed
                    .wrapping_mul(2_654_435_761)
                    .wrapping_add(i as u32 * 40_503)
                    >> 7)
                    & 0xff,
            )
            .unwrap();
        }
        assert_eq!(rk_decode(&rk_text(key)).unwrap(), key);
        let short: [u8; 16] = key[..16].try_into().unwrap();
        assert_eq!(sk_decode(&sk_text(short)).unwrap(), short);
    }
}

// ------------------------------------------------- the constant-time file

fn harness_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ct/harness/crockford.rs")
}

fn compile(source: &Path, name: &str) {
    let out = std::env::temp_dir().join(format!("ferret-ct-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&out).unwrap();
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let result = Command::new(rustc)
        .args([
            "--crate-type=lib",
            "--edition=2024",
            "--emit=metadata",
            "-D",
            "warnings",
        ])
        .arg("--crate-name")
        .arg(name)
        .arg("--out-dir")
        .arg(&out)
        .arg(source)
        .output()
        .expect("rustc must be on the PATH to compile the constant-time harness");
    let _ = std::fs::remove_dir_all(&out);
    assert!(
        result.status.success(),
        "rustc failed on {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn crockford_branch_free() {
    // The analyzer run (x86_64 and arm64, O0 to O3) is Task 14. Here: the file
    // compiles on its own with rustc, and with `core` only.
    let source = harness_path();
    compile(&source, "crockford_single_file");

    let wrapper_dir = std::env::temp_dir().join(format!("ferret-ct-wrap-{}", std::process::id()));
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let wrapper = wrapper_dir.join("no_std_wrapper.rs");
    std::fs::write(
        &wrapper,
        format!(
            "#![no_std]\ninclude!(r\"{}\");\n",
            source.canonicalize().unwrap().display()
        ),
    )
    .unwrap();
    compile(&wrapper, "crockford_no_std");
    let _ = std::fs::remove_dir_all(&wrapper_dir);

    // And it is the file the core runs: codes.rs includes it.
    let codes = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codes.rs"))
        .unwrap();
    assert!(codes.contains("include!(\"../../../ct/harness/crockford.rs\")"));

    // No lookup table of the alphabet in the harness: the alphabet string
    // appears only in comments, and there is no `const` or `static` item.
    let text = std::fs::read_to_string(&source).unwrap();
    for line in text.lines() {
        let code = line.split("//").next().unwrap();
        assert!(!code.contains("ABCDEFGH"), "alphabet in code: {line}");
        assert!(
            !code.contains("const ") && !code.contains("static "),
            "table in the harness: {line}"
        );
    }
}
