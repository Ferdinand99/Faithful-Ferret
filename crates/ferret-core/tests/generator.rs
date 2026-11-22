//! The password and passphrase generator: the rules of the options, the
//! classes, the shuffle, the uniform choice and its rejection, the
//! distribution of the characters, the EFF word list and where it came from,
//! the estimates, and the vectors in `vectors/internal/generator.json`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::generator::{AMBIGUOUS, DIGITS, LOWER, SEPARATORS, SYMBOLS, UPPER, WORD_COUNT};
use ferret_core::testing::generator::{embedded_words, log2_of, uniform_index};
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng, hex_encode};
use ferret_core::{
    Error, PassphraseOptions, PasswordOptions, SecureRng, generate_passphrase, generate_password,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const OPTIONS: Error = Error::GeneratorOptions;

fn password(
    length: u16,
    classes: [bool; 4],
    min_each: u8,
    avoid_ambiguous: bool,
) -> PasswordOptions {
    PasswordOptions {
        length,
        lower: classes[0],
        upper: classes[1],
        digits: classes[2],
        symbols: classes[3],
        min_each,
        avoid_ambiguous,
    }
}

const ALL: [bool; 4] = [true; 4];

/// The classes of the options, each without the ambiguous characters when
/// asked: the reference the tests compare with.
fn classes_of(o: &PasswordOptions) -> Vec<Vec<u8>> {
    [
        (o.lower, LOWER),
        (o.upper, UPPER),
        (o.digits, DIGITS),
        (o.symbols, SYMBOLS),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|(_, c)| {
        c.iter()
            .copied()
            .filter(|x| !(o.avoid_ambiguous && AMBIGUOUS.contains(x)))
            .collect()
    })
    .collect()
}

/// Many valid options: every set of classes, several lengths and minimums.
fn option_grid() -> Vec<PasswordOptions> {
    let mut out = Vec::new();
    for mask in 1u8..16 {
        let classes = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0, mask & 8 != 0];
        let n = u16::from(mask.count_ones() as u8);
        for length in [4u16, 5, 12, 20, 64, 128] {
            for min_each in [0u8, 1, 2, 8] {
                if u16::from(min_each) * n > length {
                    continue;
                }
                for avoid in [false, true] {
                    out.push(password(length, classes, min_each, avoid));
                }
            }
        }
    }
    out
}

/// Pearson's chi-square statistic of `counts` against equal expectations.
fn chi_square(counts: &[u64]) -> f64 {
    let total: u64 = counts.iter().sum();
    let expected = total as f64 / counts.len() as f64;
    counts
        .iter()
        .map(|&c| {
            let d = c as f64 - expected;
            d * d / expected
        })
        .sum()
}

/// The chi-square value with `df` degrees of freedom above which p < 0.001
/// (Wilson–Hilferty; z = 3.0902 is the upper 0.001 point of the normal).
fn chi_square_limit(df: usize) -> f64 {
    let k = df as f64;
    let a = 2.0 / (9.0 * k);
    k * (1.0 - a + 3.0902 * a.sqrt()).powi(3)
}

// ------------------------------------------------------------- passwords

#[test]
fn password_has_the_length_and_only_chars_of_the_chosen_classes() {
    let mut rng = TestRng::new(b"length-and-classes");
    for o in option_grid() {
        let alphabet: BTreeSet<u8> = classes_of(&o).concat().into_iter().collect();
        for _ in 0..8 {
            let g = generate_password(&o, &mut rng).unwrap();
            assert_eq!(g.value.len(), usize::from(o.length), "{o:?}");
            assert_eq!(g.value.chars().count(), usize::from(o.length), "ASCII only");
            for b in g.value.bytes() {
                assert!(
                    alphabet.contains(&b),
                    "{o:?}: {} is not in the classes",
                    char::from(b)
                );
            }
        }
    }
}

#[test]
fn every_chosen_class_appears_at_least_min_each_times() {
    let mut rng = TestRng::new(b"min-each");
    for o in option_grid() {
        let classes = classes_of(&o);
        for _ in 0..8 {
            let g = generate_password(&o, &mut rng).unwrap();
            for class in &classes {
                let n = g.value.bytes().filter(|b| class.contains(b)).count();
                assert!(n >= usize::from(o.min_each), "{o:?}: {n} of a class");
            }
        }
    }
    // When the minimums fill the whole length, each class has exactly that.
    let o = password(32, ALL, 8, false);
    for _ in 0..50 {
        let g = generate_password(&o, &mut rng).unwrap();
        for class in classes_of(&o) {
            assert_eq!(g.value.bytes().filter(|b| class.contains(b)).count(), 8);
        }
    }
}

#[test]
fn avoid_ambiguous_removes_every_ambiguous_char() {
    let mut rng = TestRng::new(b"ambiguous");
    let o = password(128, ALL, 8, true);
    let mut seen = BTreeSet::new();
    for _ in 0..400 {
        let g = generate_password(&o, &mut rng).unwrap();
        for b in g.value.bytes() {
            assert!(!AMBIGUOUS.contains(&b), "{} is ambiguous", char::from(b));
            seen.insert(b);
        }
    }
    // And every other character does come out: 78 less the six ambiguous
    // characters of the classes (`|` is in none of them).
    assert_eq!(seen.len(), 72);
    assert_eq!(classes_of(&o).concat().len(), 72);
    // Without the option, the ambiguous characters of the classes are there.
    let o = password(128, ALL, 0, false);
    let mut seen = BTreeSet::new();
    for _ in 0..400 {
        seen.extend(generate_password(&o, &mut rng).unwrap().value.bytes());
    }
    for c in b"Il1O0o" {
        assert!(
            seen.contains(c),
            "{} comes out without the option",
            char::from(*c)
        );
    }
    assert!(
        !seen.contains(&b'|'),
        "`|` is not a symbol of the generator"
    );
}

#[test]
fn class_positions_are_uniform_after_the_shuffle() {
    // Four classes, one of each, length 4: before the shuffle position 0 is
    // always the lower-case letter, 1 the upper-case one, 2 the digit, 3 the
    // symbol. After it, each position holds each class with chance 1/4.
    let mut rng = TestRng::new(b"positions");
    let o = password(4, ALL, 1, false);
    let classes = classes_of(&o);
    let mut counts = [[0u64; 4]; 4];
    let n = 40_000;
    for _ in 0..n {
        let g = generate_password(&o, &mut rng).unwrap();
        for (pos, b) in g.value.bytes().enumerate() {
            let class = classes.iter().position(|c| c.contains(&b)).unwrap();
            counts[pos][class] += 1;
        }
    }
    let limit = chi_square_limit(3);
    for (pos, row) in counts.iter().enumerate() {
        let chi = chi_square(row);
        assert!(
            chi < limit,
            "position {pos}: chi-square {chi} (limit {limit}), {row:?}"
        );
        for &c in row {
            assert!(c > n / 4 - n / 20, "position {pos}: {row:?}");
        }
    }
    // The same for a longer password with one guaranteed digit among
    // letters: the digit is not stuck at its first place.
    let o = password(8, [true, true, true, false], 1, false);
    let mut first_digit = [0u64; 8];
    for _ in 0..20_000 {
        let g = generate_password(&o, &mut rng).unwrap();
        let at = g.value.bytes().position(|b| b.is_ascii_digit()).unwrap();
        first_digit[at] += 1;
    }
    assert!(first_digit[2] < 20_000 / 2, "{first_digit:?}");
    assert!(first_digit.iter().all(|&c| c > 0), "{first_digit:?}");
}

#[test]
fn char_frequencies_are_uniform_over_a_million_draws() {
    // 50 000 passwords of 20 characters from the whole alphabet (78), with
    // no minimums: 1 000 000 characters, each equally likely.
    let mut rng = TestRng::new(b"frequencies");
    let o = password(20, ALL, 0, false);
    let alphabet = classes_of(&o).concat();
    assert_eq!(alphabet.len(), 78);
    let mut counts: BTreeMap<u8, u64> = alphabet.iter().map(|&c| (c, 0)).collect();
    for _ in 0..50_000 {
        for b in generate_password(&o, &mut rng).unwrap().value.bytes() {
            *counts.get_mut(&b).unwrap() += 1;
        }
    }
    let counts: Vec<u64> = counts.into_values().collect();
    assert_eq!(counts.iter().sum::<u64>(), 1_000_000);
    let chi = chi_square(&counts);
    let limit = chi_square_limit(77);
    assert!(
        chi < limit,
        "chi-square {chi} with 77 degrees of freedom (limit {limit})"
    );
    // A broken generator is caught by the same statistic: the first 39
    // characters twice as likely as the rest.
    let skewed: Vec<u64> = (0..78)
        .map(|i| if i < 39 { 17_094 } else { 8_547 })
        .collect();
    assert!(chi_square(&skewed) > limit);
}

#[test]
fn options_out_of_range_are_refused() {
    let refused = [
        password(3, ALL, 0, false),
        password(0, ALL, 0, false),
        password(129, ALL, 0, false),
        password(u16::MAX, ALL, 0, false),
        password(20, [false; 4], 0, false),
        password(80, ALL, 9, false),
        password(80, ALL, u8::MAX, false),
        password(7, ALL, 2, false),
        password(4, [false, false, true, false], 5, false),
        password(4, ALL, 2, true),
    ];
    for o in refused {
        // Nothing is drawn: a replay with no draws would panic on a draw.
        let mut rng = ReplayRng::new(vec![]);
        assert_eq!(
            generate_password(&o, &mut rng).unwrap_err(),
            OPTIONS,
            "{o:?}"
        );
    }
    // The edges that are allowed.
    let mut rng = TestRng::new(b"edges");
    for o in [
        password(4, ALL, 1, false),
        password(128, ALL, 8, true),
        password(4, [false, false, false, true], 4, false),
    ] {
        generate_password(&o, &mut rng).unwrap();
    }
    let phrase = |words: u8, separator: char| PassphraseOptions {
        words,
        separator,
        capitalize: false,
        number: false,
    };
    for o in [
        phrase(2, '-'),
        phrase(0, '-'),
        phrase(21, '-'),
        phrase(u8::MAX, '-'),
        phrase(5, ','),
        phrase(5, 'a'),
        phrase(5, '\t'),
        phrase(5, '\u{2010}'),
    ] {
        let mut rng = ReplayRng::new(vec![]);
        assert_eq!(
            generate_passphrase(&o, &mut rng).unwrap_err(),
            OPTIONS,
            "{o:?}"
        );
    }
    for separator in SEPARATORS {
        generate_passphrase(&phrase(3, separator), &mut rng).unwrap();
        generate_passphrase(&phrase(20, separator), &mut rng).unwrap();
    }
}

/// The first draw that `n` refuses: `n * floor(2^32 / n)`.
fn first_refused(n: u32) -> u64 {
    u64::from(n) * ((1u64 << 32) / u64::from(n))
}

fn draw(x: u64) -> Vec<u8> {
    u32::try_from(x).unwrap().to_le_bytes().to_vec()
}

#[test]
fn uniform_index_refuses_zero_and_rejects_the_biased_tail() {
    // n = 0 is refused before anything is drawn.
    assert_eq!(uniform_index(0, &mut ReplayRng::new(vec![])), Err(OPTIONS));
    for n in [
        1u32,
        2,
        3,
        10,
        26,
        62,
        72,
        78,
        128,
        7_776,
        (1 << 31) + 1,
        u32::MAX,
    ] {
        let limit = first_refused(n);
        // The last accepted draw is used; the bias starts at `limit`.
        let mut rng = ReplayRng::new(vec![draw(limit - 1)]);
        assert_eq!(
            u64::from(uniform_index(n, &mut rng).unwrap()),
            (limit - 1) % u64::from(n)
        );
        rng.finish().unwrap();
        if limit < 1 << 32 {
            // Every refused draw is thrown away, and the next one counts.
            let tail = [limit, (limit + (1 << 32)) / 2, (1 << 32) - 1];
            let mut draws: Vec<Vec<u8>> = tail.iter().map(|&x| draw(x)).collect();
            draws.push(draw(5));
            let mut rng = ReplayRng::new(draws);
            assert_eq!(
                u64::from(uniform_index(n, &mut rng).unwrap()),
                5 % u64::from(n),
                "n {n}"
            );
            rng.finish().unwrap();
        }
    }
    // For n = 3 only 0xffffffff is refused; for a power of two nothing is.
    assert_eq!(first_refused(3), 0xffff_ffff);
    assert_eq!(first_refused(64), 1 << 32);
    // Small n, every accepted draw near the edges: the result is the remainder.
    for n in 1u32..=40 {
        let limit = first_refused(n);
        for x in (0..200).chain(limit - 200..limit) {
            let mut rng = ReplayRng::new(vec![draw(x)]);
            assert_eq!(
                u64::from(uniform_index(n, &mut rng).unwrap()),
                x % u64::from(n)
            );
        }
    }
    // The vector rows carry the refused draws: every draw before the last is
    // in the tail, and some rows have them.
    let file = load_ops("generator.json", |op| op == "generator.uniform_index");
    let mut with_refusals = 0;
    for c in &file.cases {
        let n = u32::try_from(c.input["n"].as_u64().unwrap()).unwrap();
        if n == 0 {
            assert!(c.rng.is_empty());
            continue;
        }
        let draws: Vec<u64> = c
            .rng
            .iter()
            .map(|h| {
                let b = ferret_core::testing::hex_decode(h).unwrap();
                u64::from(u32::from_le_bytes(b.try_into().unwrap()))
            })
            .collect();
        let (last, refused) = draws.split_last().unwrap();
        assert!(*last < first_refused(n), "{}", c.id);
        assert!(refused.iter().all(|&x| x >= first_refused(n)), "{}", c.id);
        if !refused.is_empty() {
            with_refusals += 1;
        }
    }
    assert!(
        with_refusals >= 6,
        "{with_refusals} rows with refused draws"
    );
}

// ------------------------------------------------------------ passphrases

fn list() -> Vec<&'static str> {
    embedded_words().lines().collect()
}

#[test]
fn passphrase_has_the_words_from_the_list_and_the_separator() {
    let words: BTreeSet<&str> = list().into_iter().collect();
    let mut rng = TestRng::new(b"passphrase");
    for separator in ['.', '_', ' '] {
        for n in [3u8, 5, 6, 12, 20] {
            for capitalize in [false, true] {
                for number in [false, true] {
                    let o = PassphraseOptions {
                        words: n,
                        separator,
                        capitalize,
                        number,
                    };
                    let g = generate_passphrase(&o, &mut rng).unwrap();
                    let parts: Vec<&str> = g.value.split(separator).collect();
                    assert_eq!(parts.len(), usize::from(n), "{o:?}");
                    let digits: Vec<char> = g.value.chars().filter(char::is_ascii_digit).collect();
                    assert_eq!(digits.len(), usize::from(number), "{o:?}");
                    for part in parts {
                        let mut word = part
                            .trim_end_matches(|c: char| c.is_ascii_digit())
                            .to_owned();
                        if capitalize {
                            let first = word.chars().next().unwrap();
                            assert!(first.is_ascii_uppercase(), "{part}");
                            word = word.to_ascii_lowercase();
                        } else {
                            assert!(!word.chars().any(|c| c.is_ascii_uppercase()), "{part}");
                        }
                        assert!(
                            words.contains(word.as_str()),
                            "{part} is not a word of the list"
                        );
                    }
                }
            }
        }
    }
    // With `-` (which four words hold), the words are still the list's, one
    // after the other.
    let o = PassphraseOptions {
        words: 6,
        separator: '-',
        capitalize: false,
        number: false,
    };
    for _ in 0..50 {
        let g = generate_passphrase(&o, &mut rng).unwrap();
        assert!(g.value.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'));
        assert!(g.value.split('-').count() >= 6);
    }
}

#[test]
fn the_original_file_is_the_eff_large_list() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generator/eff_large_wordlist.txt");
    let bytes = std::fs::read(&path).unwrap();
    // SHA-256 of https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
    assert_eq!(
        hex_encode(&Sha256::digest(&bytes)),
        "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
    );
    assert_eq!(bytes.len(), 108_800);
    // Five dice (1 to 6), a tab and a word on each line, the dice in order.
    let text = std::str::from_utf8(&bytes).unwrap();
    let mut dice = [1u8; 5];
    for line in text.lines() {
        let (roll, word) = line.split_once('\t').unwrap();
        let want: String = dice.iter().map(|d| char::from(b'0' + d)).collect();
        assert_eq!(roll, want);
        assert!(!word.is_empty());
        for i in (0..5).rev() {
            if dice[i] < 6 {
                dice[i] += 1;
                break;
            }
            dice[i] = 1;
        }
    }
    assert_eq!(text.lines().count(), 7_776);
}

#[test]
fn the_embedded_words_are_derived_from_the_original() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/generator");
    let original = std::fs::read_to_string(dir.join("eff_large_wordlist.txt")).unwrap();
    // The derivation: drop the dice and the tab, keep the order, one word per
    // line with a line feed after each.
    let derived: String = original
        .lines()
        .map(|l| format!("{}\n", l.split_once('\t').unwrap().1))
        .collect();
    let file = std::fs::read_to_string(dir.join("eff_large_words.txt")).unwrap();
    assert_eq!(
        file, derived,
        "eff_large_words.txt is the words of the original"
    );
    assert_eq!(embedded_words(), derived, "and it is what is compiled in");
    let words = list();
    assert_eq!(words.len(), 7_776);
    assert_eq!(u32::try_from(words.len()).unwrap(), WORD_COUNT);
    let unique: BTreeSet<&str> = words.iter().copied().collect();
    assert_eq!(unique.len(), 7_776, "7 776 different words");
    assert!(words.iter().all(|w| (3..=9).contains(&w.len())));
    assert!(
        words
            .iter()
            .all(|w| w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
    );
}

#[test]
fn passphrase_bits_count_words_and_the_number() {
    let mut rng = TestRng::new(b"bits");
    for words in 3u8..=20 {
        for capitalize in [false, true] {
            for number in [false, true] {
                let o = PassphraseOptions {
                    words,
                    separator: '-',
                    capitalize,
                    number,
                };
                let g = generate_passphrase(&o, &mut rng).unwrap();
                let mut want = f64::from(words) * log2_of(7_776);
                if number {
                    want += log2_of(10) + log2_of(u32::from(words));
                }
                assert_eq!(g.bits, want, "{o:?}");
                // And it is the float formula, to rounding.
                let float = f64::from(words) * 7_776f64.log2()
                    + if number {
                        10f64.log2() + f64::from(words).log2()
                    } else {
                        0.0
                    };
                assert!(
                    (g.bits - float).abs() < 1e-9,
                    "{o:?}: {} vs {float}",
                    g.bits
                );
            }
        }
    }
    // Five words: 64.6 bits; six: 77.5.
    let five = PassphraseOptions {
        words: 5,
        separator: '-',
        capitalize: true,
        number: false,
    };
    assert!(
        (generate_passphrase(&five, &mut rng).unwrap().bits - 64.624_062_518_028_9).abs() < 1e-9
    );
    // A password: length times log2 of the alphabet.
    let g = generate_password(&password(20, ALL, 1, false), &mut rng).unwrap();
    assert!((g.bits - 20.0 * 78f64.log2()).abs() < 1e-9);
    let g = generate_password(&password(16, ALL, 0, true), &mut rng).unwrap();
    assert!((g.bits - 16.0 * 72f64.log2()).abs() < 1e-9);
    let g = generate_password(
        &password(6, [false, false, true, false], 0, false),
        &mut rng,
    )
    .unwrap();
    assert!((g.bits - 6.0 * 10f64.log2()).abs() < 1e-9);
}

#[test]
fn generated_debug_shows_no_value() {
    let mut rng = TestRng::new(b"debug");
    let g = generate_password(&password(20, ALL, 1, false), &mut rng).unwrap();
    let text = format!("{g:?}");
    assert!(!text.contains(g.value.as_str()));
    assert!(text.contains("redacted"));
}

// ------------------------------------------------------------- vectors

fn is_generator_op(op: &str) -> bool {
    op.starts_with("generator.")
}

fn password_of(input: &Value) -> PasswordOptions {
    let flag = |k: &str| input[k].as_bool().unwrap();
    PasswordOptions {
        length: u16::try_from(input["length"].as_u64().unwrap()).unwrap(),
        lower: flag("lower"),
        upper: flag("upper"),
        digits: flag("digits"),
        symbols: flag("symbols"),
        min_each: u8::try_from(input["min_each"].as_u64().unwrap()).unwrap(),
        avoid_ambiguous: flag("avoid_ambiguous"),
    }
}

fn passphrase_of(input: &Value) -> PassphraseOptions {
    let separator: Vec<char> = input["separator"].as_str().unwrap().chars().collect();
    assert_eq!(separator.len(), 1);
    PassphraseOptions {
        words: u8::try_from(input["words"].as_u64().unwrap()).unwrap(),
        separator: separator[0],
        capitalize: input["capitalize"].as_bool().unwrap(),
        number: input["number"].as_bool().unwrap(),
    }
}

#[test]
fn vectors_generator_pass() {
    let file = load_ops("generator.json", is_generator_op);
    let report = ferret_core::testing::vector::run_all(&file, |case, rng| {
        let input = &case.input;
        let output = match case.op.as_str() {
            "generator.password" => {
                let g = generate_password(&password_of(input), rng)?;
                json!({ "value": g.value.as_str(), "bits": as_read(g.bits) })
            }
            "generator.passphrase" => {
                let g = generate_passphrase(&passphrase_of(input), rng)?;
                json!({ "value": g.value.as_str(), "bits": as_read(g.bits) })
            }
            "generator.uniform_index" => {
                let n = u32::try_from(input["n"].as_u64().unwrap()).unwrap();
                json!({ "index": uniform_index(n, rng)? })
            }
            other => panic!("unknown op {other}"),
        };
        Ok(Outcome {
            output,
            intermediate: None,
        })
    });
    assert_all_passed(&report, 40);
    for op in [
        "generator.password",
        "generator.passphrase",
        "generator.uniform_index",
    ] {
        let n = file.cases.iter().filter(|c| c.op == op).count();
        assert!(n >= 10, "{op} has {n} cases");
    }
    assert!(
        file.cases
            .iter()
            .any(|c| c.status == ferret_core::testing::vector::Status::Invalid)
    );
}

#[test]
fn vectors_manifest_lists_the_new_file() {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(vectors_dir().join("MANIFEST.json")).unwrap())
            .unwrap();
    let listed = manifest["files"]["internal/generator.json"]
        .as_str()
        .expect("MANIFEST.json lists internal/generator.json");
    let bytes = std::fs::read(vectors_dir().join("internal/generator.json")).unwrap();
    assert_eq!(listed, hex_encode(&Sha256::digest(&bytes)));
    // The runner for bindings runs the file.
    let runner = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bindings/wasm/js/vector-runner.mjs"),
    )
    .unwrap();
    assert!(runner.contains("\"generator\""));
    // And the register describes the ops.
    let ops = std::fs::read_to_string(vectors_dir().join("OPS.md")).unwrap();
    for op in [
        "generator.password",
        "generator.passphrase",
        "generator.uniform_index",
    ] {
        assert!(ops.contains(&format!("| `{op}` |")), "{op}");
    }
}

#[test]
fn the_draws_come_from_the_rng_only() {
    // The same draws give the same password; other draws another one.
    let o = password(20, ALL, 1, false);
    let a = generate_password(&o, &mut TestRng::new(b"same")).unwrap();
    let b = generate_password(&o, &mut TestRng::new(b"same")).unwrap();
    let c = generate_password(&o, &mut TestRng::new(b"other")).unwrap();
    assert_eq!(a.value, b.value);
    assert_ne!(a.value, c.value);
    // A recording of the draws replays to the same value.
    struct Rec(TestRng, Vec<Vec<u8>>);
    impl SecureRng for Rec {
        fn fill(&mut self, dest: &mut [u8]) {
            self.0.fill(dest);
            self.1.push(dest.to_vec());
        }
    }
    let mut rec = Rec(TestRng::new(b"record"), vec![]);
    let first = generate_passphrase(
        &PassphraseOptions {
            words: 5,
            separator: '-',
            capitalize: true,
            number: true,
        },
        &mut rec,
    )
    .unwrap();
    assert_eq!(rec.1.len(), 7, "five words, the digit and its place");
    assert!(rec.1.iter().all(|d| d.len() == 4));
    let mut replay = ReplayRng::new(rec.1);
    let again = generate_passphrase(
        &PassphraseOptions {
            words: 5,
            separator: '-',
            capitalize: true,
            number: true,
        },
        &mut replay,
    )
    .unwrap();
    replay.finish().unwrap();
    assert_eq!(first.value, again.value);
}

/// `x` as the vector file holds it once read: written as the shortest text
/// that gives it back (as the generator writes the file), then parsed by
/// `serde_json`. Its default parser is not always correctly rounded, so the
/// number of the file and the number made here are compared after the same
/// trip. (JavaScript's `JSON.parse` is correctly rounded; the binding's runner
/// compares the plain numbers.)
fn as_read(x: f64) -> Value {
    serde_json::from_str(&serde_json::to_string(&x).unwrap()).unwrap()
}
