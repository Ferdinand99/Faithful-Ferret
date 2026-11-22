//! Property tests for the generator:
//! `password_length_and_classes_hold_for_any_valid_options` and
//! `passphrase_word_count_holds`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::generator::{AMBIGUOUS, DIGITS, LOWER, SEPARATORS, SYMBOLS, UPPER};
use ferret_core::testing::TestRng;
use ferret_core::testing::generator::embedded_words;
use ferret_core::{
    Error, PassphraseOptions, PasswordOptions, generate_passphrase, generate_password,
};
use proptest::prelude::*;
use std::collections::BTreeSet;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

/// Any options, valid or not: lengths around and inside the range, any set
/// of classes, minimums around the limit.
fn password_options() -> impl Strategy<Value = PasswordOptions> {
    (
        prop_oneof![0u16..=140, Just(u16::MAX)],
        any::<[bool; 4]>(),
        prop_oneof![0u8..=10, Just(u8::MAX)],
        any::<bool>(),
    )
        .prop_map(|(length, c, min_each, avoid_ambiguous)| PasswordOptions {
            length,
            lower: c[0],
            upper: c[1],
            digits: c[2],
            symbols: c[3],
            min_each,
            avoid_ambiguous,
        })
}

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

fn valid(o: &PasswordOptions) -> bool {
    let classes = classes_of(o);
    (4..=128).contains(&o.length)
        && o.min_each <= 8
        && !classes.is_empty()
        && usize::from(o.min_each) * classes.len() <= usize::from(o.length)
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn password_length_and_classes_hold_for_any_valid_options(
        o in password_options(),
        seed in any::<[u8; 16]>(),
    ) {
        let mut rng = TestRng::new(&seed);
        let result = generate_password(&o, &mut rng);
        if !valid(&o) {
            prop_assert_eq!(result.unwrap_err(), Error::GeneratorOptions);
            return Ok(());
        }
        let g = result.unwrap();
        let classes = classes_of(&o);
        prop_assert_eq!(g.value.len(), usize::from(o.length));
        for b in g.value.bytes() {
            prop_assert!(classes.iter().any(|c| c.contains(&b)), "{} is in no chosen class", char::from(b));
            prop_assert!(!(o.avoid_ambiguous && AMBIGUOUS.contains(&b)));
        }
        for class in &classes {
            let n = g.value.bytes().filter(|b| class.contains(b)).count();
            prop_assert!(n >= usize::from(o.min_each));
        }
        let alphabet = classes.iter().map(Vec::len).sum::<usize>() as f64;
        prop_assert!((g.bits - f64::from(o.length) * alphabet.log2()).abs() < 1e-9);
    }

    #[test]
    fn passphrase_word_count_holds(
        words in prop_oneof![0u8..=24, Just(u8::MAX)],
        separator in prop_oneof![
            prop::sample::select(SEPARATORS.to_vec()),
            Just(','),
            Just('a'),
            Just('\n'),
        ],
        capitalize in any::<bool>(),
        number in any::<bool>(),
        seed in any::<[u8; 16]>(),
    ) {
        let o = PassphraseOptions { words, separator, capitalize, number };
        let mut rng = TestRng::new(&seed);
        let result = generate_passphrase(&o, &mut rng);
        if !(3..=20).contains(&words) || !SEPARATORS.contains(&separator) {
            prop_assert_eq!(result.unwrap_err(), Error::GeneratorOptions);
            return Ok(());
        }
        let g = result.unwrap();
        let list: BTreeSet<&str> = embedded_words().lines().collect();
        // Split on the separator. With `-` a word of the list may hold one
        // itself ("t-shirt"), so the parts are segmented into words of the
        // list in every possible way, and one way must give `words` words.
        let parts: Vec<&str> = g.value.split(separator).collect();
        let longest = if separator == '-' { 2 } else { 1 };
        let mut counts: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); parts.len() + 1];
        counts[0].insert(0);
        for i in 0..parts.len() {
            let here: Vec<usize> = counts[i].iter().copied().collect();
            for take in 1..=longest {
                if i + take > parts.len() {
                    continue;
                }
                let joined = parts[i..i + take].join(&separator.to_string());
                let bare = joined.trim_end_matches(|c: char| c.is_ascii_digit()).to_ascii_lowercase();
                if list.contains(bare.as_str()) {
                    for n in &here {
                        counts[i + take].insert(n + 1);
                    }
                }
            }
        }
        prop_assert!(
            counts[parts.len()].contains(&usize::from(words)),
            "{:?} is not {} words of the list",
            g.value.as_str(),
            words
        );
        let digits = g.value.chars().filter(char::is_ascii_digit).count();
        prop_assert_eq!(digits, usize::from(number));
        if capitalize {
            for part in g.value.split(separator) {
                if let Some(first) = part.chars().next() {
                    prop_assert!(first.is_ascii_uppercase() || separator == '-');
                }
            }
        } else {
            prop_assert!(!g.value.chars().any(|c| c.is_ascii_uppercase()));
        }
    }
}
