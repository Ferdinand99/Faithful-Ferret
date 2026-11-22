//! Random passphrases from the EFF large word list.
//!
//! **The list.** The Electronic Frontier Foundation's large word list for
//! passphrases ("EFF's New Wordlists for Random Passphrases", 2016,
//! <https://www.eff.org/dice>), 7 776 words of 3 to 9 characters (`a`-`z`,
//! four of them with a `-`), which EFF publishes with the terms of CC BY 3.0
//! US (<https://creativecommons.org/licenses/by/3.0/us/>); the attribution is
//! in THIRD-PARTY-NOTICES. Two files are kept next to this one:
//!
//! * `eff_large_wordlist.txt`: EFF's file exactly as published
//!   (<https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>,
//!   SHA-256 `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`),
//!   one line per word: five dice digits, a tab, the word. It is not compiled
//!   in; it is there so anyone can check where the words came from.
//! * `eff_large_words.txt`: the words alone, one per line in the same order,
//!   made from the first file by dropping the dice digits and the tab. This
//!   is the file that is compiled in. A test derives it from the original
//!   again and compares.
//!
//! The words file is turned into a table when the crate is compiled: one
//! 64-bit entry per word, each letter in five bits (`a` is 1, `z` is 26, `-`
//! is 27) and the length in bits 45 to 48. A word is chosen by a walk over
//! the whole table that selects the entry with `subtle`, so the address that
//! is read does not depend on the random index, and the entry is unpacked
//! with arithmetic, not a lookup.
//!
//! **Order of the draws** (the test vectors pin it): one
//! [`super::uniform_index`]`(7776)` per word, in order; then, with `number`,
//! a digit (`uniform_index(10)`) and the word it is appended to
//! (`uniform_index(words)`). `capitalize` puts the first letter of every word
//! in upper case and draws nothing.
//!
//! **Bits.** `words * log2(7776)`, plus `log2(10) + log2(words)` with
//! `number`; `capitalize` adds nothing (it is not a choice).

use super::{Generated, log2_of, uniform_index};
use crate::error::Error;
use crate::rng::SecureRng;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

/// The words of the EFF large list, one per line (see the module
/// documentation).
pub(crate) const WORDS: &str = include_str!("eff_large_words.txt");

/// The number of words in the list.
pub const WORD_COUNT: u32 = 7_776;

/// [`WORD_COUNT`] as an index bound.
const WORD_COUNT_USIZE: usize = 7_776;

/// The longest word of the list.
pub(crate) const MAX_WORD: usize = 9;

/// Where the length of a word sits in its table entry.
const LENGTH_SHIFT: u32 = 45;

/// The code of `-` in a table entry (the letters are 1 to 26).
const DASH: u64 = 27;

/// The packed list (see the module documentation), made from [`WORDS`] when
/// the crate is compiled.
static TABLE: [u64; WORD_COUNT_USIZE] = pack(WORDS);

/// Packs the words file into the table. Runs at compile time only: a file
/// that is not 7 776 lines of 3 to 9 characters of `a`-`z` and `-` stops the
/// build.
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    reason = "evaluated at compile time: an index or a sum out of range is a build error, not a panic at run time"
)]
const fn pack(words: &str) -> [u64; WORD_COUNT_USIZE] {
    let bytes = words.as_bytes();
    let mut table = [0u64; WORD_COUNT_USIZE];
    let mut word = 0usize;
    let mut pos = 0u32;
    let mut entry = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\n' {
            assert!(
                pos >= 3 && pos as usize <= MAX_WORD,
                "a word of 3 to 9 characters"
            );
            table[word] = entry | ((pos as u64) << LENGTH_SHIFT);
            word += 1;
            pos = 0;
            entry = 0;
        } else {
            let code = if b == b'-' {
                DASH
            } else {
                assert!(b.is_ascii_lowercase(), "only a-z and -");
                (b - b'a' + 1) as u64
            };
            entry |= code << (5 * pos);
            pos += 1;
        }
        i += 1;
    }
    assert!(
        word == WORD_COUNT_USIZE && pos == 0,
        "7776 lines, each ending in a line feed"
    );
    table
}

/// The separators a passphrase may use.
pub const SEPARATORS: [char; 4] = ['-', '.', '_', ' '];

/// The fewest and the most words.
const WORDS_RANGE: core::ops::RangeInclusive<u8> = 3..=20;

/// What a passphrase is made of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PassphraseOptions {
    /// The number of words, 3 to 20.
    pub words: u8, /* 3..=20 */
    /// What goes between two words: one of [`SEPARATORS`].
    pub separator: char, /* '-' '.' '_' ' ' */
    /// Put the first letter of every word in upper case.
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub number: bool,
}

/// A random passphrase (see the module documentation).
///
/// Fails with `generator_options` when the number of words is outside 3 to
/// 20 or the separator is not one of [`SEPARATORS`]. Nothing is drawn then.
pub fn generate_passphrase<R: SecureRng>(
    o: &PassphraseOptions,
    rng: &mut R,
) -> Result<Generated, Error> {
    if !WORDS_RANGE.contains(&o.words) || !SEPARATORS.contains(&o.separator) {
        return Err(Error::GeneratorOptions);
    }
    let words = usize::from(o.words);
    let mut picked: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(words);
    for _ in 0..words {
        let index = uniform_index(WORD_COUNT, rng)?;
        let mut word = ct_word(index);
        if o.capitalize
            && let Some(first) = word.first_mut()
        {
            first.make_ascii_uppercase();
        }
        picked.push(word);
    }
    if o.number {
        let digit = uniform_index(10, rng)?;
        let at = uniform_index(u32::from(o.words), rng)?;
        let digit = b'0'.saturating_add(u8::try_from(digit).unwrap_or(0));
        // Where the digit goes shows in the result, as the lengths of the
        // words do; the branch tells nothing more.
        for (k, word) in picked.iter_mut().enumerate() {
            if u32::try_from(k).unwrap_or(u32::MAX) == at {
                word.push(digit);
            }
        }
    }

    let total = picked
        .iter()
        .map(|w| w.len())
        .sum::<usize>()
        .saturating_add(words.saturating_sub(1));
    let mut value = Zeroizing::new(String::with_capacity(total));
    for (k, word) in picked.iter().enumerate() {
        if k > 0 {
            value.push(o.separator);
        }
        for c in word.iter() {
            value.push(char::from(*c));
        }
    }
    let mut bits = f64::from(o.words) * log2_of(WORD_COUNT);
    if o.number {
        bits += log2_of(10) + log2_of(u32::from(o.words));
    }
    Ok(Generated { value, bits })
}

/// The word at `index`: the table entry is selected by a walk over the whole
/// table with `subtle`, then unpacked with arithmetic (see the module
/// documentation). Empty for an index past the end, which callers never
/// pass.
fn ct_word(index: u32) -> Zeroizing<Vec<u8>> {
    let mut entry = 0u64;
    for (k, e) in TABLE.iter().enumerate() {
        let k = u32::try_from(k).unwrap_or(u32::MAX);
        entry.conditional_assign(e, k.ct_eq(&index));
    }
    let word = unpack(entry);
    entry.zeroize();
    word
}

/// The letters of a table entry. Each five-bit code becomes `a` + code - 1,
/// or `-` for 27, chosen with `subtle`; the length (which shows in the
/// result) bounds the loop.
fn unpack(entry: u64) -> Zeroizing<Vec<u8>> {
    let len = usize::try_from((entry >> LENGTH_SHIFT) & 0xf)
        .unwrap_or(0)
        .min(MAX_WORD);
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_WORD.saturating_add(1)));
    for i in 0..len {
        let shift = u32::try_from(i).unwrap_or(0).saturating_mul(5);
        let code = u8::try_from(entry.wrapping_shr(shift) & 31).unwrap_or(0);
        let mut c = b'a'.wrapping_add(code).wrapping_sub(1);
        c.conditional_assign(&b'-', u64::from(code).ct_eq(&DASH));
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_holds_every_word_of_the_file() {
        let list: Vec<&str> = WORDS.lines().collect();
        assert_eq!(list.len(), WORD_COUNT_USIZE);
        for (i, w) in list.iter().enumerate() {
            assert_eq!(unpack(TABLE[i]).as_slice(), w.as_bytes(), "word {i}");
        }
        assert!(list.iter().all(|w| (3..=MAX_WORD).contains(&w.len())));
    }

    #[test]
    fn words_are_found_by_their_index() {
        // Each lookup walks the whole table, so a sample: the first, the
        // last, the four with a hyphen and every 97th.
        let list: Vec<&str> = WORDS.lines().collect();
        for (i, w) in list.iter().enumerate() {
            if i % 97 == 0 || i == list.len() - 1 || w.contains('-') {
                let got = ct_word(u32::try_from(i).unwrap());
                assert_eq!(got.as_slice(), w.as_bytes(), "word {i}");
            }
        }
        assert!(ct_word(7_776).is_empty(), "past the end: nothing");
    }
}
