//! Random passwords from character classes.
//!
//! The classes are the lower-case letters `a`-`z`, the upper-case letters
//! `A`-`Z`, the digits `0`-`9` and the symbols [`SYMBOLS`]
//! (`!#$%&*+-.:=?@^_~`). With `avoid_ambiguous` the characters of
//! [`AMBIGUOUS`] (`Il1|O0o`) are taken out of every class.
//!
//! **Order of the draws** (the test vectors pin it):
//!
//! 1. for each chosen class, in the order lower, upper, digits, symbols,
//!    `min_each` characters of that class;
//! 2. the rest of the length from the whole alphabet (every chosen class
//!    together, in the same order);
//! 3. a Fisher–Yates shuffle: for `i` from `length - 1` down to `1`, swap
//!    position `i` with position `uniform_index(i + 1)`.
//!
//! Each choice is one `uniform_index` (one draw of four bytes, more
//! when a draw is refused). The shuffle spreads the guaranteed characters
//! over every position, so no position is more likely to hold a given class
//! than another.
//!
//! **Bits.** `length * log2(alphabet size)`. With `min_each` above zero the
//! true entropy is a little lower (some passwords of the alphabet cannot come
//! out); the estimate is for display and says so.

use super::{Generated, ct_pick, log2_of, uniform_index};
use crate::error::Error;
use crate::rng::SecureRng;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

/// The lower-case letters.
pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// The upper-case letters.
pub const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// The digits.
pub const DIGITS: &[u8] = b"0123456789";
/// The symbols: 16 characters that sites accept and that read well.
pub const SYMBOLS: &[u8] = b"!#$%&*+-.:=?@^_~";
/// The characters that are easy to mistake for each other, left out with
/// `avoid_ambiguous`.
pub const AMBIGUOUS: &[u8] = b"Il1|O0o";

/// The shortest and the longest password.
const LENGTH_RANGE: core::ops::RangeInclusive<u16> = 4..=128;
/// The most characters of each class that may be required.
const MAX_MIN_EACH: u8 = 8;

/// What a password is made of.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PasswordOptions {
    /// The number of characters, 4 to 128.
    pub length: u16, /* 4..=128 */
    /// Use the lower-case letters.
    pub lower: bool,
    /// Use the upper-case letters.
    pub upper: bool,
    /// Use the digits.
    pub digits: bool,
    /// Use the symbols.
    pub symbols: bool,
    /// The fewest characters of each chosen class, 0 to 8.
    pub min_each: u8, /* 0..=8 */
    /// Leave out the characters of [`AMBIGUOUS`].
    pub avoid_ambiguous: bool,
}

impl PasswordOptions {
    /// The chosen classes, in the order of the draws, each without the
    /// ambiguous characters when the options say so. Fails with
    /// `generator_options` when the options are out of range.
    fn classes(&self) -> Result<Vec<Vec<u8>>, Error> {
        if !LENGTH_RANGE.contains(&self.length) || self.min_each > MAX_MIN_EACH {
            return Err(Error::GeneratorOptions);
        }
        let chosen = [
            (self.lower, LOWER),
            (self.upper, UPPER),
            (self.digits, DIGITS),
            (self.symbols, SYMBOLS),
        ];
        let classes: Vec<Vec<u8>> = chosen
            .iter()
            .filter(|(on, _)| *on)
            .map(|(_, class)| {
                class
                    .iter()
                    .copied()
                    .filter(|c| !(self.avoid_ambiguous && AMBIGUOUS.contains(c)))
                    .collect()
            })
            .collect();
        let required = usize::from(self.min_each).saturating_mul(classes.len());
        if classes.is_empty() || required > usize::from(self.length) {
            return Err(Error::GeneratorOptions);
        }
        Ok(classes)
    }
}

/// The number of entries of `list` as a `u32` (the lists here are short).
fn count(list: &[u8]) -> Result<u32, Error> {
    u32::try_from(list.len()).map_err(|_| Error::GeneratorOptions)
}

/// A random password (see the module documentation).
///
/// Fails with `generator_options` when the length is outside 4 to 128, no
/// class is chosen, `min_each` is above 8, or `min_each` times the number of
/// classes is above the length. Nothing is drawn then.
pub fn generate_password<R: SecureRng>(
    o: &PasswordOptions,
    rng: &mut R,
) -> Result<Generated, Error> {
    let classes = o.classes()?;
    let alphabet: Vec<u8> = classes.iter().flatten().copied().collect();
    let length = usize::from(o.length);
    let mut chars = Zeroizing::new(Vec::with_capacity(length));

    for class in &classes {
        for _ in 0..o.min_each {
            let i = uniform_index(count(class)?, rng)?;
            chars.push(ct_pick(class, i));
        }
    }
    let all = count(&alphabet)?;
    while chars.len() < length {
        let i = uniform_index(all, rng)?;
        chars.push(ct_pick(&alphabet, i));
    }
    shuffle(&mut chars, rng)?;

    let mut value = Zeroizing::new(String::with_capacity(length));
    for c in chars.iter() {
        value.push(char::from(*c));
    }
    let bits = f64::from(o.length) * log2_of(all);
    Ok(Generated { value, bits })
}

/// Fisher–Yates over `chars`, from the last position down. The swap with the
/// random position `j` is done by a walk over the whole prefix `0..=i` that
/// reads and writes every position and selects with `subtle`, so the address
/// does not depend on `j`.
fn shuffle<R: SecureRng>(chars: &mut [u8], rng: &mut R) -> Result<(), Error> {
    for i in (1..chars.len()).rev() {
        let bound = u32::try_from(i)
            .map_err(|_| Error::GeneratorOptions)?
            .saturating_add(1);
        let j = uniform_index(bound, rng)?;
        let (prefix, rest) = chars.split_at_mut(i);
        let Some(last) = rest.first_mut() else {
            continue;
        };
        let at_i = *last;
        // The value at j: position i itself when j == i.
        let mut at_j = at_i;
        for (k, c) in prefix.iter().enumerate() {
            let k = u32::try_from(k).unwrap_or(u32::MAX);
            at_j.conditional_assign(c, k.ct_eq(&j));
        }
        for (k, c) in prefix.iter_mut().enumerate() {
            let k = u32::try_from(k).unwrap_or(u32::MAX);
            c.conditional_assign(&at_i, k.ct_eq(&j));
        }
        *last = at_j;
    }
    Ok(())
}
