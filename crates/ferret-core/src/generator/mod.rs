//! The password and passphrase generator.
//!
//! Every client gets its generated passwords from here, so there is one
//! generator, written once and tested once. It takes all randomness from a
//! [`SecureRng`] (in production [`crate::OsRng`]) and nothing else.
//!
//! * [`generate_password`]: characters from the classes the caller chose
//!   (see [`password`]).
//! * [`generate_passphrase`]: words from the EFF large word list (see
//!   [`passphrase`]).
//!
//! **Uniform choices.** Every random choice is `uniform_index`: a draw of
//! four bytes, read as a little-endian `u32`, refused when it is at or above
//! `n * floor(2^32 / n)` (rejection sampling, so no value of `0..n` is more
//! likely than another), and reduced modulo `n`. A refused draw is thrown
//! away and a new one is made; the draws are independent, so a refusal says
//! nothing about the value that is chosen in the end.
//!
//! **Timing.** The reduction modulo `n` is a multiplication by a precomputed
//! reciprocal (Barrett reduction) with one correction step through `subtle`,
//! not a division: a division instruction can take a time that depends on its
//! operands, and here the dividend is the random draw. The character of a
//! class, the swap of the shuffle and the word of the list are found by a
//! walk over the whole alphabet, prefix or list that selects with `subtle`,
//! so the address that is read does not depend on the random index either.
//! What is not hidden is the length of the result (a passphrase's words have
//! different lengths), which the caller sees anyway, and whether a draw was
//! refused.
//!
//! **Strength.** [`Generated::bits`] is the entropy estimate for display:
//! `length * log2(alphabet)` for a password and
//! `words * log2(7776)` (plus `log2(10) + log2(words)` for the number) for a
//! passphrase. It is computed with a log2 of our own that uses only
//! multiplications (`log2_of`), so the value is the same on every platform
//! and in the test vectors.

pub mod passphrase;
pub mod password;

pub use passphrase::{PassphraseOptions, SEPARATORS, WORD_COUNT, generate_passphrase};
pub use password::{AMBIGUOUS, DIGITS, LOWER, PasswordOptions, SYMBOLS, UPPER, generate_password};

use crate::error::Error;
use crate::rng::SecureRng;
use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::{Zeroize, Zeroizing};

/// A generated password or passphrase and its entropy estimate.
///
/// The value is wiped when it is dropped. `Debug` shows only the estimate.
pub struct Generated {
    /// The password or passphrase.
    pub value: Zeroizing<String>,
    /// The entropy estimate in bits, for display (see the module
    /// documentation).
    pub bits: f64,
}

impl core::fmt::Debug for Generated {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Generated")
            .field("value", &"<redacted>")
            .field("bits", &self.bits)
            .finish()
    }
}

/// `2^32`, the number of values of one draw.
const DRAW_SPACE: u64 = 1 << 32;

/// Uniform in 0..n by rejection: draws u32 and refuses values >= n * floor(2^32 / n). Refuses n == 0.
///
/// Each attempt draws four bytes from `rng` (a little-endian `u32`). An
/// accepted draw `x` gives `x mod n`, computed without a division (see the
/// module documentation). `n == 0` is `generator_options`.
pub(crate) fn uniform_index<R: SecureRng>(n: u32, rng: &mut R) -> Result<u32, Error> {
    if n == 0 {
        return Err(Error::GeneratorOptions);
    }
    let n = u64::from(n);
    // floor(2^32 / n): a division of public numbers (n is the size of an
    // alphabet, a list or a prefix of the shuffle). `n >= 1`, so no panic.
    let reciprocal = DRAW_SPACE.checked_div(n).ok_or(Error::GeneratorOptions)?;
    // n * floor(2^32 / n) <= 2^32: the accepted draws are 0..limit, and each
    // value of 0..n is hit by exactly `reciprocal` of them.
    let limit = n.saturating_mul(reciprocal);
    let mut bytes = [0u8; 4];
    loop {
        rng.fill(&mut bytes);
        let x = u64::from(u32::from_le_bytes(bytes));
        if x < limit {
            bytes.zeroize();
            return Ok(reduce(x, n, reciprocal));
        }
    }
}

/// `x mod n` for `x < 2^32` and `1 <= n <= 2^32`, with
/// `reciprocal = floor(2^32 / n)`.
///
/// The quotient estimate `q = floor(x * reciprocal / 2^32)` is `floor(x / n)`
/// or one less (the error of the reciprocal is below `n / 2^32`, so the
/// estimate is short by less than `x / 2^32 < 1`). So `x - q * n` is in
/// `0..2n`, and one subtraction of `n`, selected with `subtle`, finishes it.
/// Only multiplications, a shift and a constant-time selection.
fn reduce(x: u64, n: u64, reciprocal: u64) -> u32 {
    // x < 2^32 and reciprocal <= 2^32, so the product fits (below 2^64).
    let q = x.wrapping_mul(reciprocal) >> 32;
    // q <= x / n, so q * n <= x: no wrap.
    let mut r = x.wrapping_sub(q.wrapping_mul(n));
    let reduced = r.wrapping_sub(n);
    r.conditional_assign(&reduced, r.ct_gt(&n.wrapping_sub(1)));
    // r < n <= 2^32 here.
    u32::try_from(r).unwrap_or(0)
}

/// The byte of `alphabet` at `index`, read by a walk over the whole alphabet
/// that selects with `subtle` (the address that is read does not depend on
/// `index`). `0` when `index` is out of range, which callers never pass.
pub(crate) fn ct_pick(alphabet: &[u8], index: u32) -> u8 {
    let mut out = 0u8;
    for (k, c) in alphabet.iter().enumerate() {
        let k = u32::try_from(k).unwrap_or(u32::MAX);
        out.conditional_assign(c, k.ct_eq(&index));
    }
    out
}

/// The base-2 logarithm of `n >= 1` with only multiplications and
/// comparisons, which IEEE 754 rounds the same way everywhere: the integer
/// part from the position of the highest bit, then 52 bits of the fraction by
/// repeated squaring of the mantissa (`m^2 >= 2` gives a one bit). The result
/// is within a few units in the last place of the exact value and is the same
/// on every platform. `0` for `n == 0`.
pub(crate) fn log2_of(n: u32) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let int_part = 31u32.saturating_sub(n.leading_zeros());
    // m = n / 2^int_part, in [1, 2), exact (a power-of-two scaling).
    let mut m = f64::from(n);
    for _ in 0..int_part {
        m *= 0.5;
    }
    let mut fraction = 0.0f64;
    let mut bit = 0.5f64;
    for _ in 0..52 {
        m *= m;
        if m >= 2.0 {
            m *= 0.5;
            fraction += bit;
        }
        bit *= 0.5;
    }
    f64::from(int_part) + fraction
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Plays back fixed draws.
    struct Draws(VecDeque<Vec<u8>>);

    impl SecureRng for Draws {
        fn fill(&mut self, dest: &mut [u8]) {
            let next = self.0.pop_front().expect("a draw is left");
            dest.copy_from_slice(&next);
        }
    }

    /// xorshift64*, for test inputs only.
    fn next(state: &mut u64) -> u64 {
        *state ^= *state >> 12;
        *state ^= *state << 25;
        *state ^= *state >> 27;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    #[test]
    fn reduce_is_the_remainder() {
        for n in 1u64..=300 {
            let reciprocal = DRAW_SPACE / n;
            let limit = n * reciprocal;
            let mut xs: Vec<u64> = (0..2000).collect();
            xs.extend((0..2000).map(|i| limit - 1 - i));
            for x in xs {
                assert_eq!(u64::from(reduce(x, n, reciprocal)), x % n, "{x} mod {n}");
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..200_000 {
            let n = (next(&mut state) >> 32).max(1);
            let reciprocal = DRAW_SPACE / n;
            let x = (next(&mut state) >> 32) % (n * reciprocal);
            assert_eq!(u64::from(reduce(x, n, reciprocal)), x % n, "{x} mod {n}");
        }
        // The largest n and the edges of 2^32.
        for n in [u64::from(u32::MAX), (1 << 31) + 1, 1 << 31, 3] {
            let reciprocal = DRAW_SPACE / n;
            for x in [0, 1, n - 1, n, n * reciprocal - 1] {
                assert_eq!(u64::from(reduce(x, n, reciprocal)), x % n);
            }
        }
    }

    #[test]
    fn uniform_index_draws_until_one_is_accepted() {
        // n = 3: limit = 3 * 1431655765 = 4294967295; the one refused value
        // is 0xffffffff.
        let mut rng = Draws(VecDeque::from(vec![
            0xffff_ffffu32.to_le_bytes().to_vec(),
            7u32.to_le_bytes().to_vec(),
        ]));
        assert_eq!(uniform_index(3, &mut rng).unwrap(), 1);
        assert!(rng.0.is_empty());
        assert_eq!(
            uniform_index(0, &mut Draws(VecDeque::new())),
            Err(Error::GeneratorOptions)
        );
    }

    #[test]
    fn pick_reads_the_index() {
        let alphabet = b"abcdef";
        for (i, c) in alphabet.iter().enumerate() {
            assert_eq!(ct_pick(alphabet, u32::try_from(i).unwrap()), *c);
        }
        assert_eq!(ct_pick(alphabet, 6), 0);
    }

    #[test]
    fn log2_is_close_to_the_float_one_and_exact_on_powers_of_two() {
        for n in 1u32..=10_000 {
            let ours = log2_of(n);
            let theirs = f64::from(n).log2();
            assert!(
                (ours - theirs).abs() < 1e-12,
                "log2({n}): {ours} vs {theirs}"
            );
        }
        for k in 0..32 {
            assert_eq!(log2_of(1 << k), f64::from(k));
        }
        assert_eq!(log2_of(0), 0.0);
        assert!((log2_of(u32::MAX) - f64::from(u32::MAX).log2()).abs() < 1e-12);
        assert!((log2_of(7776) - 12.924_812_503_605_78).abs() < 1e-12);
    }
}
