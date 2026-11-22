//! Access to the generator internals for tests and vector runners. Behind
//! `test-support`; never part of a release.

use crate::error::Error;
use crate::generator;
use crate::rng::SecureRng;

/// [`generator::uniform_index`]: uniform in `0..n` by rejection.
pub fn uniform_index<R: SecureRng>(n: u32, rng: &mut R) -> Result<u32, Error> {
    generator::uniform_index(n, rng)
}

/// The words that are compiled in, one per line.
pub fn embedded_words() -> &'static str {
    generator::passphrase::WORDS
}

/// The base-2 logarithm that the estimates use.
pub fn log2_of(n: u32) -> f64 {
    generator::log2_of(n)
}
