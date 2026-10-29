//! Test support: replaying and deterministic RNGs and the test-vector loader
//! and runner. Behind the `test-support` feature, which is never part of a
//! release build.
//!
//! This module is test tooling, not production code, so the strict
//! production lints are relaxed here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

pub mod keys;
pub mod prim;
mod replay_rng;
pub mod text;
pub mod vector;

pub use replay_rng::{ReplayError, ReplayRng, TestRng};

/// Error from [`hex_decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// Odd number of digits.
    OddLength,
    /// A character other than `0-9a-f`.
    BadDigit,
}

/// Encodes bytes as lowercase hex without a prefix.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// Decodes strict lowercase hex (no prefix, no whitespace, no capitals).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, HexError> {
    fn digit(c: u8) -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(HexError::BadDigit),
        }
    }
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(HexError::OddLength);
    }
    pairs
        .iter()
        .map(|[hi, lo]| Ok((digit(*hi)? << 4) | digit(*lo)?))
        .collect()
}
