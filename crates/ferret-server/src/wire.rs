//! The JSON shapes shared with the web vault, and the rules for how bytes and
//! ids are written in them.
//!
//! This file holds the one type the id types need today; the shapes, the
//! strict base64url and hex codecs and the list of error codes follow with the
//! wire contract (`tests/wire_contract.rs`, `tests/fixtures/wire/`).
//!
//! The rules: ids are 32 lower-case hexadecimal characters; other bytes are
//! base64url without padding; integers are at most 2^53; times are Unix
//! seconds.

use std::fmt;

/// Why a value from the wire was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// Not strict base64url without padding.
    Base64,
    /// Not 32 lower-case hexadecimal characters.
    Hex,
    /// Decoded to the wrong number of bytes.
    Length {
        /// What the field must have.
        expected: usize,
        /// What it had.
        got: usize,
    },
    /// A field that is missing, repeated or not allowed with the others.
    Field(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Base64 => f.write_str("not base64url without padding"),
            WireError::Hex => f.write_str("not 32 lower-case hexadecimal characters"),
            WireError::Length { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            WireError::Field(name) => write!(f, "field {name} is wrong"),
        }
    }
}

impl std::error::Error for WireError {}
