//! The PIN of the local unlock methods.
//!
//! Spec: Fase 1 § 7.2 ("minst 6 siffer"): a PIN is only digits
//! and is not normalized.

use crate::error::{Error, InputError};
use zeroize::Zeroizing;

/// Shortest PIN in digits. Spec: Fase 1 § 7.2.
pub const PIN_MIN_DIGITS: usize = 6;
/// Longest PIN in digits. Not in the design: a bound so that the input of
/// the stretching function stays small.
pub const PIN_MAX_DIGITS: usize = 64;

/// A PIN: ASCII digits, [`PIN_MIN_DIGITS`] to [`PIN_MAX_DIGITS`] of them.
/// The bytes are wiped on drop; there is no `Clone`, `Debug` or comparison.
pub struct Pin(Zeroizing<Vec<u8>>);

impl Pin {
    /// Checks the PIN rules and takes a copy. The caller's own buffer is the
    /// caller's to wipe.
    ///
    /// Fails with [`InputError::ForbiddenCharacter`] for anything but ASCII
    /// digits (checked first), then [`InputError::TooShort`] or
    /// [`InputError::TooLong`]. Nothing is computed from the PIN here.
    pub fn new(digits: &[u8]) -> Result<Pin, Error> {
        if !digits.iter().all(u8::is_ascii_digit) {
            return Err(Error::InvalidInput(InputError::ForbiddenCharacter));
        }
        if digits.len() < PIN_MIN_DIGITS {
            return Err(Error::InvalidInput(InputError::TooShort));
        }
        if digits.len() > PIN_MAX_DIGITS {
            return Err(Error::InvalidInput(InputError::TooLong));
        }
        Ok(Pin(Zeroizing::new(digits.to_vec())))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
