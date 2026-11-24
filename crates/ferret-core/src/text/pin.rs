//! The PIN of the local unlock methods.
//!
//! Spec: Fase 1 § 7.2 and § 3.1. A PIN is digits or text. It is normalized
//! with NFKD like the master password (Unicode 16.0 tables), so a full-width
//! digit and an ASCII digit give the same PIN. Control characters and
//! characters that are unassigned in those tables are refused. The length is
//! counted in Unicode scalar values: one to [`PIN_MAX_SCALARS`] of them, and
//! at most [`PIN_MAX_BYTES`] bytes after the normalization.
//!
//! What a PIN has to be at least is the rule of the server ([`PinRule`]),
//! never lower than [`PIN_FLOOR`]. Whether it is digits or text is not
//! recorded anywhere: nothing here or in a stored blob reveals the kind or
//! the length of a PIN.

use super::unicode::is_allowed;
use crate::error::{Error, InputError};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Most Unicode scalar values in a PIN.
pub const PIN_MAX_SCALARS: usize = 64;
/// Most bytes of a PIN, as UTF-8 after NFKD.
pub const PIN_MAX_BYTES: usize = 256;
/// The lowest minimum length that a rule can ask for. The client never
/// accepts a PIN below this, whatever the server's rule says.
pub const PIN_FLOOR: u8 = 4;

/// A PIN: NFKD as UTF-8, validated. The bytes are wiped on drop; there is no
/// `Clone`, `Debug` or comparison.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Pin(Zeroizing<Vec<u8>>);

impl Pin {
    /// Validates and normalizes `utf8` and takes a copy. The caller's own
    /// buffer is the caller's to wipe.
    ///
    /// Errors, in this order: `input_not_utf8`, `input_forbidden_character`
    /// (a control character or an unassigned one), `input_too_long` (more
    /// than [`PIN_MAX_SCALARS`] scalar values, or more than
    /// [`PIN_MAX_BYTES`] bytes after the normalization), `input_too_short`
    /// (empty). Nothing is computed from the PIN here. The rule of the
    /// server is applied by [`pin_meets_rule`], not here, so that a PIN that
    /// was valid under an older rule can still be tried.
    pub fn new(utf8: &[u8]) -> Result<Pin, Error> {
        let text =
            core::str::from_utf8(utf8).map_err(|_| Error::InvalidInput(InputError::NotUtf8))?;
        if !text.chars().all(is_allowed) {
            return Err(Error::InvalidInput(InputError::ForbiddenCharacter));
        }
        // Every input scalar gives at least one NFKD scalar, so this is exact
        // and it bounds the work and the buffers of the normalizer.
        if text.chars().nth(PIN_MAX_SCALARS).is_some() {
            return Err(Error::InvalidInput(InputError::TooLong));
        }
        // Reserved at once, so the buffer is never reallocated and no unwiped
        // copy is left behind.
        let mut bytes = Zeroizing::new(Vec::with_capacity(PIN_MAX_BYTES));
        let mut scalars = 0usize;
        let mut encoded = [0u8; 4];
        for c in text.nfkd() {
            let piece = c.encode_utf8(&mut encoded).as_bytes();
            scalars = scalars.saturating_add(1);
            if scalars > PIN_MAX_SCALARS || bytes.len().saturating_add(piece.len()) > PIN_MAX_BYTES
            {
                encoded.zeroize();
                return Err(Error::InvalidInput(InputError::TooLong));
            }
            bytes.extend_from_slice(piece);
        }
        encoded.zeroize();
        if bytes.is_empty() {
            return Err(Error::InvalidInput(InputError::TooShort));
        }
        Ok(Pin(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The length that a rule counts: Unicode scalar values of the NFC form
    /// of the normalized PIN, so a letter with a combining accent is one.
    fn rule_len(&self) -> usize {
        core::str::from_utf8(&self.0)
            .map(|text| text.nfc().count())
            .unwrap_or(0)
    }

    /// The normalized bytes, for the tests of a separate crate (behind
    /// `test-support`).
    #[cfg(feature = "test-support")]
    pub fn test_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Start of the buffer and its capacity, so that a test in a separate
    /// crate can check that a wipe clears the whole allocation.
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.0.as_ptr(), self.0.capacity())
    }
}

/// What the server demands of a PIN. Values from outside are clamped, never
/// trusted: a minimum length below [`PIN_FLOOR`] is the floor, and one above
/// [`PIN_MAX_SCALARS`] is the maximum.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PinRule {
    /// Whether a PIN is allowed at all.
    pub allowed: bool,
    /// Whether a PIN may stay on disk across a restart of the browser. The
    /// core does not read this; the extension that stores the blob does.
    pub after_restart: bool,
    /// The shortest PIN, in Unicode scalar values (4 to 64).
    pub min_length: u8,
}

/// Checks `pin` against the rule: a rule that forbids PINs refuses every PIN
/// ([`Error::PinNotAllowed`]), and a PIN shorter than the rule's minimum, or
/// than [`PIN_FLOOR`], is [`InputError::TooShort`]. Nothing is computed from
/// the PIN, and only its length is looked at.
///
/// Spec: Fase 1 § 7.2.
pub fn pin_meets_rule(pin: &Pin, rule: &PinRule) -> Result<(), Error> {
    if !rule.allowed {
        return Err(Error::PinNotAllowed);
    }
    let min = usize::from(rule.min_length).clamp(usize::from(PIN_FLOOR), PIN_MAX_SCALARS);
    if pin.rule_len() < min {
        return Err(Error::InvalidInput(InputError::TooShort));
    }
    Ok(())
}
