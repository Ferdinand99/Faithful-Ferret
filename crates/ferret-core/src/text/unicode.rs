//! NFKD and the character rules for passwords.
//!
//! Spec: Fase 1 section 3.1 (F-23). The Unicode table version is locked to
//! 16.0 for suite 1. It is a property of the exact crate versions, so the
//! constants below are checked by a test.

use crate::error::{Error, InputError};
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

/// The Unicode version of the NFKD tables (`unicode-normalization` 0.1.24).
pub use unicode_normalization::UNICODE_VERSION;

/// The Unicode version of the general category tables
/// (`unicode-general-category` 1.1.0), used for the "assigned" check.
pub const CATEGORY_UNICODE_VERSION: (u64, u64, u64) = unicode_general_category::UNICODE_VERSION;

/// Most Unicode scalar values in a normalized password.
pub const MAX_SCALARS: usize = 1_024;

/// Most bytes of the normalized password as UTF-8.
pub const MAX_BYTES: usize = 4_096;

/// True if `c` is assigned in the locked tables, that is, its general
/// category is not Cn. Noncharacters (U+FFFE, U+FFFF, U+FDD0..U+FDEF and so
/// on) are Cn, and so are characters first assigned after Unicode 16.0.
pub fn is_assigned(c: char) -> bool {
    get_general_category(c) != GeneralCategory::Unassigned
}

/// True if a password may contain `c`: assigned, and not a control
/// character (Cc, which includes U+0000, tab and U+0085).
pub fn is_allowed(c: char) -> bool {
    !matches!(
        get_general_category(c),
        GeneralCategory::Unassigned | GeneralCategory::Control
    )
}

/// NFKD of `s`. Not bounded in time or memory; use it for text of a known
/// size. Passwords go through `normalize_password`, which bounds both.
///
/// The exact UTF-8 size of the result is computed first (one extra pass), so
/// the string is allocated once and never regrown: no unwiped copy of the
/// text is left behind by a reallocation.
pub fn nfkd(s: &str) -> Zeroizing<String> {
    let size: usize = s.nfkd().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(String::with_capacity(size));
    out.extend(s.nfkd());
    out
}

/// A password after normalization.
pub(crate) struct Normalized {
    /// NFKD as UTF-8, at most [`MAX_BYTES`] bytes. Never reallocated: the
    /// capacity is reserved up front so that no copy is left behind.
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    /// Length in NFC scalar values of the input: the unit of the minimum
    /// length (plan U9 a).
    pub(crate) nfc_len: usize,
}

/// Validates and normalizes password text.
///
/// 1. The bytes must be UTF-8 (a lone surrogate cannot be). `NotUtf8`.
/// 2. No character may be Cc (including U+0000) or unassigned (Cn) in the
///    locked tables. `ForbiddenCharacter`. This is checked on the input;
///    NFKD maps assigned characters to assigned, non-control ones (a test
///    checks every scalar value).
/// 3. The input must have at most [`MAX_SCALARS`] scalars, and its NFKD at
///    most [`MAX_SCALARS`] scalars and [`MAX_BYTES`] bytes. `TooLong`. Every
///    input scalar gives at least one NFKD scalar, so the first test is
///    exact, and it runs before any normalization: the normalizer buffers a
///    run of combining marks (on the heap beyond four) until the next
///    starter, so without it a long run would cost unbounded memory and time
///    and leave an unwiped copy. After it, the buffers hold at most 1 024
///    entries. The NFKD stream then stops at the limit.
/// 4. The length of the NFC form of the input is returned for the caller's
///    minimum check.
///
/// Spec: Fase 1 section 3.1 and 4.1 step 1; plan U9 (a).
pub(crate) fn normalize_password(utf8: &[u8]) -> Result<Normalized, Error> {
    let text = core::str::from_utf8(utf8).map_err(|_| Error::InvalidInput(InputError::NotUtf8))?;
    if !text.chars().all(is_allowed) {
        return Err(Error::InvalidInput(InputError::ForbiddenCharacter));
    }
    if text.chars().nth(MAX_SCALARS).is_some() {
        return Err(Error::InvalidInput(InputError::TooLong));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES));
    let mut scalars = 0usize;
    let mut encoded = [0u8; 4];
    for c in text.nfkd() {
        let piece = c.encode_utf8(&mut encoded).as_bytes();
        scalars = scalars.saturating_add(1);
        if scalars > MAX_SCALARS || bytes.len().saturating_add(piece.len()) > MAX_BYTES {
            encoded.zeroize();
            return Err(Error::InvalidInput(InputError::TooLong));
        }
        bytes.extend_from_slice(piece);
    }
    encoded.zeroize();
    // The input has at most as many scalars as its NFKD form, so this is
    // bounded by `MAX_SCALARS` too.
    let nfc_len = text.nfc().count();
    Ok(Normalized { bytes, nfc_len })
}
