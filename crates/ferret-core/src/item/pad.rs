//! Padding of the plaintext body: ISO/IEC 7816-4.
//!
//! Spec: Fase 1 § 5.2 ("Utfylling") and plan U6.
//!
//! ```text
//! padded = plaintext ‖ 0x80 ‖ 0x00 × n
//! ```
//!
//! The length of `padded` is the smallest of 256, 512, 1 024, 2 048, 4 096
//! and then every multiple of 4 096 that is at least `len(plaintext) + 1`.
//! The largest padded body is 61 440 bytes (15 × 4 096), so that the whole
//! envelope stays within 65 536 bytes (the envelope adds at most 115 bytes).
//! There is no compression before encryption.
//!
//! The marker is found by scanning the whole buffer from the back with the
//! code in `ct/harness/unpad.rs`: no loop exit and no branch depends on
//! where the marker is or on the contents. It runs only after the AEAD has
//! accepted the ciphertext.

use crate::error::Error;
use zeroize::Zeroizing;

/// The branch-free scan, included from `ct/harness/`.
pub mod scan {
    include!("../../../../ct/harness/unpad.rs");
}

/// The marker byte after the plaintext.
const MARKER: u8 = 0x80;

/// The smallest padded length.
pub const MIN_PADDED: usize = 256;
/// Padded lengths above the powers of two are multiples of this.
pub const STEP: usize = 4_096;
/// The largest padded body (U6): 15 × 4 096.
pub const MAX_PADDED: usize = 61_440;
/// The largest plaintext that can be padded.
pub const MAX_PLAINTEXT: usize = MAX_PADDED - 1;

/// The padded length for a plaintext of `plain_len` bytes.
///
/// `Err(TooLarge)` if the padded body would exceed [`MAX_PADDED`], which is
/// the case from a plaintext of 61 440 bytes.
///
/// Spec: Fase 1 § 5.2 and plan U6.
pub fn padded_len(plain_len: usize) -> Result<usize, Error> {
    let need = plain_len.checked_add(1).ok_or(Error::TooLarge)?;
    let len = match need {
        0..=256 => 256,
        257..=512 => 512,
        513..=1_024 => 1_024,
        1_025..=2_048 => 2_048,
        2_049..=4_096 => 4_096,
        _ => need
            .div_ceil(STEP)
            .checked_mul(STEP)
            .ok_or(Error::TooLarge)?,
    };
    if len > MAX_PADDED {
        return Err(Error::TooLarge);
    }
    Ok(len)
}

/// Whether `len` is one of the padded lengths: 256, 512, 1 024, 2 048,
/// 4 096 or a multiple of 4 096 up to [`MAX_PADDED`].
pub fn is_padded_len(len: usize) -> bool {
    matches!(len, 256 | 512 | 1_024 | 2_048)
        || ((STEP..=MAX_PADDED).contains(&len) && len.checked_rem(STEP) == Some(0))
}

/// Pads `plain`. The result is wiped when dropped.
pub fn pad(plain: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let len = padded_len(plain.len())?;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(plain);
    out.push(MARKER);
    out.resize(len, 0);
    Ok(out)
}

/// Finds the plaintext in a padded buffer and returns its length.
///
/// The whole buffer is scanned the same way whatever it holds. A buffer that
/// does not end in `0x80` followed by zero bytes only is `Error::Decrypt`,
/// like every other authentication failure. Call this only after the AEAD
/// has accepted the buffer; the plaintext is `padded[..len]`.
///
/// Spec: Fase 1 § 5.2 and § 14 (constant-time padding removal).
pub fn unpad(padded: &[u8]) -> Result<usize, Error> {
    let (ok, len) = scan::unpad_scan(padded);
    if ok == 1 {
        Ok(len)
    } else {
        Err(Error::Decrypt)
    }
}
