//! HKDF-SHA256.

use crate::error::Error;
use ::hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF-SHA256 (Extract then Expand) into `out`.
///
/// `salt` is used as given; an empty salt is the same as a salt of 32 zero
/// bytes, as RFC 5869 requires. AAD-like salts are built with
/// [`crate::Tlv`].
///
/// Fails with [`Error::TooLarge`] if `out` is longer than 255 × 32 bytes.
///
/// Spec: Fase 1 § 3 (HKDF-SHA256, RFC 5869).
#[allow(dead_code)] // first used by Task 4 (key derivations)
pub(crate) fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // Extract, wipe the pseudorandom key at once (it is not needed again: the
    // expander holds its own keyed HMAC state, which `hmac` wipes on drop with
    // its `zeroize` feature), then expand.
    let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.as_mut_slice().zeroize();
    hkdf.expand(info, out).map_err(|_| Error::TooLarge)
}
