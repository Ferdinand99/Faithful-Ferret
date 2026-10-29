//! HKDF-SHA256.

use crate::error::Error;
use ::hkdf::Hkdf;
use sha2::Sha256;

/// HKDF-SHA256 (Extract then Expand) into `out`.
///
/// `salt` is used as given; an empty salt is the same as a salt of 32 zero
/// bytes, as RFC 5869 requires. AAD-like salts are built with
/// [`crate::Tlv`].
///
/// Fails with [`Error::TooLarge`] if `out` is longer than 255 × 32 bytes.
///
/// Spec: Fase 1 § 3 (HKDF-SHA256, RFC 5869).
pub(crate) fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out)
        .map_err(|_| Error::TooLarge)
}
