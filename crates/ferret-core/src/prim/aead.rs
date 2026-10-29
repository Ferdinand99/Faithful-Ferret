//! XChaCha20-Poly1305 with the stored layout `nonce ‖ ct ‖ tag`.

use crate::error::Error;
use crate::rng::SecureRng;
use chacha20poly1305::{AeadInOut, Key, KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

/// Nonce length in bytes (192 bits).
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub(crate) const TAG_LEN: usize = 16;
/// Bytes a sealed blob adds to the plaintext.
pub(crate) const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

#[cfg(feature = "test-support")]
std::thread_local! {
    /// Number of `aead_open` calls on this thread. Lets a test prove that a
    /// wrap with a wrong key commitment never reaches the AEAD.
    pub(crate) static OPENS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The cipher for `key`. The temporary key copy is wiped; the cipher wipes
/// its own copy when dropped (`zeroize` feature of `chacha20poly1305`).
fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut k = Key::from(*key);
    let cipher = XChaCha20Poly1305::new(&k);
    k.as_mut_slice().zeroize();
    cipher
}

/// Seals `pt` under `key` with `aad`: `nonce (24) ‖ ct ‖ tag (16)`.
///
/// The nonce is 24 fresh random bytes from `rng`, drawn in a single `fill`
/// call, new for every encryption and never a counter.
///
/// Fails only with [`Error::TooLarge`] if the plaintext exceeds what the
/// cipher can encrypt under one nonce.
///
/// Spec: Fase 1 § 3.1 (`AEAD(key, nonce, pt, aad)` is XChaCha20-Poly1305,
/// stored as `nonce (24) ‖ ct ‖ tag (16)`) and § 5.4.
pub(crate) fn aead_seal<R: SecureRng>(
    rng: &mut R,
    key: &[u8; 32],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce);
    // The buffer holds the plaintext until it is encrypted in place; wipe it
    // on every path, including the error return.
    let mut buf = Zeroizing::new(Vec::with_capacity(pt.len().saturating_add(TAG_LEN)));
    buf.extend_from_slice(pt);
    cipher(key)
        .encrypt_in_place(&XNonce::from(nonce), aad, &mut *buf)
        .map_err(|_| Error::TooLarge)?;
    let mut out = Vec::with_capacity(NONCE_LEN.saturating_add(buf.len()));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Opens a blob made by [`aead_seal`]. Every failure is the single
/// [`Error::Decrypt`]: a blob shorter than `nonce ‖ tag`, a wrong key, a
/// wrong AAD or a changed byte all look the same.
///
/// The plaintext is returned in a buffer that is wiped on drop.
///
/// Spec: Fase 1 § 3.1 and § 5.3 (one error for every authentication
/// failure).
pub(crate) fn aead_open(
    key: &[u8; 32],
    aad: &[u8],
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    #[cfg(feature = "test-support")]
    OPENS.set(OPENS.get().saturating_add(1));
    if blob.len() < OVERHEAD {
        return Err(Error::Decrypt);
    }
    let (nonce, ct_and_tag) = blob.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Decrypt)?;
    let mut buf = Zeroizing::new(ct_and_tag.to_vec());
    cipher(key)
        .decrypt_in_place(&XNonce::from(nonce), aad, &mut *buf)
        .map_err(|_| Error::Decrypt)?;
    Ok(buf)
}
