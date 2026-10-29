//! Ed25519 (RFC 8032).

use crate::error::Error;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

/// Length of a signature in bytes.
pub(crate) const SIGNATURE_LEN: usize = 64;
/// Length of a public key in bytes.
pub(crate) const PUBLIC_KEY_LEN: usize = 32;

/// An Ed25519 signing key made from a 32-byte seed. Zeroized on drop; no
/// `Clone`, `Debug` or comparison. `ZeroizeOnDrop` is derived, so the
/// compiler checks that the inner key wipes itself.
#[derive(ZeroizeOnDrop)]
#[allow(dead_code)] // first used by Task 6 (mutation and recovery proofs)
pub(crate) struct Ed25519Key(SigningKey);

impl Ed25519Key {
    /// The public key.
    #[allow(dead_code)] // first used by Task 6
    pub(crate) fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.verifying_key().to_bytes()
    }
}

/// The signing key for `seed`; the seed is the RFC 8032 "secret key".
///
/// Spec: Fase 1 § 3 and § 4.5 (Ed25519, RFC 8032 section 5.1.5).
#[allow(dead_code)] // first used by Task 6
pub(crate) fn ed25519_from_seed(seed: &[u8; 32]) -> Ed25519Key {
    Ed25519Key(SigningKey::from_bytes(seed))
}

/// A pure Ed25519 signature of `msg` (RFC 8032 section 5.1.6).
///
/// Spec: Fase 1 § 3 (Ed25519, RFC 8032).
#[allow(dead_code)] // first used by Task 6
pub(crate) fn ed25519_sign(key: &Ed25519Key, msg: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
    // Signing with Ed25519 cannot fail; the error is mapped, not unwrapped.
    let signature = key.0.try_sign(msg).map_err(|_| Error::Unsupported)?;
    Ok(signature.to_bytes())
}

/// Verifies a pure Ed25519 signature with the strict rules of
/// `ed25519-dalek`: the scalar `S` must be canonical, and a public key or
/// `R` of small order is rejected. This accepts every honest signature and
/// rejects the malleable forms that RFC 8032 section 5.1.7 tolerates.
///
/// Every failure, including a malformed public key, is [`Error::Decrypt`].
///
/// Spec: Fase 1 § 3 and § 4.6 (Ed25519 verification, RFC 8032 section 5.1.7).
#[allow(dead_code)] // first used by Task 6
pub(crate) fn ed25519_verify(
    public: &[u8; PUBLIC_KEY_LEN],
    msg: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::Decrypt)?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(msg, &signature)
        .map_err(|_| Error::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::Ed25519Key;
    use static_assertions::assert_not_impl_any;

    // A signing key is secret: no copies, no printing, no ordinary equality.
    assert_not_impl_any!(
        Ed25519Key: Clone,
        Copy,
        core::fmt::Debug,
        core::fmt::Display,
        PartialEq,
        Eq,
        core::hash::Hash
    );
}
