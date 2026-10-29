//! Access to the crate-internal primitives for known-answer tests and vector
//! runners. Behind `test-support`; never part of a release.
//!
//! The wrappers take and return plain byte slices. Nothing here adds
//! behaviour: each one calls the primitive of the same name in `crate::prim`.

use crate::error::Error;
use crate::prim::{self, KdfParams};
use crate::rng::SecureRng;

/// Argon2id with the floor and ceiling check (the production path).
pub fn argon2id(pwd: &[u8], salt: &[u8], p: KdfParams, out: &mut [u8]) -> Result<(), Error> {
    prim::argon2::argon2id(pwd, salt, p, out)
}

/// Argon2id without the floor and ceiling, with a secret and associated
/// data. For the RFC 9106 vector only.
pub fn argon2id_unchecked(
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    p: KdfParams,
    out: &mut [u8],
) -> Result<(), Error> {
    prim::argon2::argon2id_unchecked(pwd, salt, secret, ad, p, out)
}

/// How many Argon2 computations have started on the calling thread. A call
/// that is rejected by the bounds must leave this unchanged.
pub fn argon2_run_count() -> usize {
    prim::argon2::RUNS.get()
}

/// `nonce ‖ ct ‖ tag` under XChaCha20-Poly1305 with a nonce from `rng`.
pub fn aead_seal<R: SecureRng>(
    rng: &mut R,
    key: &[u8; 32],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>, Error> {
    prim::aead::aead_seal(rng, key, aad, pt)
}

/// Opens a blob made by [`aead_seal`]; every failure is `Error::Decrypt`.
pub fn aead_open(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, Error> {
    prim::aead::aead_open(key, aad, blob).map(|pt| pt.to_vec())
}

/// HKDF-SHA256.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) -> Result<(), Error> {
    prim::hkdf::hkdf_sha256(salt, ikm, info, out)
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; 32], Error> {
    prim::mac::hmac_sha256(key, msg)
}

/// The Ed25519 public key for a seed.
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    prim::ed25519::ed25519_from_seed(seed).public_key()
}

/// An Ed25519 signature of `msg` under the key for `seed`.
pub fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
    prim::ed25519::ed25519_sign(&prim::ed25519::ed25519_from_seed(seed), msg)
}

/// Strict Ed25519 verification; every failure is `Error::Decrypt`.
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> Result<(), Error> {
    prim::ed25519::ed25519_verify(public, msg, signature)
}

/// Constant-time byte-string comparison.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    prim::ct::ct_eq(a, b)
}
