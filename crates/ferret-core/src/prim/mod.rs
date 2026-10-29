//! Primitives: Argon2id, XChaCha20-Poly1305, HKDF-SHA256, HMAC-SHA256,
//! Ed25519 and constant-time comparison.
//!
//! Only the Argon2id bounds ([`KdfParams`], [`KDF_FLOOR`], [`KDF_CEIL`],
//! [`check_kdf_params`]) are public. The functions are crate-internal: the
//! rest of the core builds on them, and nothing outside gets raw access to
//! key material. The `test-support` feature exposes thin wrappers in
//! `testing::prim` for the known-answer tests.
//!
//! Each function wraps a RustCrypto crate and adds no cryptography of its
//! own. Failures of authentication are always [`crate::Error::Decrypt`].

// The functions are first used by later tasks (and by the `test-support`
// wrappers), so a plain build sees them unused.
#![allow(dead_code)]

pub(crate) mod aead;
pub(crate) mod argon2;
pub(crate) mod ct;
pub(crate) mod ed25519;
pub(crate) mod hkdf;
pub(crate) mod mac;

pub use self::argon2::{KDF_CEIL, KDF_FLOOR, KdfParams, check_kdf_params};
