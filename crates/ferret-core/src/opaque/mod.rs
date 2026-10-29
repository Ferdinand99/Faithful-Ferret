//! OPAQUE (RFC 9807), the client side of the account login.
//!
//! Spec: Fase 1 § 4.1 and § 4.2. The password never leaves the device: the
//! client runs OPAQUE with the server, gets the 64-byte `export_key` that only
//! it knows, and derives `KEK_pw` from it ([`crate::Kek::from_export_key`]).
//! The server half lives in the server code; the tests have one built from
//! `opaque-ke`'s server API behind `test-support`.
//!
//! # Configuration
//!
//! ristretto255 with SHA-512, 3DH, HMAC-SHA-512, HKDF-SHA-512, the internal
//! envelope, context `ferret/v1/opaque`, no client or server identities (the
//! public keys stand in), and Argon2id v1.3 as the key stretching function
//! with a salt of 16 zero bytes and an output of 64 bytes, its parameters
//! from the [`crate::KsfProfile`] (see `suite.rs` and `ksf.rs`).
//!
//! # Pinning
//!
//! `opaque_login_finish` takes a [`PinState`]. The server key pin at login is
//! defence in depth: a changed key fails the envelope check first and shows as
//! `Decrypt`. The detection of a changed key is the comparison of
//! `RegistrationFinished::server_public_key` with the pinned key on every
//! re-registration (Task 9); see `client.rs` for the whole argument.
//!
//! # `opaque-ke` and the duplicate crates
//!
//! `opaque-ke` 4.0.1 is built on the previous generation of RustCrypto
//! (`digest` 0.10, `rand` 0.8, `curve25519-dalek` 4). The core's own code uses
//! the new generation. The two live side by side; the duplicates are listed in
//! `deny.toml` with their reasons, and `opaque-ke` is pinned exactly.
//! `NOTES.md` in this directory records what was checked in the library before
//! the code was written.

pub(crate) mod client;
pub(crate) mod ksf;
pub(crate) mod suite;

pub use client::{
    LoginFinished, LoginState, PinState, RegistrationFinished, RegistrationState,
    opaque_login_finish, opaque_login_start, opaque_register_finish, opaque_register_start,
};
pub use suite::OPAQUE_CONTEXT;
