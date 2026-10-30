//! The OPAQUE suite of Ferret, for a server built on this crate.
//!
//! Only with the feature `server-suite` (off by default). The server runs the
//! very same cipher suite, context and message lengths as the client in
//! this crate, so the two cannot drift apart. The WASM package never enables
//! the feature (`scripts/check-no-test-support.sh` checks it), so the client
//! API does not grow.
//!
//! The module re-exports `opaque_ke`: a server needs no `opaque-ke`
//! dependency of its own, and so cannot end up on another version of it.
//!
//! What was read in `opaque-ke` 4.0.1 before this module was written is in
//! `NOTES-server.md` next to it; the tests in `tests/server_suite.rs` lock each
//! point.
//!
//! # `ServerRegistration::dummy` is out of reach
//!
//! The fake record that the library builds for an unknown account is
//! `pub(crate)` there, so the server cannot call it. A server that wants the
//! same answer for the same name every time builds its own fake record and
//! passes it in as an ordinary record.
//!
//! ```compile_fail,E0624
//! use ferret_core::SecureRng;
//! use ferret_core::opaque::server_suite::opaque_ke::{ServerRegistration, ServerSetup};
//! use ferret_core::opaque::server_suite::{FerretSuite, Rng06};
//!
//! fn probe<R: SecureRng>(rng: &mut R, setup: &ServerSetup<FerretSuite>) {
//!     let _ = ServerRegistration::<FerretSuite>::dummy(&mut Rng06(rng), setup);
//! }
//! ```
//!
//! The same imports and set-up, without the call that must fail, do compile:
//!
//! ```
//! use ferret_core::SecureRng;
//! use ferret_core::opaque::server_suite::opaque_ke::{ServerRegistration, ServerSetup};
//! use ferret_core::opaque::server_suite::{FerretSuite, Rng06};
//!
//! fn probe<R: SecureRng>(rng: &mut R) -> ServerSetup<FerretSuite> {
//!     let _ = ServerRegistration::<FerretSuite>::finish;
//!     ServerSetup::<FerretSuite>::new(&mut Rng06(rng))
//! }
//! ```

pub use super::client::{KE2_LEN, REGISTRATION_RESPONSE_LEN, Rng06};
pub use super::suite::{FerretSuite, OPAQUE_CONTEXT};
pub use opaque_ke;

/// Length of a `registration_request`: one ristretto255 element.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 1).
pub const REGISTRATION_REQUEST_LEN: usize = 32;

/// Length of a stored record and of a `registration_upload`: client public key
/// 32, masking key 64, envelope 96 (nonce 32, MAC 64).
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3).
pub const REGISTRATION_RECORD_LEN: usize = 192;

/// Length of `KE1`: blinded element 32, client nonce 32, client ephemeral
/// public key 32.
///
/// Spec: Fase 1 § 4.2 ("Innlogging", step 1).
pub const KE1_LEN: usize = 96;

/// Length of `KE3`: the client's MAC, HMAC-SHA-512.
///
/// Spec: Fase 1 § 4.2 ("Innlogging", step 3).
pub const KE3_LEN: usize = 64;

/// Length of the serialized `ServerSetup`: OPRF seed 64, private key 32,
/// public "dummy" key 32.
///
/// Spec: Fase 1 § 4.2 and § 11 (the file `opaque_setup`).
pub const SERVER_SETUP_LEN: usize = 128;

/// Length of the serialized `ServerLogin` between `KE2` and `KE3`: the 3DH
/// session key (64) and the MAC the server expects in `KE3` (64).
pub const SERVER_LOGIN_STATE_LEN: usize = 128;
