//! Crypto core of Faithful Ferret, a self-hosted zero-knowledge password
//! manager.
//!
//! The core is written in safe Rust, takes all randomness from a
//! [`SecureRng`], and reports failures as stable [`Error`] codes. Nothing in
//! this crate does I/O.
//!
//! # Features
//!
//! * `test-support` (off by default, never part of a release): a replaying
//!   RNG, a deterministic test RNG and the test-vector loader and runner in
//!   [`testing`].

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
// Unit tests inside the crate may use the panicking helpers; the rules above
// are for production code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

pub mod error;
pub mod ids;
pub mod rng;
pub mod secret;
#[cfg(feature = "test-support")]
pub mod testing;

pub use error::{CheckpointFailure, Error, InputError, MalformedKind};
pub use ids::{AccountId, ItemId, MethodId, VaultId};
pub use rng::{OsRng, SecureRng};
pub use secret::{
    AuthSeed, ExportContentKey, ExportKey, ItemKey, KDel, KHead, KMeta, Kek, PrfOutput, PrfSeed,
    RecoveryKey, SecretKey, VaultKey,
};
#[cfg(feature = "test-support")]
pub use testing::{ReplayRng, TestRng};
