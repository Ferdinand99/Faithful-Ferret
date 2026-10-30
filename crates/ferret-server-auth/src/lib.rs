//! Server half of the OPAQUE login of Faithful Ferret, a self-hosted
//! zero-knowledge password manager.
//!
//! The library holds everything a server needs around the OPAQUE protocol
//! (RFC 9807) and nothing else: no HTTP, no database, no logging, and no
//! clock or randomness of its own. Randomness comes from a `SecureRng` of
//! `ferret-core` that the caller passes in, time from a [`Clock`]. The OPAQUE
//! suite, its context string and the message lengths are the ones of
//! `ferret-core`, so client and server cannot drift apart.
//!
//! This is a server crate. It enables the `server-suite` feature of
//! `ferret-core` and must never be part of a client release.
//!
//! # Errors and status codes
//!
//! Every failure is an [`AuthError`]. An endpoint answers from its
//! [`ErrorClass`] and, for a throttle, from the error itself:
//!
//! | class | status | body |
//! |---|---|---|
//! | [`ErrorClass::BadRequest`] | 400 | the public code of the error |
//! | [`ErrorClass::Denied`] | 401 | one fixed body for every denial |
//! | [`ErrorClass::Forbidden`] | 403 | the code `forbidden` |
//! | [`ErrorClass::TooManyRequests`] | 429 | the code `throttled`; `retry_after_secs` is read from [`AuthError::Throttled`] |
//! | [`ErrorClass::Internal`] | 500 | the code `internal`, never the cause |
//!
//! A [`DenyReason`] is for the server's own log. An endpoint must not choose
//! a status or a body from it.
//!
//! # Rate limits
//!
//! The library counts nothing. It asks a [`Throttle`] before it does any
//! work for a request and reports the outcome afterwards. A refusal is an
//! [`AuthError::Throttled`] with a wait between one second and one hour.
//! The library groups the caller's address itself (an IPv6 address as its
//! /64, an IPv4-mapped one as IPv4) and counts a caller without an address in
//! one shared bucket, so a limit cannot be skipped by a missing header.
//!
//! # Features
//!
//! * `test-support` (off by default, never part of a release): the manual
//!   clock `ManualClock` and the replay RNGs of the core.

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

pub mod clock;
mod ct;
pub mod error;
pub mod ids;
pub mod throttle;
pub mod keys;
pub mod secret_file;
pub mod startup;

#[cfg(feature = "test-support")]
pub use clock::ManualClock;
pub use clock::{Clock, SystemClock};
pub use error::{AuthError, DenyReason, ErrorClass, InternalKind, Malformed};
pub use ids::{CredentialId, LoginId, SessionBinding, StateKey};
pub use throttle::{Caller, NoThrottle, Outcome, RetryAfter, Stage, Throttle, ThrottleKey};
#[cfg(feature = "test-support")]
pub use throttle::{RecordingThrottle, ThrottleCall};
pub use keys::{
    CreatePolicy, FileOrigin, LoadedSecrets, PreloginSecret, ServerKeys, SetupFingerprint,
    load_or_create,
};
pub use secret_file::{
    FileKind, OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE, SecretFileError, decode_secret_file,
    encode_secret_file, permissions_enforced, read_secret_file, write_new_secret_file,
};
pub use startup::{StartupDecision, StartupRefusal, startup_decision};

/// How long the sealed state between `login_start` and `login_finish` lives,
/// in seconds. The state is used once.
///
/// One minute is long enough for a client to answer, and short enough that an
/// abandoned login does not linger.
pub const STATE_TTL_SECS: u64 = 60;

/// How long a nonce for a signed request stays valid, in seconds.
///
/// Spec: Fase 1 § 4.6.
pub const CHALLENGE_TTL_SECS: u64 = 300;
