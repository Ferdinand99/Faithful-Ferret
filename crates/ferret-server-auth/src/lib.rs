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
//! # Login state
//!
//! Between `login_start` and `login_finish` the server keeps the state of the
//! OPAQUE exchange, sealed, in a [`LoginStateStore`]. The state lives for
//! [`STATE_TTL_SECS`] seconds and is used once: the first `take` removes it,
//! so a repeated or simultaneous `login_finish` finds nothing.
//!
//! # Login
//!
//! [`login_start`] and [`login_finish`] are the two server steps of an OPAQUE
//! login. A name without an account and a disabled account are answered from
//! a made-up record, in the same steps and with the same shape as a real
//! one, so the answer to the first message does not tell which names exist.
//! The module documentation of [`login`] has the order of the steps.
//!
//! # Start-up
//!
//! A server loads its secrets (`load_or_create`), takes the
//! [`startup_decision`], builds its [`PreloginPolicy`] from the shares of the
//! real accounts, and only then serves. [`PreloginPolicy::new`] refuses a
//! policy that names a key stretching profile that clients do not know, so a
//! bad policy fails at start-up and never on a request: a made-up answer with
//! a profile no client accepts would make every unknown name fail while real
//! names work. [`AuthContext::new`] only bundles borrows and is cheap enough
//! to build for every request.
//!
//! # Features
//!
//! * `test-support` (off by default, never part of a release): the manual
//!   clock `ManualClock`, the replay RNGs of the core, the recording
//!   throttle, and the `testing` module with the checks every login state
//!   store must pass.

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
pub mod keys;
pub mod login;
pub mod name;
pub mod prelogin;
pub mod record;
pub mod registration;
pub mod scope;
pub mod secret_file;
pub mod startup;
pub mod state;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod throttle;

#[cfg(feature = "test-support")]
pub use clock::ManualClock;
pub use clock::{Clock, SystemClock};
pub use error::{AuthError, DenyReason, ErrorClass, InternalKind, Malformed};
pub use ids::{CredentialId, LoginId, SessionBinding, StateKey};
pub use keys::{
    CreatePolicy, FileOrigin, LoadedSecrets, PreloginSecret, ServerKeys, SetupFingerprint,
    load_or_create,
};
pub use login::{
    AccountLookup, AuthContext, LoginFinishRequest, LoginStartRequest, LoginStartResponse,
    LoginVerified, login_finish, login_start,
};
pub use name::{LOGIN_NAME_MAX_BYTES, NormalizedLoginName, normalize_login_name};
pub use prelogin::{
    PreloginAnswer, PreloginPolicy, fake_credential_id, fake_prelogin, resolve_credential,
};
pub use record::{ProfileRules, RegistrationKind, StoredRecord, ValidatedRecord};
pub use registration::{register_finish, register_start};
pub use scope::{Capability, ScopeEffect, SessionScope, authorize};
pub use secret_file::{
    FileKind, OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE, SecretFileError, decode_secret_file,
    encode_secret_file, permissions_enforced, read_secret_file, write_new_secret_file,
};
pub use startup::{StartupDecision, StartupRefusal, startup_decision};
pub use state::{
    InMemoryLoginStateStore, LoginPurpose, LoginStateStore, SealedState, StateSealKey, StoreError,
};
pub use throttle::{Caller, NoThrottle, Outcome, RetryAfter, Stage, Throttle, ThrottleKey};
#[cfg(feature = "test-support")]
pub use throttle::{RecordingThrottle, ThrottleCall};

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
