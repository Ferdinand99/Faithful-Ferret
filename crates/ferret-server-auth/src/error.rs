//! Errors of the library and the codes a client may see.
//!
//! These rules shape this file.
//!
//! * Every failure of authentication is [`AuthError::Denied`], and its public
//!   code is `"denied"` whatever the [`DenyReason`]. The reason is for the
//!   server's own log and for tests; a client that could tell a missing state
//!   from a wrong password could use the difference. The one exception is
//!   `ScopeForbids`, which only a caller that is already signed in can get:
//!   its code is `"forbidden"` and its class is [`ErrorClass::Forbidden`].
//! * A server file that is damaged or missing is [`AuthError::Internal`] with
//!   [`InternalKind::SecretFile`], not a fault of the client.
//! * [`AuthError::Malformed`] depends on the bytes of the client alone, never
//!   on stored state or a secret.
//! * [`AuthError::Internal`] never reaches a client with its cause.

use core::fmt;

/// Which part of a request was not well formed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Malformed {
    /// The OPAQUE registration request.
    RegistrationRequest,
    /// The OPAQUE registration record.
    RegistrationRecord,
    /// The first OPAQUE login message.
    Ke1,
    /// The third OPAQUE login message.
    Ke3,
    /// The login id.
    LoginId,
    /// A nonce.
    Nonce,
    /// A signed proof.
    Proof,
    /// The login name.
    LoginName,
}

impl Malformed {
    /// Every kind, for tests that must cover all of them.
    pub const ALL: &'static [Malformed] = &[
        Malformed::RegistrationRequest,
        Malformed::RegistrationRecord,
        Malformed::Ke1,
        Malformed::Ke3,
        Malformed::LoginId,
        Malformed::Nonce,
        Malformed::Proof,
        Malformed::LoginName,
    ];

    /// The code of the kind, as it appears in an error body.
    pub const fn public_code(&self) -> &'static str {
        match self {
            Malformed::RegistrationRequest => "malformed_registration_request",
            Malformed::RegistrationRecord => "malformed_registration_record",
            Malformed::Ke1 => "malformed_ke1",
            Malformed::Ke3 => "malformed_ke3",
            Malformed::LoginId => "malformed_login_id",
            Malformed::Nonce => "malformed_nonce",
            Malformed::Proof => "malformed_proof",
            Malformed::LoginName => "malformed_login_name",
        }
    }
}

/// Why an authentication failed. For the server's log and for tests; it is
/// never part of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DenyReason {
    /// There is no login state for the id (never issued, used or removed).
    StateMissing,
    /// The login state has expired.
    StateExpired,
    /// The sealed login state did not open or did not parse.
    StateInvalid,
    /// The state belongs to another purpose (login or re-authentication).
    PurposeMismatch,
    /// The state belongs to another session.
    SessionMismatch,
    /// The third OPAQUE message did not verify.
    Ke3,
    /// The nonce was never issued, or is already used.
    NonceUnknown,
    /// The nonce has expired.
    NonceExpired,
    /// The signature of a proof did not verify.
    ProofInvalid,
    /// The scope of the session does not allow the call.
    ScopeForbids,
}

impl DenyReason {
    /// Every reason, for tests that must cover all of them.
    pub const ALL: &'static [DenyReason] = &[
        DenyReason::StateMissing,
        DenyReason::StateExpired,
        DenyReason::StateInvalid,
        DenyReason::PurposeMismatch,
        DenyReason::SessionMismatch,
        DenyReason::Ke3,
        DenyReason::NonceUnknown,
        DenyReason::NonceExpired,
        DenyReason::ProofInvalid,
        DenyReason::ScopeForbids,
    ];
}

/// What went wrong inside the server. Never part of a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InternalKind {
    /// A store of login states or challenges failed.
    Storage,
    /// A secret file could not be read, written or created.
    SecretFile,
}

/// The class of status a caller should answer with. The library does not
/// know HTTP; the endpoint maps a class to a status code:
///
/// | class | status | body |
/// |---|---|---|
/// | `BadRequest` | 400 | the public code of the error |
/// | `Denied` | 401 | one fixed body for every reason |
/// | `Forbidden` | 403 | the code `forbidden` |
/// | `TooManyRequests` | 429 | the code `throttled`, with `retry_after_secs` read from the [`AuthError`] |
/// | `Internal` | 500 | the code `internal`, never the cause |
///
/// A class does not carry the retry time, so the endpoint reads it from
/// `AuthError::Throttled`. It never needs to look at a [`DenyReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorClass {
    /// The request itself is wrong (a 4xx that is not a login failure).
    BadRequest,
    /// The authentication failed. One status and one body for every reason,
    /// so a client cannot tell a wrong password from a missing state.
    Denied,
    /// The caller holds a session, and the scope of that session does not
    /// allow the call. Only returned after authentication, so it tells a
    /// client nothing about accounts.
    Forbidden,
    /// The caller must wait.
    TooManyRequests,
    /// The server failed.
    Internal,
}

/// Every failure the library reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// A message of the client was not well formed.
    Malformed(Malformed),
    /// An authentication or an authorization failed. The public code is
    /// `"denied"` for every reason except [`DenyReason::ScopeForbids`], which
    /// can only happen to a caller that is already signed in and has the
    /// code `"forbidden"`.
    Denied(DenyReason),
    /// A signed call named an unknown or too low key stretching profile. It
    /// depends on the stored profile, so it may be returned only after the
    /// proof or the session has been checked.
    ProfileRejected,
    /// The caller made too many attempts.
    Throttled {
        /// Seconds the caller should wait.
        retry_after_secs: u32,
    },
    /// Storage or a file failed.
    Internal(InternalKind),
}

impl AuthError {
    /// The code for an error body. The same for every [`DenyReason`] except
    /// the scope refusal of a signed-in caller.
    pub const fn public_code(&self) -> &'static str {
        match self {
            AuthError::Malformed(kind) => kind.public_code(),
            AuthError::Denied(DenyReason::ScopeForbids) => "forbidden",
            AuthError::Denied(_) => "denied",
            AuthError::ProfileRejected => "profile_rejected",
            AuthError::Throttled { .. } => "throttled",
            AuthError::Internal(_) => "internal",
        }
    }

    /// The class of status to answer with.
    pub const fn http_class(&self) -> ErrorClass {
        match self {
            AuthError::Malformed(_) | AuthError::ProfileRejected => ErrorClass::BadRequest,
            AuthError::Denied(DenyReason::ScopeForbids) => ErrorClass::Forbidden,
            AuthError::Denied(_) => ErrorClass::Denied,
            AuthError::Throttled { .. } => ErrorClass::TooManyRequests,
            AuthError::Internal(_) => ErrorClass::Internal,
        }
    }
}

/// Shows the public code only, so a stray `to_string()` cannot leak the
/// reason of a denial. `Debug` is for the server's own log.
impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.public_code())
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_code_is_the_same_for_every_denial() {
        assert!(!DenyReason::ALL.is_empty());
        for reason in DenyReason::ALL {
            let error = AuthError::Denied(*reason);
            if *reason == DenyReason::ScopeForbids {
                continue;
            }
            assert_eq!(error.public_code(), "denied", "{reason:?}");
            assert_eq!(error.to_string(), "denied", "{reason:?}");
            assert_eq!(error.http_class(), ErrorClass::Denied, "{reason:?}");
        }
    }

    #[test]
    fn a_scope_refusal_is_forbidden_and_nothing_else_is() {
        let error = AuthError::Denied(DenyReason::ScopeForbids);
        assert_eq!(error.public_code(), "forbidden");
        assert_eq!(error.to_string(), "forbidden");
        assert_eq!(error.http_class(), ErrorClass::Forbidden);
        let others = DenyReason::ALL
            .iter()
            .filter(|r| AuthError::Denied(**r).http_class() == ErrorClass::Forbidden)
            .count();
        assert_eq!(others, 1);
    }

    /// `ALL` must list every variant: these matches have no wildcard arm, so a
    /// new variant stops compiling here until it is added to both places.
    #[test]
    fn all_lists_every_variant_once() {
        fn deny_index(r: DenyReason) -> usize {
            match r {
                DenyReason::StateMissing => 0,
                DenyReason::StateExpired => 1,
                DenyReason::StateInvalid => 2,
                DenyReason::PurposeMismatch => 3,
                DenyReason::SessionMismatch => 4,
                DenyReason::Ke3 => 5,
                DenyReason::NonceUnknown => 6,
                DenyReason::NonceExpired => 7,
                DenyReason::ProofInvalid => 8,
                DenyReason::ScopeForbids => 9,
            }
        }
        fn malformed_index(m: Malformed) -> usize {
            match m {
                Malformed::RegistrationRequest => 0,
                Malformed::RegistrationRecord => 1,
                Malformed::Ke1 => 2,
                Malformed::Ke3 => 3,
                Malformed::LoginId => 4,
                Malformed::Nonce => 5,
                Malformed::Proof => 6,
                Malformed::LoginName => 7,
            }
        }
        let deny: Vec<usize> = DenyReason::ALL.iter().map(|r| deny_index(*r)).collect();
        assert_eq!(deny, (0..10).collect::<Vec<_>>());
        let malformed: Vec<usize> = Malformed::ALL.iter().map(|m| malformed_index(*m)).collect();
        assert_eq!(malformed, (0..8).collect::<Vec<_>>());
    }

    #[test]
    fn error_codes_are_stable() {
        let golden = [
            (
                Malformed::RegistrationRequest,
                "malformed_registration_request",
            ),
            (
                Malformed::RegistrationRecord,
                "malformed_registration_record",
            ),
            (Malformed::Ke1, "malformed_ke1"),
            (Malformed::Ke3, "malformed_ke3"),
            (Malformed::LoginId, "malformed_login_id"),
            (Malformed::Nonce, "malformed_nonce"),
            (Malformed::Proof, "malformed_proof"),
            (Malformed::LoginName, "malformed_login_name"),
        ];
        assert_eq!(golden.len(), Malformed::ALL.len());
        for (kind, code) in golden {
            let error = AuthError::Malformed(kind);
            assert_eq!(error.public_code(), code);
            assert_eq!(error.to_string(), code);
            assert_eq!(error.http_class(), ErrorClass::BadRequest);
        }
        assert_eq!(AuthError::ProfileRejected.public_code(), "profile_rejected");
        assert_eq!(
            AuthError::Throttled {
                retry_after_secs: 7
            }
            .public_code(),
            "throttled"
        );
        for kind in [InternalKind::Storage, InternalKind::SecretFile] {
            assert_eq!(AuthError::Internal(kind).public_code(), "internal");
        }
    }

    #[test]
    fn classes_follow_the_error() {
        assert_eq!(
            AuthError::ProfileRejected.http_class(),
            ErrorClass::BadRequest
        );
        assert_eq!(
            AuthError::Throttled {
                retry_after_secs: 1
            }
            .http_class(),
            ErrorClass::TooManyRequests
        );
        assert_eq!(
            AuthError::Internal(InternalKind::Storage).http_class(),
            ErrorClass::Internal
        );
    }
}
