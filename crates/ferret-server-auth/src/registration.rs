//! Registration on the server: the answer to the client's first message and
//! the packing of its upload.
//!
//! Who may register or change a password (an invitation, a valid session, an
//! account reset) is for the endpoint to decide, except for what the session
//! authority says: [`register_start`] checks the scope and the account of a
//! session, and asks the throttle itself.
//!
//! # The credential identifier
//!
//! OPAQUE binds a record to a `credential_identifier`. Ferret uses the
//! `account_id` (Fase 1 § 4.2). The OPRF key of an account is a function of
//! the server's OPRF seed and that identifier only, so it does not change
//! when the password changes: registering again under the same id gives the
//! same OPRF key. The key is not rotated per registration.

use core::fmt;

use ferret_core::opaque::server_suite::opaque_ke::{RegistrationRequest, ServerRegistration};
use ferret_core::opaque::server_suite::{FerretSuite, REGISTRATION_REQUEST_LEN};

use crate::ct::ct_eq;
use crate::error::{AuthError, DenyReason, InternalKind, Malformed};
use crate::ids::CredentialId;
use crate::keys::ServerKeys;
use crate::record::{ProfileRules, RegistrationKind, StoredRecord, ValidatedRecord};
use crate::scope::{Capability, SessionScope, authorize};
use crate::throttle::{Caller, Outcome, Stage, Throttle, admit};

/// On whose authority a registration starts.
///
/// There are two honest ways to get here, and the library asks the endpoint
/// to say which, so that neither has to pretend to be the other.
#[derive(Clone, Copy)]
pub enum RegistrationAuthority {
    /// A new account, by invitation, with no session. The endpoint has
    /// already checked the invitation and has assigned the credential id
    /// itself: a fresh id that no account row has. The id must never come
    /// from the request, or the caller could ask for an answer under the key
    /// of an existing account.
    NewAccount,
    /// A registration inside a session, to change a password, upgrade the
    /// key stretching profile or recover. The session may register for its
    /// own account only, whatever its scope.
    Session {
        /// The scope of the session, as the endpoint stored it. It must
        /// allow [`Capability::OpaqueRegisterStart`].
        scope: SessionScope,
        /// The account that owns the session, taken from the session the
        /// endpoint has found and never from the request.
        account: CredentialId,
    },
}

impl fmt::Debug for RegistrationAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationAuthority::NewAccount => f.write_str("RegistrationAuthority::NewAccount"),
            RegistrationAuthority::Session { scope, .. } => {
                write!(f, "RegistrationAuthority::Session({scope:?}, ..)")
            }
        }
    }
}

/// The first message of a registration, with what the library needs to decide
/// whether to answer it.
#[derive(Clone, Copy)]
pub struct RegisterStartRequest<'a> {
    /// Who is calling.
    pub caller: Caller,
    /// On whose authority the registration starts.
    pub authority: RegistrationAuthority,
    /// The credential id to register under (the account id, Fase 1 § 4.2).
    /// For a [`RegistrationAuthority::Session`] it must be the session's own
    /// account.
    pub credential: CredentialId,
    /// The `registration_request`, exactly 32 bytes.
    pub request: &'a [u8],
}

impl fmt::Debug for RegisterStartRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegisterStartRequest([redacted])")
    }
}

/// Answers the client's `registration_request`: the `registration_response`
/// (64 bytes, the evaluated element and the server's public key).
///
/// # Order of the steps
///
/// 1. For a [`RegistrationAuthority::Session`], the scope of the session must
///    allow [`Capability::OpaqueRegisterStart`], and the credential id must be
///    the session's own account, compared in constant time, **whatever the
///    scope**: a session never gets an answer under the key of another
///    account, which would let it test password guesses offline and use up
///    that account's registration budget. Both refusals are
///    `Denied(ScopeForbids)` (403). A [`RegistrationAuthority::NewAccount`]
///    has no session; the endpoint has checked the invitation and assigned
///    the id. Nothing has been done yet and the throttle has not been asked,
///    so a refusal here costs no budget. It is not counted either: an
///    endpoint that wants to see sessions probing other accounts must log
///    `ScopeForbids` itself.
/// 2. The throttle is asked (`Stage::RegisterStart`) before any other work,
///    and the outcome is reported once. Only `admit` and `finish` of the
///    crate's throttle module are used; the library never calls
///    `Throttle::record` itself and an endpoint has no way to.
/// 3. The request is checked: exactly 32 bytes and a valid ristretto255
///    element. Anything else, trailing bytes included, is
///    [`Malformed::RegistrationRequest`], which depends on the bytes alone.
/// 4. The answer is made from the server's keys, the id and the request.
///
/// Draws nothing. `now` is the time from the server's clock and goes to the
/// throttle only.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 1).
pub fn register_start(
    keys: &ServerKeys,
    throttle: &dyn Throttle,
    now: u64,
    req: &RegisterStartRequest<'_>,
) -> Result<Vec<u8>, AuthError> {
    if let RegistrationAuthority::Session { scope, account } = req.authority {
        authorize(scope, Capability::OpaqueRegisterStart)?;
        if !ct_eq(account.as_bytes(), req.credential.as_bytes()) {
            return Err(AuthError::Denied(DenyReason::ScopeForbids));
        }
    }
    let ticket = admit(
        throttle,
        Stage::RegisterStart,
        &req.caller,
        Some(&req.credential),
        now,
    )?;
    let answer = start_admitted(keys, &req.credential, req.request);
    let outcome = if answer.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    answer
}

/// The part of `register_start` that runs after the limiter let it through.
fn start_admitted(
    keys: &ServerKeys,
    id: &CredentialId,
    request: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let malformed = AuthError::Malformed(Malformed::RegistrationRequest);
    // The parser of `opaque-ke` ignores trailing bytes: check the length here.
    if request.len() != REGISTRATION_REQUEST_LEN {
        return Err(malformed);
    }
    let request =
        RegistrationRequest::<FerretSuite>::deserialize(request).map_err(|_| malformed)?;
    // A request that decoded cannot make the library fail: what is left is
    // the derivation of the OPRF key from the seed and the id. A failure
    // there is a fault of the server, not of the client.
    let started = ServerRegistration::<FerretSuite>::start(keys.setup(), request, id.as_bytes())
        .or(Err(AuthError::Internal(InternalKind::Crypto)))?;
    Ok(started.message.serialize().to_vec())
}

/// Packs the record the client uploaded and checks the profile it claims.
///
/// The upload must be exactly 192 bytes with a valid client public key
/// ([`ValidatedRecord::parse`]). The shape is checked before the profile, so
/// an error for a bad record never depends on what is stored. The profile is
/// checked by `rules`; `kind` says whether the account is new or already has
/// a record, and in that case carries the stored profile (from the stored row,
/// never from the request).
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3).
pub fn register_finish(
    upload: &[u8],
    claimed_profile: u32,
    rules: &ProfileRules,
    kind: RegistrationKind,
) -> Result<StoredRecord, AuthError> {
    let record = ValidatedRecord::parse(upload)?;
    let ksf_profile = rules.accept(claimed_profile, kind)?;
    Ok(StoredRecord {
        record,
        ksf_profile,
    })
}
