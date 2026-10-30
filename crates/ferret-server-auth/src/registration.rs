//! Registration on the server: the answer to the client's first message and
//! the packing of its upload.
//!
//! Who may register or change a password (an invitation, a valid session, an
//! account reset) is for the endpoint to decide before it calls here.
//!
//! # The credential identifier
//!
//! OPAQUE binds a record to a `credential_identifier`. Ferret uses the
//! `account_id` (Fase 1 § 4.2). The OPRF key of an account is a function of
//! the server's OPRF seed and that identifier only, so it does not change
//! when the password changes: registering again under the same id gives the
//! same OPRF key. The key is not rotated per registration.

use ferret_core::opaque::server_suite::opaque_ke::{RegistrationRequest, ServerRegistration};
use ferret_core::opaque::server_suite::{FerretSuite, REGISTRATION_REQUEST_LEN};

use crate::error::{AuthError, Malformed};
use crate::ids::CredentialId;
use crate::keys::ServerKeys;
use crate::record::{ProfileRules, StoredRecord, ValidatedRecord};

/// Answers the client's `registration_request`: the `registration_response`
/// (64 bytes, the evaluated element and the server's public key).
///
/// Draws nothing: the answer is a function of the server's keys, the id and
/// the request. The request must be exactly 32 bytes and a valid ristretto255
/// element; anything else, trailing bytes included, is
/// [`Malformed::RegistrationRequest`], which depends on the bytes alone.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 1).
pub fn register_start(
    keys: &ServerKeys,
    id: &CredentialId,
    request: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let malformed = AuthError::Malformed(Malformed::RegistrationRequest);
    // The parser of `opaque-ke` ignores trailing bytes: check the length here.
    if request.len() != REGISTRATION_REQUEST_LEN {
        return Err(malformed);
    }
    // A request that decoded cannot make the library fail. If it ever does,
    // the caller gets the one error for a bad request and not a variant.
    let started = RegistrationRequest::<FerretSuite>::deserialize(request)
        .ok()
        .and_then(|request| {
            ServerRegistration::<FerretSuite>::start(keys.setup(), request, id.as_bytes()).ok()
        })
        .ok_or(malformed)?;
    Ok(started.message.serialize().to_vec())
}

/// Packs the record the client uploaded and checks the profile it claims.
///
/// The upload must be exactly 192 bytes with a valid client public key
/// ([`ValidatedRecord::parse`]). The shape is checked before the profile, so
/// an error for a bad record never depends on what is stored. The profile is
/// checked by `rules` against `current`, the stored profile of an existing
/// account or `None` for a new one.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3).
pub fn register_finish(
    upload: &[u8],
    claimed_profile: u32,
    rules: &ProfileRules,
    current: Option<u8>,
) -> Result<StoredRecord, AuthError> {
    let record = ValidatedRecord::parse(upload)?;
    let ksf_profile = rules.accept(claimed_profile, current)?;
    Ok(StoredRecord {
        record,
        ksf_profile,
    })
}
