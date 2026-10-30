//! The stored OPAQUE record and the key stretching profiles the server
//! accepts.
//!
//! The server cannot tell which password or which profile a record was made
//! with. All it can check is the shape: the length, and that the client's
//! public key inside it is a valid ristretto255 element. Everything else is
//! the client's to get right, and a record that is wrong in some other way
//! only locks its own account (see [`StoredRecord`]).

use core::fmt;

use ferret_core::KsfProfile;
use ferret_core::opaque::server_suite::opaque_ke::RegistrationUpload;
use ferret_core::opaque::server_suite::{FerretSuite, REGISTRATION_RECORD_LEN};
use zeroize::Zeroizing;

use crate::error::{AuthError, Malformed};

/// A record that is well formed: exactly 192 bytes, with a client public key
/// that is a valid ristretto255 element.
///
/// The server cannot know more than that. The bytes hold the masking key of
/// the record, so they are wiped when the value is dropped.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 3).
#[derive(Clone)]
pub struct ValidatedRecord(Zeroizing<Vec<u8>>);

impl ValidatedRecord {
    /// Checks `bytes` and keeps a copy.
    ///
    /// The length is checked first and must be exactly 192: the parser of
    /// `opaque-ke` reads a prefix and ignores whatever follows, so a record
    /// with trailing bytes would otherwise be stored as it came. The answer
    /// depends on the given bytes and on nothing else.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        let malformed = AuthError::Malformed(Malformed::RegistrationRecord);
        if bytes.len() != REGISTRATION_RECORD_LEN {
            return Err(malformed);
        }
        RegistrationUpload::<FerretSuite>::deserialize(bytes).map_err(|_| malformed)?;
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }

    /// The 192 bytes, as the client made them.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ValidatedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValidatedRecord([redacted])")
    }
}

/// What the server stores for an account after a registration: the record
/// and the key stretching profile the client said it used.
///
/// The server cannot see the profile in the record. It trusts the number the
/// caller passed with a signed or invited request. A wrong claim does not
/// help an attacker: the client then stretches with another profile than the
/// one it stored, and its own unlock fails until the account is recovered.
#[derive(Clone)]
pub struct StoredRecord {
    /// The record.
    pub record: ValidatedRecord,
    /// The profile number that goes with it.
    pub ksf_profile: u8,
}

impl fmt::Debug for StoredRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredRecord([redacted])")
    }
}

/// Whether a registration creates an account or replaces the record of one
/// that exists.
///
/// The caller has to say which, so a missing stored profile cannot pass as a
/// new account. `Existing` carries the profile stored for the account. It
/// must come from the stored row and never from the request.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegistrationKind {
    /// A new account: only the table and the minimum apply.
    NewAccount,
    /// An account that already has a record with this profile number. The
    /// new profile may not be lower.
    Existing(u8),
}

impl fmt::Debug for RegistrationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistrationKind::NewAccount => f.write_str("RegistrationKind::NewAccount"),
            RegistrationKind::Existing(_) => f.write_str("RegistrationKind::Existing(..)"),
        }
    }
}

/// Which profile numbers the server accepts, and the lowest one for a new
/// account.
///
/// Built from the table of the client itself, so the two cannot disagree on
/// which numbers exist.
///
/// Spec: Fase 1 § 4.2 (table "KSF-profiler"). A password change or an upgrade
/// never gets a profile lower than the one stored. A recovery is the one
/// exception, see [`ProfileRules::accept_recovery`].
#[derive(Clone)]
pub struct ProfileRules {
    known: Vec<u8>,
    minimum: u8,
}

impl ProfileRules {
    /// The profiles of suite 1: every number the client's table knows, and
    /// profile 1 as the lowest.
    pub fn ferret_v1() -> Self {
        let known = (1..=u32::from(u8::MAX))
            .filter_map(|n| KsfProfile::from_wire(n).ok())
            .map(KsfProfile::number)
            .collect();
        Self { known, minimum: 1 }
    }

    /// Rules with chosen numbers, for tests that need a table longer than
    /// the one of the client.
    #[cfg(feature = "test-support")]
    pub fn for_tests(known: &[u8], minimum: u8) -> Self {
        Self {
            known: known.to_vec(),
            minimum,
        }
    }

    /// Checks the profile a caller claims and returns it as a stored number.
    ///
    /// The claim is refused with [`AuthError::ProfileRejected`] when it is
    ///
    /// * not a number the table knows (this includes anything above 255),
    /// * below the minimum for a new account, or
    /// * below the profile already stored for the account
    ///   ([`RegistrationKind::Existing`]).
    ///
    /// A new account is not compared with anything stored. The answer
    /// depends on the stored profile, so an endpoint may give it only after
    /// the caller has been authorized.
    pub fn accept(&self, claimed: u32, kind: RegistrationKind) -> Result<u8, AuthError> {
        let rejected = AuthError::ProfileRejected;
        let claimed = u8::try_from(claimed).map_err(|_| rejected)?;
        if !self.known.contains(&claimed) || claimed < self.minimum {
            return Err(rejected);
        }
        match kind {
            RegistrationKind::Existing(stored) if claimed < stored => Err(rejected),
            RegistrationKind::Existing(_) | RegistrationKind::NewAccount => Ok(claimed),
        }
    }

    /// Checks the profile a recovery claims and returns it as a stored
    /// number.
    ///
    /// A recovery needs the holder of the recovery key, who can replace the
    /// whole record anyway. It may therefore set any profile the rules
    /// accept, one lower than the stored profile included: that is how a
    /// wrongly claimed higher profile is undone (a client that claimed a
    /// profile it did not use cannot unlock its account until it is
    /// recovered). The claim is refused with [`AuthError::ProfileRejected`]
    /// when it is not a number the table knows or is below the minimum. The
    /// stored profile is not read, so the answer does not depend on it.
    pub fn accept_recovery(&self, claimed: u32) -> Result<u8, AuthError> {
        self.accept(claimed, RegistrationKind::NewAccount)
    }
}

impl fmt::Debug for ProfileRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProfileRules { .. }")
    }
}
