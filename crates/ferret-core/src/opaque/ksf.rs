//! The key stretching function of OPAQUE: Argon2id with a fixed profile.
//!
//! Spec: Fase 1 § 4.2 (row "KSF"): Argon2id v1.3, salt 16 zero bytes, output
//! 64 bytes (`Nh`), parameters from the `ksf_profile`.
//!
//! `opaque-ke` asks for a type that implements `Ksf: Default`, which has no
//! room for parameters. The profile therefore travels as an *instance*: the
//! client passes `Some(&FerretKsf::new(profile))` in the finish parameters,
//! and `opaque-ke` calls that instance. `Default` (profile 1) is what the
//! library would use if it were given no instance; the client never relies on
//! it, and a test shows that the supplied instance is the one that is used.
//!
//! Two points on why this is a wrapper of our own, not the `argon2` feature of
//! `opaque-ke`: that feature pulls in `argon2` 0.5 (a second copy of the
//! crate), and it keeps no `zeroize` of the input.

use crate::error::Error;
use crate::ksf_profile::KsfProfile;
use crate::prim::{KdfParams, argon2::argon2id};
use core::cell::Cell;
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use zeroize::Zeroize;

/// The Argon2 salt: 16 zero bytes. `opaque-ke`'s own `Argon2` implementation
/// uses the same (`[0; RECOMMENDED_SALT_LEN]`), and RFC 9807 section 10.11
/// explains why no extra salt is needed: the OPRF key acts as the secret
/// salt, unique per server and account.
///
/// Spec: Fase 1 § 4.2 (row "KSF").
pub(crate) const KSF_SALT: [u8; 16] = [0; 16];

/// The Argon2id function behind a KSF: the checked one in production.
type Run = fn(&[u8], &[u8], KdfParams, &mut [u8]) -> Result<(), Error>;

/// Argon2id for OPAQUE with the parameters of one profile.
pub(crate) struct FerretKsf {
    params: KdfParams,
    run: Run,
    /// Why the last call failed, for the caller (opaque-ke can only say "the
    /// KSF failed"). Not a secret: it is an out-of-memory or a range error.
    failure: Cell<Option<Error>>,
}

impl FerretKsf {
    /// The KSF of `profile`. Argon2id runs through the checked path, so the
    /// floor and ceiling hold even if the table were wrong.
    pub(crate) fn new(profile: KsfProfile) -> Self {
        Self {
            params: profile.params(),
            run: argon2id,
            failure: Cell::new(None),
        }
    }

    /// A KSF with any parameters and no floor or ceiling. Only for
    /// `test-support`, to run the protocol in milliseconds.
    #[cfg(feature = "test-support")]
    pub(crate) fn unchecked(params: KdfParams) -> Self {
        Self {
            params,
            run: crate::prim::argon2::argon2id_unchecked_plain,
            failure: Cell::new(None),
        }
    }

    /// The error of the last failed call, if any (and forgets it).
    pub(crate) fn take_failure(&self) -> Option<Error> {
        self.failure.take()
    }

    /// The parameters of this instance.
    #[cfg(feature = "test-support")]
    pub(crate) fn params(&self) -> KdfParams {
        self.params
    }
}

impl Default for FerretKsf {
    /// Profile 1. The client always supplies an instance, so this is not
    /// used by it.
    fn default() -> Self {
        Self::new(KsfProfile::P1)
    }
}

impl Ksf for FerretKsf {
    /// `Argon2id(input, salt = 16 × 0x00, profile, |output| = |input|)`; the
    /// input is wiped.
    ///
    /// Spec: Fase 1 § 4.2 (row "KSF"); RFC 9807 section 2 (`Stretch`).
    fn hash<L: ArrayLength<u8>>(
        &self,
        mut input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::<u8, L>::default();
        let result = (self.run)(&input, &KSF_SALT, self.params, &mut output);
        input.as_mut_slice().zeroize();
        match result {
            Ok(()) => Ok(output),
            Err(e) => {
                output.as_mut_slice().zeroize();
                self.failure.set(Some(e));
                Err(InternalError::KsfError)
            }
        }
    }
}
