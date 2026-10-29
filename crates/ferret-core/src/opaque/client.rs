//! The OPAQUE client: registration and login, as thin functions over
//! `opaque-ke`.
//!
//! Spec: Fase 1 § 4.1 (the password input) and § 4.2 (OPAQUE), RFC 9807.
//!
//! The functions take an [`OpaqueInput`] (the NFKD master password, with the
//! secret key appended when the account has one), hand it to `opaque-ke`, and
//! give back bytes and an [`ExportKey`]. Nothing else of the library leaks
//! out: the protocol states are our own types without `Clone` or `Debug`, and
//! the 3DH session key is wiped as soon as it exists (the session key is used
//! for nothing else, Fase 1 § 4.2 step 4).
//!
//! # What is checked, and when
//!
//! [`opaque_login_finish`] checks, in this order and *before* any Argon2id
//! runs:
//!
//! 1. the profile number the server states against the client's own table
//!    ([`Error::KdfProfileUnknown`]);
//! 2. with a pinned record: the SK bit of the input against the pinned bit
//!    ([`PinnedField::SkBit`]; the bit never comes from the server) and the
//!    profile against the pinned one ([`Error::KdfProfileDowngrade`]);
//! 3. the profile's parameters against the floor and ceiling
//!    ([`Error::KdfOutOfRange`]);
//! 4. the length of the server's message ([`MalformedKind::OpaqueMessage`]).
//!
//! After `opaque-ke` has opened the envelope and verified the server's MAC,
//! the server public key it showed is compared with the pinned one
//! ([`PinnedField::ServerKey`]). If none is pinned yet, the key is returned
//! and the first successful unlock pins it (trust on first use, plan U19; see
//! [`crate::Pinned`]).
//!
//! # Errors
//!
//! A wrong password, a wrong secret key, a server with another context and
//! any tampered server message that parses are all the single
//! [`Error::Decrypt`]. A message of the wrong length, or one that holds a
//! point that is not on the curve, is [`MalformedKind::OpaqueMessage`]: that
//! depends on the server's bytes only, never on a secret.
//!
//! # Randomness
//!
//! `opaque-ke` draws, in this order (checked by the replay tests):
//!
//! * `register_start`: the blind, 64 bytes (a scalar reduced mod the group
//!   order);
//! * `register_finish`: the envelope nonce, 32 bytes;
//! * `login_start`: the blind (64), the seed of the client's ephemeral key
//!   (32), the client nonce (32);
//! * `login_finish`: nothing.

use super::ksf::FerretKsf;
use super::suite::{FerretSuite, OPAQUE_CONTEXT};
use crate::error::{Error, InputError, MalformedKind, PinnedField};
use crate::ksf_profile::KsfProfile;
use crate::pinning::Pinned;
use crate::prim::check_kdf_params;
use crate::rng::SecureRng;
use crate::secret::ExportKey;
use crate::text::OpaqueInput;
use opaque_ke::errors::{InternalError, ProtocolError};
use opaque_ke::key_exchange::group::Group;
use opaque_ke::keypair::PublicKey;
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use zeroize::Zeroize;
#[cfg(feature = "test-support")]
use zeroize::Zeroizing;

/// Length of a `RegistrationResponse`: the evaluated element and the
/// server's public key, 32 + 32 bytes.
pub(crate) const REGISTRATION_RESPONSE_LEN: usize = 64;
/// Length of `KE2`: evaluated element 32, masking nonce 32, masked response
/// 128 (server public key 32, envelope 96), server nonce 32, server ephemeral
/// public key 32, MAC 64.
pub(crate) const KE2_LEN: usize = 320;
/// The longest OPRF input `opaque-ke` accepts, in bytes (the shortest is 1).
const PASSWORD_MAX: usize = u16::MAX as usize;

// ------------------------------------------------------------ RNG adapter

/// `SecureRng` as the `rand_core 0.6` generator that `opaque-ke` wants.
///
/// Every request is forwarded as one `fill` call of the same length, so the
/// draws the library makes can be recorded and replayed exactly (the vectors
/// list them). The operating system's generator of `rand 0.8` is never
/// used.
pub(crate) struct Rng06<'a, R: SecureRng>(pub(crate) &'a mut R);

impl<R: SecureRng> opaque_ke::rand::RngCore for Rng06<'_, R> {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.0.fill(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), opaque_ke::rand::Error> {
        self.0.fill(dest);
        Ok(())
    }
}

impl<R: SecureRng> opaque_ke::rand::CryptoRng for Rng06<'_, R> {}

// ------------------------------------------------------- shared helpers

/// A KSF that can say why it failed.
pub(crate) trait KsfFailure {
    /// The error of the last failed call, if any.
    fn take_failure(&self) -> Option<Error>;
}

impl KsfFailure for FerretKsf {
    fn take_failure(&self) -> Option<Error> {
        FerretKsf::take_failure(self)
    }
}

#[cfg(feature = "test-support")]
impl KsfFailure for opaque_ke::ksf::Identity {
    fn take_failure(&self) -> Option<Error> {
        None
    }
}

/// Checks the length of the password input: the OPRF takes 1 to 65 535
/// bytes. A master password is far below the upper limit.
fn check_password(pwd: &[u8]) -> Result<(), Error> {
    if pwd.is_empty() {
        Err(Error::InvalidInput(InputError::TooShort))
    } else if pwd.len() > PASSWORD_MAX {
        Err(Error::InvalidInput(InputError::TooLong))
    } else {
        Ok(())
    }
}

/// An `opaque-ke` error while a message was being read: the structure was
/// wrong, nothing secret was involved.
fn malformed(_: ProtocolError) -> Error {
    Error::Malformed(MalformedKind::OpaqueMessage)
}

/// An `opaque-ke` error in a finish step, after the message has parsed. All
/// of them are the one authentication failure, whatever step found it
/// (reflected OPRF value, envelope MAC, server MAC, a masked response that
/// does not open). The one exception is the key stretching function itself,
/// which cannot fail for a secret-dependent reason: it is the error the KSF
/// recorded (out of memory).
fn finish_error(e: ProtocolError, ksf: &impl KsfFailure) -> Error {
    match e {
        ProtocolError::LibraryError(InternalError::KsfError) => {
            ksf.take_failure().unwrap_or(Error::KdfOutOfMemory)
        }
        _ => Error::Decrypt,
    }
}

/// The export key as our secret type; the library's copy is wiped.
fn export_key_from(out: &mut [u8]) -> Result<ExportKey, Error> {
    let mut bytes = [0u8; ExportKey::LEN];
    if out.len() != bytes.len() {
        out.zeroize();
        return Err(Error::Decrypt);
    }
    bytes.copy_from_slice(out);
    out.zeroize();
    Ok(ExportKey::from_array_wiping(&mut bytes))
}

/// The 32 bytes of the server's public key.
fn public_key_bytes<G: Group>(pk: &PublicKey<G>) -> Result<[u8; 32], Error> {
    <[u8; 32]>::try_from(pk.serialize().as_slice()).map_err(|_| Error::Decrypt)
}

/// The result of a registration finish.
pub(crate) struct Registered {
    pub(crate) record: Vec<u8>,
    pub(crate) export_key: ExportKey,
    pub(crate) server_public_key: [u8; 32],
}

/// The result of a login finish. The 3DH session key is wiped inside the
/// call; only a `test-support` build keeps a copy, so that a test can compare
/// it with the server's.
pub(crate) struct LoggedIn {
    pub(crate) ke3: Vec<u8>,
    pub(crate) export_key: ExportKey,
    #[cfg(feature = "test-support")]
    pub(crate) session_key: Zeroizing<Vec<u8>>,
    pub(crate) server_public_key: [u8; 32],
}

/// Defines the protocol functions for one cipher suite in a module of their
/// own. `opaque-ke`'s bounds on a generic suite cannot be written from
/// outside the crate, so the code is instantiated per suite instead:
/// `prod` for [`FerretSuite`] and, for the RFC 9807 vectors, `rfc`.
macro_rules! protocol {
    ($(#[$meta:meta])* $name:ident, $suite:ty) => {
        $(#[$meta])*
        pub(crate) mod $name {
            use super::*;

            type Ksf = <$suite as CipherSuite>::Ksf;

            /// Registration, first message: the blinded password.
            pub(crate) fn register_start<R: SecureRng>(
                rng: &mut R,
                pwd: &[u8],
            ) -> Result<(Vec<u8>, ClientRegistration<$suite>), Error> {
                check_password(pwd)?;
                let started = ClientRegistration::<$suite>::start(&mut Rng06(rng), pwd)
                    .map_err(|_| Error::Decrypt)?;
                Ok((started.message.serialize().to_vec(), started.state))
            }

            /// Registration, second message: the record to upload.
            pub(crate) fn register_finish<R: SecureRng>(
                rng: &mut R,
                state: ClientRegistration<$suite>,
                pwd: &[u8],
                response: &[u8],
                identifiers: Identifiers<'_>,
                ksf: &Ksf,
            ) -> Result<Registered, Error> {
                check_password(pwd)?;
                if response.len() != REGISTRATION_RESPONSE_LEN {
                    return Err(Error::Malformed(MalformedKind::OpaqueMessage));
                }
                let response =
                    RegistrationResponse::<$suite>::deserialize(response).map_err(malformed)?;
                let params =
                    ClientRegistrationFinishParameters::<$suite>::new(identifiers, Some(ksf));
                let finished = state
                    .finish(&mut Rng06(rng), pwd, response, params)
                    .map_err(|e| finish_error(e, ksf))?;
                let mut export = finished.export_key;
                Ok(Registered {
                    record: finished.message.serialize().to_vec(),
                    export_key: export_key_from(&mut export)?,
                    server_public_key: public_key_bytes(&finished.server_s_pk)?,
                })
            }

            /// Login, first message `KE1`.
            pub(crate) fn login_start<R: SecureRng>(
                rng: &mut R,
                pwd: &[u8],
            ) -> Result<(Vec<u8>, ClientLogin<$suite>), Error> {
                check_password(pwd)?;
                let started = ClientLogin::<$suite>::start(&mut Rng06(rng), pwd)
                    .map_err(|_| Error::Decrypt)?;
                Ok((started.message.serialize().to_vec(), started.state))
            }

            /// Login, final message `KE3`.
            pub(crate) fn login_finish<R: SecureRng>(
                rng: &mut R,
                state: ClientLogin<$suite>,
                pwd: &[u8],
                ke2: &[u8],
                context: Option<&[u8]>,
                identifiers: Identifiers<'_>,
                ksf: &Ksf,
            ) -> Result<LoggedIn, Error> {
                check_password(pwd)?;
                if ke2.len() != KE2_LEN {
                    return Err(Error::Malformed(MalformedKind::OpaqueMessage));
                }
                let response =
                    CredentialResponse::<$suite>::deserialize(ke2).map_err(malformed)?;
                let params =
                    ClientLoginFinishParameters::<$suite>::new(context, identifiers, Some(ksf));
                let finished = state
                    .finish(&mut Rng06(rng), pwd, response, params)
                    .map_err(|e| finish_error(e, ksf))?;
                let mut export = finished.export_key;
                let mut session = finished.session_key;
                #[cfg(feature = "test-support")]
                let session_key = Zeroizing::new(session.to_vec());
                session.as_mut_slice().zeroize();
                Ok(LoggedIn {
                    ke3: finished.message.serialize().to_vec(),
                    export_key: export_key_from(&mut export)?,
                    #[cfg(feature = "test-support")]
                    session_key,
                    server_public_key: public_key_bytes(&finished.server_s_pk)?,
                })
            }
        }
    };
}

protocol!(
    /// The protocol of Ferret suite 1.
    prod,
    FerretSuite
);

protocol!(
    /// The protocol of the RFC 9807 test vectors (identity KSF).
    #[cfg(feature = "test-support")]
    rfc,
    crate::opaque::suite::RfcSuite
);

// ------------------------------------------------------------ public API

/// The state of a registration between its two messages. It holds the blind
/// of the OPRF; it has no `Clone` and no `Debug`, and is wiped on drop.
pub struct RegistrationState(pub(crate) ClientRegistration<FerretSuite>);

/// The state of a login between its two messages. It holds the blind of the
/// OPRF and the client's ephemeral key; it has no `Clone` and no `Debug`, and
/// is wiped on drop.
pub struct LoginState(pub(crate) ClientLogin<FerretSuite>);

/// What a registration gives back after the server's answer.
pub struct RegistrationFinished {
    /// The registration record (`RegistrationUpload`, 192 bytes) for the
    /// server to store.
    pub record: Vec<u8>,
    /// The OPAQUE export key; `KEK_pw` comes from it (`Kek::from_export_key`).
    pub export_key: ExportKey,
    /// The server's OPAQUE public key as the response showed it, to pin.
    pub server_public_key: [u8; 32],
}

/// What a login gives back after the server's `KE2`.
///
/// There is no session key here, on purpose: the 3DH session key is wiped
/// inside the call and the client uses nothing but the export key.
///
/// ```compile_fail,E0609
/// fn peek(f: ferret_core::LoginFinished) {
///     let _ = f.session_key;
/// }
/// ```
///
/// The fields that do exist:
///
/// ```
/// fn use_it(f: ferret_core::LoginFinished) -> usize {
///     f.ke3.len() + f.server_public_key.len()
/// }
/// ```
pub struct LoginFinished {
    /// `KE3`, the message to send to the server (64 bytes).
    pub ke3: Vec<u8>,
    /// The OPAQUE export key; `KEK_pw` comes from it.
    pub export_key: ExportKey,
    /// The server's OPAQUE public key as the login showed it. It has been
    /// compared with the pinned one when there is one.
    pub server_public_key: [u8; 32],
}

/// Registration, step 1: blinds the password and returns the
/// `registration_request` (32 bytes) with the state for step 2.
///
/// Draws the blind, 64 bytes.
///
/// Spec: Fase 1 § 4.2 ("Registrering", step 1); RFC 9807 section 5.1.
pub fn opaque_register_start<R: SecureRng>(
    rng: &mut R,
    input: &OpaqueInput,
) -> Result<(Vec<u8>, RegistrationState), Error> {
    let (request, state) = prod::register_start(rng, input.as_bytes())?;
    Ok((request, RegistrationState(state)))
}

/// Registration, step 2: finishes with the server's `registration_response`
/// (64 bytes) and returns the record to upload, the export key and the
/// server's public key.
///
/// The key stretching function is Argon2id with `profile`. The caller pins
/// `server_public_key` (a new account) or compares it with the pinned one
/// (a change of password or profile on a known account).
///
/// Draws the envelope nonce, 32 bytes.
///
/// Spec: Fase 1 § 4.2 ("Registrering"); RFC 9807 section 5.1.
pub fn opaque_register_finish<R: SecureRng>(
    rng: &mut R,
    st: RegistrationState,
    input: &OpaqueInput,
    response: &[u8],
    profile: KsfProfile,
) -> Result<RegistrationFinished, Error> {
    check_kdf_params(profile.params())?;
    let ksf = FerretKsf::new(profile);
    let done = prod::register_finish(
        rng,
        st.0,
        input.as_bytes(),
        response,
        Identifiers::default(),
        &ksf,
    )?;
    Ok(RegistrationFinished {
        record: done.record,
        export_key: done.export_key,
        server_public_key: done.server_public_key,
    })
}

/// Login, step 1: blinds the password and returns `KE1` (96 bytes) with the
/// state for step 2.
///
/// Draws the blind (64 bytes), the seed of the ephemeral key (32) and the
/// client nonce (32).
///
/// Spec: Fase 1 § 4.2 ("Innlogging", step 1); RFC 9807 section 6.3.
pub fn opaque_login_start<R: SecureRng>(
    rng: &mut R,
    input: &OpaqueInput,
) -> Result<(Vec<u8>, LoginState), Error> {
    let (ke1, state) = prod::login_start(rng, input.as_bytes())?;
    Ok((ke1, LoginState(state)))
}

/// Login, step 2: checks the profile and the pins, runs the key stretching,
/// opens the envelope and returns `KE3` and the export key.
///
/// `server_profile` is the number the server states; the parameters come
/// from the client's own table and never from the server. With `pinned`, the
/// SK bit of `input`, the profile and (when it is pinned) the OPAQUE server
/// public key must agree with the record. See the module docs for the order
/// of the checks and for the errors.
///
/// Spec: Fase 1 § 4.2 ("Innlogging", step 2, "Pinning og SK-bit"); RFC 9807
/// section 6.3; plan U19.
pub fn opaque_login_finish<R: SecureRng>(
    rng: &mut R,
    st: LoginState,
    input: &OpaqueInput,
    ke2: &[u8],
    server_profile: u32,
    pinned: Option<&Pinned>,
) -> Result<LoginFinished, Error> {
    let profile = KsfProfile::from_wire(server_profile)?;
    if let Some(pin) = pinned {
        if input.includes_secret_key() != pin.sk_bit {
            return Err(Error::Pinned(PinnedField::SkBit));
        }
        if profile.number() < pin.ksf_profile {
            return Err(Error::KdfProfileDowngrade);
        }
    }
    check_kdf_params(profile.params())?;
    let ksf = FerretKsf::new(profile);
    // The session key is dropped (and wiped) with the `LoggedIn`.
    let done = finish_login(rng, st, input, ke2, &ksf, Some(OPAQUE_CONTEXT), pinned)?;
    Ok(LoginFinished {
        ke3: done.ke3,
        export_key: done.export_key,
        server_public_key: done.server_public_key,
    })
}

/// The part of the login finish that the checks do not touch: the protocol
/// itself with the given KSF and context, then the pin check on the server's
/// key. The tests run it with other parameters and contexts.
pub(crate) fn finish_login<R: SecureRng>(
    rng: &mut R,
    st: LoginState,
    input: &OpaqueInput,
    ke2: &[u8],
    ksf: &FerretKsf,
    context: Option<&[u8]>,
    pinned: Option<&Pinned>,
) -> Result<LoggedIn, Error> {
    let done = prod::login_finish(
        rng,
        st.0,
        input.as_bytes(),
        ke2,
        context,
        Identifiers::default(),
        ksf,
    )?;
    check_server_key(pinned, &done.server_public_key)?;
    Ok(done)
}

/// The pin check on the server's OPAQUE public key: a pinned key must be
/// shown again exactly; without a pinned key anything is accepted (trust on
/// first use).
///
/// Spec: plan U19; Fase 1 § 4.2 ("Pinning og SK-bit").
fn check_server_key(pinned: Option<&Pinned>, shown: &[u8; 32]) -> Result<(), Error> {
    match pinned.and_then(|p| p.server_public_key.as_ref()) {
        Some(pinned_key) if pinned_key != shown => Err(Error::Pinned(PinnedField::ServerKey)),
        _ => Ok(()),
    }
}
