//! OPAQUE for tests and vector runners: a server half built from
//! `opaque-ke`'s server API, the client with a key stretching function of
//! other parameters, and the RFC 9807 suite (identity KSF) with the session
//! key in view. Behind `test-support`; never part of a release, where the
//! only OPAQUE code is the client in [`crate::opaque`] (no server half, no
//! other parameters, no session key).

use crate::error::{Error, MalformedKind};
use crate::opaque::PinState;
use crate::opaque::client::{self, KE2_LEN, REGISTRATION_RESPONSE_LEN, Rng06, prod, rfc};
use crate::opaque::ksf::FerretKsf;
use crate::opaque::suite::{FerretSuite, OPAQUE_CONTEXT};
use crate::prim::KdfParams;
use crate::rng::SecureRng;
use crate::text::OpaqueInput;
use crate::{KsfProfile, LoginFinished, LoginState, RegistrationFinished, RegistrationState};
use opaque_ke::generic_array::{GenericArray, typenum::U64};
use opaque_ke::ksf::Ksf;
use opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};

fn malformed() -> Error {
    Error::Malformed(MalformedKind::OpaqueMessage)
}

/// The length of `KE2`, `RegistrationResponse`, in bytes.
pub const KE2_BYTES: usize = KE2_LEN;
/// The length of a `RegistrationResponse`, in bytes.
pub const REGISTRATION_RESPONSE_BYTES: usize = REGISTRATION_RESPONSE_LEN;

// ------------------------------------------------------------ the server

/// The server half of OPAQUE, from `opaque-ke`: its setup (OPRF seed and key
/// pair), its context and the three steps it takes.
pub struct Server {
    setup: ServerSetup<FerretSuite>,
    context: Vec<u8>,
    identities: Option<(Vec<u8>, Vec<u8>)>,
}

/// A server login between `KE2` and `KE3`.
pub struct ServerLoginState {
    login: ServerLogin<FerretSuite>,
    context: Vec<u8>,
    identities: Option<(Vec<u8>, Vec<u8>)>,
}

fn identifiers(ids: &Option<(Vec<u8>, Vec<u8>)>) -> Identifiers<'_> {
    match ids {
        Some((client, server)) => Identifiers {
            client: Some(client),
            server: Some(server),
        },
        None => Identifiers::default(),
    }
}

impl Server {
    /// A new server setup, drawing its key material from `rng`. The context
    /// is Ferret's.
    pub fn new<R: SecureRng>(rng: &mut R) -> Self {
        Self {
            setup: ServerSetup::<FerretSuite>::new(&mut Rng06(rng)),
            context: OPAQUE_CONTEXT.to_vec(),
            identities: None,
        }
    }

    /// The same server with client and server identities set (Ferret's are
    /// empty: the public keys stand in).
    #[must_use]
    pub fn with_identities(mut self, client: &[u8], server: &[u8]) -> Self {
        self.identities = Some((client.to_vec(), server.to_vec()));
        self
    }

    /// This server's OPRF seed and records with the key pair of `other`: what
    /// a server does that keeps its database and presents another OPAQUE
    /// public key.
    #[must_use]
    pub fn with_key_of(&self, other: &Server) -> Server {
        let mine = self.setup.serialize();
        let theirs = other.setup.serialize();
        // OPRF seed (64) ‖ private key (32) ‖ dummy public key (32).
        assert_eq!(mine.len(), 128);
        let mut bytes = mine.to_vec();
        bytes[64..96].copy_from_slice(&theirs[64..96]);
        Server {
            setup: ServerSetup::<FerretSuite>::deserialize(&bytes).expect("a valid setup"),
            context: self.context.clone(),
            identities: self.identities.clone(),
        }
    }

    /// The same server with another context.
    #[must_use]
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.context = context.to_vec();
        self
    }

    /// The server's OPAQUE public key.
    pub fn public_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.setup.keypair().public().serialize());
        out
    }

    /// The `registration_response` to a `registration_request`.
    pub fn register_response(
        &self,
        credential_id: &[u8],
        request: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let request =
            RegistrationRequest::<FerretSuite>::deserialize(request).map_err(|_| malformed())?;
        let started = ServerRegistration::<FerretSuite>::start(&self.setup, request, credential_id)
            .map_err(|_| Error::Decrypt)?;
        Ok(started.message.serialize().to_vec())
    }

    /// `KE2` for a `KE1`, from the stored `record` (or none, for an unknown
    /// account: the server then answers with a fake record).
    pub fn login_start<R: SecureRng>(
        &self,
        rng: &mut R,
        record: Option<&[u8]>,
        credential_id: &[u8],
        ke1: &[u8],
    ) -> Result<(Vec<u8>, ServerLoginState), Error> {
        let record = record
            .map(|r| ServerRegistration::<FerretSuite>::deserialize(r).map_err(|_| malformed()))
            .transpose()?;
        let request =
            CredentialRequest::<FerretSuite>::deserialize(ke1).map_err(|_| malformed())?;
        let started = ServerLogin::<FerretSuite>::start(
            &mut Rng06(rng),
            &self.setup,
            record,
            request,
            credential_id,
            ServerLoginParameters {
                context: Some(&self.context),
                identifiers: identifiers(&self.identities),
            },
        )
        .map_err(|_| Error::Decrypt)?;
        Ok((
            started.message.serialize().to_vec(),
            ServerLoginState {
                login: started.state,
                context: self.context.clone(),
                identities: self.identities.clone(),
            },
        ))
    }
}

impl ServerLoginState {
    /// Checks `KE3` and returns the server's session key.
    pub fn finish(self, ke3: &[u8]) -> Result<Vec<u8>, Error> {
        let message =
            CredentialFinalization::<FerretSuite>::deserialize(ke3).map_err(|_| malformed())?;
        let done = self
            .login
            .finish(
                message,
                ServerLoginParameters {
                    context: Some(&self.context),
                    identifiers: identifiers(&self.identities),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        Ok(done.session_key.to_vec())
    }
}

// ----------------------------------------- the client with another KSF

/// The key stretching function of Ferret, for tests: with the parameters of
/// a profile, or with any parameters and no floor or ceiling.
pub struct TestKsf(FerretKsf);

impl TestKsf {
    /// Argon2id with any parameters; no floor or ceiling.
    pub fn new(params: KdfParams) -> Self {
        Self(FerretKsf::unchecked(params))
    }

    /// The KSF of `profile`, on the checked path.
    pub fn of_profile(profile: KsfProfile) -> Self {
        Self(FerretKsf::new(profile))
    }

    /// The parameters of this instance.
    pub fn params(&self) -> KdfParams {
        self.0.params()
    }

    /// The stretched value of `input` (64 bytes in, 64 bytes out).
    pub fn hash(&self, input: &[u8; 64]) -> Result<[u8; 64], Error> {
        hash_with(&self.0, input)
    }
}

/// What `FerretKsf::default()` gives for `input`: the library's default
/// instance, which is profile 1. The client never uses it.
pub fn default_ksf_hash(input: &[u8; 64]) -> Result<[u8; 64], Error> {
    hash_with(&FerretKsf::default(), input)
}

fn hash_with(ksf: &FerretKsf, input: &[u8; 64]) -> Result<[u8; 64], Error> {
    let out = ksf
        .hash(GenericArray::<u8, U64>::clone_from_slice(input))
        .map_err(|_| ksf.take_failure().unwrap_or(Error::Decrypt))?;
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&out);
    Ok(bytes)
}

/// [`crate::opaque_register_finish`] with the given KSF, without the profile
/// table.
pub fn register_finish_with<R: SecureRng>(
    rng: &mut R,
    st: RegistrationState,
    input: &OpaqueInput,
    response: &[u8],
    ksf: &TestKsf,
) -> Result<RegistrationFinished, Error> {
    let done = prod::register_finish(
        rng,
        st.0,
        input.as_bytes(),
        response,
        Identifiers::default(),
        &ksf.0,
    )?;
    Ok(RegistrationFinished {
        record: done.record,
        export_key: done.export_key,
        server_public_key: done.server_public_key,
    })
}

/// A finished login with the session key that production code wipes.
pub struct LoginWithSession {
    /// What [`crate::opaque_login_finish`] returns.
    pub finished: LoginFinished,
    /// The 3DH session key, 64 bytes.
    pub session_key: Vec<u8>,
}

/// The login finish with the given KSF and context, and the check on the
/// pinned server key, but without the checks of the profile and the SK bit.
/// The session key is returned so a test can compare it with the server's.
pub fn login_finish_with<R: SecureRng>(
    rng: &mut R,
    st: LoginState,
    input: &OpaqueInput,
    ke2: &[u8],
    ksf: &TestKsf,
    context: Option<&[u8]>,
    pin: PinState<'_>,
) -> Result<LoginWithSession, Error> {
    let done = client::finish_login(rng, st, input, ke2, &ksf.0, context, pin)?;
    Ok(LoginWithSession {
        finished: LoginFinished {
            ke3: done.ke3,
            export_key: done.export_key,
            server_public_key: done.server_public_key,
        },
        session_key: done.session_key.to_vec(),
    })
}

// ----------------------------------------------------- RFC 9807 suite

/// A registration run with the RFC 9807 suite (identity KSF).
pub struct RfcRegistration {
    /// `registration_request`.
    pub request: Vec<u8>,
    /// `registration_upload`.
    pub upload: Vec<u8>,
    /// `export_key`, 64 bytes.
    pub export_key: [u8; 64],
    /// The server's public key from the response.
    pub server_public_key: [u8; 32],
}

/// A login run with the RFC 9807 suite (identity KSF).
pub struct RfcLogin {
    /// `KE1`.
    pub ke1: Vec<u8>,
    /// `KE3`.
    pub ke3: Vec<u8>,
    /// `export_key`, 64 bytes.
    pub export_key: [u8; 64],
    /// The 3DH `session_key`, 64 bytes.
    pub session_key: Vec<u8>,
    /// The server's public key from the response.
    pub server_public_key: [u8; 32],
}

fn rfc_identifiers<'a>(ids: Option<(&'a [u8], &'a [u8])>) -> Identifiers<'a> {
    match ids {
        Some((client, server)) => Identifiers {
            client: Some(client),
            server: Some(server),
        },
        None => Identifiers::default(),
    }
}

/// Registration start and finish with the RFC suite. `rng` gives the draws in
/// order: the blind (64 bytes), then the envelope nonce (32 bytes).
pub fn rfc_register<R: SecureRng>(
    rng: &mut R,
    password: &[u8],
    response: &[u8],
    identifiers: Option<(&[u8], &[u8])>,
) -> Result<RfcRegistration, Error> {
    let (request, state) = rfc::register_start(rng, password)?;
    let done = rfc::register_finish(
        rng,
        state,
        password,
        response,
        rfc_identifiers(identifiers),
        &opaque_ke::ksf::Identity,
    )?;
    Ok(RfcRegistration {
        request,
        upload: done.record,
        export_key: *done.export_key.expose(),
        server_public_key: done.server_public_key,
    })
}

/// Login start and finish with the RFC suite and its context. `rng` gives
/// the draws in order: the blind (64 bytes), the seed of the client's
/// ephemeral key (32 bytes), the client nonce (32 bytes).
pub fn rfc_login<R: SecureRng>(
    rng: &mut R,
    password: &[u8],
    ke2: &[u8],
    context: &[u8],
    identifiers: Option<(&[u8], &[u8])>,
) -> Result<RfcLogin, Error> {
    let (ke1, state) = rfc::login_start(rng, password)?;
    let done = rfc::login_finish(
        rng,
        state,
        password,
        ke2,
        Some(context),
        rfc_identifiers(identifiers),
        &opaque_ke::ksf::Identity,
    )?;
    Ok(RfcLogin {
        ke1,
        ke3: done.ke3,
        export_key: *done.export_key.expose(),
        session_key: done.session_key.to_vec(),
        server_public_key: done.server_public_key,
    })
}

/// Runs the guard that wipes `opaque-ke`'s key arrays in place and ends its
/// scope, so a test can see that the borrowed bytes are zero afterwards.
pub fn wipe_on_drop_probe(bytes: &mut [u8]) {
    let guard = client::WipeOnDrop(bytes);
    drop(guard);
}
