//! OPAQUE login on the server: [`login_start`] answers the client's first
//! message, [`login_finish`] checks its last.
//!
//! # No account list
//!
//! A server that answers the first message of a login differently for a
//! known and an unknown name hands out the list of its users. `login_start`
//! therefore does the same work for every name:
//!
//! * the made-up credential id and the made-up record are always computed,
//!   and the real or the made-up one is chosen with a branch-free selection
//!   (`ct_select_bytes`), so the steps that follow are the same ones;
//! * a name without an account, and an account that is disabled, are both
//!   answered from the made-up record. The answer has the same shape (320
//!   bytes of KE2, a profile, a second-factor hint) and is the same on every
//!   ask for the same name and KE1;
//! * the throttle is asked first, with the resolved credential id, so a
//!   limiter sees the same kind of request for both.
//!
//! The one thing that tells a known account apart is the content of the
//! answer, which only the OPAQUE client can interpret: with the wrong
//! password, or for a made-up record, it fails to open the envelope.
//!
//! # Order of the steps
//!
//! `login_start`:
//!
//! 1. for a [`LoginPurpose::Reauth`] login, check that the scope of the
//!    session allows [`Capability::ReauthLogin`] (`Denied(ScopeForbids)`, 403);
//!    an ordinary login has no session and skips this;
//! 2. refuse to start when the clock reads `u64::MAX` (a clock that failed);
//! 3. resolve the credential id and ask the throttle (`Stage::LoginStart`)
//!    before any other work;
//! 4. check the length of KE1 (exactly 96 bytes) and parse it
//!    ([`Malformed::Ke1`] depends on the client's bytes alone);
//! 5. compute the made-up pre-login answer and the made-up record, and
//!    select the real or the made-up ones;
//! 6. parse the chosen record once and run `ServerLogin::start` with the
//!    context `ferret/v1/opaque` and no identities;
//! 7. seal the 128-byte state, put it in the store for
//!    [`STATE_TTL_SECS`](crate::STATE_TTL_SECS) seconds, and answer.
//!
//! `login_finish`:
//!
//! 1. check the structure: the login id and the length of KE3 (exactly 64
//!    bytes). The store is not touched for a request that is malformed;
//! 2. `take` the sealed state (the store makes it single use) and open it,
//!    which checks the purpose, the session and the expiry;
//! 3. ask the throttle (`Stage::LoginFinish`) with the credential id of the
//!    state, or with the address alone when no state could be opened;
//! 4. run `ServerLogin::finish` on the KE3 and wipe the session key.
//!
//! The state is gone after step 2 whatever happens next: a wrong KE3, a
//! throttled caller or a failed check each cost the client a new
//! `login_start`. That is the price of single use, and it is what stops a
//! guess at KE3 from being repeated against the same state.
//!
//! Every refusal of `login_finish` is [`AuthError::Denied`] with an own
//! [`DenyReason`] for the server's log and the one public code `denied`; the
//! only other answers are [`AuthError::Malformed`] for a bad structure,
//! [`AuthError::Throttled`] and [`AuthError::Internal`]. They are the same
//! for a real and a made-up credential.
//!
//! # The throttle
//!
//! Only `admit` and `finish` of the crate's throttle module are used. A
//! request that was admitted reports `Success` or `Failure` exactly once;
//! `login_start` reports `Success` when it answered. The library never calls
//! `Throttle::record` directly.
//!
//! # No session key
//!
//! OPAQUE computes a session key. Ferret uses none (Fase 1 § 4.2), so it is
//! wiped inside `login_finish` and [`LoginVerified`] has no field for it.
//!
//! ```compile_fail,E0609
//! fn peek(v: ferret_server_auth::LoginVerified) {
//!     let _ = v.session_key;
//! }
//! ```
//!
//! Spec: Fase 1 § 4.2 ("Innlogging"); RFC 9807 section 6.3.

use core::fmt;

use ferret_core::SecureRng;
use ferret_core::opaque::server_suite::opaque_ke::{
    CredentialFinalization, CredentialRequest, Identifiers, ServerLogin, ServerLoginParameters,
    ServerRegistration,
};
use ferret_core::opaque::server_suite::{
    FerretSuite, KE1_LEN, KE3_LEN, OPAQUE_CONTEXT, REGISTRATION_RECORD_LEN, Rng06,
};
use zeroize::{Zeroize, Zeroizing};

use crate::clock::Clock;
use crate::ct::{ct_eq, ct_select_bytes, ct_select_u8};
use crate::error::{AuthError, DenyReason, InternalKind, Malformed};
use crate::ids::{CredentialId, LoginId, SessionBinding};
use crate::keys::{PreloginSecret, ServerKeys};
use crate::name::NormalizedLoginName;
use crate::prelogin::{PreloginPolicy, fake_credential_id, fake_prelogin, fake_record_bytes, step};
use crate::record::{ProfileRules, StoredRecord};
use crate::scope::{Capability, SessionScope, authorize};
use crate::state::{
    LoginPurpose, LoginStateStore, SERVER_LOGIN_LEN, SealedState, StatePlain, StateSealKey,
    open_state, seal_state,
};
use crate::throttle::{Caller, Outcome, Stage, Throttle, admit};

/// A zero record, the "real" side of the selection for a name without an
/// account.
const ZERO_RECORD: [u8; REGISTRATION_RECORD_LEN] = [0; REGISTRATION_RECORD_LEN];

/// Everything the login functions need from the server: borrows of its keys,
/// secrets, clock, throttle and rules.
///
/// Building it costs nothing, so a server may build one for every request.
/// The start-up check of the pre-login policy is in [`PreloginPolicy::new`],
/// which refuses a profile that clients do not know: load the secrets
/// (`load_or_create`), take the [`startup_decision`](crate::startup_decision),
/// build the policy from the shares of the real accounts, and refuse to serve
/// on an error.
///
/// The profile rules are kept for the registration entry points, which share
/// this context; the login functions do not read them.
#[derive(Clone, Copy)]
pub struct AuthContext<'a> {
    keys: &'a ServerKeys,
    prelogin: &'a PreloginSecret,
    seal: &'a StateSealKey,
    clock: &'a dyn Clock,
    throttle: &'a dyn Throttle,
    policy: &'a PreloginPolicy,
    profiles: &'a ProfileRules,
}

impl<'a> AuthContext<'a> {
    /// Bundles the server's keys, secrets, clock, throttle and rules.
    pub const fn new(
        keys: &'a ServerKeys,
        prelogin: &'a PreloginSecret,
        seal: &'a StateSealKey,
        clock: &'a dyn Clock,
        throttle: &'a dyn Throttle,
        policy: &'a PreloginPolicy,
        profiles: &'a ProfileRules,
    ) -> Self {
        Self {
            keys,
            prelogin,
            seal,
            clock,
            throttle,
            policy,
            profiles,
        }
    }

    /// The OPAQUE keys of the server.
    pub const fn keys(&self) -> &'a ServerKeys {
        self.keys
    }

    /// The secret the made-up answers are derived from.
    pub const fn prelogin(&self) -> &'a PreloginSecret {
        self.prelogin
    }

    /// The key that seals login states.
    pub const fn seal(&self) -> &'a StateSealKey {
        self.seal
    }

    /// The clock.
    pub const fn clock(&self) -> &'a dyn Clock {
        self.clock
    }

    /// The rate limiter.
    pub const fn throttle(&self) -> &'a dyn Throttle {
        self.throttle
    }

    /// The spread of the made-up pre-login answers.
    pub const fn policy(&self) -> &'a PreloginPolicy {
        self.policy
    }

    /// The key stretching profiles the server accepts.
    pub const fn profiles(&self) -> &'a ProfileRules {
        self.profiles
    }
}

impl fmt::Debug for AuthContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthContext { .. }")
    }
}

/// What the caller found when it looked up the login name.
///
/// A name without an account and an account that is disabled are both
/// answered from the made-up record: to the world, a disabled account does
/// not exist.
#[derive(Clone, Copy)]
pub enum AccountLookup<'a> {
    /// An account that may log in.
    Active {
        /// The stored record and its key stretching profile.
        record: &'a StoredRecord,
        /// Whether the account has a second factor.
        sk_hint: bool,
    },
    /// No account has this name.
    Unknown,
    /// An account exists but may not log in.
    Disabled,
}

impl fmt::Debug for AccountLookup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Which variant it is would tell a log reader whether the name exists.
        f.write_str("AccountLookup([redacted])")
    }
}

/// The first message of a login.
#[derive(Clone, Copy)]
pub struct LoginStartRequest<'a> {
    /// Who is calling.
    pub caller: Caller,
    /// The login name, normalized. It decides the made-up answers.
    pub name: &'a NormalizedLoginName,
    /// The credential id of the account that was looked up. Read only for an
    /// [`AccountLookup::Active`]; for the other two the library uses the
    /// made-up id of the name and ignores this value.
    pub credential: CredentialId,
    /// What the lookup of the name found.
    pub lookup: AccountLookup<'a>,
    /// What the login is for.
    pub purpose: LoginPurpose,
    /// The scope of the session the request was made in. Read only for a
    /// [`LoginPurpose::Reauth`] login, which needs [`Capability::ReauthLogin`]:
    /// `None` is refused there, like a session without a scope. Pass `None`
    /// for an ordinary login, which has no session. The check depends on the
    /// purpose and the scope alone, never on the name, so it tells nothing
    /// about which names exist.
    pub session_scope: Option<SessionScope>,
    /// `KE1`, exactly 96 bytes.
    pub ke1: &'a [u8],
}

impl fmt::Debug for LoginStartRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginStartRequest([redacted])")
    }
}

/// The answer to the first message of a login.
pub struct LoginStartResponse {
    /// The identifier of the login in progress. The client sends it back with
    /// `KE3`.
    pub login_id: LoginId,
    /// `KE2`, 320 bytes.
    pub ke2: Vec<u8>,
    /// The key stretching profile the client must use.
    pub ksf_profile: u8,
    /// Whether the account has a second factor.
    pub sk_hint: bool,
}

impl fmt::Debug for LoginStartResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginStartResponse([redacted])")
    }
}

/// The last message of a login.
#[derive(Clone, Copy)]
pub struct LoginFinishRequest<'a> {
    /// Who is calling.
    pub caller: Caller,
    /// The login id as the client sent it (32 lower-case hex characters).
    pub login_id: &'a [u8],
    /// `KE3`, exactly 64 bytes.
    pub ke3: &'a [u8],
    /// The session that the request was made in and the account that owns
    /// it, for a re-authentication, or `None` for an ordinary login. A state
    /// made for a login is not accepted with a session, and a state made for
    /// a session is not accepted without that session.
    ///
    /// The endpoint takes both values from the session it has found, never
    /// from the request body. The login is refused unless it was for that
    /// account (`Denied(StateInvalid)`): a caller who holds a session of one
    /// account and knows the password of another cannot use it to
    /// re-authenticate.
    pub current_session: Option<(SessionBinding, CredentialId)>,
}

impl fmt::Debug for LoginFinishRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginFinishRequest([redacted])")
    }
}

/// A login that the client proved with the right password.
///
/// There is no session key here, on purpose: it is wiped inside
/// [`login_finish`] and Ferret uses none.
///
/// A state lives for 60 seconds, so an account that was disabled between
/// `login_start` and `login_finish` still finishes with `Ok`. The caller must
/// look the account up again and refuse a disabled one before it issues a
/// session.
pub struct LoginVerified {
    /// The account the login was for.
    pub credential: CredentialId,
    /// What the login was for, as the request expected it.
    pub purpose: LoginPurpose,
}

impl fmt::Debug for LoginVerified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginVerified([redacted])")
    }
}

/// The OPAQUE context and identities of `login_start`. The server uses the
/// ones in [`Params::FERRET`]; tests run others to show that a server that
/// differs cannot authenticate. The sealed state holds the MAC that the
/// client must send, computed at the start with these values, so
/// `login_finish` has no choice to make.
pub(crate) struct Params<'p> {
    pub(crate) context: &'p [u8],
    pub(crate) client_identity: Option<&'p [u8]>,
    pub(crate) server_identity: Option<&'p [u8]>,
}

impl fmt::Debug for Params<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Params { .. }")
    }
}

impl Params<'static> {
    /// Ferret's: the context `ferret/v1/opaque`, no identities (the public
    /// keys stand in).
    pub(crate) const FERRET: Params<'static> = Params {
        context: OPAQUE_CONTEXT,
        client_identity: None,
        server_identity: None,
    };
}

impl<'p> Params<'p> {
    fn opaque(&self) -> ServerLoginParameters<'p, 'p> {
        ServerLoginParameters {
            context: Some(self.context),
            identifiers: Identifiers {
                client: self.client_identity,
                server: self.server_identity,
            },
        }
    }
}

const fn crypto_failed() -> AuthError {
    AuthError::Internal(InternalKind::Crypto)
}

const fn clock_failed() -> AuthError {
    AuthError::Internal(InternalKind::Clock)
}

/// Answers the first message of a login.
///
/// The throttle is asked first. After that the function draws, in this order,
/// the 64, 32, 32 and 32 bytes of `ServerLogin::start`, then the 16 bytes of
/// the login id and the 24 bytes of the seal nonce, and nothing else. A
/// known account, an unknown name and a disabled account run the same steps
/// in the same order; see the module documentation.
///
/// Errors: [`DenyReason::ScopeForbids`] when a re-authentication is asked for
/// from a session whose scope does not allow it, [`AuthError::Throttled`]
/// from the limiter, [`Malformed::Ke1`] for a KE1 that is not exactly 96 bytes or not a valid
/// message, and [`AuthError::Internal`] for a clock that failed or a store
/// that could not keep the state.
///
/// Spec: Fase 1 § 4.2 ("Innlogging", steps 1 and 2).
pub fn login_start<R: SecureRng, S: LoginStateStore>(
    cx: &AuthContext<'_>,
    store: &S,
    rng: &mut R,
    req: &LoginStartRequest<'_>,
) -> Result<LoginStartResponse, AuthError> {
    start_with(cx, store, rng, req, &Params::FERRET)
}

/// `login_start` with another context or other identities, for tests.
pub(crate) fn start_with<R: SecureRng, S: LoginStateStore>(
    cx: &AuthContext<'_>,
    store: &S,
    rng: &mut R,
    req: &LoginStartRequest<'_>,
    params: &Params<'_>,
) -> Result<LoginStartResponse, AuthError> {
    // A re-authentication needs a session that may re-authenticate. Pure
    // check on the purpose and the scope, before any other work.
    if matches!(req.purpose, LoginPurpose::Reauth { .. }) {
        authorize(
            req.session_scope.unwrap_or(SessionScope::Unverified),
            Capability::ReauthLogin,
        )?;
    }
    let now = cx.clock.now_unix();
    // A clock that failed reads `u64::MAX`; a state made then would become
    // valid again once the clock is repaired.
    if now == u64::MAX {
        return Err(clock_failed());
    }
    let stored = match req.lookup {
        AccountLookup::Active { record, sk_hint } => Stored {
            active: 1,
            record: record.record.as_bytes(),
            ksf_profile: record.ksf_profile,
            sk_hint: u8::from(sk_hint),
        },
        AccountLookup::Unknown | AccountLookup::Disabled => Stored {
            active: 0,
            record: ZERO_RECORD.as_slice(),
            ksf_profile: 0,
            sk_hint: 0,
        },
    };

    // The id OPAQUE binds the answer to: the account's own, or the made-up
    // one of the name. Both are computed, one is selected.
    let fake_id = fake_credential_id(cx.prelogin, req.name);
    step("select-id");
    let mut chosen_id = [0u8; 16];
    ct_select_bytes(
        stored.active,
        req.credential.as_bytes(),
        fake_id.as_bytes(),
        &mut chosen_id,
    );
    let id = CredentialId::from_bytes(chosen_id);

    // Nothing but pure computation has happened so far. The limiter comes
    // before any OPAQUE work, any draw and any write.
    step("admit");
    let ticket = admit(cx.throttle, Stage::LoginStart, &req.caller, Some(&id), now)?;
    let answer = start_admitted(cx, store, rng, req, params, (&id, &stored), now);
    let outcome = if answer.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    answer
}

/// What the lookup of the name gave, unpacked for the selection: the real
/// side of every choice between a real and a made-up value. Zero for a name
/// without an account.
struct Stored<'a> {
    /// 1 for an account that may log in, else 0.
    active: u8,
    record: &'a [u8],
    ksf_profile: u8,
    sk_hint: u8,
}

impl fmt::Debug for Stored<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Stored([redacted])")
    }
}

/// The part of `login_start` that runs after the limiter let the request
/// through. `chosen` is the credential id in use and the unpacked lookup.
fn start_admitted<R: SecureRng, S: LoginStateStore>(
    cx: &AuthContext<'_>,
    store: &S,
    rng: &mut R,
    req: &LoginStartRequest<'_>,
    params: &Params<'_>,
    chosen: (&CredentialId, &Stored<'_>),
    now: u64,
) -> Result<LoginStartResponse, AuthError> {
    let (id, stored) = chosen;

    step("parse-ke1");
    let request = parse_ke1(req.ke1)?;

    // The made-up answer and the made-up record are always computed; the
    // real ones are chosen without a branch.
    let fake = fake_prelogin(cx.prelogin, req.name, cx.policy);
    let fake_record = fake_record_bytes(cx.keys, cx.prelogin, id);
    step("select-record");
    let mut record = Zeroizing::new([0u8; REGISTRATION_RECORD_LEN]);
    ct_select_bytes(
        stored.active,
        stored.record,
        fake_record.as_slice(),
        record.as_mut_slice(),
    );
    let ksf_profile = ct_select_u8(stored.active, stored.ksf_profile, fake.ksf_profile);
    let sk_hint = ct_select_u8(stored.active, stored.sk_hint, u8::from(fake.sk_hint)) == 1;

    step("parse-record");
    let registration = ServerRegistration::<FerretSuite>::deserialize(record.as_slice())
        .map_err(|_| crypto_failed())?;

    step("opaque-start");
    let started = ServerLogin::<FerretSuite>::start(
        &mut Rng06(&mut *rng),
        cx.keys.setup(),
        Some(registration),
        request,
        id.as_bytes(),
        params.opaque(),
    )
    .map_err(|_| crypto_failed())?;

    step("seal");
    let login_id = LoginId::random(rng);
    let expires_at = StatePlain::expiry_from(now)?;
    let server_login = server_login_bytes(&started.state)?;
    let plain = StatePlain {
        credential: *id,
        purpose: req.purpose,
        expires_at,
        ksf_profile,
        server_login,
    };
    let sealed = seal_state(cx.seal, rng, &login_id, &plain, now)?;

    step("put");
    store
        .put(login_id.store_key(), sealed, expires_at, now)
        .map_err(AuthError::from)?;

    Ok(LoginStartResponse {
        login_id,
        ke2: started.message.serialize().to_vec(),
        ksf_profile,
        sk_hint,
    })
}

/// The serialized `ServerLogin`, in a buffer that wipes itself. The 128 bytes
/// are the session key and the expected MAC of the client.
fn server_login_bytes(
    state: &ServerLogin<FerretSuite>,
) -> Result<Zeroizing<[u8; SERVER_LOGIN_LEN]>, AuthError> {
    let mut serialized = state.serialize();
    let mut out = Zeroizing::new([0u8; SERVER_LOGIN_LEN]);
    let fits = serialized.len() == SERVER_LOGIN_LEN;
    if fits {
        for (slot, byte) in out.iter_mut().zip(serialized.iter()) {
            *slot = *byte;
        }
    }
    serialized.as_mut_slice().zeroize();
    if fits { Ok(out) } else { Err(crypto_failed()) }
}

/// KE1: exactly 96 bytes (the parser of `opaque-ke` ignores a tail) and a
/// valid message. The answer depends on the client's bytes alone.
fn parse_ke1(bytes: &[u8]) -> Result<CredentialRequest<FerretSuite>, AuthError> {
    let malformed = AuthError::Malformed(Malformed::Ke1);
    if bytes.len() != KE1_LEN {
        return Err(malformed);
    }
    CredentialRequest::<FerretSuite>::deserialize(bytes).map_err(|_| malformed)
}

/// KE3: exactly 64 bytes and a valid message.
fn parse_ke3(bytes: &[u8]) -> Result<CredentialFinalization<FerretSuite>, AuthError> {
    let malformed = AuthError::Malformed(Malformed::Ke3);
    if bytes.len() != KE3_LEN {
        return Err(malformed);
    }
    CredentialFinalization::<FerretSuite>::deserialize(bytes).map_err(|_| malformed)
}

/// Checks the last message of a login.
///
/// The structure is checked first and without touching the store. The state
/// is then taken (single use) and opened; only after that is the limiter
/// asked, with the credential id of the state, and only then does any OPAQUE
/// work start. When no state could be opened the limiter is asked with the
/// address alone.
///
/// Every refusal of the proof is [`AuthError::Denied`] with a reason of its
/// own and the one public code `denied`; a missing, used, expired, foreign
/// or wrongly bound state and a wrong KE3 cannot be told apart by a client.
///
/// An expired state is reported as [`DenyReason::StateMissing`], not as an
/// expiry: the store drops a state at its expiry time (`now >= expires_at`)
/// before the library opens it, so by then there is nothing to find. The
/// expiry check inside the sealed state is a second line behind the store
/// and can only be reached by a store that returns a stale state. The public
/// answer is the same either way.
///
/// Spec: Fase 1 § 4.2 ("Innlogging", steps 3 and 4).
pub fn login_finish<S: LoginStateStore>(
    cx: &AuthContext<'_>,
    store: &S,
    req: &LoginFinishRequest<'_>,
) -> Result<LoginVerified, AuthError> {
    let now = cx.clock.now_unix();
    let expected = match req.current_session {
        Some((session, account)) => LoginPurpose::Reauth { session, account },
        None => LoginPurpose::Login,
    };

    step("parse-finish");
    let (login_id, ke3) =
        match LoginId::parse(req.login_id).and_then(|id| Ok((id, parse_ke3(req.ke3)?))) {
            Ok(parsed) => parsed,
            Err(error) => return Err(refuse_without_id(cx, req, now, error)),
        };

    step("take");
    let taken = match store.take(&login_id.store_key(), now) {
        Ok(taken) => taken,
        // A store that fails is also a request that was admitted and failed.
        Err(error) => return Err(refuse_without_id(cx, req, now, AuthError::from(error))),
    };
    let sealed: Option<SealedState> = taken;
    let Some(sealed) = sealed else {
        let missing = AuthError::Denied(DenyReason::StateMissing);
        return Err(refuse_without_id(cx, req, now, missing));
    };
    step("open");
    let state = match open_state(cx.seal, &login_id, &sealed, &expected, now) {
        Ok(state) => state,
        Err(error) => return Err(refuse_without_id(cx, req, now, error)),
    };

    // A re-authentication is for the account of the session. A login that was
    // for another account (a name the caller knows the password of) is
    // refused, and the account of the state is not used for the throttle.
    if let Some(account) = expected.account()
        && !ct_eq(state.credential.as_bytes(), account.as_bytes())
    {
        let wrong = AuthError::Denied(DenyReason::StateInvalid);
        return Err(refuse_without_id(cx, req, now, wrong));
    }

    // The state tells which account this is. A refusal here drops (and
    // wipes) the state; it has already been taken out of the store.
    step("admit");
    let ticket = admit(
        cx.throttle,
        Stage::LoginFinish,
        &req.caller,
        Some(&state.credential),
        now,
    )?;

    step("opaque-finish");
    let proof = check_proof(&state, ke3);
    let outcome = if proof.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    };
    ticket.finish(outcome, now);
    proof?;
    Ok(LoginVerified {
        credential: state.credential,
        purpose: expected,
    })
}

/// Ends a request that failed before the account was known: the limiter is
/// asked with the address alone, and told it failed. A caller the limiter
/// refuses gets the throttle error instead of `error`.
fn refuse_without_id(
    cx: &AuthContext<'_>,
    req: &LoginFinishRequest<'_>,
    now: u64,
    error: AuthError,
) -> AuthError {
    step("admit");
    match admit(cx.throttle, Stage::LoginFinish, &req.caller, None, now) {
        Ok(ticket) => {
            ticket.finish(Outcome::Failure, now);
            error
        }
        Err(throttled) => throttled,
    }
}

/// `ServerLogin::finish` on the state and the client's KE3. The session key
/// is wiped before anything is returned.
fn check_proof(
    state: &StatePlain,
    ke3: CredentialFinalization<FerretSuite>,
) -> Result<(), AuthError> {
    let login = ServerLogin::<FerretSuite>::deserialize(state.server_login.as_slice())
        .map_err(|_| crypto_failed())?;
    // The expected MAC is part of the state: the parameters given here are
    // not part of what is compared.
    let mut done = login
        .finish(ke3, Params::FERRET.opaque())
        .map_err(|_| AuthError::Denied(DenyReason::Ke3))?;
    done.session_key.as_mut_slice().zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ferret_core::TestRng;

    use super::*;
    use crate::prelogin::{clear_steps, steps};
    use crate::state::{InMemoryLoginStateStore, StoreError};
    use crate::testing::{FIXTURE_PASSWORD, LoginFixture};
    use crate::throttle::RetryAfter;
    use crate::{STATE_TTL_SECS, StateKey};

    /// The order in which the effects of a call happen.
    struct OrderLog(Mutex<Vec<&'static str>>);

    impl OrderLog {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
        }

        fn push(&self, what: &'static str) {
            self.0.lock().unwrap().push(what);
        }

        fn take(&self) -> Vec<&'static str> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    impl fmt::Debug for OrderLog {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("OrderLog")
        }
    }

    /// A throttle that logs its calls and refuses when told.
    struct OrderThrottle<'a> {
        log: &'a OrderLog,
        refuse: AtomicBool,
    }

    impl fmt::Debug for OrderThrottle<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("OrderThrottle")
        }
    }

    impl Throttle for OrderThrottle<'_> {
        fn admit(
            &self,
            _stage: Stage,
            _keys: &[crate::ThrottleKey],
            _now: u64,
        ) -> Result<(), RetryAfter> {
            self.log.push("admit");
            if self.refuse.load(Ordering::SeqCst) {
                Err(RetryAfter::new(5))
            } else {
                Ok(())
            }
        }

        fn record(
            &self,
            _stage: Stage,
            _keys: &[crate::ThrottleKey],
            _outcome: Outcome,
            _now: u64,
        ) {
            self.log.push("record");
        }
    }

    /// A store that logs `put` and `take`.
    struct OrderStore<'a> {
        log: &'a OrderLog,
        inner: InMemoryLoginStateStore,
    }

    impl fmt::Debug for OrderStore<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("OrderStore")
        }
    }

    impl LoginStateStore for OrderStore<'_> {
        fn put(
            &self,
            key: StateKey,
            sealed: SealedState,
            expires_at: u64,
            now: u64,
        ) -> Result<(), StoreError> {
            self.log.push("put");
            self.inner.put(key, sealed, expires_at, now)
        }

        fn take(&self, key: &StateKey, now: u64) -> Result<Option<SealedState>, StoreError> {
            self.log.push("take");
            self.inner.take(key, now)
        }

        fn purge_expired(&self, now: u64) -> Result<usize, StoreError> {
            self.inner.purge_expired(now)
        }
    }

    /// A random source that logs every draw.
    struct OrderRng<'a> {
        log: &'a OrderLog,
        inner: TestRng,
    }

    impl fmt::Debug for OrderRng<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("OrderRng")
        }
    }

    impl SecureRng for OrderRng<'_> {
        fn fill(&mut self, dest: &mut [u8]) {
            self.log.push("draw");
            self.inner.fill(dest);
        }
    }

    fn context<'a>(f: &'a LoginFixture, throttle: &'a OrderThrottle<'a>) -> AuthContext<'a> {
        AuthContext::new(
            &f.keys,
            &f.prelogin,
            &f.seal,
            &f.clock,
            throttle,
            &f.policy,
            &f.profiles,
        )
    }

    fn start_request<'a>(
        f: &'a LoginFixture,
        lookup: AccountLookup<'a>,
        ke1: &'a [u8],
    ) -> LoginStartRequest<'a> {
        LoginStartRequest {
            caller: LoginFixture::caller(),
            name: &f.name,
            credential: f.credential,
            lookup,
            purpose: LoginPurpose::Login,
            session_scope: None,
            ke1,
        }
    }

    fn finish_request<'a>(login_id: &'a [u8], ke3: &'a [u8]) -> LoginFinishRequest<'a> {
        LoginFinishRequest {
            caller: LoginFixture::caller(),
            login_id,
            ke3,
            current_session: None,
        }
    }

    const START_STEPS: [&str; 11] = [
        "fake-id",
        "select-id",
        "admit",
        "parse-ke1",
        "fake-prelogin",
        "fake-record",
        "select-record",
        "parse-record",
        "opaque-start",
        "seal",
        "put",
    ];

    #[test]
    fn known_and_unknown_run_the_same_steps_in_the_same_order() {
        let f = LoginFixture::new();
        let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
        let trace = |lookup| {
            clear_steps();
            f.start(lookup, &ke1, LoginPurpose::Login).unwrap();
            steps()
        };
        let known = trace(f.active());
        assert_eq!(known, START_STEPS);
        assert_eq!(trace(AccountLookup::Unknown), known);
        assert_eq!(trace(AccountLookup::Disabled), known);
    }

    #[test]
    fn a_malformed_ke1_stops_after_the_same_steps_for_every_lookup() {
        let f = LoginFixture::new();
        let trace = |lookup| {
            clear_steps();
            f.start(lookup, &[0u8; 95], LoginPurpose::Login)
                .unwrap_err();
            steps()
        };
        let known = trace(f.active());
        assert_eq!(known, ["fake-id", "select-id", "admit", "parse-ke1"]);
        assert_eq!(trace(AccountLookup::Unknown), known);
        assert_eq!(trace(AccountLookup::Disabled), known);
    }

    #[test]
    fn finish_runs_the_same_steps_for_known_and_unknown_accounts() {
        let f = LoginFixture::new();
        let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
        let trace = |lookup| {
            let response = f.start(lookup, &ke1, LoginPurpose::Login).unwrap();
            clear_steps();
            let error = f.finish(&response.login_id, &[9u8; 64], None).unwrap_err();
            assert_eq!(error, AuthError::Denied(DenyReason::Ke3));
            steps()
        };
        let known = trace(f.active());
        assert_eq!(
            known,
            ["parse-finish", "take", "open", "admit", "opaque-finish"]
        );
        assert_eq!(trace(AccountLookup::Unknown), known);
        assert_eq!(trace(AccountLookup::Disabled), known);
    }

    #[test]
    fn a_throttled_start_stops_at_the_limiter() {
        let f = LoginFixture::new();
        let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
        f.throttle.refuse_with(Some(RetryAfter::new(3)));
        clear_steps();
        f.start(f.active(), &ke1, LoginPurpose::Login).unwrap_err();
        assert_eq!(steps(), ["fake-id", "select-id", "admit"]);
    }

    #[test]
    fn admit_is_the_first_effect_of_login_start() {
        let f = LoginFixture::new();
        let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
        let log = OrderLog::new();
        let throttle = OrderThrottle {
            log: &log,
            refuse: AtomicBool::new(false),
        };
        let store = OrderStore {
            log: &log,
            inner: InMemoryLoginStateStore::new(),
        };
        let cx = context(&f, &throttle);
        for lookup in [f.active(), AccountLookup::Unknown, AccountLookup::Disabled] {
            let mut rng = OrderRng {
                log: &log,
                inner: TestRng::new(b"order"),
            };
            let request = start_request(&f, lookup, &ke1);
            login_start(&cx, &store, &mut rng, &request).unwrap();
            // Four draws of the OPAQUE start, the login id, the seal nonce.
            let mut expected = vec!["admit"];
            expected.extend(["draw"; 6]);
            expected.extend(["put", "record"]);
            assert_eq!(log.take(), expected);
            // Each run starts from an empty store.
            store.inner.purge_expired(u64::MAX).unwrap();
            log.take();
        }
        // A refusal ends the call at the limiter: no draw, no write.
        throttle.refuse.store(true, Ordering::SeqCst);
        let mut rng = OrderRng {
            log: &log,
            inner: TestRng::new(b"order"),
        };
        let request = start_request(&f, f.active(), &ke1);
        let error = login_start(&cx, &store, &mut rng, &request).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 5
            }
        );
        assert_eq!(log.take(), ["admit"]);
    }

    #[test]
    fn admit_comes_before_any_opaque_work_in_login_finish() {
        let f = LoginFixture::new();
        let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client");
        let log = OrderLog::new();
        let throttle = OrderThrottle {
            log: &log,
            refuse: AtomicBool::new(false),
        };
        let store = OrderStore {
            log: &log,
            inner: InMemoryLoginStateStore::new(),
        };
        let cx = context(&f, &throttle);
        let mut rng = TestRng::new(b"order");
        let response =
            login_start(&cx, &store, &mut rng, &start_request(&f, f.active(), &ke1)).unwrap();
        let ke3 = f
            .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
            .unwrap();
        log.take();
        let hex = response.login_id.to_hex();

        // Success: the state is taken, then the limiter, then the proof.
        clear_steps();
        login_finish(&cx, &store, &finish_request(hex.as_bytes(), &ke3)).unwrap();
        assert_eq!(log.take(), ["take", "admit", "record"]);
        assert_eq!(
            steps(),
            ["parse-finish", "take", "open", "admit", "opaque-finish"]
        );

        // No state: the limiter, with the address alone, and no proof.
        clear_steps();
        login_finish(&cx, &store, &finish_request(hex.as_bytes(), &ke3)).unwrap_err();
        assert_eq!(log.take(), ["take", "admit", "record"]);
        assert_eq!(steps(), ["parse-finish", "take", "admit"]);

        // A structure error: the limiter first, the store is not touched.
        clear_steps();
        login_finish(&cx, &store, &finish_request(hex.as_bytes(), &ke3[..63])).unwrap_err();
        assert_eq!(log.take(), ["admit", "record"]);
        assert_eq!(steps(), ["parse-finish", "admit"]);

        // A refused caller: the state is taken, the proof is not looked at.
        let (ke1, state) = f.client_start(FIXTURE_PASSWORD, "client again");
        let mut rng = TestRng::new(b"order 2");
        let response =
            login_start(&cx, &store, &mut rng, &start_request(&f, f.active(), &ke1)).unwrap();
        let ke3 = f
            .client_finish(state, FIXTURE_PASSWORD, &response.ke2, OPAQUE_CONTEXT)
            .unwrap();
        log.take();
        throttle.refuse.store(true, Ordering::SeqCst);
        clear_steps();
        let hex = response.login_id.to_hex();
        let error = login_finish(&cx, &store, &finish_request(hex.as_bytes(), &ke3)).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 5
            }
        );
        assert_eq!(log.take(), ["take", "admit"]);
        assert_eq!(steps(), ["parse-finish", "take", "open", "admit"]);
    }

    #[test]
    fn a_state_lives_for_the_documented_time() {
        let f = LoginFixture::new();
        let (ke1, _) = f.client_start(FIXTURE_PASSWORD, "client");
        let response = f.start(f.active(), &ke1, LoginPurpose::Login).unwrap();
        assert_eq!(STATE_TTL_SECS, 60);
        let key = response.login_id.store_key();
        let gone = LoginFixture::START + STATE_TTL_SECS;
        assert!(f.store.take(&key, gone).unwrap().is_none());
    }
}
