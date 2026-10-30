//! A small server and the client of `ferret-core`, wired the way an endpoint
//! wires them.
//!
//! Nothing here reaches into the library: every call goes through the public
//! API, with the context, the stores, the throttle and the clock a server
//! holds. The accounts are made by `create_account` of the core, and changed
//! by `change_password` and `recover`. `crates/ferret-core/tests/common` is the
//! pattern for the helpers, but nothing is shared with it.
//!
//! The bodies of the signed requests in these tests are `profile (4 bytes,
//! big endian) ‖ record` for a password change and `profile ‖ pk_r_new (32
//! bytes) ‖ record` for a recovery. The library does not read bodies; the
//! format belongs to the test's parser, as the JSON of a real endpoint
//! belongs to the endpoint.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::sync::atomic::{AtomicU32, Ordering};

use ferret_core::testing::keys::export_key_bytes;
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    AccountId, AuthPublicKey, Error, KdfParams, KsfProfile, ManifestRow, MasterPassword, MethodId,
    MpPolicy, NewAccount, NewAccountIds, NewPassword, OPAQUE_CONTEXT, OpaqueInput, PasswordChange,
    PinState, Recovered, RecoveryInput, RecoveryPublicKey, RegistrationFinished, SecureRng,
    TestRng, VaultId, change_password, create_account, encode_recovery_key, opaque_login_finish,
    opaque_login_start, opaque_register_finish, opaque_register_start, recover,
};
use ferret_server_auth::testing::{SMALL, TestAccountStore};
use ferret_server_auth::{
    AccountAuthState, AccountLookup, AuthContext, AuthError, Caller, Clock, CredentialId,
    InMemoryChallengeStore, InMemoryLoginStateStore, LoginFinishRequest, LoginId, LoginPurpose,
    LoginStartRequest, LoginStartResponse, LoginVerified, ManualClock, Outcome, PreloginPolicy,
    PreloginSecret, ProfileRules, RecordingThrottle, RegisterStartRequest, RegistrationAuthority,
    RegistrationKind, ReplaceFields, ReplaceKind, ReplacePermit, ReplaceRequest, ServerKeys,
    SessionBinding, SessionScope, SignedAccount, Stage, StateSealKey, StoredRecord, ThrottleCall,
    authorize_replacement, issue_challenge, login_finish, login_start, normalize_login_name,
    register_finish, register_start, resolve_credential,
};

pub const URL: &str = "https://ferret.example";
pub const PASSWORD: &str = "correct horse battery staple";
pub const PASSWORD_2: &str = "tr0ub4dor and three more words";
pub const IP: &str = "192.0.2.7";
/// The time the clock of a new server starts at.
pub const START: u64 = 1_700_000_000;

/// The parameters of "profile 2" in the tests that need a second profile. The
/// client of the core knows profile 1 only, so these tests use the test
/// stretching function with other parameters to stand for it.
pub const PROFILE_2_PARAMS: KdfParams = KdfParams {
    m_kib: 64,
    t: 2,
    p: 1,
};

/// Which key stretching function the client runs.
#[derive(Clone, Copy)]
pub enum Ksf {
    /// The test function with small parameters: milliseconds.
    Small,
    /// The test function with other parameters.
    Params(KdfParams),
    /// Argon2id with the real parameters of profile 1 (64 MiB).
    Production,
}

impl Ksf {
    fn test(self) -> Option<TestKsf> {
        match self {
            Ksf::Small => Some(TestKsf::new(SMALL)),
            Ksf::Params(params) => Some(TestKsf::new(params)),
            Ksf::Production => None,
        }
    }
}

/// A session binding of 32 equal bytes.
pub fn session(fill: u8) -> SessionBinding {
    SessionBinding([fill; 32])
}

pub fn caller() -> Caller {
    Caller {
        ip: Some(IP.parse().unwrap()),
    }
}

/// The OPAQUE input of a password that is created or changed.
pub fn new_input(text: &str) -> OpaqueInput {
    MasterPassword::new(text.as_bytes(), MpPolicy::WithoutSecretKey)
        .unwrap()
        .opaque_input(None)
}

/// The OPAQUE input of a password that is typed to unlock.
pub fn unlock_input(text: &str) -> OpaqueInput {
    MasterPassword::for_unlock(text.as_bytes())
        .unwrap()
        .opaque_input(None)
}

// ------------------------------------------------------------- the server

/// Everything a server holds between requests: its keys and secrets, a clock
/// the test sets, a throttle that remembers, the stores for login states and
/// nonces, and the rules for key stretching profiles.
pub struct Server {
    pub keys: ServerKeys,
    pub prelogin: PreloginSecret,
    pub seal: StateSealKey,
    pub clock: ManualClock,
    pub throttle: RecordingThrottle,
    pub policy: PreloginPolicy,
    pub profiles: ProfileRules,
    pub logins: InMemoryLoginStateStore,
    pub nonces: InMemoryChallengeStore,
    draws: AtomicU32,
}

impl Server {
    /// A server with the rules of the real client: profile 1 only.
    pub fn new() -> Self {
        Self::seeded("server", ProfileRules::ferret_v1())
    }

    /// A server whose keys come from `label`, with the given rules.
    pub fn seeded(label: &str, profiles: ProfileRules) -> Self {
        let keys =
            ServerKeys::generate(&mut TestRng::new(format!("{label} keys").as_bytes())).unwrap();
        let prelogin =
            PreloginSecret::generate(&mut TestRng::new(format!("{label} prelogin").as_bytes()));
        let seal = StateSealKey::derive(&prelogin).unwrap();
        Self {
            keys,
            prelogin,
            seal,
            clock: ManualClock::new(START),
            throttle: RecordingThrottle::new(),
            policy: PreloginPolicy::single(KsfProfile::P1),
            profiles,
            logins: InMemoryLoginStateStore::new(),
            nonces: InMemoryChallengeStore::new(),
            draws: AtomicU32::new(0),
        }
    }

    /// A server with profiles 1 and 2 and a floor of 1, for the upgrade and
    /// downgrade tests.
    pub fn with_two_profiles() -> Self {
        Self::seeded("server", ProfileRules::for_tests(&[1, 2], 1))
    }

    pub fn cx(&self) -> AuthContext<'_> {
        AuthContext::new(
            &self.keys,
            &self.prelogin,
            &self.seal,
            &self.clock,
            &self.throttle,
            &self.policy,
            &self.profiles,
        )
    }

    /// A random source of its own for each call, so no two requests draw the
    /// same bytes.
    pub fn rng(&self, what: &str) -> TestRng {
        let n = self.draws.fetch_add(1, Ordering::Relaxed);
        TestRng::new(format!("{what} {n}").as_bytes())
    }

    /// The throttle calls so far, as stage and outcome (`None` for an admit).
    pub fn stages(&self) -> Vec<(Stage, Option<Outcome>)> {
        self.throttle
            .calls()
            .into_iter()
            .map(|call| match call {
                ThrottleCall::Admit { stage, .. } => (stage, None),
                ThrottleCall::Record { stage, outcome, .. } => (stage, Some(outcome)),
            })
            .collect()
    }

    /// The throttle calls so far with the kinds of their keys, and nothing
    /// else: what must be equal for a known and an unknown name.
    pub fn shape(&self) -> Vec<String> {
        self.throttle
            .calls()
            .into_iter()
            .map(|call| match call {
                ThrottleCall::Admit { stage, keys, .. } => format!("admit {stage:?} {keys:?}"),
                ThrottleCall::Record {
                    stage,
                    keys,
                    outcome,
                    ..
                } => format!("record {stage:?} {keys:?} {outcome:?}"),
            })
            .collect()
    }

    // ------------------------------------------------------ registration

    /// `register_start` as an endpoint calls it: with the throttle, the clock,
    /// the scope of the session and the account that owns it.
    pub fn register_response(
        &self,
        authority: RegistrationAuthority,
        credential: &CredentialId,
        request: &[u8],
    ) -> Result<Vec<u8>, AuthError> {
        register_start(
            &self.keys,
            &self.throttle,
            self.clock.now_unix(),
            &RegisterStartRequest {
                caller: caller(),
                authority,
                credential: *credential,
                request,
            },
        )
    }

    /// The client registers `input` under `credential` against this server in
    /// a full session of that account: `opaque_register_start`, the
    /// library's `register_start`, then the client's finish with the key
    /// stretching function `ksf`.
    pub fn client_register(
        &self,
        credential: &CredentialId,
        input: &OpaqueInput,
        ksf: Ksf,
        seed: &str,
    ) -> RegistrationFinished {
        self.client_register_in(
            RegistrationAuthority::Session {
                scope: SessionScope::Full,
                account: *credential,
            },
            credential,
            input,
            ksf,
            seed,
        )
    }

    /// A new account registers by invitation: no session, and the id is the
    /// fresh one the server assigned.
    pub fn client_register_new(
        &self,
        credential: &CredentialId,
        input: &OpaqueInput,
        ksf: Ksf,
        seed: &str,
    ) -> RegistrationFinished {
        self.client_register_in(
            RegistrationAuthority::NewAccount,
            credential,
            input,
            ksf,
            seed,
        )
    }

    /// [`Server::client_register`] with the authority given.
    pub fn client_register_in(
        &self,
        authority: RegistrationAuthority,
        credential: &CredentialId,
        input: &OpaqueInput,
        ksf: Ksf,
        seed: &str,
    ) -> RegistrationFinished {
        let mut rng = TestRng::new(format!("client register {seed}").as_bytes());
        let (request, state) = opaque_register_start(&mut rng, input).unwrap();
        let response = self
            .register_response(authority, credential, &request)
            .unwrap();
        match ksf.test() {
            Some(test) => register_finish_with(&mut rng, state, input, &response, &test).unwrap(),
            None => {
                opaque_register_finish(&mut rng, state, input, &response, KsfProfile::P1).unwrap()
            }
        }
    }

    /// A new account, made the way a client makes it: the OPAQUE
    /// registration, `create_account`, and the library's `register_finish`
    /// for the record the server stores. `tag` makes the ids.
    pub fn create_account(&self, tag: u8, login_name: &str, password: &str, ksf: Ksf) -> Account {
        let account_id = AccountId::from_bytes([tag; 16]);
        let credential = CredentialId::from(&account_id);
        let input = new_input(password);
        let registration = self.client_register_new(&credential, &input, ksf, "account");
        let registration_export = export_key_bytes(&registration.export_key);
        let new = create_account(
            &mut TestRng::new(format!("account {tag}").as_bytes()),
            &NewAccountIds {
                account_id,
                vault_id: VaultId::from_bytes([tag ^ 0x80; 16]),
                password_method_id: MethodId::from_bytes([tag ^ 0x70; 16]),
                recovery_method_id: MethodId::from_bytes([tag ^ 0x71; 16]),
            },
            NewPassword {
                input: &input,
                registration,
                profile: KsfProfile::P1,
            },
            None,
        )
        .unwrap();
        let stored = register_finish(
            &new.registration_record,
            1,
            &self.profiles,
            RegistrationKind::NewAccount,
        )
        .unwrap();
        let row = TestAccountStore::new(
            SignedAccount {
                account_id,
                pk_a: AuthPublicKey::new(new.pk_a),
                pk_r: RecoveryPublicKey::new(new.pk_r),
                vk_epoch: 1,
                row_version: 1,
            },
            stored,
        );
        Account {
            account_id,
            credential,
            login_name: login_name.to_owned(),
            password: password.to_owned(),
            registration_export,
            new,
            row,
        }
    }

    // ------------------------------------------------------------- login

    /// `login_start` as an endpoint calls it: look the name up, resolve the
    /// credential id, hand the lookup to the library. Returns what the client
    /// needs to go on.
    pub fn begin(
        &self,
        target: &Target<'_>,
        password: &str,
        purpose: LoginPurpose,
    ) -> Result<Started, AuthError> {
        self.begin_with(
            target,
            password,
            purpose,
            (&mut self.rng("login client"), &mut self.rng("login server")),
        )
    }

    /// [`Server::begin`] with the random sources of the client and the server
    /// given.
    pub fn begin_with<C: SecureRng, S: SecureRng>(
        &self,
        target: &Target<'_>,
        password: &str,
        purpose: LoginPurpose,
        rngs: (&mut C, &mut S),
    ) -> Result<Started, AuthError> {
        // A re-authentication is asked for from a full session.
        let scope = matches!(purpose, LoginPurpose::Reauth { .. }).then_some(SessionScope::Full);
        self.begin_in(target, password, purpose, scope, rngs)
    }

    /// [`Server::begin_with`] with the scope of the session the request is
    /// made in given too.
    pub fn begin_in<C: SecureRng, S: SecureRng>(
        &self,
        target: &Target<'_>,
        password: &str,
        purpose: LoginPurpose,
        session_scope: Option<SessionScope>,
        (client_rng, server_rng): (&mut C, &mut S),
    ) -> Result<Started, AuthError> {
        let name = normalize_login_name(target.login_name()).unwrap();
        let credential = resolve_credential(&self.prelogin, &name, target.account_id().as_ref());
        let row = target.account().map(|a| a.row.read());
        let lookup = match (target, &row) {
            (Target::Active(_), Some(row)) => AccountLookup::Active {
                record: &row.record,
                sk_hint: false,
            },
            (Target::Disabled(_), _) => AccountLookup::Disabled,
            _ => AccountLookup::Unknown,
        };
        let input = unlock_input(password);
        let (ke1, state) = opaque_login_start(client_rng, &input).unwrap();
        let response = login_start(
            &self.cx(),
            &self.logins,
            server_rng,
            &LoginStartRequest {
                caller: caller(),
                name: &name,
                credential,
                lookup,
                purpose,
                session_scope,
                ke1: &ke1,
            },
        )?;
        Ok(Started {
            response,
            state,
            input,
        })
    }

    /// `login_finish` as an endpoint calls it.
    pub fn finish(
        &self,
        login_id: &LoginId,
        ke3: &[u8],
        current_session: Option<(SessionBinding, CredentialId)>,
    ) -> Result<LoginVerified, AuthError> {
        login_finish(
            &self.cx(),
            &self.logins,
            &LoginFinishRequest {
                caller: caller(),
                login_id: login_id.to_hex().as_bytes(),
                ke3,
                current_session,
            },
        )
    }

    /// A whole login: start, the client's answer, finish.
    pub fn login(
        &self,
        target: &Target<'_>,
        password: &str,
        ksf: Ksf,
        purpose: LoginPurpose,
        current_session: Option<(SessionBinding, CredentialId)>,
    ) -> Result<LoginDone, LoginFailure> {
        let started = self
            .begin(target, password, purpose)
            .map_err(LoginFailure::Start)?;
        let (login_id, answer) = started.client_answer(ksf);
        let answer = answer.map_err(LoginFailure::Client)?;
        let verified = self
            .finish(&login_id, &answer.ke3, current_session)
            .map_err(LoginFailure::Finish)?;
        Ok(LoginDone {
            export: export_key_bytes(&answer.export_key),
            server_key: answer.server_public_key,
            verified,
        })
    }

    // -------------------------------------------------- signed requests

    /// A nonce for `session`, issued the way an endpoint does it.
    pub fn challenge(
        &self,
        scope: SessionScope,
        session: &SessionBinding,
        account: &AccountId,
    ) -> Result<[u8; 32], AuthError> {
        issue_challenge(
            &self.cx(),
            &self.nonces,
            &mut self.rng("nonce"),
            &caller(),
            scope,
            session,
            account,
        )
        .map(|c| c.nonce)
    }

    /// The client's change of password to `text` (profile 1, test function).
    pub fn password_change(&self, account: &Account, text: &str, seed: &str) -> PasswordChange {
        let input = new_input(text);
        let registration = self.client_register(&account.credential, &input, Ksf::Small, seed);
        let a = &account.new;
        change_password(
            &mut self.rng("change"),
            &a.vault,
            NewPassword {
                input: &input,
                registration,
                profile: KsfProfile::P1,
            },
            &a.pinned(URL).unwrap(),
            &a.wraps[0],
            &ManifestRow {
                rev: a.manifest.rev,
                envelope: &a.manifest.envelope,
                tag: &a.manifest.tag,
            },
        )
        .unwrap()
    }

    /// The client's recovery to `text`, from the recovery key of the account.
    /// `ksf` is the function that makes the new record.
    pub fn recovered(&self, account: &Account, text: &str, ksf: Ksf, seed: &str) -> Recovered {
        let input = new_input(text);
        let registration = self.client_register_in(
            RegistrationAuthority::Session {
                scope: SessionScope::AccountReset,
                account: account.credential,
            },
            &account.credential,
            &input,
            ksf,
            seed,
        );
        self.recovered_with(account, &input, registration, PinState::FirstUse)
    }

    /// The client's recovery with a registration it already made, and the pin
    /// state of the device.
    pub fn recovered_with(
        &self,
        account: &Account,
        input: &OpaqueInput,
        registration: RegistrationFinished,
        pin: PinState<'_>,
    ) -> Recovered {
        self.try_recovered(account, input, registration, pin)
            .unwrap()
    }

    pub fn try_recovered(
        &self,
        account: &Account,
        input: &OpaqueInput,
        registration: RegistrationFinished,
        pin: PinState<'_>,
    ) -> Result<Recovered, Error> {
        let a = &account.new;
        let code = encode_recovery_key(&a.recovery_key).to_string();
        recover(
            &mut self.rng("recover"),
            &RecoveryInput {
                ctx: a.vault.context(),
                rk_code: &code,
                rk_wrap: &a.wraps[1],
                manifest: ManifestRow {
                    rev: a.manifest.rev,
                    envelope: &a.manifest.envelope,
                    tag: &a.manifest.tag,
                },
                new_recovery_method_id: MethodId::from_bytes([0x73; 16]),
            },
            NewPassword {
                input,
                registration,
                profile: KsfProfile::P1,
            },
            pin,
        )
    }

    /// `authorize_replacement` against the row as the store holds it now.
    pub fn replace(&self, account: &Account, req: &Req) -> Result<ReplacePermit, AuthError> {
        self.replace_raw(account, &req.as_request())
    }

    /// The same for a request the test has changed after the fact.
    pub fn replace_raw(
        &self,
        account: &Account,
        req: &ReplaceRequest<'_>,
    ) -> Result<ReplacePermit, AuthError> {
        let row = account.row.read();
        authorize_replacement(
            &self.cx(),
            &self.nonces,
            &AccountAuthState {
                account: row.account,
                current: &row.record,
            },
            req,
            parse_for(req.kind),
        )
    }

    /// A signed password change: a nonce for `session`, the body, the proof.
    pub fn put_req(
        &self,
        account: &Account,
        change: &PasswordChange,
        claimed_profile: u32,
        session: SessionBinding,
    ) -> Req {
        let nonce = self
            .challenge(SessionScope::Full, &session, &account.account_id)
            .unwrap();
        let body = put_body(claimed_profile, &change.registration_record);
        let proof = change.sign(&account.new.vault, &nonce, &body).unwrap();
        Req {
            kind: ReplaceKind::PasswordPut,
            scope: SessionScope::Full,
            session,
            nonce,
            proof,
            body,
        }
    }

    /// A signed recovery in a reset session.
    pub fn recover_req(
        &self,
        account: &Account,
        rec: &Recovered,
        claimed_profile: u32,
        session: SessionBinding,
    ) -> Req {
        let nonce = self
            .challenge(SessionScope::AccountReset, &session, &account.account_id)
            .unwrap();
        let body = recover_body(claimed_profile, &rec.pk_r, &rec.registration_record);
        let proof = rec.sign(&nonce, &body).unwrap();
        Req {
            kind: ReplaceKind::Recover,
            scope: SessionScope::AccountReset,
            session,
            nonce,
            proof,
            body,
        }
    }
}

// ------------------------------------------------------------- accounts

/// An account as the client made it and as the server stores it.
pub struct Account {
    pub account_id: AccountId,
    pub credential: CredentialId,
    pub login_name: String,
    pub password: String,
    /// The export key of the registration.
    pub registration_export: [u8; 64],
    /// What the client holds: vault, wraps, keys.
    pub new: NewAccount,
    /// What the server holds: the record and the keys it checks proofs with.
    pub row: TestAccountStore,
}

/// What a lookup of a login name found.
pub enum Target<'a> {
    Active(&'a Account),
    Disabled(&'a Account),
    /// A name nobody has.
    Unknown(&'a str),
}

impl Target<'_> {
    fn account(&self) -> Option<&Account> {
        match self {
            Target::Active(a) | Target::Disabled(a) => Some(a),
            Target::Unknown(_) => None,
        }
    }

    fn account_id(&self) -> Option<AccountId> {
        self.account().map(|a| a.account_id)
    }

    fn login_name(&self) -> &str {
        match self {
            Target::Active(a) | Target::Disabled(a) => &a.login_name,
            Target::Unknown(name) => name,
        }
    }
}

// ---------------------------------------------------------- login steps

/// A login after `login_start`: the server's answer and the client's state.
pub struct Started {
    pub response: LoginStartResponse,
    state: ferret_core::LoginState,
    input: OpaqueInput,
}

/// What the client sends after KE2: KE3 and the keys it saw.
pub struct ClientAnswer {
    pub ke3: Vec<u8>,
    pub export_key: ferret_core::ExportKey,
    pub server_public_key: [u8; 32],
}

impl Started {
    /// The client's last step. The profile is the one the server stated.
    pub fn client_answer(self, ksf: Ksf) -> (LoginId, Result<ClientAnswer, Error>) {
        let Started {
            response,
            state,
            input,
        } = self;
        let mut rng = TestRng::new(b"client login finish");
        let answer = match ksf.test() {
            Some(test) => login_finish_with(
                &mut rng,
                state,
                &input,
                &response.ke2,
                &test,
                Some(OPAQUE_CONTEXT),
                PinState::FirstUse,
            )
            .map(|done| done.finished),
            None => opaque_login_finish(
                &mut rng,
                state,
                &input,
                &response.ke2,
                u32::from(response.ksf_profile),
                PinState::FirstUse,
            ),
        };
        (
            response.login_id,
            answer.map(|done| ClientAnswer {
                ke3: done.ke3,
                export_key: done.export_key,
                server_public_key: done.server_public_key,
            }),
        )
    }
}

/// A login that went through on both sides.
pub struct LoginDone {
    /// The export key the client got from the login.
    pub export: [u8; 64],
    /// The server key the login showed.
    pub server_key: [u8; 32],
    pub verified: LoginVerified,
}

/// Where a login stopped.
#[derive(Debug)]
pub enum LoginFailure {
    /// `login_start` refused.
    Start(AuthError),
    /// The client could not finish (a wrong password is `Decrypt`).
    Client(Error),
    /// `login_finish` refused.
    Finish(AuthError),
}

// ------------------------------------------------------ signed requests

/// A request to `authorize_replacement`, with owned bytes.
#[derive(Clone)]
pub struct Req {
    pub kind: ReplaceKind,
    pub scope: SessionScope,
    pub session: SessionBinding,
    pub nonce: [u8; 32],
    pub proof: [u8; 64],
    pub body: Vec<u8>,
}

impl Req {
    pub fn as_request(&self) -> ReplaceRequest<'_> {
        ReplaceRequest {
            caller: caller(),
            kind: self.kind,
            scope: self.scope,
            session: self.session,
            nonce: &self.nonce,
            proof: &self.proof,
            body: &self.body,
        }
    }
}

/// The body of a password change: the claimed profile, then the record.
pub fn put_body(profile: u32, record: &[u8]) -> Vec<u8> {
    let mut body = profile.to_be_bytes().to_vec();
    body.extend_from_slice(record);
    body
}

/// The body of a recovery: the claimed profile, the new `pk_r`, the record.
pub fn recover_body(profile: u32, pk_r: &[u8; 32], record: &[u8]) -> Vec<u8> {
    let mut body = profile.to_be_bytes().to_vec();
    body.extend_from_slice(pk_r);
    body.extend_from_slice(record);
    body
}

fn too_short() -> AuthError {
    AuthError::Malformed(ferret_server_auth::Malformed::RegistrationRecord)
}

fn parse_put(body: &[u8]) -> Result<ReplaceFields, AuthError> {
    let (profile, record) = body.split_first_chunk::<4>().ok_or_else(too_short)?;
    Ok(ReplaceFields {
        record: record.to_vec(),
        ksf_profile: u32::from_be_bytes(*profile),
        pk_r_new: None,
    })
}

fn parse_recover(body: &[u8]) -> Result<ReplaceFields, AuthError> {
    let (profile, rest) = body.split_first_chunk::<4>().ok_or_else(too_short)?;
    let (key, record) = rest.split_first_chunk::<32>().ok_or_else(too_short)?;
    Ok(ReplaceFields {
        record: record.to_vec(),
        ksf_profile: u32::from_be_bytes(*profile),
        pk_r_new: Some(RecoveryPublicKey::new(*key)),
    })
}

type Parser = fn(&[u8]) -> Result<ReplaceFields, AuthError>;

fn parse_for(kind: ReplaceKind) -> Parser {
    match kind {
        ReplaceKind::PasswordPut => parse_put,
        ReplaceKind::Recover => parse_recover,
    }
}

/// The stored record of an account now.
pub fn stored(account: &Account) -> StoredRecord {
    account.row.read().record
}
