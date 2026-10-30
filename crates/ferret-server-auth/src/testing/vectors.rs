//! Runs the `server.*` operations of `vectors/OPS.md`: the cases of
//! `vectors/internal/server-opaque.json` and `server-secrets.json`.
//!
//! The same function runs a case for the generator (`tools/vectorgen`, which
//! records the answer of the server for the operations that need OPAQUE
//! messages) and for the test of this crate (`tests/vectors.rs`). It adds no
//! logic of its own: every operation builds the arguments of a public
//! function of the crate (or, for the made-up record and the sealed state,
//! of the crate-internal function behind it) from the `input` of the case
//! and writes down what it returns.
//!
//! The helpers at the end ([`rfc_register_response`], [`login_start_with_identifier`] and
//! [`peek_server_login`]) are for the test against the published vectors of
//! RFC 9807, whose credential identifier has 4 bytes.

use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ferret_core::testing::vector::Case;
use ferret_core::testing::{ReplayRng, TestRng, hex_decode, hex_encode};
use ferret_core::{AccountId, AuthPublicKey, RecoveryPublicKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::state::{StatePlain, open_state, seal_state};
use crate::{
    AccountAuthState, AccountLookup, AuthContext, AuthError, Caller, CredentialId, FileKind,
    InMemoryChallengeStore, InMemoryLoginStateStore, LoginFinishRequest, LoginId, LoginPurpose,
    LoginStartRequest, LoginStateStore, ManualClock, PreloginPolicy, PreloginSecret, ProfileRules,
    RecordingThrottle, RegisterStartRequest, RegistrationAuthority, ReplaceFields, ReplaceKind,
    ReplaceRequest, RetryAfter, SealedState, ServerKeys, SessionBinding, SessionScope,
    SignedAccount, StateSealKey, StoredRecord, ValidatedRecord, authorize_replacement,
    decode_secret_file, encode_secret_file, login_finish, login_start, normalize_login_name,
    register_start,
};
use crate::{fake_credential_id, fake_prelogin};

/// The answer of an operation: the `expect` value, or the error code.
pub type Outcome = Result<Value, String>;

/// Runs one case of the server vector files. The draws of the case are
/// replayed, and a case that leaves a draw unused or asks for one more than it
/// lists fails (as an error that is not a code of the register).
pub fn run_case(case: &Case) -> Outcome {
    let mut draws = Vec::new();
    for draw in &case.rng {
        draws.push(hex_decode(draw).map_err(|_| "bad_rng_hex".to_string())?);
    }
    let mut rng = ReplayRng::new(draws);
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        dispatch(&case.op, &case.input, &mut rng)
    }))
    .unwrap_or_else(|_| Err("panic".to_string()));
    if rng.finish().is_err() {
        return Err("rng_not_used_up".to_string());
    }
    outcome
}

fn dispatch(op: &str, input: &Value, rng: &mut ReplayRng) -> Outcome {
    match op {
        "server.register_response" => register_response(input),
        "server.setup_fingerprint" => setup_fingerprint(input),
        "server.secret_file.encode" => secret_file_encode(input),
        "server.secret_file.decode" => secret_file_decode(input),
        "server.fake_credential_id" => fake_id(input),
        "server.fake_prelogin" => fake_prelogin_answer(input),
        "server.fake_record" => fake_record(input),
        "server.challenge_key" => challenge_key(input),
        "server.state_seal" => state_seal(input, rng),
        "server.state_open" => state_open(input),
        "server.login_start" => login_start_op(input, rng),
        "server.login_finish" => login_finish_op(input),
        "server.replace_authorize" => replace_authorize(input),
        other => Err(format!("unknown_op {other}")),
    }
}

// ---------------------------------------------------------------- inputs

fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, String> {
    v.get(key).ok_or_else(|| format!("missing input {key}"))
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    field(v, key)?
        .as_str()
        .ok_or_else(|| format!("input {key} is not text"))
}

fn bytes(v: &Value, key: &str) -> Result<Vec<u8>, String> {
    hex_decode(text(v, key)?).map_err(|_| format!("input {key} is not hex"))
}

fn array<const N: usize>(v: &Value, key: &str) -> Result<[u8; N], String> {
    bytes(v, key)?
        .try_into()
        .map_err(|_| format!("input {key} is not {N} bytes"))
}

fn number(v: &Value, key: &str) -> Result<u64, String> {
    text(v, key)?
        .parse()
        .map_err(|_| format!("input {key} is not a number"))
}

fn small(v: &Value, key: &str) -> Result<u64, String> {
    field(v, key)?
        .as_u64()
        .ok_or_else(|| format!("input {key} is not a number"))
}

fn flag(v: &Value, key: &str) -> Result<bool, String> {
    field(v, key)?
        .as_bool()
        .ok_or_else(|| format!("input {key} is not true or false"))
}

fn code(error: AuthError) -> String {
    error.public_code().to_string()
}

fn keys_of(v: &Value) -> Result<ServerKeys, String> {
    ServerKeys::from_payload(&bytes(v, "setup_hex")?).map_err(|_| "setup_invalid".to_string())
}

fn secret_of(v: &Value) -> Result<PreloginSecret, String> {
    PreloginSecret::from_payload(&bytes(v, "prelogin_secret")?)
        .map_err(|_| "prelogin_secret_invalid".to_string())
}

fn name_of(v: &Value) -> Result<crate::NormalizedLoginName, String> {
    normalize_login_name(text(v, "name")?).map_err(code)
}

fn credential_of(v: &Value, key: &str) -> Result<CredentialId, String> {
    Ok(CredentialId::from_bytes(array::<16>(v, key)?))
}

fn policy_of(v: &Value) -> Result<PreloginPolicy, String> {
    let policy = field(v, "policy")?;
    let mut shares = Vec::new();
    for pair in field(policy, "profiles")?
        .as_array()
        .ok_or("policy profiles is not a list")?
    {
        let profile = pair[0].as_u64().ok_or("bad profile")?;
        let share = pair[1].as_u64().ok_or("bad share")?;
        shares.push((
            u8::try_from(profile).map_err(|_| "bad profile")?,
            u16::try_from(share).map_err(|_| "bad share")?,
        ));
    }
    let hint = u16::try_from(small(policy, "sk_true_permille")?).map_err(|_| "bad hint share")?;
    // The profiles of a vector may be longer than the table of the client.
    PreloginPolicy::for_tests(&shares, hint).map_err(code)
}

fn purpose_of(v: &Value) -> Result<LoginPurpose, String> {
    match text(v, "type")? {
        "login" => Ok(LoginPurpose::Login),
        "reauth" => Ok(LoginPurpose::Reauth {
            session: SessionBinding(array::<32>(v, "session")?),
            account: credential_of(v, "account")?,
        }),
        other => Err(format!("unknown purpose {other}")),
    }
}

fn purpose_json(purpose: &LoginPurpose) -> Value {
    match purpose {
        LoginPurpose::Login => json!({ "type": "login" }),
        LoginPurpose::Reauth { session, account } => json!({
            "type": "reauth",
            "session": hex_encode(&session.0),
            "account": hex_encode(account.as_bytes()),
        }),
    }
}

fn kind_of(v: &Value) -> Result<FileKind, String> {
    match text(v, "kind")? {
        "opaque_setup" => Ok(FileKind::OpaqueSetup),
        "prelogin_secret" => Ok(FileKind::PreloginSecret),
        other => Err(format!("unknown file kind {other}")),
    }
}

/// A throttle that admits everyone, or refuses everyone for the given
/// seconds when the input has `throttle_wait_secs`.
fn throttle_of(v: &Value) -> Result<RecordingThrottle, String> {
    match v.get("throttle_wait_secs") {
        None => Ok(RecordingThrottle::new()),
        Some(secs) => {
            let secs = secs
                .as_u64()
                .and_then(|s| u32::try_from(s).ok())
                .ok_or("throttle_wait_secs is not a number")?;
            Ok(RecordingThrottle::refusing(RetryAfter::new(secs)))
        }
    }
}

fn named_scope(name: Option<&str>) -> Result<SessionScope, String> {
    match name {
        None | Some("full") => Ok(SessionScope::Full),
        Some("pending_2fa") => Ok(SessionScope::Pending2fa),
        Some("account_reset") => Ok(SessionScope::AccountReset),
        Some("unverified") => Ok(SessionScope::Unverified),
        Some(other) => Err(format!("unknown scope {other}")),
    }
}

/// The `scope` of a signed request; a full session when it is not given.
fn scope_of(v: &Value) -> Result<SessionScope, String> {
    named_scope(v.get("scope").and_then(Value::as_str))
}

/// The `session_scope` of a login start: `None` when it is not given.
fn session_scope_of(v: &Value) -> Result<Option<SessionScope>, String> {
    v.get("session_scope")
        .and_then(Value::as_str)
        .map(|name| named_scope(Some(name)))
        .transpose()
}

fn caller() -> Caller {
    Caller {
        ip: Some(IpAddr::from([192, 0, 2, 7])),
    }
}

// ------------------------------------------------------------ the secrets

fn setup_fingerprint(input: &Value) -> Outcome {
    let keys = keys_of(input)?;
    Ok(json!({ "fingerprint": hex_encode(&keys.fingerprint().0) }))
}

fn file_error(error: crate::SecretFileError) -> String {
    use crate::SecretFileError as E;
    match error {
        E::BadMagic => "bad_magic",
        E::UnsupportedVersion(_) => "unsupported_version",
        E::WrongKind => "wrong_kind",
        E::UnsupportedSuite(_) => "unsupported_suite",
        E::BadLength => "bad_length",
        E::BadChecksum => "bad_checksum",
        E::TrailingBytes => "trailing_bytes",
        _ => "internal",
    }
    .to_string()
}

fn secret_file_encode(input: &Value) -> Outcome {
    let file =
        encode_secret_file(kind_of(input)?, &bytes(input, "payload")?).map_err(file_error)?;
    Ok(json!({ "file": hex_encode(&file) }))
}

fn secret_file_decode(input: &Value) -> Outcome {
    let payload =
        decode_secret_file(kind_of(input)?, &bytes(input, "file")?).map_err(file_error)?;
    Ok(json!({ "payload": hex_encode(&payload) }))
}

// --------------------------------------------------------- made-up answers

fn fake_id(input: &Value) -> Outcome {
    let id = fake_credential_id(&secret_of(input)?, &name_of(input)?);
    Ok(json!({ "credential_id": hex_encode(id.as_bytes()) }))
}

fn fake_prelogin_answer(input: &Value) -> Outcome {
    let policy = policy_of(input)?;
    let answer = fake_prelogin(&secret_of(input)?, &name_of(input)?, &policy);
    Ok(json!({ "ksf_profile": answer.ksf_profile, "sk_hint": answer.sk_hint }))
}

fn fake_record(input: &Value) -> Outcome {
    let record = crate::prelogin::fake_record_bytes(
        &keys_of(input)?,
        &secret_of(input)?,
        &credential_of(input, "credential_id")?,
    );
    Ok(json!({ "record": hex_encode(record.as_slice()) }))
}

// ------------------------------------------------------------ registration

fn register_response(input: &Value) -> Outcome {
    let authority = match input.get("authority") {
        None | Some(Value::Null) => RegistrationAuthority::NewAccount,
        Some(session) if text(session, "type")? == "session" => RegistrationAuthority::Session {
            scope: named_scope(Some(text(session, "scope")?))?,
            account: credential_of(session, "account")?,
        },
        Some(_) => return Err("unknown authority".to_string()),
    };
    let request = bytes(input, "request")?;
    let response = register_start(
        &keys_of(input)?,
        &throttle_of(input)?,
        number(input, "now")?,
        &RegisterStartRequest {
            caller: caller(),
            authority,
            credential: credential_of(input, "credential_id")?,
            request: &request,
        },
    )
    .map_err(code)?;
    Ok(json!({ "response": hex_encode(&response) }))
}

// ------------------------------------------------------------ challenges

fn challenge_key(input: &Value) -> Outcome {
    let session = SessionBinding(array::<32>(input, "session")?);
    let key = crate::ChallengeKey::new(&session, &array::<32>(input, "nonce")?);
    Ok(json!({ "key": hex_encode(key.as_bytes()) }))
}

// ------------------------------------------------------------- the state

fn login_id_of(v: &Value) -> Result<LoginId, String> {
    LoginId::parse(text(v, "login_id")?.as_bytes()).map_err(code)
}

fn state_json(state: &StatePlain) -> Value {
    json!({
        "expires_at": state.expires_at.to_string(),
        "purpose": purpose_json(&state.purpose),
        "credential": hex_encode(state.credential.as_bytes()),
        "ksf_profile": state.ksf_profile,
        "server_login": hex_encode(state.server_login.as_slice()),
    })
}

fn state_seal(input: &Value, rng: &mut ReplayRng) -> Outcome {
    let key = StateSealKey::derive(&secret_of(input)?).map_err(code)?;
    let plain = field(input, "state")?;
    let state = StatePlain {
        credential: credential_of(plain, "credential")?,
        purpose: purpose_of(field(plain, "purpose")?)?,
        expires_at: number(plain, "expires_at")?,
        ksf_profile: u8::try_from(small(plain, "ksf_profile")?)
            .map_err(|_| "ksf_profile is not a byte")?,
        server_login: Zeroizing::new(array::<128>(plain, "server_login")?),
    };
    let sealed = seal_state(
        &key,
        rng,
        &login_id_of(input)?,
        &state,
        number(input, "now")?,
    )
    .map_err(code)?;
    Ok(json!({ "blob": hex_encode(sealed.as_bytes()) }))
}

fn state_open(input: &Value) -> Outcome {
    let key = StateSealKey::derive(&secret_of(input)?).map_err(code)?;
    let sealed = SealedState::from_bytes(bytes(input, "blob")?);
    let expected = purpose_of(field(input, "expected")?)?;
    let state = open_state(
        &key,
        &login_id_of(input)?,
        &sealed,
        &expected,
        number(input, "now")?,
    )
    .map_err(code)?;
    Ok(json!({ "state": state_json(&state) }))
}

// ----------------------------------------------------------------- login

/// The server of a case: its keys and secrets, a clock, a throttle that admits
/// everyone, the made-up pre-login policy and an empty store.
struct Env {
    keys: ServerKeys,
    prelogin: PreloginSecret,
    seal: StateSealKey,
    clock: ManualClock,
    throttle: RecordingThrottle,
    policy: PreloginPolicy,
    profiles: ProfileRules,
    store: InMemoryLoginStateStore,
    now: u64,
}

impl core::fmt::Debug for Env {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Env([redacted])")
    }
}

impl Env {
    fn new(input: &Value) -> Result<Self, String> {
        let prelogin = secret_of(input)?;
        let now = number(input, "now")?;
        let policy = if input.get("policy").is_some() {
            policy_of(input)?
        } else {
            PreloginPolicy::single(
                ferret_core::KsfProfile::from_wire(1).map_err(|_| "no profile 1")?,
            )
        };
        Ok(Self {
            keys: keys_of(input)?,
            seal: StateSealKey::derive(&prelogin).map_err(code)?,
            prelogin,
            clock: ManualClock::new(now),
            throttle: throttle_of(input)?,
            policy,
            profiles: ProfileRules::ferret_v1(),
            store: InMemoryLoginStateStore::new(),
            now,
        })
    }

    fn cx(&self) -> AuthContext<'_> {
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
}

fn login_start_op(input: &Value, rng: &mut ReplayRng) -> Outcome {
    let env = Env::new(input)?;
    let name = name_of(input)?;
    let stored = match text(input, "lookup")? {
        "known" => Some(StoredRecord {
            record: ValidatedRecord::parse(&bytes(input, "record")?).map_err(code)?,
            ksf_profile: u8::try_from(small(input, "stored_ksf_profile")?)
                .map_err(|_| "stored_ksf_profile is not a byte")?,
        }),
        "unknown" | "disabled" => None,
        other => return Err(format!("unknown lookup {other}")),
    };
    let lookup = match (&stored, text(input, "lookup")?) {
        (Some(record), _) => AccountLookup::Active {
            record,
            sk_hint: flag(input, "sk_hint")?,
        },
        (None, "disabled") => AccountLookup::Disabled,
        (None, _) => AccountLookup::Unknown,
    };
    let ke1 = bytes(input, "ke1")?;
    let request = LoginStartRequest {
        caller: caller(),
        name: &name,
        credential: credential_of(input, "credential_id")?,
        lookup,
        purpose: purpose_of(field(input, "purpose")?)?,
        session_scope: session_scope_of(input)?,
        ke1: &ke1,
    };
    let response = login_start(&env.cx(), &env.store, rng, &request).map_err(code)?;
    let blob = super::take_state(&env.store, &response.login_id, env.now);
    Ok(json!({
        "login_id": response.login_id.to_hex(),
        "ke2": hex_encode(&response.ke2),
        "ksf_profile": response.ksf_profile,
        "sk_hint": response.sk_hint,
        "state_blob": hex_encode(blob.as_bytes()),
    }))
}

fn login_finish_op(input: &Value) -> Outcome {
    let env = Env::new(input)?;
    let login_id = text(input, "login_id")?;
    if let Some(blob) = input.get("state_blob").and_then(Value::as_str)
        && let Ok(id) = LoginId::parse(login_id.as_bytes())
    {
        let blob = hex_decode(blob).map_err(|_| "state_blob is not hex")?;
        super::put_state(&env.store, &id, SealedState::from_bytes(blob), env.now);
    }
    let current_session = match input.get("current_session") {
        Some(Value::Null) | None => None,
        Some(session) => Some((
            SessionBinding(array::<32>(session, "session")?),
            credential_of(session, "account")?,
        )),
    };
    let ke3 = bytes(input, "ke3")?;
    let verified = login_finish(
        &env.cx(),
        &env.store,
        &LoginFinishRequest {
            caller: caller(),
            login_id: login_id.as_bytes(),
            ke3: &ke3,
            current_session,
        },
    )
    .map_err(code)?;
    Ok(json!({
        "credential_id": hex_encode(verified.credential.as_bytes()),
        "purpose": purpose_json(&verified.purpose),
    }))
}

// ---------------------------------------------------------- replacement

/// The reference parser of the replacement body, for the vectors and the fuzz
/// target; the endpoint has its own. It reads a password change or a recovery: the body is
/// the JSON the client sent, and the fields are
/// `{ "registration_record": hex, "ksf_profile": number, "pk_r_new": hex }`.
/// Other fields (the wraps, the manifest) are the endpoint's business and are
/// ignored here. `pk_r_new` is there for a recovery only. Public so the fuzz
/// target of the replacement can run it on a body that carries a valid proof.
pub fn parse_body(body: &[u8]) -> Result<ReplaceFields, AuthError> {
    let bad = AuthError::Malformed(crate::Malformed::RegistrationRecord);
    let json: Value = serde_json::from_slice(body).map_err(|_| bad)?;
    let record = json
        .get("registration_record")
        .and_then(Value::as_str)
        .and_then(|text| hex_decode(text).ok())
        .ok_or(bad)?;
    let ksf_profile = json
        .get("ksf_profile")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(bad)?;
    let pk_r_new = match json.get("pk_r_new") {
        None | Some(Value::Null) => None,
        Some(key) => key
            .as_str()
            .and_then(|text| hex_decode(text).ok())
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .map(RecoveryPublicKey::new)
            .ok_or(AuthError::Malformed(crate::Malformed::RecoveryKey))
            .map(Some)?,
    };
    Ok(ReplaceFields {
        record,
        ksf_profile,
        pk_r_new,
    })
}

fn replace_authorize(input: &Value) -> Outcome {
    let kind = match text(input, "kind")? {
        "password_put" => ReplaceKind::PasswordPut,
        "recover" => ReplaceKind::Recover,
        other => return Err(format!("unknown kind {other}")),
    };
    let account = field(input, "account")?;
    let signed = SignedAccount {
        account_id: AccountId::from_bytes(array::<16>(account, "account_id")?),
        pk_a: AuthPublicKey::new(array::<32>(account, "pk_a")?),
        pk_r: RecoveryPublicKey::new(array::<32>(account, "pk_r")?),
        vk_epoch: number(account, "vk_epoch")?,
        row_version: number(account, "row_version")?,
    };
    let current = field(input, "current")?;
    let current = StoredRecord {
        record: ValidatedRecord::parse(&bytes(current, "record")?).map_err(code)?,
        ksf_profile: u8::try_from(small(current, "ksf_profile")?)
            .map_err(|_| "current ksf_profile is not a byte")?,
    };
    let session = SessionBinding(array::<32>(input, "session")?);
    // The nonce and the proof may have the wrong length: the library refuses
    // them, and a vector can say so.
    let nonce = bytes(input, "nonce")?;
    let now = number(input, "now")?;

    let prelogin = PreloginSecret::generate(&mut TestRng::new(b"replace vectors"));
    let env = Env {
        keys: ServerKeys::generate(&mut TestRng::new(b"replace vectors"))
            .map_err(|_| "keys".to_string())?,
        seal: StateSealKey::derive(&prelogin).map_err(code)?,
        prelogin,
        clock: ManualClock::new(now),
        throttle: throttle_of(input)?,
        policy: PreloginPolicy::single(
            ferret_core::KsfProfile::from_wire(1).map_err(|_| "no profile 1")?,
        ),
        profiles: ProfileRules::ferret_v1(),
        store: InMemoryLoginStateStore::new(),
        now,
    };
    let challenges = InMemoryChallengeStore::new();
    if flag(input, "nonce_issued")?
        && let Ok(issued) = <[u8; 32]>::try_from(nonce.as_slice())
    {
        super::put_nonce(&challenges, &session, &issued, now);
    }
    let proof = bytes(input, "proof")?;
    let body = bytes(input, "body")?;
    let permit = authorize_replacement(
        &env.cx(),
        &challenges,
        &AccountAuthState {
            account: signed,
            current: &current,
        },
        &ReplaceRequest {
            caller: caller(),
            kind,
            scope: scope_of(input)?,
            session,
            nonce: &nonce,
            proof: &proof,
            body: &body,
        },
        parse_body,
    )
    .map_err(code)?;
    Ok(json!({
        "permit": {
            "kind": text(input, "kind")?,
            "account_id": hex_encode(permit.account_id.as_bytes()),
            "record": hex_encode(permit.new.record.as_bytes()),
            "ksf_profile": permit.new.ksf_profile,
            "new_pk_r": permit.new_pk_r.map(|key| hex_encode(key.as_bytes())),
            "body_sha256": hex_encode(&permit.body_sha256),
            "stored_ksf_profile": permit.stored_ksf_profile,
        }
    }))
}

// ------------------------------------------------- the test of RFC 9807

/// `register_start` for any credential identifier. The server always passes
/// the 16 bytes of a credential id; the vectors of RFC 9807 use 4 bytes.
pub fn rfc_register_response(
    keys: &ServerKeys,
    identifier: &[u8],
    request: &[u8],
) -> Result<Vec<u8>, AuthError> {
    crate::registration::start_for_identifier(keys, identifier, request)
}

/// `login_start` with another OPAQUE context, other identities and another
/// credential identifier than Ferret's: the configuration of the published
/// vectors of RFC 9807. The code that runs is `login_start`.
pub fn login_start_with_identifier<R: ferret_core::SecureRng, S: LoginStateStore>(
    cx: &AuthContext<'_>,
    store: &S,
    rng: &mut R,
    req: &LoginStartRequest<'_>,
    context: &[u8],
    identities: Option<(&[u8], &[u8])>,
    identifier: &[u8],
) -> Result<crate::LoginStartResponse, AuthError> {
    let params = crate::login::Params {
        context,
        client_identity: identities.map(|(client, _)| client),
        server_identity: identities.map(|(_, server)| server),
        credential_identifier: Some(identifier),
    };
    crate::login::start_with(cx, store, rng, req, &params)
}

/// The 128 bytes of `ServerLogin` of a login that has been started: the
/// session key (64) and the MAC the server expects in `KE3` (64). The state
/// is taken out of the store, opened, and put back, so `login_finish` can
/// still use it. The public API never gives these bytes out; this is the one
/// way a test can compare the session key with a published value.
pub fn peek_server_login<S: LoginStateStore>(
    seal: &StateSealKey,
    store: &S,
    id: &LoginId,
    now: u64,
) -> Result<Zeroizing<[u8; 128]>, AuthError> {
    let sealed = super::take_state(store, id, now);
    let opened = open_state(seal, id, &sealed, &LoginPurpose::Login, now);
    super::put_state(store, id, sealed, now);
    opened.map(|state| state.server_login.clone())
}
