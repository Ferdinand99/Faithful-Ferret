//! The vector groups for the server half of the login (`server-opaque.json`
//! and `server-secrets.json`).
//!
//! Two kinds of expected value are in these files, and the difference matters.
//!
//! * **Worked out here, from the specification.** The secret file layout and
//!   its checksum, the fingerprint of the set-up, the made-up credential id,
//!   pre-login answer and record, the key of a challenge nonce and the sealed
//!   login state (key derivation, associated data, plaintext layout) are
//!   computed in this file from the byte layouts in `vectors/OPS.md` with
//!   plain HMAC, HKDF, SHA-256 and XChaCha20-Poly1305. The server library is
//!   not called to make them. `tools/xcheck` works the same values out a
//!   third time, in JavaScript.
//! * **Recorded from the server.** The OPAQUE messages (`registration_response`,
//!   `KE2`, the sealed state that holds the OPAQUE state, the decision of a
//!   `login_finish` and of a replacement) cannot be worked out by hand. They are
//!   recorded from the server library, and are regression pins, not
//!   independent checks. What ties the server to the standard is the test
//!   against the published vectors of RFC 9807
//!   (`crates/ferret-server-auth/tests/rfc9807_server.rs`), which runs the very
//!   same server code.
//!
//! Every case is checked against the server library while the file is made, so
//! a value that disagrees with it stops the generator. Every case is
//! `native-only`: the server half has no WebAssembly binding.

use crate::groups::generator;
use crate::{Error, render};
use ferret_core::opaque::server_suite::OPAQUE_CONTEXT;
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::testing::prim::{aead_seal, ed25519_public_key, ed25519_sign};
use ferret_core::testing::vector::{Case, FORMAT, Status, Tag, VectorFile};
use ferret_core::testing::{ReplayRng, TestRng, hex_encode};
use ferret_core::{
    MasterPassword, OpaqueInput, PinState, SecureRng, opaque_login_start, opaque_register_start,
};
use ferret_server_auth::ServerKeys;
use ferret_server_auth::testing::SMALL;
use ferret_server_auth::testing::vectors::run_case;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha512};

const NATIVE_ONLY: &str = "the server half has no WebAssembly binding";

/// The time all flows start at.
const NOW: u64 = 1_700_000_000;

// ---------------------------------------------------------------- bytes

fn rnd(seed: &str, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    TestRng::new(seed.as_bytes()).fill(&mut out);
    out
}

fn pattern(start: u8, n: usize) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add(i as u8)).collect()
}

fn h(bytes: &[u8]) -> Value {
    json!(hex_encode(bytes))
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 0x01;
    out
}

fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().to_vec()
}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().to_vec()
}

/// HKDF (RFC 5869) over HMAC-SHA256 with an empty salt, written out from the
/// RFC.
fn hkdf256(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hmac256(&[0u8; 32], &[ikm]);
    expand(len, |previous, counter| {
        hmac256(&prk, &[previous, info, &[counter]])
    })
}

/// HKDF over HMAC-SHA512 with an empty salt.
fn hkdf512(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = hmac512(&[0u8; 64], &[ikm]);
    expand(len, |previous, counter| {
        hmac512(&prk, &[previous, info, &[counter]])
    })
}

fn expand(len: usize, block: impl Fn(&[u8], u8) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        previous = block(&previous, counter);
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(len);
    out
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    out
}

fn label(text: &str) -> Vec<u8> {
    tlv(0x01, text.as_bytes())
}

// ----------------------------------------------------------------- cases

fn case(id: &str, title: &str, op: &str, input: Value, rng: &[Vec<u8>]) -> Case {
    Case {
        id: id.into(),
        title: title.into(),
        op: op.into(),
        status: Status::Valid,
        tags: vec![Tag::NativeOnly],
        synthetic: true,
        skip_reason: Some(NATIVE_ONLY.into()),
        rng: rng.iter().map(|d| hex_encode(d)).collect(),
        input,
        intermediate: None,
        expect: None,
        expect_error: None,
    }
}

/// A case whose expected value is worked out in this file.
fn known(id: &str, title: &str, op: &str, input: Value, rng: &[Vec<u8>], expect: Value) -> Case {
    let mut c = case(id, title, op, input, rng);
    c.expect = Some(expect);
    c
}

/// A case that the server must refuse with `code`.
fn refused(id: &str, title: &str, op: &str, input: Value, rng: &[Vec<u8>], code: &str) -> Case {
    let mut c = case(id, title, op, input, rng);
    c.status = Status::Invalid;
    c.expect_error = Some(code.into());
    c
}

/// A case whose answer is the one the server gives.
fn recorded(id: &str, title: &str, op: &str, input: Value, rng: &[Vec<u8>]) -> Result<Case, Error> {
    let mut c = case(id, title, op, input, rng);
    c.expect = Some(run_case(&c).map_err(|e| format!("{id}: the server refused: {e}"))?);
    Ok(c)
}

/// The answer of the server, as a value.
fn answer(c: &Case) -> Result<Value, Error> {
    run_case(c).map_err(|e| format!("{}: the server refused: {e}", c.id).into())
}

/// Stops the generator when the server does not give the answer a case states.
fn check(c: &Case) -> Result<(), Error> {
    let got = run_case(c);
    let ok = match (c.status, &c.expect, &c.expect_error) {
        (Status::Valid, Some(want), _) => got.as_ref() == Ok(want),
        (Status::Invalid, _, Some(code)) => got.as_ref() == Err(code),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{}: the server gives {got:?}, the case states {:?} / {:?}",
            c.id, c.expect, c.expect_error
        )
        .into())
    }
}

fn finish(group: &str, spec: &str, cases: Vec<Case>) -> Result<Vec<u8>, Error> {
    for c in &cases {
        check(c)?;
    }
    render(&VectorFile {
        format: FORMAT.into(),
        group: group.into(),
        suite: 1,
        spec: spec.into(),
        generator: generator(),
        cases,
    })
}

// ----------------------------------------------------------------- world

/// A server: its set-up (`opaque_setup`) and its pre-login secret.
struct World {
    setup: Vec<u8>,
    prelogin: Vec<u8>,
}

fn world(name: &str) -> Result<World, Error> {
    let keys = ServerKeys::generate(&mut TestRng::new(format!("server/{name}/setup").as_bytes()))
        .map_err(|e| format!("keys: {e}"))?;
    Ok(World {
        setup: keys.payload().to_vec(),
        prelogin: rnd(&format!("server/{name}/prelogin"), 32),
    })
}

impl World {
    /// The inputs every operation that builds a server takes.
    fn base(&self) -> Value {
        json!({ "setup_hex": h(&self.setup), "prelogin_secret": h(&self.prelogin) })
    }

    /// Only the set-up, for the operations that need no pre-login secret.
    fn setup_with(&self, extra: Value) -> Value {
        let mut input = json!({ "setup_hex": h(&self.setup), "now": NOW.to_string() });
        for (k, v) in extra.as_object().into_iter().flatten() {
            input[k] = v.clone();
        }
        input
    }

    fn with(&self, extra: Value) -> Value {
        let mut input = self.base();
        for (k, v) in extra.as_object().into_iter().flatten() {
            input[k] = v.clone();
        }
        input
    }
}

// ------------------------------------------------------------- the client

const PASSWORD: &str = "correct horse battery";

fn input_of(password: &str) -> Result<OpaqueInput, Error> {
    let mp = MasterPassword::for_unlock(password.as_bytes()).map_err(|e| e.code())?;
    Ok(mp.opaque_input(None))
}

/// An account that registered on a server.
struct Account {
    credential: [u8; 16],
    password: String,
    request: Vec<u8>,
    record: Vec<u8>,
}

fn register(w: &World, credential: [u8; 16], password: &str, seed: &str) -> Result<Account, Error> {
    let input = input_of(password)?;
    let mut rng = TestRng::new(seed.as_bytes());
    let (request, state) = opaque_register_start(&mut rng, &input).map_err(|e| e.code())?;
    let response = answer(&case(
        "registration/response",
        "response",
        "server.register_response",
        w.setup_with(json!({ "credential_id": h(&credential), "request": h(&request) })),
        &[],
    ))?;
    let response = hex_of(&response["response"])?;
    let done = register_finish_with(&mut rng, state, &input, &response, &TestKsf::new(SMALL))
        .map_err(|e| e.code())?;
    Ok(Account {
        credential,
        password: password.into(),
        request,
        record: done.record,
    })
}

fn hex_of(v: &Value) -> Result<Vec<u8>, Error> {
    ferret_core::testing::hex_decode(v.as_str().ok_or("not text")?).map_err(|_| "not hex".into())
}

fn ke1_of(password: &str, seed: &str) -> Result<(Vec<u8>, ferret_core::LoginState), Error> {
    opaque_login_start(&mut TestRng::new(seed.as_bytes()), &input_of(password)?)
        .map_err(|e| e.code().into())
}

/// KE3 of a client that types `password`, after the server's `ke2`.
fn ke3_of(state: ferret_core::LoginState, password: &str, ke2: &[u8]) -> Result<Vec<u8>, Error> {
    login_finish_with(
        &mut TestRng::new(b"server vectors/client finish"),
        state,
        &input_of(password)?,
        ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .map(|done| done.finished.ke3)
    .map_err(|e| e.code().into())
}

/// The six draws of `login_start`: the fake masking key (64), the masking
/// nonce, the server key seed and the server nonce (32 each), the login id
/// (16) and the nonce of the seal (24).
fn start_draws(seed: &str) -> Vec<Vec<u8>> {
    [64usize, 32, 32, 32, 16, 24]
        .iter()
        .enumerate()
        .map(|(i, n)| rnd(&format!("{seed}/draw{i}"), *n))
        .collect()
}

fn login_purpose() -> Value {
    json!({ "type": "login" })
}

fn reauth_purpose(session: &[u8], account: &[u8]) -> Value {
    json!({ "type": "reauth", "session": h(session), "account": h(account) })
}

// ------------------------------------------------------------- the files

const CRED_ALICE: [u8; 16] = [0x42; 16];
const CRED_BOB: [u8; 16] = [0x43; 16];

pub(crate) fn server_opaque() -> Result<Vec<u8>, Error> {
    let w = world("a")?;
    let other = world("b")?;
    let alice = register(&w, CRED_ALICE, PASSWORD, "server vectors/alice")?;
    let bob = register(&w, CRED_BOB, "another long password", "server vectors/bob")?;
    let mut cases = Vec::new();
    registration_cases(&mut cases, &w, &other, &alice, &bob)?;
    login_cases(&mut cases, &w, &other, &alice, &bob)?;
    replace_cases(&mut cases, &alice)?;
    finish("server-opaque", "Fase 1 § 4.2 and § 4.6; RFC 9807", cases)
}

fn registration_cases(
    cases: &mut Vec<Case>,
    w: &World,
    other: &World,
    alice: &Account,
    bob: &Account,
) -> Result<(), Error> {
    let op = "server.register_response";
    for (name, account) in [("alice", alice), ("bob", bob)] {
        cases.push(recorded(
            &format!("server-opaque/register_response/{name}"),
            &format!("registration response for {name}"),
            op,
            w.setup_with(json!({
                "credential_id": h(&account.credential),
                "request": h(&account.request),
            })),
            &[],
        )?);
    }
    // The OPRF key is a function of the seed and the credential id only: the
    // same request under another id, and under another set-up, differs.
    cases.push(recorded(
        "server-opaque/register_response/alice_request_under_bobs_id",
        "the same request under another credential id gives another response",
        op,
        w.setup_with(json!({ "credential_id": h(&bob.credential), "request": h(&alice.request) })),
        &[],
    )?);
    cases.push(recorded(
        "server-opaque/register_response/alice_request_on_another_server",
        "the same request on another server gives another response",
        op,
        other.setup_with(
            json!({ "credential_id": h(&alice.credential), "request": h(&alice.request) }),
        ),
        &[],
    )?);
    // On the authority of a session: its own account only, and a scope that
    // may register.
    let session = |scope: &str, account: &[u8; 16]| {
        w.setup_with(json!({
            "credential_id": h(&alice.credential),
            "request": h(&alice.request),
            "authority": { "type": "session", "scope": scope, "account": h(account) },
        }))
    };
    for scope in ["full", "account_reset"] {
        cases.push(recorded(
            &format!("server-opaque/register_response/session_{scope}_own_account"),
            "a session registers for its own account",
            op,
            session(scope, &alice.credential),
            &[],
        )?);
    }
    cases.push(refused(
        "server-opaque/register_response/session_other_account",
        "a session never gets an answer under the key of another account",
        op,
        session("full", &bob.credential),
        &[],
        "forbidden",
    ));
    for scope in ["pending_2fa", "unverified"] {
        cases.push(refused(
            &format!("server-opaque/register_response/session_{scope}"),
            "a session that may not register is told so",
            op,
            session(scope, &alice.credential),
            &[],
            "forbidden",
        ));
    }
    let mut throttled = w.setup_with(json!({
        "credential_id": h(&alice.credential),
        "request": h(&alice.request),
    }));
    throttled["throttle_wait_secs"] = json!(30);
    cases.push(refused(
        "server-opaque/register_response/throttled",
        "a caller the limiter refuses is told to wait",
        op,
        throttled,
        &[],
        "throttled",
    ));
    let bad = |name: &str, title: &str, request: Vec<u8>| {
        refused(
            &format!("server-opaque/register_response/{name}"),
            title,
            op,
            w.setup_with(json!({ "credential_id": h(&alice.credential), "request": h(&request) })),
            &[],
            "malformed_registration_request",
        )
    };
    let mut long = alice.request.clone();
    long.push(0);
    cases.push(bad(
        "request_31_bytes",
        "31 bytes",
        alice.request[..31].to_vec(),
    ));
    cases.push(bad("request_33_bytes", "a byte after the element", long));
    cases.push(bad("request_empty", "empty", vec![]));
    cases.push(bad(
        "request_not_an_element",
        "32 bytes that are no element",
        vec![0xff; 32],
    ));
    cases.push(bad("request_identity", "the identity element", vec![0; 32]));
    Ok(())
}

/// The record of an account as the server stores it, and the lookup of it.
fn known_start(
    w: &World,
    account: &Account,
    name: &str,
    ke1: &[u8],
    purpose: Value,
    sk_hint: bool,
) -> Value {
    let scope = (purpose["type"] == "reauth").then_some("full");
    w.with(json!({
        "session_scope": scope,
        "name": name,
        "lookup": "known",
        "record": h(&account.record),
        "stored_ksf_profile": 1,
        "sk_hint": sk_hint,
        "credential_id": h(&account.credential),
        "purpose": purpose,
        "ke1": h(ke1),
        "now": NOW.to_string(),
    }))
}

fn login_cases(
    cases: &mut Vec<Case>,
    w: &World,
    other: &World,
    alice: &Account,
    bob: &Account,
) -> Result<(), Error> {
    let start = "server.login_start";
    let finish_op = "server.login_finish";
    let session = pattern(0x50, 32);
    let alice_name = "alice@example.com";
    let (ke1, client) = ke1_of(&alice.password, "server vectors/alice login")?;

    // ---- login_start
    let login = recorded(
        "server-opaque/login_start/known_login",
        "an account that may log in, for a login",
        start,
        known_start(w, alice, alice_name, &ke1, login_purpose(), false),
        &start_draws("server vectors/start/known"),
    )?;
    let started = answer(&login)?;
    cases.push(login.clone());
    cases.push(recorded(
        "server-opaque/login_start/known_with_second_factor_hint",
        "the hint of the account is carried to the answer",
        start,
        known_start(w, alice, alice_name, &ke1, login_purpose(), true),
        &start_draws("server vectors/start/known"),
    )?);
    let reauth = reauth_purpose(&session, &CRED_ALICE);
    let reauth_start = recorded(
        "server-opaque/login_start/known_reauth",
        "an account that may log in, for a re-authentication of a session",
        start,
        known_start(w, alice, alice_name, &ke1, reauth.clone(), false),
        &start_draws("server vectors/start/reauth"),
    )?;
    let reauth_started = answer(&reauth_start)?;
    cases.push(reauth_start);
    let unknown_input = |name: &str, extra: Value| {
        let mut input = w.with(json!({
            "name": name,
            "lookup": "unknown",
            "credential_id": h(&[0x99; 16]),
            "purpose": login_purpose(),
            "ke1": h(&ke1),
            "now": NOW.to_string(),
        }));
        for (k, v) in extra.as_object().into_iter().flatten() {
            input[k] = v.clone();
        }
        input
    };
    cases.push(recorded(
        "server-opaque/login_start/unknown_name",
        "a name without an account is answered from the made-up record",
        start,
        unknown_input("nobody@example.com", json!({})),
        &start_draws("server vectors/start/unknown"),
    )?);
    cases.push(recorded(
        "server-opaque/login_start/unknown_name_spread",
        "the made-up profile and hint follow the shares of the policy",
        start,
        unknown_input(
            "nobody@example.com",
            json!({ "policy": { "profiles": [[1, 500], [2, 500]], "sk_true_permille": 500 } }),
        ),
        &start_draws("server vectors/start/unknown"),
    )?);
    let mut disabled = unknown_input(alice_name, json!({}));
    disabled["lookup"] = json!("disabled");
    cases.push(recorded(
        "server-opaque/login_start/disabled_account",
        "a disabled account is answered from the made-up record of its name",
        start,
        disabled,
        &start_draws("server vectors/start/unknown"),
    )?);
    cases.push(recorded(
        "server-opaque/login_start/known_on_another_server",
        "the same record and KE1 on another server give another KE2",
        start,
        {
            let mut input = known_start(w, alice, alice_name, &ke1, login_purpose(), false);
            input["setup_hex"] = h(&other.setup);
            input["prelogin_secret"] = h(&other.prelogin);
            input
        },
        &start_draws("server vectors/start/known"),
    )?);
    for (name, scope) in [
        ("reauth_without_a_scope", Value::Null),
        ("reauth_pending_2fa", json!("pending_2fa")),
        ("reauth_unverified", json!("unverified")),
    ] {
        let mut input = known_start(w, alice, alice_name, &ke1, reauth.clone(), false);
        input["session_scope"] = scope;
        cases.push(refused(
            &format!("server-opaque/login_start/{name}"),
            "a re-authentication needs a session that may re-authenticate",
            start,
            input,
            &[],
            "forbidden",
        ));
    }
    let mut throttled = known_start(w, alice, alice_name, &ke1, login_purpose(), false);
    throttled["throttle_wait_secs"] = json!(30);
    cases.push(refused(
        "server-opaque/login_start/throttled",
        "a caller the limiter refuses is told to wait, before any other work",
        start,
        throttled,
        &[],
        "throttled",
    ));
    let bad_ke1 = |name: &str, title: &str, ke1: Vec<u8>| {
        refused(
            &format!("server-opaque/login_start/{name}"),
            title,
            start,
            known_start(w, alice, alice_name, &ke1, login_purpose(), false),
            &[],
            "malformed_ke1",
        )
    };
    let mut long = ke1.clone();
    long.push(0);
    cases.push(bad_ke1(
        "ke1_95_bytes",
        "KE1 of 95 bytes",
        ke1[..95].to_vec(),
    ));
    cases.push(bad_ke1("ke1_97_bytes", "KE1 of 97 bytes", long));
    cases.push(bad_ke1("ke1_empty", "empty KE1", vec![]));
    cases.push(bad_ke1(
        "ke1_not_elements",
        "96 bytes that are no elements",
        vec![0xff; 96],
    ));
    cases.push(bad_ke1(
        "ke1_first_element_identity",
        "the blinded element is the identity",
        {
            let mut bytes = ke1.clone();
            bytes[..32].fill(0);
            bytes
        },
    ));

    // ---- login_finish
    let login_id = started["login_id"].as_str().ok_or("login_id")?.to_string();
    let blob = started["state_blob"].as_str().ok_or("blob")?.to_string();
    let ke2 = hex_of(&started["ke2"])?;
    let ke3 = ke3_of(client, &alice.password, &ke2)?;
    let finish_input =
        |login_id: &str, blob: Option<&str>, ke3: &[u8], now: u64, session: Value| {
            w.with(json!({
                "now": now.to_string(),
                "login_id": login_id,
                "state_blob": blob,
                "ke3": h(ke3),
                "current_session": session,
            }))
        };
    cases.push(recorded(
        "server-opaque/login_finish/login",
        "the right KE3 finishes the login of the account",
        finish_op,
        finish_input(&login_id, Some(&blob), &ke3, NOW + 5, Value::Null),
        &[],
    )?);
    // A re-authentication.
    let re_id = reauth_started["login_id"].as_str().ok_or("id")?.to_string();
    let re_blob = reauth_started["state_blob"]
        .as_str()
        .ok_or("blob")?
        .to_string();
    let (_, re_client) = ke1_of(&alice.password, "server vectors/alice login")?;
    let re_ke3 = ke3_of(re_client, &alice.password, &hex_of(&reauth_started["ke2"])?)?;
    let session_json = |s: &[u8], a: &[u8]| json!({ "session": h(s), "account": h(a) });
    cases.push(recorded(
        "server-opaque/login_finish/reauth",
        "the right KE3 finishes a re-authentication of the session of the account",
        finish_op,
        finish_input(
            &re_id,
            Some(&re_blob),
            &re_ke3,
            NOW + 5,
            session_json(&session, &CRED_ALICE),
        ),
        &[],
    )?);

    let denied = |name: &str, title: &str, input: Value| {
        refused(
            &format!("server-opaque/login_finish/{name}"),
            title,
            finish_op,
            input,
            &[],
            "denied",
        )
    };
    cases.push(denied(
        "ke3_bit_flipped",
        "a changed bit in KE3",
        finish_input(&login_id, Some(&blob), &flip(&ke3, 0), NOW + 5, Value::Null),
    ));
    cases.push(denied(
        "ke3_last_bit_flipped",
        "a changed last bit in KE3",
        finish_input(
            &login_id,
            Some(&blob),
            &flip(&ke3, 63),
            NOW + 5,
            Value::Null,
        ),
    ));
    cases.push(denied(
        "ke3_zero",
        "KE3 of 64 zero bytes",
        finish_input(&login_id, Some(&blob), &[0u8; 64], NOW + 5, Value::Null),
    ));
    // KE3 of another login (another KE1 and KE2) does not fit this state.
    let (other_ke1, other_client) = ke1_of(&bob.password, "server vectors/bob login")?;
    let bob_start = recorded(
        "server-opaque/login_start/known_login_bob",
        "a second account that may log in, for a login",
        start,
        known_start(
            w,
            bob,
            "bob@example.com",
            &other_ke1,
            login_purpose(),
            false,
        ),
        &start_draws("server vectors/start/bob"),
    )?;
    let bob_started = answer(&bob_start)?;
    let bob_ke3 = ke3_of(other_client, &bob.password, &hex_of(&bob_started["ke2"])?)?;
    cases.push(bob_start);
    cases.push(denied(
        "ke3_of_another_login",
        "KE3 of another account's login",
        finish_input(&login_id, Some(&blob), &bob_ke3, NOW + 5, Value::Null),
    ));
    cases.push(denied(
        "state_missing",
        "no login state for the id",
        finish_input(&login_id, None, &ke3, NOW + 5, Value::Null),
    ));
    cases.push(denied(
        "state_tampered",
        "a changed byte in the sealed state",
        finish_input(
            &login_id,
            Some(&hex_encode(&flip(&hex_of(&json!(blob))?, 100))),
            &ke3,
            NOW + 5,
            Value::Null,
        ),
    ));
    cases.push(denied(
        "state_of_another_login_id",
        "the sealed state under the id of another login",
        finish_input(
            bob_started["login_id"].as_str().ok_or("id")?,
            Some(&blob),
            &ke3,
            NOW + 5,
            Value::Null,
        ),
    ));
    cases.push(denied(
        "state_expired",
        "the state is used after its 60 seconds",
        finish_input(&login_id, Some(&blob), &ke3, NOW + 60, Value::Null),
    ));
    cases.push(denied(
        "login_state_with_a_session",
        "a state made for a login is not finished as a re-authentication",
        finish_input(
            &login_id,
            Some(&blob),
            &ke3,
            NOW + 5,
            session_json(&session, &CRED_ALICE),
        ),
    ));
    cases.push(denied(
        "reauth_state_without_a_session",
        "a state made for a re-authentication is not finished as a login",
        finish_input(&re_id, Some(&re_blob), &re_ke3, NOW + 5, Value::Null),
    ));
    cases.push(denied(
        "reauth_for_another_session",
        "a re-authentication is for one session",
        finish_input(
            &re_id,
            Some(&re_blob),
            &re_ke3,
            NOW + 5,
            session_json(&pattern(0x70, 32), &CRED_ALICE),
        ),
    ));
    cases.push(denied(
        "reauth_for_another_account",
        "a re-authentication is for the account of the session",
        finish_input(
            &re_id,
            Some(&re_blob),
            &re_ke3,
            NOW + 5,
            session_json(&session, &CRED_BOB),
        ),
    ));
    let mut throttled = finish_input(&login_id, Some(&blob), &ke3, NOW + 5, Value::Null);
    throttled["throttle_wait_secs"] = json!(30);
    cases.push(refused(
        "server-opaque/login_finish/throttled",
        "a caller the limiter refuses is told to wait after the state is taken",
        finish_op,
        throttled,
        &[],
        "throttled",
    ));
    let malformed = |name: &str, title: &str, code: &str, id: &str, ke3: &[u8]| {
        refused(
            &format!("server-opaque/login_finish/{name}"),
            title,
            finish_op,
            finish_input(id, Some(&blob), ke3, NOW + 5, Value::Null),
            &[],
            code,
        )
    };
    cases.push(malformed(
        "ke3_63_bytes",
        "KE3 of 63 bytes",
        "malformed_ke3",
        &login_id,
        &ke3[..63],
    ));
    let mut long = ke3.clone();
    long.push(0);
    cases.push(malformed(
        "ke3_65_bytes",
        "KE3 of 65 bytes",
        "malformed_ke3",
        &login_id,
        &long,
    ));
    cases.push(malformed(
        "ke3_empty",
        "empty KE3",
        "malformed_ke3",
        &login_id,
        &[],
    ));
    cases.push(malformed(
        "login_id_upper_case",
        "a login id in upper case",
        "malformed_login_id",
        &login_id.to_uppercase(),
        &ke3,
    ));
    cases.push(malformed(
        "login_id_31_characters",
        "a login id of 31 characters",
        "malformed_login_id",
        &login_id[..31],
        &ke3,
    ));
    Ok(())
}

// ------------------------------------------------------------ replacement

/// `TLV[label, op, account_id, nonce, vk_epoch, hash = SHA-256(body)]`
/// (Fase 1 § 4.6), written out.
fn proof_message(
    label_text: &str,
    op: &str,
    account: &[u8],
    nonce: &[u8],
    epoch: u64,
    body: &[u8],
) -> Vec<u8> {
    [
        label(label_text),
        tlv(0x36, op.as_bytes()),
        tlv(0x10, account),
        tlv(0x33, nonce),
        tlv(0x20, &epoch.to_be_bytes()),
        tlv(0x35, &sha256(&[body])),
    ]
    .concat()
}

/// A body as the client sends it: compact JSON with the record in hex, the
/// profile number and, for a recovery, the new `pk_r`. The proof covers these
/// bytes exactly.
fn body_of(record: &[u8], profile: u32, pk_r_new: Option<&[u8]>) -> Vec<u8> {
    let key = pk_r_new.map_or(String::new(), |k| {
        format!(r#","pk_r_new":"{}""#, hex_encode(k))
    });
    format!(
        r#"{{"registration_record":"{}","ksf_profile":{profile}{key}}}"#,
        hex_encode(record)
    )
    .into_bytes()
}

fn replace_cases(cases: &mut Vec<Case>, alice: &Account) -> Result<(), Error> {
    let op = "server.replace_authorize";
    let account = pattern(0x10, 16);
    let seed_a: [u8; 32] = pattern(0xa0, 32).try_into().map_err(|_| "seed")?;
    let rk: [u8; 32] = pattern(0xc0, 32).try_into().map_err(|_| "rk")?;
    let seed_r = crate::key_groups::seed_r(account.as_slice().try_into().map_err(|_| "id")?, &rk)?;
    let pk_a = ed25519_public_key(&seed_a);
    let pk_r = ed25519_public_key(&seed_r);
    let new_pk_r = ed25519_public_key(&[0x77; 32]);
    let session = pattern(0x50, 32);
    let nonce = pattern(0xa0, 32);
    let epoch = 1u64;

    let input = |kind: &str,
                 body: &[u8],
                 proof: &[u8],
                 nonce: &[u8],
                 nonce_issued: bool,
                 account_epoch: u64,
                 current_profile: u8| {
        json!({
            "kind": kind,
            "account": {
                "account_id": h(&account),
                "pk_a": h(&pk_a),
                "pk_r": h(&pk_r),
                "vk_epoch": account_epoch.to_string(),
                "row_version": "7",
            },
            "current": { "record": h(&alice.record), "ksf_profile": current_profile },
            "session": h(&session),
            "nonce": h(nonce),
            "nonce_issued": nonce_issued,
            "proof": h(proof),
            "body": h(body),
            "now": NOW.to_string(),
        })
    };
    let sign_a = |body: &[u8]| -> Result<[u8; 64], Error> {
        let message = proof_message(
            "ferret/v1/mutation",
            "unlock-method.password.put",
            &account,
            &nonce,
            epoch,
            body,
        );
        ed25519_sign(&seed_a, &message).map_err(|e| format!("sign: {e}").into())
    };
    let sign_r = |body: &[u8]| -> Result<[u8; 64], Error> {
        let message = proof_message(
            "ferret/v1/recovery-req",
            "recover",
            &account,
            &nonce,
            epoch,
            body,
        );
        ed25519_sign(&seed_r, &message).map_err(|e| format!("sign: {e}").into())
    };

    let put_body = body_of(&alice.record, 1, None);
    let put_proof = sign_a(&put_body)?;
    cases.push(recorded(
        "server-opaque/replace_authorize/password_put",
        "a signed change of the password with the stored profile",
        op,
        input(
            "password_put",
            &put_body,
            &put_proof,
            &nonce,
            true,
            epoch,
            1,
        ),
        &[],
    )?);
    let recover_body = body_of(&alice.record, 1, Some(&new_pk_r));
    let recover_proof = sign_r(&recover_body)?;
    cases.push(recorded(
        "server-opaque/replace_authorize/recover",
        "a signed recovery with a new recovery key",
        op,
        input(
            "recover",
            &recover_body,
            &recover_proof,
            &nonce,
            true,
            epoch,
            1,
        ),
        &[],
    )?);

    let bad = |name: &str, title: &str, value: Value, code: &str| {
        refused(
            &format!("server-opaque/replace_authorize/{name}"),
            title,
            op,
            value,
            &[],
            code,
        )
    };
    let mut forbidden = input(
        "password_put",
        &put_body,
        &put_proof,
        &nonce,
        true,
        epoch,
        1,
    );
    forbidden["scope"] = json!("pending_2fa");
    cases.push(bad(
        "scope_pending_2fa",
        "a session that has not finished the second factor may not change the password",
        forbidden,
        "forbidden",
    ));
    let mut throttled = input(
        "password_put",
        &put_body,
        &put_proof,
        &nonce,
        true,
        epoch,
        1,
    );
    throttled["throttle_wait_secs"] = json!(30);
    cases.push(bad(
        "throttled",
        "a caller the limiter refuses is told to wait",
        throttled,
        "throttled",
    ));
    cases.push(bad(
        "nonce_not_issued",
        "a nonce that was never issued to the session",
        input(
            "password_put",
            &put_body,
            &put_proof,
            &nonce,
            false,
            epoch,
            1,
        ),
        "denied",
    ));
    cases.push(bad(
        "proof_bit_flipped",
        "a changed bit in the proof",
        input(
            "password_put",
            &put_body,
            &flip(&put_proof, 5),
            &nonce,
            true,
            epoch,
            1,
        ),
        "denied",
    ));
    cases.push(bad(
        "body_changed_after_signing",
        "a body other than the one that was signed",
        input(
            "password_put",
            &body_of(&alice.record, 2, None),
            &put_proof,
            &nonce,
            true,
            epoch,
            1,
        ),
        "denied",
    ));
    cases.push(bad(
        "epoch_of_the_account_is_higher",
        "the proof was made for an older vault key epoch",
        input("password_put", &put_body, &put_proof, &nonce, true, 2, 1),
        "denied",
    ));
    cases.push(bad(
        "recovery_signed_by_the_auth_key",
        "a recovery signed with sk_a",
        input(
            "recover",
            &recover_body,
            &sign_a(&recover_body)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "denied",
    ));
    cases.push(bad(
        "password_put_signed_by_the_recovery_key",
        "a change of the password signed with sk_r",
        input(
            "password_put",
            &put_body,
            &sign_r(&put_body)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "denied",
    ));
    cases.push(bad(
        "nonce_31_bytes",
        "a nonce of 31 bytes",
        input(
            "password_put",
            &put_body,
            &put_proof,
            &nonce[..31],
            true,
            epoch,
            1,
        ),
        "malformed_nonce",
    ));
    cases.push(bad(
        "proof_63_bytes",
        "a proof of 63 bytes",
        input(
            "password_put",
            &put_body,
            &put_proof[..63],
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_proof",
    ));
    // Signed correctly, but what the body asks is refused.
    let unknown_profile = body_of(&alice.record, 7, None);
    cases.push(bad(
        "profile_unknown",
        "a profile that clients do not know",
        input(
            "password_put",
            &unknown_profile,
            &sign_a(&unknown_profile)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "profile_rejected",
    ));
    let below = body_of(&alice.record, 1, None);
    cases.push(bad(
        "profile_below_the_stored_one",
        "a profile below the one that is stored",
        input(
            "password_put",
            &below,
            &sign_a(&below)?,
            &nonce,
            true,
            epoch,
            2,
        ),
        "profile_rejected",
    ));
    let mut broken = alice.record.clone();
    broken[..32].fill(0xff);
    let broken_body = body_of(&broken, 1, None);
    cases.push(bad(
        "record_with_a_bad_public_key",
        "a record whose client public key is no element",
        input(
            "password_put",
            &broken_body,
            &sign_a(&broken_body)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_registration_record",
    ));
    let short = body_of(&alice.record[..191], 1, None);
    cases.push(bad(
        "record_191_bytes",
        "a record of 191 bytes",
        input(
            "password_put",
            &short,
            &sign_a(&short)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_registration_record",
    ));
    // A recovery may lower the profile (it undoes a wrongly claimed one); a
    // password change may not.
    cases.push(recorded(
        "server-opaque/replace_authorize/recover_lowers_the_profile",
        "a recovery may set a profile below the stored one",
        op,
        input(
            "recover",
            &recover_body,
            &recover_proof,
            &nonce,
            true,
            epoch,
            2,
        ),
        &[],
    )?);
    let unknown_recover = body_of(&alice.record, 7, Some(&new_pk_r));
    cases.push(bad(
        "recover_profile_unknown",
        "a recovery with a profile that clients do not know",
        input(
            "recover",
            &unknown_recover,
            &sign_r(&unknown_recover)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "profile_rejected",
    ));
    // The parser reads three fields and ignores the rest of the JSON.
    let extra = format!(
        r#"{{"wrap":"00","registration_record":"{}","kek_generation":2,"ksf_profile":1,"manifest":{{"rev":2}}}}"#,
        hex_encode(&alice.record)
    )
    .into_bytes();
    cases.push(recorded(
        "server-opaque/replace_authorize/body_with_other_fields",
        "the fields the endpoint reads for itself are not the library's business",
        op,
        input(
            "password_put",
            &extra,
            &sign_a(&extra)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        &[],
    )?);
    let not_json = b"not json".to_vec();
    cases.push(bad(
        "body_not_json",
        "a body that is signed but is no JSON",
        input(
            "password_put",
            &not_json,
            &sign_a(&not_json)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_registration_record",
    ));
    let short_key = format!(
        r#"{{"registration_record":"{}","ksf_profile":1,"pk_r_new":"00"}}"#,
        hex_encode(&alice.record)
    )
    .into_bytes();
    cases.push(bad(
        "recovery_key_of_one_byte",
        "a new recovery key that is not 32 bytes",
        input(
            "recover",
            &short_key,
            &sign_r(&short_key)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_recovery_key",
    ));
    let same_key = body_of(&alice.record, 1, Some(&pk_r));
    cases.push(bad(
        "recovery_with_the_old_recovery_key",
        "a recovery that keeps the stored recovery key",
        input(
            "recover",
            &same_key,
            &sign_r(&same_key)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_recovery_key",
    ));
    let no_key = body_of(&alice.record, 1, None);
    cases.push(bad(
        "recovery_without_a_new_key",
        "a recovery without a new recovery key",
        input(
            "recover",
            &no_key,
            &sign_r(&no_key)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_recovery_key",
    ));
    let extra_key = body_of(&alice.record, 1, Some(&new_pk_r));
    cases.push(bad(
        "password_put_with_a_recovery_key",
        "a change of the password that brings a recovery key",
        input(
            "password_put",
            &extra_key,
            &sign_a(&extra_key)?,
            &nonce,
            true,
            epoch,
            1,
        ),
        "malformed_recovery_key",
    ));
    Ok(())
}

// ------------------------------------------------------------- the secrets

/// A secret file, written out: `FSEC`, version, kind, suite, length, payload,
/// SHA-256 of all of it so far.
fn secret_file(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = b"FSEC".to_vec();
    out.extend_from_slice(&[1, kind, 1]);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    let checksum = sha256(&[&out]);
    out.extend_from_slice(&checksum);
    out
}

pub(crate) fn server_secrets() -> Result<Vec<u8>, Error> {
    let w = world("a")?;
    let other = world("b")?;
    let mut cases = Vec::new();
    file_cases(&mut cases, &w, &other);
    fingerprint_cases(&mut cases, &w, &other);
    made_up_cases(&mut cases, &w, &other)?;
    challenge_cases(&mut cases);
    state_cases(&mut cases, &w, &other)?;
    login_state_cases(&mut cases, &w)?;
    finish("server-secrets", "Fase 1 § 4.2 and § 11", cases)
}

fn file_cases(cases: &mut Vec<Case>, w: &World, other: &World) {
    let setup_file = secret_file(1, &w.setup);
    let prelogin_file = secret_file(2, &w.prelogin);
    for (name, kind, payload, file) in [
        ("opaque_setup", "opaque_setup", &w.setup, &setup_file),
        (
            "opaque_setup_other",
            "opaque_setup",
            &other.setup,
            &secret_file(1, &other.setup),
        ),
        (
            "prelogin_secret",
            "prelogin_secret",
            &w.prelogin,
            &prelogin_file,
        ),
    ] {
        cases.push(known(
            &format!("server-secrets/secret_file_encode/{name}"),
            &format!("the file for a {kind} payload"),
            "server.secret_file.encode",
            json!({ "kind": kind, "payload": h(payload) }),
            &[],
            json!({ "file": h(file) }),
        ));
        cases.push(known(
            &format!("server-secrets/secret_file_decode/{name}"),
            &format!("a good {kind} file"),
            "server.secret_file.decode",
            json!({ "kind": kind, "file": h(file) }),
            &[],
            json!({ "payload": h(payload) }),
        ));
    }
    let encode_bad = |name: &str, kind: &str, payload: Vec<u8>| {
        refused(
            &format!("server-secrets/secret_file_encode/{name}"),
            "a payload of the wrong length",
            "server.secret_file.encode",
            json!({ "kind": kind, "payload": h(&payload) }),
            &[],
            "bad_length",
        )
    };
    cases.push(encode_bad(
        "setup_127_bytes",
        "opaque_setup",
        w.setup[..127].to_vec(),
    ));
    cases.push(encode_bad(
        "prelogin_33_bytes",
        "prelogin_secret",
        pattern(0, 33),
    ));
    cases.push(encode_bad("prelogin_empty", "prelogin_secret", vec![]));

    let decode_bad = |name: &str, title: &str, kind: &str, file: Vec<u8>, code: &str| {
        refused(
            &format!("server-secrets/secret_file_decode/{name}"),
            title,
            "server.secret_file.decode",
            json!({ "kind": kind, "file": h(&file) }),
            &[],
            code,
        )
    };
    let with = |at: usize, byte: u8| {
        let mut file = setup_file.clone();
        file[at] = byte;
        file
    };
    let setup = "opaque_setup";
    cases.push(decode_bad(
        "empty",
        "an empty file",
        setup,
        vec![],
        "bad_length",
    ));
    cases.push(decode_bad(
        "magic_prefix_only",
        "only the start of the magic",
        setup,
        b"FSE".to_vec(),
        "bad_length",
    ));
    cases.push(decode_bad(
        "header_cut",
        "a file cut inside the header",
        setup,
        setup_file[..8].to_vec(),
        "bad_length",
    ));
    cases.push(decode_bad(
        "magic_wrong",
        "another file format",
        setup,
        b"PK\x03\x04 and the rest".to_vec(),
        "bad_magic",
    ));
    cases.push(decode_bad(
        "magic_last_byte",
        "the magic with a wrong last byte",
        setup,
        with(3, b'D'),
        "bad_magic",
    ));
    cases.push(decode_bad(
        "version_2",
        "an unknown version",
        setup,
        with(4, 2),
        "unsupported_version",
    ));
    cases.push(decode_bad(
        "version_0",
        "version 0",
        setup,
        with(4, 0),
        "unsupported_version",
    ));
    cases.push(decode_bad(
        "kind_prelogin_for_setup",
        "a prelogin_secret file read as opaque_setup",
        setup,
        prelogin_file.clone(),
        "wrong_kind",
    ));
    cases.push(decode_bad(
        "kind_unknown",
        "an unknown kind byte",
        setup,
        with(5, 3),
        "wrong_kind",
    ));
    cases.push(decode_bad(
        "kind_setup_for_prelogin",
        "an opaque_setup file read as prelogin_secret",
        "prelogin_secret",
        setup_file.clone(),
        "wrong_kind",
    ));
    cases.push(decode_bad(
        "suite_2",
        "an unknown suite",
        setup,
        with(6, 2),
        "unsupported_suite",
    ));
    cases.push(decode_bad(
        "length_field_129",
        "a length field that is not the kind's",
        setup,
        with(8, 129),
        "bad_length",
    ));
    cases.push(decode_bad(
        "length_field_prelogin_size",
        "the length of the other kind",
        setup,
        with(8, 32),
        "bad_length",
    ));
    cases.push(decode_bad(
        "truncated_checksum",
        "a file without its last byte",
        setup,
        setup_file[..168].to_vec(),
        "bad_length",
    ));
    cases.push(decode_bad(
        "truncated_payload",
        "a file cut inside the payload",
        setup,
        setup_file[..100].to_vec(),
        "bad_length",
    ));
    cases.push(decode_bad(
        "trailing_byte",
        "a byte after the checksum",
        setup,
        [setup_file.clone(), vec![0]].concat(),
        "trailing_bytes",
    ));
    cases.push(decode_bad(
        "checksum_last_bit",
        "a changed bit in the checksum",
        setup,
        with(168, setup_file[168] ^ 1),
        "bad_checksum",
    ));
    cases.push(decode_bad(
        "checksum_payload_bit",
        "a changed bit in the payload",
        setup,
        with(50, setup_file[50] ^ 1),
        "bad_checksum",
    ));
    cases.push(decode_bad(
        "checksum_prelogin",
        "a changed bit in a prelogin_secret file",
        "prelogin_secret",
        {
            let mut file = prelogin_file.clone();
            file[9] ^= 1;
            file
        },
        "bad_checksum",
    ));
}

fn fingerprint_cases(cases: &mut Vec<Case>, w: &World, other: &World) {
    let fingerprint = |setup: &[u8]| sha256(&[b"ferret/v1/setup-fp", setup]);
    for (name, world) in [("a", w), ("b", other)] {
        cases.push(known(
            &format!("server-secrets/setup_fingerprint/{name}"),
            "the fingerprint of the set-up",
            "server.setup_fingerprint",
            json!({ "setup_hex": h(&world.setup) }),
            &[],
            json!({ "fingerprint": h(&fingerprint(&world.setup)) }),
        ));
    }
    // A swap of the seed alone, or of the dummy key alone, changes it.
    let swapped = |at: usize, with: &[u8]| {
        let mut setup = w.setup.clone();
        setup[at..at + 32].copy_from_slice(with);
        setup
    };
    for (name, setup) in [
        ("seed_swapped", swapped(0, &other.setup[..32])),
        ("dummy_key_swapped", swapped(96, &other.setup[96..128])),
    ] {
        cases.push(known(
            &format!("server-secrets/setup_fingerprint/{name}"),
            "a set-up with one part of another server",
            "server.setup_fingerprint",
            json!({ "setup_hex": h(&setup) }),
            &[],
            json!({ "fingerprint": h(&fingerprint(&setup)) }),
        ));
    }
}

fn made_up_cases(cases: &mut Vec<Case>, w: &World, other: &World) -> Result<(), Error> {
    // ---- credential id: HMAC-SHA256(secret, "prelogin-id" || name)[..16]
    let id_of = |secret: &[u8], name: &str| {
        hmac256(secret, &[b"prelogin-id", name.as_bytes()])[..16].to_vec()
    };
    let names: [(&str, &str, &str); 7] = [
        ("plain", "alice@example.com", "alice@example.com"),
        ("upper_case", "Alice@Example.COM", "alice@example.com"),
        (
            "full_width",
            "\u{ff21}\u{ff2c}\u{ff29}\u{ff23}\u{ff25}@example.com",
            "alice@example.com",
        ),
        ("padded", "  bob@example.com\t", "bob@example.com"),
        ("other", "bob@example.com", "bob@example.com"),
        (
            "plus_tag",
            "carol+work@example.org",
            "carol+work@example.org",
        ),
        // U+0085 is white space to the library, so it is trimmed.
        (
            "next_line_trimmed",
            "dave@example.org\u{85}",
            "dave@example.org",
        ),
    ];
    for (key, raw, normal) in names {
        cases.push(known(
            &format!("server-secrets/fake_credential_id/{key}"),
            "the made-up credential id of a name",
            "server.fake_credential_id",
            json!({ "prelogin_secret": h(&w.prelogin), "name": raw }),
            &[],
            json!({ "credential_id": h(&id_of(&w.prelogin, normal)) }),
        ));
    }
    cases.push(known(
        "server-secrets/fake_credential_id/other_secret",
        "the same name under another secret",
        "server.fake_credential_id",
        json!({ "prelogin_secret": h(&other.prelogin), "name": "alice@example.com" }),
        &[],
        json!({ "credential_id": h(&id_of(&other.prelogin, "alice@example.com")) }),
    ));
    let long_name = format!("{}@example.com", "a".repeat(254 - "@example.com".len()));
    cases.push(known(
        "server-secrets/fake_credential_id/longest_name",
        "a name of 254 bytes",
        "server.fake_credential_id",
        json!({ "prelogin_secret": h(&w.prelogin), "name": long_name }),
        &[],
        json!({ "credential_id": h(&id_of(&w.prelogin, &long_name)) }),
    ));
    let bad_name = |key: &str, title: &str, name: String| {
        refused(
            &format!("server-secrets/fake_credential_id/{key}"),
            title,
            "server.fake_credential_id",
            json!({ "prelogin_secret": h(&w.prelogin), "name": name }),
            &[],
            "malformed_login_name",
        )
    };
    cases.push(bad_name("empty", "an empty name", String::new()));
    cases.push(bad_name("blank", "a name of white space", " \t ".into()));
    cases.push(bad_name(
        "control_character",
        "a control character in the name",
        "a\u{7}b@example.com".into(),
    ));
    cases.push(bad_name(
        "byte_order_mark_not_trimmed",
        "U+FEFF is no white space, so it stays and is refused",
        "\u{feff}dave@example.org".into(),
    ));
    cases.push(bad_name(
        "zero_width_space",
        "an invisible character in the name",
        "al\u{200b}ice@example.com".into(),
    ));
    cases.push(bad_name(
        "too_long",
        "a name of 255 bytes",
        format!("{}@example.com", "a".repeat(255 - "@example.com".len())),
    ));

    // ---- pre-login answer
    let answer_of = |secret: &[u8], name: &str, profiles: &[(u8, u16)], hint: u16| {
        let digest = hmac256(secret, &[b"prelogin-hint", name.as_bytes()]);
        let draw =
            |at: usize| u64::from_be_bytes(digest[at..at + 8].try_into().expect("8 bytes")) % 1000;
        let mut upper = 0u64;
        let mut profile = profiles.last().map_or(0, |p| p.0);
        for (number, share) in profiles {
            upper += u64::from(*share);
            if draw(0) < upper {
                profile = *number;
                break;
            }
        }
        json!({ "ksf_profile": profile, "sk_hint": draw(8) < u64::from(hint) })
    };
    let policy = |profiles: &[(u8, u16)], hint: u16| json!({ "profiles": profiles.iter().map(|(p, s)| json!([p, s])).collect::<Vec<_>>(), "sk_true_permille": hint });
    let spread: &[(u8, u16)] = &[(1, 700), (2, 300)];
    for index in 0..8 {
        let name = format!("user{index}@example.com");
        cases.push(known(
            &format!("server-secrets/fake_prelogin/spread_{index}"),
            "the made-up answer follows the shares of the policy",
            "server.fake_prelogin",
            json!({ "prelogin_secret": h(&w.prelogin), "name": name, "policy": policy(spread, 400) }),
            &[],
            answer_of(&w.prelogin, &name, spread, 400),
        ));
    }
    let single: &[(u8, u16)] = &[(1, 1000)];
    cases.push(known(
        "server-secrets/fake_prelogin/single_profile_always_hinted",
        "one profile and every answer says there is a second factor",
        "server.fake_prelogin",
        json!({ "prelogin_secret": h(&w.prelogin), "name": "alice@example.com", "policy": policy(single, 1000) }),
        &[],
        answer_of(&w.prelogin, "alice@example.com", single, 1000),
    ));
    cases.push(known(
        "server-secrets/fake_prelogin/never_hinted",
        "no answer says there is a second factor",
        "server.fake_prelogin",
        json!({ "prelogin_secret": h(&w.prelogin), "name": "alice@example.com", "policy": policy(single, 0) }),
        &[],
        answer_of(&w.prelogin, "alice@example.com", single, 0),
    ));
    cases.push(known(
        "server-secrets/fake_prelogin/normalized_name",
        "the answer is that of the normalized name",
        "server.fake_prelogin",
        json!({ "prelogin_secret": h(&w.prelogin), "name": "Alice@Example.COM", "policy": policy(spread, 400) }),
        &[],
        answer_of(&w.prelogin, "alice@example.com", spread, 400),
    ));
    cases.push(known(
        "server-secrets/fake_prelogin/other_secret",
        "the same name under another secret",
        "server.fake_prelogin",
        json!({ "prelogin_secret": h(&other.prelogin), "name": "user3@example.com", "policy": policy(spread, 400) }),
        &[],
        answer_of(&other.prelogin, "user3@example.com", spread, 400),
    ));
    let bad_policy = |key: &str, title: &str, profiles: &[(u8, u16)], hint: u16| {
        refused(
            &format!("server-secrets/fake_prelogin/{key}"),
            title,
            "server.fake_prelogin",
            json!({ "prelogin_secret": h(&w.prelogin), "name": "alice@example.com", "policy": policy(profiles, hint) }),
            &[],
            "internal",
        )
    };
    cases.push(bad_policy(
        "shares_add_up_to_999",
        "shares that add up to 999",
        &[(1, 600), (2, 399)],
        0,
    ));
    cases.push(bad_policy(
        "shares_add_up_to_1001",
        "shares that add up to 1001",
        &[(1, 600), (2, 401)],
        0,
    ));
    cases.push(bad_policy(
        "profile_twice",
        "a profile named twice",
        &[(1, 500), (1, 500)],
        0,
    ));
    cases.push(bad_policy("profile_zero", "profile 0", &[(0, 1000)], 0));
    cases.push(bad_policy(
        "hint_above_1000",
        "a hint share above 1000",
        single,
        1001,
    ));
    cases.push(bad_policy("no_profiles", "no profile at all", &[], 0));

    // ---- made-up record: dummy_pk || HKDF-SHA512(secret, "…/record" || id)[..160]
    let record_of = |world: &World, id: &[u8]| {
        let body = hkdf512(
            &world.prelogin,
            &[b"ferret/v1/prelogin/record".as_slice(), id].concat(),
            160,
        );
        [world.setup[96..128].to_vec(), body].concat()
    };
    for (key, world, id) in [
        ("alice", w, vec![0x42; 16]),
        ("sequence", w, pattern(0, 16)),
        ("other_secret", other, vec![0x42; 16]),
    ] {
        cases.push(known(
            &format!("server-secrets/fake_record/{key}"),
            "the made-up record for a credential id",
            "server.fake_record",
            world.with(json!({ "credential_id": h(&id) })),
            &[],
            json!({ "record": h(&record_of(world, &id)) }),
        ));
    }
    let mixed = World {
        setup: other.setup.clone(),
        prelogin: w.prelogin.clone(),
    };
    cases.push(known(
        "server-secrets/fake_record/other_setup",
        "another set-up changes the public key at the start and nothing else",
        "server.fake_record",
        mixed.with(json!({ "credential_id": h(&[0x42; 16]) })),
        &[],
        json!({ "record": h(&record_of(&mixed, &[0x42; 16])) }),
    ));
    Ok(())
}

fn challenge_cases(cases: &mut Vec<Case>) {
    for (key, session, nonce) in [
        ("first", pattern(0x50, 32), pattern(0xa0, 32)),
        ("other_session", pattern(0x51, 32), pattern(0xa0, 32)),
        ("other_nonce", pattern(0x50, 32), pattern(0xa1, 32)),
        ("zeros", vec![0; 32], vec![0; 32]),
    ] {
        cases.push(known(
            &format!("server-secrets/challenge_key/{key}"),
            "the key a nonce is stored under",
            "server.challenge_key",
            json!({ "session": h(&session), "nonce": h(&nonce) }),
            &[],
            json!({ "key": h(&sha256(&[&session, &nonce])) }),
        ));
    }
}

// ------------------------------------------------------------- the state

/// The plaintext of a sealed state, written out.
struct Plain {
    expires_at: u64,
    purpose: u8,
    flag: u8,
    binding: Vec<u8>,
    credential: Vec<u8>,
    ksf_profile: u8,
    server_login: Vec<u8>,
}

impl Plain {
    fn bytes(&self) -> Vec<u8> {
        [
            self.expires_at.to_be_bytes().to_vec(),
            vec![self.purpose, self.flag],
            self.binding.clone(),
            self.credential.clone(),
            vec![self.ksf_profile],
            self.server_login.clone(),
        ]
        .concat()
    }
}

fn login_plain(expires_at: u64) -> Plain {
    Plain {
        expires_at,
        purpose: 0,
        flag: 0,
        binding: vec![0; 48],
        credential: vec![0x42; 16],
        ksf_profile: 1,
        server_login: pattern(0x80, 128),
    }
}

fn reauth_plain(expires_at: u64, session: &[u8], account: &[u8]) -> Plain {
    Plain {
        purpose: 1,
        flag: 1,
        binding: [session, account].concat(),
        ..login_plain(expires_at)
    }
}

/// The JSON a case states a plaintext with.
fn plain_input(plain: &Plain) -> Value {
    let purpose = if plain.purpose == 0 {
        login_purpose()
    } else {
        reauth_purpose(&plain.binding[..32], &plain.binding[32..])
    };
    json!({
        "expires_at": plain.expires_at.to_string(),
        "purpose": purpose,
        "credential": h(&plain.credential),
        "ksf_profile": plain.ksf_profile,
        "server_login": h(&plain.server_login),
    })
}

/// A blob, worked out: `0x01 || nonce || XChaCha20-Poly1305(key, nonce, aad, plaintext)`.
fn seal(prelogin: &[u8], login_id: &[u8], nonce: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    let key: [u8; 32] = hkdf256(prelogin, b"ferret/v1/state-seal", 32)
        .try_into()
        .map_err(|_| "key")?;
    let aad = [
        label("ferret/v1/server/login-state"),
        tlv(0x02, &[1]),
        tlv(0x03, &[1]),
        tlv(0x33, login_id),
    ]
    .concat();
    let sealed = aead_seal(&mut ReplayRng::new(vec![nonce.to_vec()]), &key, &aad, plain)
        .map_err(|e| format!("aead: {e}"))?;
    Ok([vec![1u8], sealed].concat())
}

fn state_cases(cases: &mut Vec<Case>, w: &World, other: &World) -> Result<(), Error> {
    let login_id = pattern(0x20, 16);
    let login_id_hex = hex_encode(&login_id);
    let nonce = pattern(0xe0, 24);
    let session = pattern(0x50, 32);
    let account = vec![0x42u8; 16];
    let expires = NOW + 60;
    let plain_login = login_plain(expires);
    let plain_reauth = reauth_plain(expires, &session, &account);
    let blob_login = seal(&w.prelogin, &login_id, &nonce, &plain_login.bytes())?;
    let blob_reauth = seal(&w.prelogin, &login_id, &nonce, &plain_reauth.bytes())?;
    assert_eq!(blob_login.len(), 244);

    let open_input = |secret: &[u8], id: &str, blob: &[u8], now: u64, expected: Value| {
        json!({
            "prelogin_secret": h(secret),
            "login_id": id,
            "blob": h(blob),
            "now": now.to_string(),
            "expected": expected,
        })
    };
    let seal_input = |secret: &[u8], plain: &Plain, now: u64| {
        json!({
            "prelogin_secret": h(secret),
            "login_id": login_id_hex,
            "now": now.to_string(),
            "state": plain_input(plain),
        })
    };
    let state_of = |plain: &Plain| json!({ "state": plain_input(plain) });

    // ---- state_seal
    for (key, plain, blob) in [
        ("login", &plain_login, &blob_login),
        ("reauth", &plain_reauth, &blob_reauth),
    ] {
        cases.push(known(
            &format!("server-secrets/state_seal/{key}"),
            "a sealed login state",
            "server.state_seal",
            seal_input(&w.prelogin, plain, NOW),
            std::slice::from_ref(&nonce),
            json!({ "blob": h(blob) }),
        ));
    }
    let long_lived = Plain {
        ksf_profile: 3,
        credential: pattern(0x01, 16),
        server_login: vec![0xff; 128],
        ..login_plain(u64::MAX - 1)
    };
    cases.push(known(
        "server-secrets/state_seal/other_fields",
        "other credential, profile, expiry and state bytes",
        "server.state_seal",
        seal_input(&other.prelogin, &long_lived, NOW),
        std::slice::from_ref(&nonce),
        json!({ "blob": h(&seal(&other.prelogin, &login_id, &nonce, &long_lived.bytes())?) }),
    ));
    let other_nonce = pattern(0x10, 24);
    cases.push(known(
        "server-secrets/state_seal/other_nonce",
        "another nonce gives another blob",
        "server.state_seal",
        seal_input(&w.prelogin, &plain_login, NOW),
        std::slice::from_ref(&other_nonce),
        json!({ "blob": h(&seal(&w.prelogin, &login_id, &other_nonce, &plain_login.bytes())?) }),
    ));
    for (key, now) in [("already_expired", expires), ("clock_failed", u64::MAX)] {
        cases.push(refused(
            &format!("server-secrets/state_seal/{key}"),
            "a state that is dead when it is made is not sealed",
            "server.state_seal",
            seal_input(&w.prelogin, &plain_login, now),
            &[],
            "internal",
        ));
    }

    // ---- state_open
    let login_expected = login_purpose();
    let reauth_expected = reauth_purpose(&session, &account);
    for (key, plain, blob, expected) in [
        ("login", &plain_login, &blob_login, login_expected.clone()),
        (
            "reauth",
            &plain_reauth,
            &blob_reauth,
            reauth_expected.clone(),
        ),
    ] {
        cases.push(known(
            &format!("server-secrets/state_open/{key}"),
            "a sealed state opens for the purpose it was made for",
            "server.state_open",
            open_input(&w.prelogin, &login_id_hex, blob, NOW + 10, expected),
            &[],
            state_of(plain),
        ));
    }
    cases.push(known(
        "server-secrets/state_open/last_second",
        "a state is valid until the second before its expiry",
        "server.state_open",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_login,
            expires - 1,
            login_expected.clone(),
        ),
        &[],
        state_of(&plain_login),
    ));
    let denied = |key: &str, title: &str, input: Value| {
        refused(
            &format!("server-secrets/state_open/{key}"),
            title,
            "server.state_open",
            input,
            &[],
            "denied",
        )
    };
    cases.push(denied(
        "expired",
        "a state at its expiry second",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_login,
            expires,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "other_login_id",
        "a blob under the id of another login",
        open_input(
            &w.prelogin,
            &hex_encode(&pattern(0x21, 16)),
            &blob_login,
            NOW,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "other_secret",
        "a blob under the key of another server",
        open_input(
            &other.prelogin,
            &login_id_hex,
            &blob_login,
            NOW,
            login_expected.clone(),
        ),
    ));
    for (key, at) in [
        ("version", 0usize),
        ("nonce", 5),
        ("ciphertext", 60),
        ("tag", 243),
    ] {
        cases.push(denied(
            &format!("changed_{key}"),
            "a changed bit in the blob",
            open_input(
                &w.prelogin,
                &login_id_hex,
                &flip(&blob_login, at),
                NOW,
                login_expected.clone(),
            ),
        ));
    }
    cases.push(denied(
        "version_2",
        "a blob of version 2",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &{
                let mut blob = blob_login.clone();
                blob[0] = 2;
                blob
            },
            NOW,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "blob_243_bytes",
        "a blob that is a byte short",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_login[..243],
            NOW,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "blob_245_bytes",
        "a blob with a byte after the tag",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &[blob_login.clone(), vec![0]].concat(),
            NOW,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "blob_empty",
        "an empty blob",
        open_input(&w.prelogin, &login_id_hex, &[], NOW, login_expected.clone()),
    ));
    cases.push(denied(
        "login_state_for_a_reauth",
        "a login state is not opened as a re-authentication",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_login,
            NOW,
            reauth_expected.clone(),
        ),
    ));
    cases.push(denied(
        "reauth_state_for_a_login",
        "a re-authentication state is not opened as a login",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_reauth,
            NOW,
            login_expected.clone(),
        ),
    ));
    cases.push(denied(
        "reauth_other_session",
        "a re-authentication state is for one session",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_reauth,
            NOW,
            reauth_purpose(&pattern(0x51, 32), &account),
        ),
    ));
    cases.push(denied(
        "reauth_other_account",
        "a re-authentication state is for one account",
        open_input(
            &w.prelogin,
            &login_id_hex,
            &blob_reauth,
            NOW,
            reauth_purpose(&session, &[0x43; 16]),
        ),
    ));
    // Blobs that are sealed correctly but hold something the reader refuses.
    let malformed = |key: &str, title: &str, plain: Vec<u8>| -> Result<Case, Error> {
        Ok(denied(
            key,
            title,
            open_input(
                &w.prelogin,
                &login_id_hex,
                &seal(&w.prelogin, &login_id, &nonce, &plain)?,
                NOW,
                login_expected.clone(),
            ),
        ))
    };
    let mut purpose_two = plain_login.bytes();
    purpose_two[8] = 2;
    cases.push(malformed(
        "plaintext_unknown_purpose",
        "an unknown purpose byte under a good seal",
        purpose_two,
    )?);
    let mut flag_set = plain_login.bytes();
    flag_set[9] = 1;
    cases.push(malformed(
        "plaintext_flag_without_reauth",
        "the binding flag on a login",
        flag_set,
    )?);
    let mut binding_set = plain_login.bytes();
    binding_set[10] = 1;
    cases.push(malformed(
        "plaintext_login_with_a_binding",
        "a login with a binding",
        binding_set,
    )?);
    let mut short = plain_login.bytes();
    short.pop();
    cases.push(malformed(
        "plaintext_short",
        "a plaintext a byte short",
        short,
    )?);
    let mut long = plain_login.bytes();
    long.push(0);
    cases.push(malformed(
        "plaintext_long",
        "a plaintext a byte long",
        long,
    )?);
    Ok(())
}

/// The states `login_start` really writes (the OPAQUE state inside is the
/// server's own, so the answer is recorded), opened. `xcheck` opens the same
/// blobs with the layout of `OPS.md` and must find the same account, profile,
/// expiry and purpose.
fn login_state_cases(cases: &mut Vec<Case>, w: &World) -> Result<(), Error> {
    let alice = register(w, CRED_ALICE, PASSWORD, "server vectors/alice")?;
    let (ke1, _) = ke1_of(&alice.password, "server vectors/alice login")?;
    let session = pattern(0x50, 32);
    let mut unknown = w.with(json!({
        "name": "nobody@example.com",
        "lookup": "unknown",
        "credential_id": h(&[0x99; 16]),
        "purpose": login_purpose(),
        "ke1": h(&ke1),
        "now": NOW.to_string(),
    }));
    let reauth = reauth_purpose(&session, &CRED_ALICE);
    let mut inputs = vec![
        (
            "login",
            known_start(w, &alice, "alice@example.com", &ke1, login_purpose(), false),
            login_purpose(),
        ),
        (
            "reauth",
            known_start(w, &alice, "alice@example.com", &ke1, reauth.clone(), false),
            reauth,
        ),
    ];
    unknown["lookup"] = json!("unknown");
    inputs.push(("unknown_name", unknown, login_purpose()));
    for (name, start_input, expected) in inputs {
        let draws = start_draws(&format!("server vectors/state/{name}"));
        let started = answer(&case(
            "login_start",
            "login_start",
            "server.login_start",
            start_input,
            &draws,
        ))?;
        cases.push(recorded(
            &format!("server-secrets/state_open/from_login_start_{name}"),
            "the state a login start wrote opens, with the layout of the register",
            "server.state_open",
            json!({
                "prelogin_secret": h(&w.prelogin),
                "login_id": started["login_id"],
                "blob": started["state_blob"],
                "now": (NOW + 5).to_string(),
                "expected": expected,
            }),
            &[],
        )?);
    }
    Ok(())
}
