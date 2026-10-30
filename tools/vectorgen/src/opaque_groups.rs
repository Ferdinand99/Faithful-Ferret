//! The vector group for the OPAQUE client (`opaque.json`): registration and
//! login with profile 1, and what the client refuses.
//!
//! Unlike the other groups, the expected values here are recorded from the
//! core: OPAQUE cannot be worked out by hand. What ties the file to the
//! standard is the RFC 9807 test (`tests/opaque_rfc9807.rs`), which runs the
//! very same client code on the published vectors; this file fixes the
//! Ferret configuration on top of it (profile 1 Argon2id with 16 zero bytes
//! of salt, context `ferret/v1/opaque`, no identities, the NFKD password with
//! and without the secret key) and the randomness the client draws, so that
//! every binding (Node, browsers, later Swift and Kotlin) must give the same
//! bytes. The server half of each exchange is `opaque-ke`'s server with a
//! deterministic setup; its answers are inputs of the cases, not outputs.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::testing::opaque::Server;
use ferret_core::testing::vector::{Case, FORMAT, Tag, VectorFile};
use ferret_core::testing::{TestRng, hex_encode};
use ferret_core::{
    KsfProfile, LoginState, MasterPassword, OpaqueInput, SecretKey, SecureRng, opaque_login_finish,
    opaque_login_start, opaque_register_finish, opaque_register_start,
};
use serde_json::{Value, json};

const CRED: &[u8] = b"0123456789abcdef";

/// Records the draws of a generator, so that a case can list them.
pub(crate) struct Recording {
    inner: TestRng,
    pub(crate) draws: Vec<String>,
}

impl Recording {
    pub(crate) fn new(seed: &str) -> Self {
        Self {
            inner: TestRng::new(seed.as_bytes()),
            draws: vec![],
        }
    }
}

impl SecureRng for Recording {
    fn fill(&mut self, dest: &mut [u8]) {
        self.inner.fill(dest);
        self.draws.push(hex_encode(dest));
    }
}

/// One account of the file: a password, an optional secret key and the
/// registration on a server.
struct Acct {
    password: String,
    sk: Option<[u8; 16]>,
    server: Server,
    server_key: [u8; 32],
    record: Vec<u8>,
    export_key: [u8; 64],
    reg_response: Vec<u8>,
    reg_rng: Vec<String>,
    reg_request: Vec<u8>,
}

fn input_of(password: &str, sk: Option<[u8; 16]>) -> Result<OpaqueInput, Error> {
    let mp = MasterPassword::for_unlock(password.as_bytes()).map_err(|e| e.code())?;
    Ok(mp.opaque_input(sk.map(SecretKey::from_test_bytes).as_ref()))
}

fn account(
    seed: &str,
    password: &str,
    sk: Option<[u8; 16]>,
    context: Option<&[u8]>,
) -> Result<Acct, Error> {
    let mut server = Server::new(&mut TestRng::new(
        format!("opaque/{seed}/server").as_bytes(),
    ));
    if let Some(c) = context {
        server = server.with_context(c);
    }
    let pw = input_of(password, sk)?;
    let mut rng = Recording::new(&format!("opaque/{seed}/client"));
    let (request, state) = opaque_register_start(&mut rng, &pw).map_err(|e| e.code())?;
    let response = server
        .register_response(CRED, &request)
        .map_err(|e| e.code())?;
    let done = opaque_register_finish(&mut rng, state, &pw, &response, KsfProfile::P1)
        .map_err(|e| e.code())?;
    Ok(Acct {
        password: password.into(),
        sk,
        server_key: server.public_key(),
        server,
        record: done.record,
        export_key: ferret_core::testing::keys::export_key_bytes(&done.export_key),
        reg_response: response,
        reg_rng: rng.draws,
        reg_request: request,
    })
}

/// The input of an `opaque.login` case.
fn login_input(
    password: &str,
    sk: Option<[u8; 16]>,
    ke2: &[u8],
    server_profile: u32,
    pinned: Option<Value>,
) -> Value {
    json!({
        "password": password,
        "password_hex": hex_encode(password.as_bytes()),
        "secret_key": sk.map(|k| hex_encode(&k)),
        "server_profile": server_profile,
        "ke2": hex_encode(ke2),
        "pinned": pinned,
    })
}

/// `KE1` and the draws of a login start for `password`, and the server's
/// `KE2` for a server login on `acct` (or a fake record).
struct Round {
    ke2: Vec<u8>,
    ke1: Vec<u8>,
    draws: Vec<String>,
}

fn round(
    seed: &str,
    acct: &Acct,
    password: &str,
    sk: Option<[u8; 16]>,
    fake: bool,
) -> Result<Round, Error> {
    let pw = input_of(password, sk)?;
    let mut rng = Recording::new(&format!("opaque/{seed}/client"));
    let (ke1, _state): (Vec<u8>, LoginState) =
        opaque_login_start(&mut rng, &pw).map_err(|e| e.code())?;
    let mut srng = TestRng::new(format!("opaque/{seed}/server-login").as_bytes());
    let record = if fake {
        None
    } else {
        Some(acct.record.as_slice())
    };
    let (ke2, _s) = acct
        .server
        .login_start(&mut srng, record, CRED, &ke1)
        .map_err(|e| e.code())?;
    Ok(Round {
        ke2,
        ke1,
        draws: rng.draws,
    })
}

/// `KE3`, the export key and the server public key of a finished login.
type LoginOutcome = (Vec<u8>, [u8; 64], [u8; 32]);

/// Runs the production login on a round's draws to record the outcome.
fn run_login(
    r: &Round,
    password: &str,
    sk: Option<[u8; 16]>,
    server_profile: u32,
    pin: ferret_core::PinState<'_>,
) -> Result<LoginOutcome, ferret_core::Error> {
    let pw = input_of(password, sk).map_err(|_| ferret_core::Error::Unsupported)?;
    let mut replay = ferret_core::testing::ReplayRng::new(
        r.draws
            .iter()
            .map(|d| ferret_core::testing::hex_decode(d).unwrap_or_default())
            .collect(),
    );
    let (_ke1, state) = opaque_login_start(&mut replay, &pw)?;
    let done = opaque_login_finish(&mut replay, state, &pw, &r.ke2, server_profile, pin)?;
    Ok((
        done.ke3,
        ferret_core::testing::keys::export_key_bytes(&done.export_key),
        done.server_public_key,
    ))
}

fn pinned_record(profile: u8, sk_bit: bool, server_key: Option<[u8; 32]>) -> ferret_core::Pinned {
    ferret_core::Pinned {
        server_url: "https://ferret.example".into(),
        account_id: ferret_core::AccountId::from_bytes([0x11; 16]),
        vault_id: ferret_core::VaultId::from_bytes([0x22; 16]),
        ksf_profile: profile,
        kek_generation_max: vec![],
        vk_epoch_max: 1,
        sk_bit,
        pk_a: [7; 32],
        server_public_key: server_key,
    }
}

fn pinned_json(profile: u8, sk_bit: bool, server_key: Option<[u8; 32]>) -> Value {
    json!({
        "ksf_profile": profile,
        "sk_bit": sk_bit,
        "server_public_key": server_key.map(|k| hex_encode(&k)),
    })
}

fn with_rng(mut case: Case, draws: &[String], slow: bool) -> Case {
    case.rng = draws.to_vec();
    if slow {
        case.tags = vec![Tag::Slow];
    }
    case
}

pub(crate) fn opaque() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();

    let pw_a = "correct horse battery staple";
    // Decomposed a + ring above and o + diaeresis: NFKD keeps them as they
    // are; the composed forms must give the same bytes, which `kdf.json`
    // already checks for the input.
    let pw_b = "a\u{30a}ndr\u{e9}s \u{c6}\u{d8}\u{c5} pass\u{2460}";
    let sk_b: [u8; 16] = [0x5a; 16];
    let a = account("a", pw_a, None, None)?;
    let b = account("b", pw_b, Some(sk_b), None)?;
    let other_ctx = account("ctx", pw_a, None, Some(b"ferret/v1/other"))?;

    // ---- registration
    for (n, title, acct) in [
        ("001", "register, no secret key", &a),
        ("002", "register, NFKD password with a secret key", &b),
    ] {
        let input = json!({
            "password": acct.password,
            "password_hex": hex_encode(acct.password.as_bytes()),
            "secret_key": acct.sk.map(|k| hex_encode(&k)),
            "ksf_profile": 1,
            "response": hex_encode(&acct.reg_response),
        });
        let expect = json!({
            "request": hex_encode(&acct.reg_request),
            "record": hex_encode(&acct.record),
            "export_key": hex_encode(&acct.export_key),
            "server_public_key": hex_encode(&acct.server_key),
        });
        cases.push(with_rng(
            valid_case(
                &format!("opaque/register/{n}"),
                title,
                "opaque.register",
                vec![],
                input,
                expect,
            ),
            &acct.reg_rng,
            true,
        ));
    }
    // An unknown profile number is not a registration input: the profile is
    // typed. The wire number is checked at login (below).

    // ---- login, valid
    let ok_a = round("a/login", &a, pw_a, None, false)?;
    let (ke3, export_key, server_key) =
        run_login(&ok_a, pw_a, None, 1, ferret_core::PinState::FirstUse)
            .map_err(|e| format!("login a: {}", e.code()))?;
    assert_eq!(export_key, a.export_key, "login and registration agree");
    let login_expect = |round: &Round, ke3: &[u8], export_key: &[u8; 64], server_key: &[u8; 32]| {
        json!({
            "ke1": hex_encode(&round.ke1),
            "ke3": hex_encode(ke3),
            "export_key": hex_encode(export_key),
            "server_public_key": hex_encode(server_key),
        })
    };
    cases.push(with_rng(
        valid_case(
            "opaque/login/001",
            "login, no secret key",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &ok_a.ke2, 1, None),
            login_expect(&ok_a, &ke3, &export_key, &server_key),
        ),
        &ok_a.draws,
        true,
    ));

    let ok_b = round("b/login", &b, pw_b, Some(sk_b), false)?;
    let (ke3_b, export_b, server_key_b) =
        run_login(&ok_b, pw_b, Some(sk_b), 1, ferret_core::PinState::FirstUse)
            .map_err(|e| format!("login b: {}", e.code()))?;
    assert_eq!(export_b, b.export_key);
    cases.push(with_rng(
        valid_case(
            "opaque/login/002",
            "login, NFKD password with a secret key",
            "opaque.login",
            vec![],
            login_input(pw_b, Some(sk_b), &ok_b.ke2, 1, None),
            login_expect(&ok_b, &ke3_b, &export_b, &server_key_b),
        ),
        &ok_b.draws,
        true,
    ));

    // The pinned record agrees: same result as 001 (slow).
    cases.push(with_rng(
        valid_case(
            "opaque/login/003",
            "login with a pinned record that agrees (profile, SK bit, server key)",
            "opaque.login",
            vec![],
            login_input(
                pw_a,
                None,
                &ok_a.ke2,
                1,
                Some(pinned_json(1, false, Some(a.server_key))),
            ),
            login_expect(&ok_a, &ke3, &export_key, &server_key),
        ),
        &ok_a.draws,
        true,
    ));

    // ---- login, authentication failures: one error for all
    let wrong_pw = "correct horse battery stapl3";
    let r = round("a/wrong-pw", &a, wrong_pw, None, false)?;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/004",
            "wrong password",
            "opaque.login",
            vec![],
            login_input(wrong_pw, None, &r.ke2, 1, None),
            "decrypt",
        ),
        &r.draws,
        true,
    ));
    let r = round("b/wrong-sk", &b, pw_b, Some([0x5b; 16]), false)?;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/005",
            "right password, wrong secret key",
            "opaque.login",
            vec![],
            login_input(pw_b, Some([0x5b; 16]), &r.ke2, 1, None),
            "decrypt",
        ),
        &r.draws,
        true,
    ));
    let r = round("b/no-sk", &b, pw_b, None, false)?;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/006",
            "right password, secret key left out",
            "opaque.login",
            vec![],
            login_input(pw_b, None, &r.ke2, 1, None),
            "decrypt",
        ),
        &r.draws,
        true,
    ));
    // The server's KE2 with the last byte (the MAC) changed.
    let mut bad = ok_a.ke2.clone();
    if let Some(last) = bad.last_mut() {
        *last ^= 0x01;
    }
    cases.push(with_rng(
        invalid_case(
            "opaque/login/007",
            "KE2 with the server MAC changed",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &bad, 1, None),
            "decrypt",
        ),
        &ok_a.draws,
        true,
    ));
    // The masked response (the server key and the envelope) changed.
    let mut bad = ok_a.ke2.clone();
    if let Some(byte) = bad.get_mut(70) {
        *byte ^= 0x80;
    }
    cases.push(with_rng(
        invalid_case(
            "opaque/login/008",
            "KE2 with a byte of the masked response changed",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &bad, 1, None),
            "decrypt",
        ),
        &ok_a.draws,
        true,
    ));
    // A server that uses another context.
    let r = round("ctx/login", &other_ctx, pw_a, None, false)?;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/009",
            "server with another context (ferret/v1/other)",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &r.ke2, 1, None),
            "decrypt",
        ),
        &r.draws,
        true,
    ));
    // An account the server does not know: it answers with a fake record.
    let r = round("a/fake", &a, pw_a, None, true)?;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/010",
            "unknown account (the server's fake record)",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &r.ke2, 1, None),
            "decrypt",
        ),
        &r.draws,
        true,
    ));

    // ---- login, refused before Argon2id
    for (n, title, profile) in [
        ("011", "server states profile 2 (unknown)", 2u32),
        ("012", "server states profile 0 (unknown)", 0),
        (
            "013",
            "server states profile 4294967295 (unknown)",
            u32::MAX,
        ),
    ] {
        cases.push(with_rng(
            invalid_case(
                &format!("opaque/login/{n}"),
                title,
                "opaque.login",
                vec![],
                login_input(pw_a, None, &ok_a.ke2, profile, None),
                "kdf_profile_unknown",
            ),
            &ok_a.draws,
            false,
        ));
    }
    cases.push(with_rng(
        invalid_case(
            "opaque/login/014",
            "profile 1 against a device that pinned profile 2",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &ok_a.ke2, 1, Some(pinned_json(2, false, None))),
            "kdf_profile_downgrade",
        ),
        &ok_a.draws,
        false,
    ));
    cases.push(with_rng(
        invalid_case(
            "opaque/login/015",
            "no secret key where the device pinned an account with one",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &ok_a.ke2, 1, Some(pinned_json(1, true, None))),
            "pinned_sk_bit",
        ),
        &ok_a.draws,
        false,
    ));
    cases.push(with_rng(
        invalid_case(
            "opaque/login/016",
            "secret key where the device pinned an account without one",
            "opaque.login",
            vec![],
            login_input(
                pw_b,
                Some(sk_b),
                &ok_b.ke2,
                1,
                Some(pinned_json(1, false, None)),
            ),
            "pinned_sk_bit",
        ),
        &ok_b.draws,
        false,
    ));
    // The server shows another OPAQUE key than the pinned one: found after the
    // envelope opens, so the stretching has run.
    let mut other_key = a.server_key;
    other_key[0] ^= 0x01;
    cases.push(with_rng(
        invalid_case(
            "opaque/login/017",
            "server public key differs from the pinned one",
            "opaque.login",
            vec![],
            login_input(
                pw_a,
                None,
                &ok_a.ke2,
                1,
                Some(pinned_json(1, false, Some(other_key))),
            ),
            "pinned_server_key",
        ),
        &ok_a.draws,
        true,
    ));

    // ---- login, malformed
    let short = &ok_a.ke2[..ok_a.ke2.len() - 1];
    cases.push(with_rng(
        invalid_case(
            "opaque/login/018",
            "KE2 one byte short",
            "opaque.login",
            vec![],
            login_input(pw_a, None, short, 1, None),
            "malformed_opaque_message",
        ),
        &ok_a.draws,
        false,
    ));
    let mut long = ok_a.ke2.clone();
    long.push(0);
    cases.push(with_rng(
        invalid_case(
            "opaque/login/019",
            "KE2 one byte long",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &long, 1, None),
            "malformed_opaque_message",
        ),
        &ok_a.draws,
        false,
    ));
    let mut bad_point = ok_a.ke2.clone();
    bad_point[..32].copy_from_slice(&[0xee; 32]);
    cases.push(with_rng(
        invalid_case(
            "opaque/login/020",
            "KE2 whose evaluated element is not a group element",
            "opaque.login",
            vec![],
            login_input(pw_a, None, &bad_point, 1, None),
            "malformed_opaque_message",
        ),
        &ok_a.draws,
        false,
    ));

    // The pinned helper is also used to check the cases at generation time.
    let pin_ok = pinned_record(1, false, Some(a.server_key));
    run_login(&ok_a, pw_a, None, 1, ferret_core::PinState::Pinned(&pin_ok))
        .map_err(|e| format!("pinned login: {}", e.code()))?;

    render(&VectorFile {
        format: FORMAT.into(),
        group: "opaque".into(),
        suite: 1,
        spec: "Fase 1 § 4.1, § 4.2 and plan U1, U19; RFC 9807".into(),
        generator: generator(),
        cases,
    })
}
