//! Registration on the server, against the registration of the `ferret-core`
//! client.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use ferret_core::opaque::server_suite::{
    REGISTRATION_RECORD_LEN, REGISTRATION_REQUEST_LEN, REGISTRATION_RESPONSE_LEN,
};
use ferret_core::testing::keys::export_key_bytes;
use ferret_core::testing::opaque::{TestKsf, register_finish_with};
use ferret_core::{
    KdfParams, KsfProfile, MasterPassword, OpaqueInput, ReplayRng, SecureRng, TestRng,
    opaque_register_finish, opaque_register_start,
};
use ferret_server_auth::testing::register_start_open;
use ferret_server_auth::{
    AuthError, Caller, Capability, CredentialId, DenyReason, Malformed, Outcome, ProfileRules,
    RecordingThrottle, RegisterStartRequest, RegistrationKind, RetryAfter, ServerKeys,
    SessionScope, Stage, StoredRecord, ThrottleCall, ThrottleKey, ValidatedRecord, register_finish,
    register_start,
};

/// A few KiB: far below the floor, so that the tests run in milliseconds.
const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

const BAD_REQUEST: AuthError = AuthError::Malformed(Malformed::RegistrationRequest);
const BAD_RECORD: AuthError = AuthError::Malformed(Malformed::RegistrationRecord);

// ---------------------------------------------------------------- helpers

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn keys() -> ServerKeys {
    ServerKeys::generate(&mut rng("server keys")).unwrap()
}

fn id(n: u8) -> CredentialId {
    CredentialId::from_bytes([n; 16])
}

fn password(text: &str) -> OpaqueInput {
    MasterPassword::for_unlock(text.as_bytes())
        .unwrap()
        .opaque_input(None)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The 32 bytes of a request, as the client makes them.
fn request_for(text: &str, seed: &str) -> Vec<u8> {
    opaque_register_start(&mut rng(seed), &password(text))
        .unwrap()
        .0
}

/// A whole client registration against `register_start`: the request, the
/// server's response, the uploaded record and the export key.
struct Registration {
    request: Vec<u8>,
    response: Vec<u8>,
    record: Vec<u8>,
    export_key: [u8; 64],
}

/// `draws` replace the client's random source: the blind (64 bytes), then
/// the envelope nonce (32 bytes).
fn register_with_draws(
    keys: &ServerKeys,
    id: &CredentialId,
    text: &str,
    blind: &[u8; 64],
    nonce: &[u8; 32],
) -> Registration {
    let input = password(text);
    let mut client = ReplayRng::new(vec![blind.to_vec(), nonce.to_vec()]);
    let (request, state) = opaque_register_start(&mut client, &input).unwrap();
    let response = register_start_open(keys, id, &request).unwrap();
    let done =
        register_finish_with(&mut client, state, &input, &response, &TestKsf::new(SMALL)).unwrap();
    client.finish().unwrap();
    Registration {
        request,
        response,
        record: done.record,
        export_key: export_key_bytes(&done.export_key),
    }
}

fn register_plain(keys: &ServerKeys, id: &CredentialId, text: &str, seed: &str) -> Registration {
    let mut blind = [0u8; 64];
    let mut nonce = [0u8; 32];
    let mut source = rng(seed);
    source.fill(&mut blind);
    source.fill(&mut nonce);
    register_with_draws(keys, id, text, &blind, &nonce)
}

/// Byte strings that are not a ristretto255 element the protocol accepts.
fn invalid_points() -> Vec<[u8; 32]> {
    let all_ones = [0xffu8; 32];
    let negative = {
        let mut b = [0u8; 32];
        b[0] = 1; // s = 1 is negative (odd)
        b
    };
    let above_modulus = {
        let mut b = [0xffu8; 32];
        b[31] = 0x7f; // s = 2^255 - 1 is not below the field modulus
        b
    };
    let identity = [0u8; 32]; // decodes, but is refused as an OPRF input
    vec![all_ones, negative, above_modulus, identity]
}

// ---------------------------------------------------------- register_start

#[test]
fn register_start_is_deterministic_per_id() {
    let keys = keys();
    let request = request_for("correct horse", "client");
    let first = register_start_open(&keys, &id(1), &request).unwrap();
    assert_eq!(first.len(), REGISTRATION_RESPONSE_LEN);
    assert_eq!(register_start_open(&keys, &id(1), &request).unwrap(), first);
    assert_ne!(register_start_open(&keys, &id(2), &request).unwrap(), first);
    // Another request gives another answer for the same id.
    let other = request_for("correct horse", "another blind");
    assert_ne!(register_start_open(&keys, &id(1), &other).unwrap(), first);
    // The same keys restored from their file answer alike.
    let restored = ServerKeys::from_payload(&keys.payload()).unwrap();
    assert_eq!(
        register_start_open(&restored, &id(1), &request).unwrap(),
        first
    );
    // Other keys answer differently.
    let stranger = ServerKeys::generate(&mut rng("another server")).unwrap();
    assert_ne!(
        register_start_open(&stranger, &id(1), &request).unwrap(),
        first
    );
}

#[test]
fn register_start_matches_the_pinned_vector() {
    // The function takes no random source, so the same call twice cannot
    // differ. This pins the answer for fixed keys, id and request: the bytes
    // are the evaluated element and then the public key of the server.
    let keys = keys();
    let request = request_for("pinned", "pinned client");
    let response = register_start_open(&keys, &id(7), &request).unwrap();
    assert_eq!(hex(&request), PINNED_REQUEST);
    assert_eq!(hex(&response), PINNED_RESPONSE);
    assert_eq!(&response[32..], keys.public_key());
}

// Spec: Fase 1 § 4.2 ("Registrering", step 1). Synthetic keys: the server
// from TestRng("server keys"), the client from TestRng("pinned client").
//
// These bytes were produced by this code, so they are a regression pin and
// not an independent check: they catch a change in the answer, not a mistake
// that was there from the start. The OPRF itself is checked by
// `same_id_after_password_change_keeps_the_oprf_key` and by the client
// finishing the registration against the answer. Independent vectors come
// with the shared test vectors.
const PINNED_REQUEST: &str = "4e43ed1bfda05f44e21b852d4d10c6f40ff90ae54d5361f173946e786f06de6b";
const PINNED_RESPONSE: &str = "1263874e3ee78038bb4c5b6031d3c74f24010bd4c12d2c5492e22a9a1452a6583e5b4cd1a70c1d5fe1179a5d48b5332443df219fbde26258c64f9f61be339524";

#[test]
fn register_response_ends_with_server_public_key() {
    let keys = keys();
    for n in 0..8u8 {
        let request = request_for("pw", &format!("client {n}"));
        let response = register_start_open(&keys, &id(n), &request).unwrap();
        assert_eq!(response.len(), REGISTRATION_RESPONSE_LEN);
        assert_eq!(&response[32..], keys.public_key().as_slice());
        // The first half is the evaluated element, not the request.
        assert_ne!(&response[..32], request.as_slice());
    }
}

#[test]
fn register_start_rejects_every_length_except_32() {
    let keys = keys();
    let request = request_for("pw", "client");
    assert_eq!(request.len(), REGISTRATION_REQUEST_LEN);
    // Shorter: every prefix. Longer: the valid request with a tail, so only
    // the length can be the reason.
    let mut lengths: Vec<usize> = (0..=64).collect();
    lengths.push(1024 * 1024);
    for len in lengths {
        let mut input = request.clone();
        input.resize(len, 0);
        let result = register_start_open(&keys, &id(1), &input);
        if len == REGISTRATION_REQUEST_LEN {
            assert!(result.is_ok(), "length {len}");
        } else {
            assert_eq!(result.unwrap_err(), BAD_REQUEST, "length {len}");
        }
    }
    // The same with a request that is all zeros before the tail: still the
    // length, not the content.
    assert_eq!(
        register_start_open(&keys, &id(1), &[0u8; 33]).unwrap_err(),
        BAD_REQUEST
    );
}

#[test]
fn register_start_rejects_non_canonical_point() {
    let keys = keys();
    for point in invalid_points() {
        assert_eq!(
            register_start_open(&keys, &id(1), &point).unwrap_err(),
            BAD_REQUEST,
            "{}",
            hex(&point)
        );
    }
    // A flipped bit in a real request is either refused or answered, never a
    // panic.
    let request = request_for("pw", "client");
    for bit in 0..256 {
        let mut flipped = request.clone();
        flipped[bit / 8] ^= 1 << (bit % 8);
        match register_start_open(&keys, &id(1), &flipped) {
            Ok(response) => assert_eq!(response.len(), REGISTRATION_RESPONSE_LEN),
            Err(error) => assert_eq!(error, BAD_REQUEST),
        }
    }
}

#[test]
fn register_start_errors_depend_on_the_bytes_only() {
    // An error depends on the bytes alone: the same bytes fail the same way
    // for another id and for other keys.
    let (a, b) = (keys(), ServerKeys::generate(&mut rng("other")).unwrap());
    for point in invalid_points() {
        for (keys, n) in [(&a, 1u8), (&b, 2u8)] {
            assert_eq!(
                register_start_open(keys, &id(n), &point).unwrap_err(),
                BAD_REQUEST
            );
        }
    }
}

// --------------------------------------------------------- register_finish

#[test]
fn register_finish_accepts_a_real_client_record() {
    let keys = keys();
    let done = register_plain(&keys, &id(3), "a real password", "client");
    assert_eq!(done.record.len(), REGISTRATION_RECORD_LEN);
    let new = RegistrationKind::NewAccount;
    let stored = register_finish(&done.record, 1, &ProfileRules::ferret_v1(), new).unwrap();
    assert_eq!(stored.ksf_profile, 1);
    assert_eq!(stored.record.as_bytes(), done.record.as_slice());
    // The record is the same value that ValidatedRecord::parse gives.
    let parsed = ValidatedRecord::parse(&done.record).unwrap();
    assert_eq!(parsed.as_bytes(), stored.record.as_bytes());
}

/// The path of production: profile 1 with its real Argon2id parameters.
#[test]
fn register_finish_accepts_a_record_made_with_profile_one() {
    let keys = keys();
    let input = password("production path");
    let mut client = rng("client");
    let (request, state) = opaque_register_start(&mut client, &input).unwrap();
    let response = register_start_open(&keys, &id(4), &request).unwrap();
    let done =
        opaque_register_finish(&mut client, state, &input, &response, KsfProfile::P1).unwrap();
    assert_eq!(done.server_public_key, keys.public_key());
    let claimed = u32::from(KsfProfile::P1.number());
    let new = RegistrationKind::NewAccount;
    let stored = register_finish(&done.record, claimed, &ProfileRules::ferret_v1(), new).unwrap();
    assert_eq!(stored.ksf_profile, KsfProfile::P1.number());
    assert_eq!(stored.record.as_bytes(), done.record.as_slice());
}

#[test]
fn register_finish_rejects_191_and_193_bytes() {
    let keys = keys();
    let record = register_plain(&keys, &id(3), "pw", "client").record;
    let rules = ProfileRules::ferret_v1();
    let mut longer = record.clone();
    longer.push(0);
    let shorter = record[..REGISTRATION_RECORD_LEN - 1].to_vec();
    assert_eq!(shorter.len(), 191);
    assert_eq!(longer.len(), 193);
    for bad in [shorter, longer] {
        assert_eq!(
            register_finish(&bad, 1, &rules, RegistrationKind::NewAccount).unwrap_err(),
            BAD_RECORD
        );
        assert_eq!(ValidatedRecord::parse(&bad).unwrap_err(), BAD_RECORD);
    }
    // Every other length, the empty input and 1 MiB included.
    let mut lengths: Vec<usize> = (0..=256).filter(|n| *n != 192).collect();
    lengths.push(1024 * 1024);
    for len in lengths {
        let mut input = record.clone();
        input.resize(len, 0);
        assert_eq!(
            register_finish(&input, 1, &rules, RegistrationKind::NewAccount).unwrap_err(),
            BAD_RECORD,
            "length {len}"
        );
    }
}

#[test]
fn register_finish_rejects_an_invalid_public_key() {
    let keys = keys();
    let record = register_plain(&keys, &id(3), "pw", "client").record;
    let rules = ProfileRules::ferret_v1();
    for point in invalid_points() {
        let mut bad = record.clone();
        bad[..32].copy_from_slice(&point);
        assert_eq!(bad.len(), REGISTRATION_RECORD_LEN);
        assert_eq!(
            register_finish(&bad, 1, &rules, RegistrationKind::NewAccount).unwrap_err(),
            BAD_RECORD,
            "{}",
            hex(&point)
        );
    }
    // The rest of the record is opaque to the server: changing it is not
    // detectable and is accepted.
    let mut other = record.clone();
    other[100] ^= 1;
    assert!(register_finish(&other, 1, &rules, RegistrationKind::NewAccount).is_ok());
}

#[test]
fn register_finish_checks_the_record_before_the_profile() {
    let keys = keys();
    let record = register_plain(&keys, &id(3), "pw", "client").record;
    let rules = ProfileRules::ferret_v1();
    // A bad record with a bad profile is a bad record, whatever is stored.
    for current in [
        RegistrationKind::NewAccount,
        RegistrationKind::Existing(1),
        RegistrationKind::Existing(200),
    ] {
        assert_eq!(
            register_finish(&record[..191], 99, &rules, current).unwrap_err(),
            BAD_RECORD
        );
    }
    // A good record with a bad profile is a rejected profile.
    assert_eq!(
        register_finish(&record, 99, &rules, RegistrationKind::NewAccount).unwrap_err(),
        AuthError::ProfileRejected
    );
}

// ------------------------------------------------------------ ProfileRules

#[test]
fn profile_rules_refuse_unknown_profiles() {
    let rules = ProfileRules::ferret_v1();
    // 0, 2 (not in the table of the client yet), 255 and numbers that do not
    // fit a byte.
    for claimed in [0u32, 2, 3, 255, 256, 257, 65_537, u32::MAX] {
        assert_eq!(
            rules
                .accept(claimed, RegistrationKind::NewAccount)
                .unwrap_err(),
            AuthError::ProfileRejected,
            "{claimed}"
        );
    }
    assert_eq!(rules.accept(1, RegistrationKind::NewAccount), Ok(1));
    // A number that wraps to a known one in a byte is still unknown.
    assert_eq!(
        rules
            .accept(1 + 256, RegistrationKind::NewAccount)
            .unwrap_err(),
        AuthError::ProfileRejected
    );
}

#[test]
fn profile_rules_match_the_table_of_the_client() {
    let rules = ProfileRules::ferret_v1();
    for n in 0..=300u32 {
        let known = KsfProfile::from_wire(n).is_ok();
        assert_eq!(
            rules.accept(n, RegistrationKind::NewAccount).is_ok(),
            known,
            "{n}"
        );
    }
}

#[test]
fn profile_rules_refuse_below_the_minimum() {
    let rules = ProfileRules::for_tests(&[1, 2, 3], 2);
    assert_eq!(
        rules.accept(1, RegistrationKind::NewAccount).unwrap_err(),
        AuthError::ProfileRejected
    );
    assert_eq!(rules.accept(2, RegistrationKind::NewAccount), Ok(2));
    assert_eq!(rules.accept(3, RegistrationKind::NewAccount), Ok(3));
    // The minimum applies to an existing account as well.
    assert_eq!(
        rules.accept(1, RegistrationKind::Existing(1)).unwrap_err(),
        AuthError::ProfileRejected
    );
}

#[test]
fn profile_rules_refuse_below_the_current_profile() {
    let rules = ProfileRules::for_tests(&[1, 2, 3], 1);
    assert_eq!(
        rules.accept(1, RegistrationKind::Existing(2)).unwrap_err(),
        AuthError::ProfileRejected
    );
    assert_eq!(
        rules.accept(2, RegistrationKind::Existing(3)).unwrap_err(),
        AuthError::ProfileRejected
    );
    // Equal and higher are accepted.
    assert_eq!(rules.accept(2, RegistrationKind::Existing(2)), Ok(2));
    assert_eq!(rules.accept(3, RegistrationKind::Existing(2)), Ok(3));
    assert_eq!(rules.accept(1, RegistrationKind::Existing(1)), Ok(1));
    // An unknown number stays refused whatever is stored.
    assert_eq!(
        rules.accept(4, RegistrationKind::Existing(1)).unwrap_err(),
        AuthError::ProfileRejected
    );
}

#[test]
fn a_downgrade_is_refused_for_an_existing_account_and_not_for_a_new_one() {
    let rules = ProfileRules::for_tests(&[1, 2, 3], 1);
    // The same claim: allowed for a new account, refused once the account is
    // known to have a higher profile. The caller has to say which it is.
    assert_eq!(rules.accept(1, RegistrationKind::NewAccount), Ok(1));
    for stored in [2u8, 3] {
        assert_eq!(
            rules.accept(1, RegistrationKind::Existing(stored)),
            Err(AuthError::ProfileRejected),
            "stored {stored}"
        );
    }
    // The same through register_finish.
    let record = register_plain(&keys(), &id(3), "pw", "client").record;
    assert!(register_finish(&record, 1, &rules, RegistrationKind::NewAccount).is_ok());
    assert_eq!(
        register_finish(&record, 1, &rules, RegistrationKind::Existing(2)).unwrap_err(),
        AuthError::ProfileRejected
    );
    assert!(register_finish(&record, 2, &rules, RegistrationKind::Existing(2)).is_ok());
}

#[test]
fn profile_rules_with_an_empty_table_refuse_everything() {
    let rules = ProfileRules::for_tests(&[], 1);
    for claimed in [0u32, 1, 2, 255] {
        assert!(rules.accept(claimed, RegistrationKind::NewAccount).is_err());
    }
    // A minimum above every known number does the same.
    let high = ProfileRules::for_tests(&[1, 2], 3);
    for claimed in [1u32, 2, 3] {
        assert!(high.accept(claimed, RegistrationKind::NewAccount).is_err());
    }
}

// ---------------------------------------------------------- the OPRF key

/// The credential identifier is the account id (Fase 1 § 4.2), so the OPRF
/// key of an account is the same for every registration under that id. A
/// change of password does not rotate it.
///
/// The client's randomness is replayed: the same envelope nonce and a
/// different blind each time. The record and the export key depend on the
/// password, the nonce and the OPRF key alone, so they can only be equal when
/// the OPRF key was.
#[test]
fn same_id_after_password_change_keeps_the_oprf_key() {
    let keys = keys();
    let (blind_a, blind_b, blind_c) = ([1u8; 64], [2u8; 64], [3u8; 64]);
    let nonce = [9u8; 32];

    let before = register_with_draws(&keys, &id(5), "first password", &blind_a, &nonce);
    // The password changes under the same id.
    let changed = register_with_draws(&keys, &id(5), "second password", &blind_b, &nonce);
    assert_ne!(changed.record, before.record);
    assert_ne!(changed.export_key, before.export_key);
    // The old password again, with a new blind: the same record and key.
    let again = register_with_draws(&keys, &id(5), "first password", &blind_c, &nonce);
    assert_ne!(again.request, before.request);
    assert_ne!(again.response, before.response);
    assert_eq!(again.record, before.record);
    assert_eq!(again.export_key, before.export_key);

    // Another id gets another OPRF key, so another record for the same
    // password and nonce.
    let other = register_with_draws(&keys, &id(6), "first password", &blind_c, &nonce);
    assert_ne!(other.record, before.record);
    assert_ne!(other.export_key, before.export_key);
}

// ---------------------------------------------------------------- hygiene

#[test]
fn debug_output_shows_no_record_bytes() {
    let keys = keys();
    let record = register_plain(&keys, &id(3), "pw", "client").record;
    let new = RegistrationKind::NewAccount;
    let stored: StoredRecord =
        register_finish(&record, 1, &ProfileRules::ferret_v1(), new).unwrap();
    let shown = [
        format!("{:?}", stored),
        format!("{:?}", stored.record),
        format!("{:#?}", stored.record),
        format!("{:?}", ProfileRules::ferret_v1()),
    ];
    for text in shown {
        assert!(!text.contains(&hex(&record[..8])), "{text}");
        assert!(!text.contains(&format!("{:?}", &record[..8])), "{text}");
        assert!(text.len() < 60, "{text}");
    }
    assert!(format!("{:?}", stored.record).contains("redacted"));
}

// ------------------------------------------- throttle, scope and account

const NOW: u64 = 1_700_000_000;
const FORBIDDEN: AuthError = AuthError::Denied(DenyReason::ScopeForbids);

fn caller() -> Caller {
    Caller {
        ip: Some("192.0.2.7".parse().unwrap()),
    }
}

fn start_request<'a>(
    scope: SessionScope,
    session_account: Option<CredentialId>,
    credential: CredentialId,
    request: &'a [u8],
) -> RegisterStartRequest<'a> {
    RegisterStartRequest {
        caller: caller(),
        scope,
        session_account,
        credential,
        request,
    }
}

#[test]
fn register_start_asks_the_throttle_before_any_work() {
    let keys = keys();
    let good = request_for("correct horse", "client");
    let wait = RetryAfter::new(42);

    // A refusing throttle stops the request before the request is looked at:
    // a request that is not even well formed is answered with the wait, and
    // the throttle sees one admit and nothing else.
    for request in [good.as_slice(), &[1u8; 5][..], &[][..]] {
        let throttle = RecordingThrottle::refusing(wait);
        let req = start_request(SessionScope::Full, None, id(1), request);
        let error = register_start(&keys, &throttle, NOW, &req).unwrap_err();
        assert_eq!(
            error,
            AuthError::Throttled {
                retry_after_secs: 42
            }
        );
        let calls = throttle.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        match &calls[0] {
            ThrottleCall::Admit { stage, keys, now } => {
                assert_eq!(*stage, Stage::RegisterStart);
                assert_eq!(*now, NOW);
                // The keys of the stage: the address and the account.
                assert_eq!(
                    keys,
                    &[
                        ThrottleKey::Ip("192.0.2.7".parse().unwrap()),
                        ThrottleKey::Account(id(1)),
                    ]
                );
            }
            other @ ThrottleCall::Record { .. } => panic!("{other:?}"),
        }
    }
}

#[test]
fn register_start_reports_its_outcome_once() {
    let keys = keys();
    let good = request_for("correct horse", "client");

    let throttle = RecordingThrottle::new();
    let req = start_request(SessionScope::Full, None, id(1), &good);
    register_start(&keys, &throttle, NOW, &req).unwrap();
    let outcomes = recorded(&throttle);
    assert_eq!(outcomes, [None, Some(Outcome::Success)]);

    // A request that is admitted and then found malformed is a failure.
    let throttle = RecordingThrottle::new();
    let req = start_request(SessionScope::Full, None, id(1), &good[..31]);
    assert_eq!(
        register_start(&keys, &throttle, NOW, &req).unwrap_err(),
        BAD_REQUEST
    );
    assert_eq!(recorded(&throttle), [None, Some(Outcome::Failure)]);
}

/// The calls in order: `None` for an admit, the outcome for a record.
fn recorded(throttle: &RecordingThrottle) -> Vec<Option<Outcome>> {
    throttle
        .calls()
        .iter()
        .map(|call| match call {
            ThrottleCall::Admit { stage, .. } => {
                assert_eq!(*stage, Stage::RegisterStart);
                None
            }
            ThrottleCall::Record { stage, outcome, .. } => {
                assert_eq!(*stage, Stage::RegisterStart);
                Some(*outcome)
            }
        })
        .collect()
}

#[test]
fn register_start_needs_a_scope_that_allows_it() {
    let keys = keys();
    let request = request_for("correct horse", "client");
    for scope in [
        SessionScope::Full,
        SessionScope::Pending2fa,
        SessionScope::AccountReset,
        SessionScope::Unverified,
    ] {
        let throttle = RecordingThrottle::new();
        // The session's own account, so only the scope can refuse.
        let req = start_request(scope, Some(id(1)), id(1), &request);
        let result = register_start(&keys, &throttle, NOW, &req);
        if scope.allows(Capability::OpaqueRegisterStart) {
            assert_eq!(
                result.unwrap().len(),
                REGISTRATION_RESPONSE_LEN,
                "{scope:?}"
            );
        } else {
            // Refused before the throttle is asked: no budget is used.
            assert_eq!(result.unwrap_err(), FORBIDDEN, "{scope:?}");
            assert!(throttle.calls().is_empty(), "{scope:?}");
        }
    }
}

#[test]
fn a_reset_session_may_register_for_its_own_account_only() {
    let keys = keys();
    let request = request_for("correct horse", "client");
    let own = id(1);
    let other = id(2);

    let throttle = RecordingThrottle::new();
    let req = start_request(SessionScope::AccountReset, Some(own), own, &request);
    let response = register_start(&keys, &throttle, NOW, &req).unwrap();
    assert_eq!(response.len(), REGISTRATION_RESPONSE_LEN);

    // Another account, or no account for the session: refused, and the
    // throttle is not asked.
    let throttle = RecordingThrottle::new();
    for session_account in [Some(own), None, Some(other)] {
        let credential = if session_account == Some(other) {
            own
        } else {
            other
        };
        let req = start_request(
            SessionScope::AccountReset,
            session_account,
            credential,
            &request,
        );
        assert_eq!(
            register_start(&keys, &throttle, NOW, &req).unwrap_err(),
            FORBIDDEN,
            "{session_account:?}"
        );
    }
    assert!(throttle.calls().is_empty());

    // Every other id differing in one byte is refused, too.
    for byte in 0..16 {
        let mut near = *own.as_bytes();
        near[byte] ^= 1;
        let req = start_request(
            SessionScope::AccountReset,
            Some(own),
            CredentialId::from_bytes(near),
            &request,
        );
        assert_eq!(
            register_start(&keys, &throttle, NOW, &req).unwrap_err(),
            FORBIDDEN
        );
    }
}

#[test]
fn a_full_session_is_not_tied_to_one_account_by_the_library() {
    // The endpoint decides which account a full session may change; the
    // answer for another id is an ordinary one (it is made from the keys, the
    // id and the request, and finishing it needs a signed request).
    let keys = keys();
    let request = request_for("correct horse", "client");
    let req = start_request(SessionScope::Full, Some(id(1)), id(2), &request);
    let throttle = RecordingThrottle::new();
    let response = register_start(&keys, &throttle, NOW, &req).unwrap();
    assert_eq!(
        response,
        register_start_open(&keys, &id(2), &request).unwrap()
    );
}

#[test]
fn a_recovery_may_set_a_lower_profile_than_the_stored_one() {
    // The rules of the tests: profiles 1 and 2, with 1 as the lowest.
    let rules = ProfileRules::for_tests(&[1, 2], 1);
    // A password change or an upgrade from profile 2 may not claim 1.
    assert_eq!(
        rules.accept(1, RegistrationKind::Existing(2)).unwrap_err(),
        AuthError::ProfileRejected
    );
    // A recovery may: it does not read the stored profile.
    assert_eq!(rules.accept_recovery(1), Ok(1));
    assert_eq!(rules.accept_recovery(2), Ok(2));
    // The table and the minimum still apply.
    for claimed in [0, 3, 255, 256, u32::MAX] {
        assert_eq!(
            rules.accept_recovery(claimed).unwrap_err(),
            AuthError::ProfileRejected,
            "{claimed}"
        );
    }
    let floor = ProfileRules::for_tests(&[1, 2, 3], 2);
    assert_eq!(
        floor.accept_recovery(1).unwrap_err(),
        AuthError::ProfileRejected
    );
    assert_eq!(floor.accept_recovery(2), Ok(2));
    // The real client knows profile 1 only.
    assert_eq!(ProfileRules::ferret_v1().accept_recovery(1), Ok(1));
    assert_eq!(
        ProfileRules::ferret_v1().accept_recovery(2).unwrap_err(),
        AuthError::ProfileRejected
    );
}
