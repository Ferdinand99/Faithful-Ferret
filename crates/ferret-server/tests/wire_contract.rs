//! The wire contract: the JSON shapes of the server API, as the fixtures in
//! `tests/fixtures/wire/` write them, and the inputs in `invalid.json` that
//! must be refused. `web/test/unit/wire.test.mjs` reads the same files.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use ferret_server::error::ApiError;
use ferret_server::wire::{
    self, BatchOpForm, BatchOpJson, BatchReq, BatchRes, BatchResultJson, CHECKPOINT_ENTRY_LEN,
    ChangeJson, ChangesRes, CheckpointHeadJson, CheckpointJson, CheckpointPutRes,
    CheckpointStaleRes, ConflictRes, ERROR_CODES, ErrorRes, HandoffRedeemRes, HandoffReq,
    HandoffRes, ItemsRes, LoginFinishReq, LoginFinishRes, LoginPurposeJson, LoginStartReq,
    LoginStartRes, MAX_BATCH_BYTES, MAX_BATCH_OPS, MAX_CHECKPOINT_ENTRIES, MethodsRes, PutItemForm,
    PutItemReq, PutItemRes, RedeemReq, RegisterFinishReq, RegisterFinishRes, RegisterStartReq,
    RegisterStartRes, SealedRowJson, SessionRes, SyncEventJson, WireError, WrapJson, b64url, hex16,
    parse_handoff_code, refusal_code,
};
use ferret_server_auth::{AuthError, DenyReason, Malformed};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wire")
}

fn read(name: &str) -> String {
    fs::read_to_string(dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn parse<T: DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(&read(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn json_of(name: &str) -> Value {
    serde_json::from_str(&read(name)).unwrap()
}

/// Files in the directory that are not fixtures of one shape.
const NOT_SHAPES: &[&str] = &[
    "headers.json",
    "generate.mjs",
    "error_codes.json",
    "error_statuses.json",
    "invalid.json",
];

/// All fixture files: (file name, shape name before the first dot).
fn fixtures() -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = fs::read_dir(dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| !NOT_SHAPES.contains(&name.as_str()))
        .map(|name| {
            let shape = name.split('.').next().unwrap().to_string();
            (name, shape)
        })
        .collect();
    out.sort();
    out
}

/// Reads `text` as `T` and writes it back.
fn through<T: DeserializeOwned + Serialize>(text: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(&serde_json::from_str::<T>(text)?)
}

/// Reads and writes `text` as the shape `shape`.
fn round_trip(shape: &str, text: &str) -> Result<String, serde_json::Error> {
    match shape {
        "sealed_row" => through::<SealedRowJson>(text),
        "wrap" => through::<WrapJson>(text),
        "checkpoint" => through::<CheckpointJson>(text),
        "checkpoint_head" => through::<CheckpointHeadJson>(text),
        "register_start_req" => through::<RegisterStartReq>(text),
        "register_start_res" => through::<RegisterStartRes>(text),
        "register_finish_req" => through::<RegisterFinishReq>(text),
        "register_finish_res" => through::<RegisterFinishRes>(text),
        "login_start_req" => through::<LoginStartReq>(text),
        "login_start_res" => through::<LoginStartRes>(text),
        "login_finish_req" => through::<LoginFinishReq>(text),
        "login_finish_res" => through::<LoginFinishRes>(text),
        "handoff_req" => through::<HandoffReq>(text),
        "handoff_res" => through::<HandoffRes>(text),
        "redeem_req" => through::<RedeemReq>(text),
        "handoff_redeem_res" => through::<HandoffRedeemRes>(text),
        "session_res" => through::<SessionRes>(text),
        "methods_res" => through::<MethodsRes>(text),
        "change" => through::<ChangeJson>(text),
        "changes_res" => through::<ChangesRes>(text),
        "put_item_req" => through::<PutItemReq>(text),
        "put_item_res" => through::<PutItemRes>(text),
        "conflict_res" => through::<ConflictRes>(text),
        "error_res" => through::<ErrorRes>(text),
        "batch_req" => through::<BatchReq>(text),
        "batch_res" => through::<BatchRes>(text),
        "checkpoint_put_req" => through::<CheckpointJson>(text),
        "checkpoint_put_res" => through::<CheckpointPutRes>(text),
        "checkpoint_stale_res" => through::<CheckpointStaleRes>(text),
        "items_res" => through::<ItemsRes>(text),
        "sync_event" => through::<SyncEventJson>(text),
        other => panic!("no shape for the fixture kind {other}"),
    }
}

const SHAPES: &[&str] = &[
    "sealed_row",
    "wrap",
    "checkpoint",
    "checkpoint_head",
    "register_start_req",
    "register_start_res",
    "register_finish_req",
    "register_finish_res",
    "login_start_req",
    "login_start_res",
    "login_finish_req",
    "login_finish_res",
    "handoff_req",
    "handoff_res",
    "redeem_req",
    "handoff_redeem_res",
    "session_res",
    "methods_res",
    "change",
    "changes_res",
    "put_item_req",
    "put_item_res",
    "conflict_res",
    "error_res",
    "batch_req",
    "batch_res",
    "checkpoint_put_req",
    "checkpoint_put_res",
    "checkpoint_stale_res",
    "items_res",
    "sync_event",
];

/// The shapes that came with the second milestone.
const M2_SHAPES: &[&str] = &[
    "batch_req",
    "batch_res",
    "checkpoint_put_req",
    "checkpoint_put_res",
    "checkpoint_stale_res",
    "items_res",
    "sync_event",
];

#[test]
fn every_fixture_roundtrips_byte_for_byte() {
    let all = fixtures();
    assert!(all.len() >= 30, "found only {} fixtures", all.len());
    for (name, shape) in &all {
        let text = read(name);
        let written = round_trip(shape, text.trim_end_matches('\n'))
            .unwrap_or_else(|e| panic!("{name} does not parse: {e}"));
        assert_eq!(
            written,
            text.trim_end_matches('\n'),
            "{name} changes when it is read and written"
        );
        assert!(text.ends_with('\n') && !text.ends_with("\n\n"), "{name}");
    }
    // Every shape has a fixture, and every fixture a shape.
    let covered: BTreeSet<&str> = all.iter().map(|(_, shape)| shape.as_str()).collect();
    let known: BTreeSet<&str> = SHAPES.iter().copied().collect();
    assert_eq!(covered, known);
}

#[test]
fn optional_fields_have_a_fixture_with_and_without() {
    // Left out when empty, so the text above is what a client may send.
    assert!(json_of("register_start_req.json")["setup_token"].is_string());
    assert!(json_of("register_start_req.no_token.json")["setup_token"].is_null());
    assert!(json_of("login_start_req.json")["purpose"].is_null());
    assert_eq!(json_of("login_start_req.reauth.json")["purpose"], "reauth");
    assert!(json_of("login_finish_req.json")["purpose"].is_null());
    assert_eq!(json_of("login_finish_req.reauth.json")["purpose"], "reauth");
    let finish: LoginFinishReq = parse("login_finish_req.reauth.json");
    assert_eq!(finish.purpose, Some(LoginPurposeJson::Reauth));
    assert!(json_of("session_res.admin.json")["account_id"].is_null());
    assert!(json_of("changes_res.empty.json")["checkpoint"].is_null());
    assert!(json_of("wrap.passkey.json")["credential_id"].is_string());
    assert!(json_of("wrap.password.json")["credential_id"].is_null());
    assert!(json_of("put_item_req.live.json")["resurrect"].is_null());
    assert_eq!(json_of("put_item_req.resurrect.json")["resurrect"], true);
}

#[test]
fn b64url_rejects_padding_standard_alphabet_and_whitespace() {
    assert_eq!(b64url::decode("").unwrap(), Vec::<u8>::new());
    assert_eq!(b64url::decode("AAEC").unwrap(), vec![0, 1, 2]);
    assert_eq!(b64url::decode("-_8").unwrap(), vec![0xfb, 0xff]);
    for bad in [
        "AA==",   // padding
        "AAE=",   // padding
        "+/8",    // standard alphabet
        "-_8=",   // padding after the right alphabet
        "AA EC",  // space
        " AAEC",  // leading space
        "AAEC ",  // trailing space
        "AAEC\n", // newline
        "AA\tEC", // tab
        "AB",     // spare bits that are not zero
        "A",      // one character is never a whole byte
        "AAEC\u{e9}",
    ] {
        assert_eq!(b64url::decode(bad), Err(WireError::Base64), "{bad:?}");
    }
    for len in 0..70usize {
        let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
        let text = b64url::encode(&bytes);
        assert!(!text.contains(['=', '+', '/']));
        assert_eq!(b64url::decode(&text).unwrap(), bytes);
    }
}

#[test]
fn hex16_rejects_uppercase_short_and_long() {
    let id = [
        0x00, 0x01, 0x0a, 0x0f, 0x10, 0xa0, 0xf0, 0xff, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
        0xf0,
    ];
    let text = hex16::encode(&id);
    assert_eq!(text, "00010a0f10a0f0ff123456789abcdef0");
    assert_eq!(hex16::decode(&text).unwrap(), id);
    for bad in [
        "00010A0F10A0F0FF123456789ABCDEF0",  // upper case
        "00010a0f10a0f0ff123456789abcdeF0",  // one upper-case digit
        "00010a0f10a0f0ff123456789abcde",    // short
        "00010a0f10a0f0ff123456789abcdef",   // one short
        "00010a0f10a0f0ff123456789abcdef00", // one long
        "",                                  // empty
        "0x010a0f10a0f0ff123456789abcdef0",  // prefix
        "00010a0f10a0f0ff123456789abcdef ",  // space
        "00010a0f10a0f0ff123456789abcdeg0",  // not hexadecimal
        "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", // 32 bytes of text
    ] {
        assert_eq!(hex16::decode(bad), Err(WireError::Hex), "{bad:?}");
    }
}

/// Puts `"x": 1` into the object at the top of `value`.
fn with_unknown(value: &Value) -> String {
    let mut value = value.clone();
    value.as_object_mut().unwrap().insert("x".into(), json!(1));
    value.to_string()
}

#[test]
fn unknown_fields_are_rejected_in_every_request_type() {
    for (name, shape) in fixtures() {
        let text = with_unknown(&json_of(&name));
        assert!(
            round_trip(&shape, &text).is_err(),
            "{name} accepts an unknown field"
        );
    }
    // Also inside the parts of a request.
    let base = json_of("register_finish_req.json");
    for path in ["manifest", "checkpoint"] {
        let mut value = base.clone();
        value[path]
            .as_object_mut()
            .unwrap()
            .insert("x".into(), json!(1));
        assert!(
            serde_json::from_value::<RegisterFinishReq>(value).is_err(),
            "{path}"
        );
    }
    let mut value = base;
    value["wraps"][0]
        .as_object_mut()
        .unwrap()
        .insert("x".into(), json!(1));
    assert!(serde_json::from_value::<RegisterFinishReq>(value).is_err());
}

#[test]
fn a_repeated_field_is_rejected() {
    let text = r#"{"base_rev":1,"base_rev":2,"deleted":true,"tomb":"AAAA","idem":"00000000000000000000000000000000"}"#;
    assert!(serde_json::from_str::<PutItemReq>(text).is_err());
}

fn put_item(value: Value) -> PutItemReq {
    let mut base = json!({ "base_rev": 1, "idem": hex16::encode(&[7; 16]) });
    base.as_object_mut()
        .unwrap()
        .extend(value.as_object().unwrap().clone());
    serde_json::from_value(base).unwrap()
}

#[test]
fn put_item_requires_exactly_one_form() {
    let blob = b64url::encode(&[1, 1, 1, 9, 9]);
    let tag = b64url::encode(&[3; 32]);
    let tomb = b64url::encode(&[4; 40]);

    // The two good forms.
    let live = put_item(json!({ "blob": blob, "tag": tag }));
    assert!(matches!(live.validate(), Ok(PutItemForm::Live { .. })));
    let live_false = put_item(json!({ "blob": blob, "tag": tag, "deleted": false }));
    assert!(matches!(
        live_false.validate(),
        Ok(PutItemForm::Live { .. })
    ));
    let deleted = put_item(json!({ "deleted": true, "tomb": tomb }));
    match deleted.validate().unwrap() {
        PutItemForm::Deleted { tomb } => assert_eq!(tomb, &[4; 40][..]),
        PutItemForm::Live { .. } => panic!("a tombstone is not live"),
    }
    for fixture in ["put_item_req.live.json", "put_item_req.tombstone.json"] {
        assert!(parse::<PutItemReq>(fixture).validate().is_ok(), "{fixture}");
    }

    // Everything else is refused.
    let bad = [
        (
            "both blob and tomb",
            json!({ "blob": blob, "tag": tag, "tomb": tomb }),
        ),
        (
            "blob, tag, tomb and deleted",
            json!({ "blob": blob, "tag": tag, "deleted": true, "tomb": tomb }),
        ),
        ("neither", json!({})),
        ("deleted only", json!({ "deleted": true })),
        (
            "deleted:false with tomb",
            json!({ "deleted": false, "tomb": tomb }),
        ),
        ("tomb without deleted", json!({ "tomb": tomb })),
        ("blob without tag", json!({ "blob": blob })),
        ("tag without blob", json!({ "tag": tag })),
        (
            "deleted:true with blob",
            json!({ "deleted": true, "blob": blob, "tag": tag }),
        ),
        (
            "deleted:true, tomb and tag",
            json!({ "deleted": true, "tomb": tomb, "tag": tag }),
        ),
        (
            "deleted:true, tomb and blob",
            json!({ "deleted": true, "tomb": tomb, "blob": blob }),
        ),
        (
            "live with null tomb",
            json!({ "blob": blob, "tag": tag, "tomb": null }),
        ),
    ];
    for (label, value) in bad {
        let request = put_item(value);
        if label == "live with null tomb" {
            // `null` is the same as a field that is left out.
            assert!(request.validate().is_ok(), "{label}");
        } else {
            assert!(request.validate().is_err(), "{label}");
        }
    }
}

fn len_of(value: &Value) -> usize {
    b64url::decode(value.as_str().unwrap()).unwrap().len()
}

#[test]
fn lengths_match_the_spec() {
    // OPAQUE messages (Spec: Fase 1 § 4).
    assert_eq!(len_of(&json_of("login_start_req.json")["ke1"]), 96);
    assert_eq!(len_of(&json_of("login_start_res.json")["ke2"]), 320);
    assert_eq!(len_of(&json_of("login_finish_req.json")["ke3"]), 64);
    assert_eq!(len_of(&json_of("register_start_req.json")["request"]), 32);
    assert_eq!(len_of(&json_of("register_start_res.json")["response"]), 64);
    let finish: RegisterFinishReq = parse("register_finish_req.json");
    assert_eq!(finish.record.len(), 192);

    // Wraps: password 104, recovery 72 (Spec: Fase 1 § 3).
    assert_eq!(finish.wraps.len(), 2);
    for wrap in finish
        .wraps
        .iter()
        .chain(parse::<MethodsRes>("methods_res.json").methods.iter())
    {
        match wrap.method_type {
            1 => assert_eq!(wrap.wrap.len(), 104),
            2 => assert_eq!(wrap.wrap.len(), 72),
            3 => {
                assert_eq!(wrap.wrap.len(), 104);
                assert_eq!(wrap.credential_id.as_ref().unwrap().len(), 32);
                assert!(wrap.prf_salt.is_some());
            }
            other => panic!("method type {other}"),
        }
    }
    assert_eq!(parse::<WrapJson>("wrap.password.json").wrap.len(), 104);
    assert_eq!(parse::<WrapJson>("wrap.recovery.json").wrap.len(), 72);

    // Checkpoint: 56 bytes for each row, the digest is the SHA-256 of them.
    let checkpoint = finish.checkpoint;
    assert_eq!(checkpoint.entries.len(), 56);
    assert_eq!(
        checkpoint.digest[..],
        Sha256::digest(&checkpoint.entries)[..]
    );
    assert_eq!(checkpoint.seq, 1);
    assert_eq!(checkpoint.mac.len(), 32);

    // Tombstone 40, tag 32, public keys 32, handoff challenge 32.
    let tombstone: PutItemReq = parse("put_item_req.tombstone.json");
    assert_eq!(tombstone.tomb.as_ref().unwrap().len(), 40);
    let live: PutItemReq = parse("put_item_req.live.json");
    assert_eq!(live.tag.unwrap().len(), 32);
    let deleted: ChangeJson = parse("change.deleted.json");
    assert_eq!(deleted.tomb.as_ref().unwrap().len(), 40);
    assert!(deleted.blob.is_none() && deleted.tag.is_none());
    let alive: ChangeJson = parse("change.live.json");
    assert_eq!(alive.tag.unwrap().len(), 32);
    assert!(alive.tomb.is_none());
    assert_eq!(finish.pk_a.len(), 32);
    assert_eq!(finish.pk_r.len(), 32);
    assert_eq!(finish.manifest.tag.len(), 32);
    assert_eq!(finish.manifest.rev, 1);
    assert_eq!(len_of(&json_of("handoff_req.json")["challenge"]), 32);
    let head: CheckpointHeadJson = parse("checkpoint_head.json");
    assert_eq!((head.digest.len(), head.mac.len()), (32, 32));
    assert_eq!(len_of(&json_of("methods_res.json")["pk_a"]), 32);

    // Ids are 32 hex characters.
    for (name, key) in [
        ("register_start_res.json", "registration_id"),
        ("register_start_res.json", "account_id"),
        ("register_start_res.json", "vault_id"),
        ("register_finish_req.json", "device_id"),
        ("login_start_res.json", "login_id"),
        ("put_item_req.live.json", "idem"),
        ("change.live.json", "id"),
    ] {
        let text = json_of(name)[key].as_str().unwrap().to_string();
        assert_eq!(text.len(), 32, "{name} {key}");
        assert!(hex16::decode(&text).is_ok(), "{name} {key}");
    }
}

#[test]
fn error_statuses_json_matches_code_status() {
    // The same file is read by the web vault, which decides what to do with an
    // error from its status; both sides must agree on every code.
    let golden: serde_json::Map<String, Value> =
        serde_json::from_str(&read("error_statuses.json")).unwrap();
    assert_eq!(
        golden.len(),
        ERROR_CODES.len(),
        "the file lists every code once"
    );
    for code in ERROR_CODES {
        let status = golden
            .get(*code)
            .unwrap_or_else(|| panic!("{code} has no status in error_statuses.json"));
        assert_eq!(
            u64::from(ferret_server::error::status_of(code).as_u16()),
            status.as_u64().unwrap(),
            "{code}"
        );
    }
}

#[test]
fn error_codes_are_stable_and_unique() {
    let golden: Vec<String> = serde_json::from_str(&read("error_codes.json")).unwrap();
    assert_eq!(
        ERROR_CODES,
        golden.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let unique: BTreeSet<&str> = ERROR_CODES.iter().copied().collect();
    assert_eq!(unique.len(), ERROR_CODES.len(), "a code is listed twice");
    for code in ERROR_CODES {
        assert!(
            !code.is_empty()
                && code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{code}"
        );
    }
    // Codes that later endpoints rely on.
    for needed in [
        "manifest_not_writable",
        "tombstone_invalid",
        "insecure_transport",
        "handoff_invalid",
        "registration_closed",
        "idem_reuse",
        "protocol_header_missing",
    ] {
        assert!(ERROR_CODES.contains(&needed), "{needed}");
    }
    // The codes of the OPAQUE library and of the server's own constructors.
    let listed = |code: &str| ERROR_CODES.contains(&code);
    for kind in [
        Malformed::RegistrationRequest,
        Malformed::RegistrationRecord,
        Malformed::Ke1,
        Malformed::Ke3,
        Malformed::LoginId,
        Malformed::Nonce,
        Malformed::Proof,
        Malformed::LoginName,
        Malformed::RecoveryKey,
    ] {
        assert!(listed(kind.public_code()), "{}", kind.public_code());
    }
    for error in [
        AuthError::ProfileRejected,
        AuthError::Denied(DenyReason::Ke3),
        AuthError::Denied(DenyReason::ScopeForbids),
        AuthError::Throttled {
            retry_after_secs: 1,
        },
    ] {
        assert!(listed(error.public_code()), "{}", error.public_code());
    }
    for error in [
        ApiError::unauthorized(),
        ApiError::forbidden_origin(),
        ApiError::not_found(),
        ApiError::internal(),
        ApiError::throttled(1),
    ] {
        assert!(listed(error.code), "{}", error.code);
    }
    // An error body is the code and nothing else.
    let body: ErrorRes = parse("error_res.json");
    assert!(listed(&body.error));
}

#[test]
fn device_id_is_required_and_device_name_is_optional_and_at_most_64_chars() {
    let finish = json_of("register_finish_req.json");
    let login = json_of("login_finish_req.json");
    fn register(v: Value) -> Result<(), serde_json::Error> {
        serde_json::from_value::<RegisterFinishReq>(v).map(|_| ())
    }
    fn sign_in(v: Value) -> Result<(), serde_json::Error> {
        serde_json::from_value::<LoginFinishReq>(v).map(|_| ())
    }
    type ParseFn = fn(Value) -> Result<(), serde_json::Error>;
    let cases: [(&Value, ParseFn); 2] = [(&finish, register), (&login, sign_in)];
    for (value, parse) in cases {
        // The device id is required.
        let mut without = value.clone();
        without.as_object_mut().unwrap().remove("device_id");
        assert!(parse(without).is_err());
        // A device id is an id.
        let mut upper = value.clone();
        upper["device_id"] = json!("00000000000000000000000000000000".replace('0', "A"));
        assert!(parse(upper).is_err());
        // The name is optional, and `null` is a name that is left out.
        let mut none = value.clone();
        none.as_object_mut().unwrap().remove("device_name");
        assert!(parse(none).is_ok());
        let mut null = value.clone();
        null["device_name"] = Value::Null;
        assert!(parse(null).is_ok());
        // 64 characters: yes. 65: no. Characters, not bytes.
        for (name, ok) in [
            ("a".repeat(64), true),
            ("a".repeat(65), false),
            ("\u{e5}".repeat(64), true), // 128 bytes, 64 characters
            ("\u{e5}".repeat(65), false),
            (String::new(), true),
            ("tab\there".into(), false),
            ("line\nbreak".into(), false),
            ("nul\u{0}".into(), false),
            ("phone\u{202e}knil".into(), false), // right-to-left override
            ("phone\u{2066}x".into(), false),    // bidirectional isolate
            ("pho\u{200b}ne".into(), false),     // zero-width space
            ("\u{feff}phone".into(), false),     // byte order mark
            ("a\u{200d}b".into(), true),         // zero-width joiner stays: it is part of scripts
        ] {
            let mut named = value.clone();
            named["device_name"] = json!(name);
            assert_eq!(parse(named).is_ok(), ok, "{name:?}");
        }
        // A name is a string.
        let mut number = value.clone();
        number["device_name"] = json!(5);
        assert!(parse(number).is_err());
    }
    let minimal: LoginFinishReq = parse("login_finish_req.minimal.json");
    assert!(minimal.device_name.is_none());
    let minimal: RegisterFinishReq = parse("register_finish_req.minimal.json");
    assert!(minimal.device_name.is_none());
}

#[test]
fn handoff_code_is_43_chars_base64url() {
    let res: HandoffRes = parse("handoff_res.json");
    assert_eq!(res.code.len(), 43);
    assert_eq!(res.expires_in, 60);
    assert_eq!(parse_handoff_code(&res.code).unwrap().len(), 32);
    let redeem: RedeemReq = parse("redeem_req.json");
    assert_eq!(redeem.code, res.code);
    assert!(parse_handoff_code(&redeem.code).is_ok());

    let good = res.code.clone();
    for bad in [
        good[..42].to_string(),
        format!("{good}A"),
        format!("{good}="),
        good.replace(&good[..1], "+"),
        format!(" {}", &good[1..]),
        format!("{}B", &good[..42]), // spare bits are not zero
        String::new(),
    ] {
        assert!(parse_handoff_code(&bad).is_err(), "{bad:?}");
    }
    assert_eq!(
        parse_handoff_code(&"A".repeat(42)),
        Err(WireError::Length {
            expected: 43,
            got: 42
        })
    );
}

#[test]
fn integers_are_whole_and_at_most_2_pow_53_minus_1() {
    let base = |n: &str| format!(r#"{{"rev":{n},"seq":1,"replayed":false}}"#);
    let max = wire::MAX_JSON_INT;
    assert_eq!(max, 9_007_199_254_740_991);
    assert!(serde_json::from_str::<PutItemRes>(&base("9007199254740991")).is_ok());
    for bad in [
        "9007199254740992",
        "18446744073709551615",
        "-1",
        "1.5",
        "1e3",
        "\"1\"",
    ] {
        assert!(
            serde_json::from_str::<PutItemRes>(&base(bad)).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn purposes_are_the_lower_case_words() {
    let start: LoginStartReq = parse("login_start_req.reauth.json");
    assert_eq!(start.purpose, Some(LoginPurposeJson::Reauth));
    let mut value = json_of("login_start_req.json");
    value["purpose"] = json!("Login");
    assert!(serde_json::from_value::<LoginStartReq>(value.clone()).is_err());
    value["purpose"] = json!("login");
    assert_eq!(
        serde_json::from_value::<LoginStartReq>(value)
            .unwrap()
            .purpose,
        Some(LoginPurposeJson::Login)
    );
    let mut value = json_of("handoff_req.json");
    value["purpose"] = json!("delete");
    assert!(serde_json::from_value::<HandoffReq>(value).is_err());
}

#[test]
fn types_with_ciphertext_never_print_it() {
    let finish: RegisterFinishReq = parse("register_finish_req.json");
    let shown = format!("{finish:?}");
    assert_eq!(shown, "RegisterFinishReq([redacted])");
    for (name, shown) in [
        (
            "put_item_req.live.json",
            format!("{:?}", parse::<PutItemReq>("put_item_req.live.json")),
        ),
        (
            "login_start_req.json",
            format!("{:?}", parse::<LoginStartReq>("login_start_req.json")),
        ),
        (
            "handoff_res.json",
            format!("{:?}", parse::<HandoffRes>("handoff_res.json")),
        ),
        (
            "redeem_req.json",
            format!("{:?}", parse::<RedeemReq>("redeem_req.json")),
        ),
        (
            "changes_res.json",
            format!("{:?}", parse::<ChangesRes>("changes_res.json")),
        ),
        (
            "methods_res.json",
            format!("{:?}", parse::<MethodsRes>("methods_res.json")),
        ),
        (
            "conflict_res.live.json",
            format!("{:?}", parse::<ConflictRes>("conflict_res.live.json")),
        ),
    ] {
        assert!(shown.ends_with("([redacted])"), "{name}: {shown}");
    }
    let put: PutItemReq = parse("put_item_req.live.json");
    assert_eq!(
        format!("{:?}", put.validate().unwrap()),
        "PutItemForm::Live([redacted])"
    );
}

#[derive(serde::Deserialize)]
struct Invalid {
    name: String,
    shape: String,
    json: String,
    layer: String,
    error: String,
    why: String,
}

/// The check that comes with a shape after it is read; the answer is its code.
fn check_step(shape: &str, text: &str) -> Result<(), &'static str> {
    match shape {
        "put_item_req" => serde_json::from_str::<PutItemReq>(text)
            .unwrap()
            .validate()
            .map(|_| ())
            .map_err(|e| e.code()),
        "redeem_req" => {
            let request: RedeemReq = serde_json::from_str(text).unwrap();
            parse_handoff_code(&request.code)
                .map(|_| ())
                .map_err(|_| "handoff_invalid")
        }
        "batch_req" => {
            let request: BatchReq = serde_json::from_str(text).unwrap();
            request.validate().map_err(|e| e.code())?;
            request
                .ops
                .iter()
                .try_for_each(|op| op.validate().map(|_| ()))
                .map_err(|e| e.code())
        }
        "batch_res" => {
            let answer: BatchRes = serde_json::from_str(text).unwrap();
            answer.validate().map_err(|e| e.code())
        }
        "items_res" => {
            let page: ItemsRes = serde_json::from_str(text).unwrap();
            page.validate().map_err(|e| e.code())
        }
        _ => Ok(()),
    }
}

/// Asserts that `case` is refused at its layer with its code.
fn assert_refused(case: &Invalid) {
    let label = format!("{} ({})", case.name, case.why);
    assert!(!case.why.is_empty(), "{label}");
    assert!(
        ERROR_CODES.contains(&case.error.as_str()),
        "{label}: {} is not a listed code",
        case.error
    );
    match round_trip(&case.shape, &case.json) {
        Err(error) => {
            assert_eq!(case.layer, "parse", "{label}: refused at parse time");
            assert_eq!(
                refusal_code(&error.to_string()),
                case.error,
                "{label}: {error}"
            );
        }
        Ok(_) => {
            assert_eq!(case.layer, "validate", "{label}: read without error");
            assert_eq!(
                check_step(&case.shape, &case.json),
                Err(case.error.as_str()),
                "{label}: check passed"
            );
        }
    }
}

#[test]
fn invalid_inputs_are_refused_at_their_layer_with_their_code() {
    let cases: Vec<Invalid> = parse("invalid.json");
    assert!(cases.len() >= 200, "found only {} cases", cases.len());
    let names: BTreeSet<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names.len(), cases.len(), "a case name is used twice");
    for case in &cases {
        assert_refused(case);
    }
    // Both layers and every code the parse layer can give are covered.
    let layers: BTreeSet<&str> = cases.iter().map(|c| c.layer.as_str()).collect();
    assert_eq!(layers, BTreeSet::from(["parse", "validate"]));
    let codes: BTreeSet<&str> = cases.iter().map(|c| c.error.as_str()).collect();
    for code in [
        "bad_request",
        "handoff_invalid",
        "malformed_ke1",
        "malformed_ke3",
        "malformed_registration_request",
        "malformed_registration_record",
        "tombstone_invalid",
    ] {
        assert!(codes.contains(code), "no case for {code}");
    }
    // Every shape has an invalid case.
    let shapes: BTreeSet<&str> = cases.iter().map(|c| c.shape.as_str()).collect();
    for shape in SHAPES {
        assert!(shapes.contains(shape), "no invalid case for {shape}");
    }
}

#[test]
fn every_fixture_passes_its_own_check() {
    for (name, shape) in fixtures() {
        let text = read(&name);
        let result = check_step(&shape, &text);
        if name == "put_item_req.resurrect.json" {
            // It reads, and this version of the server refuses it.
            assert_eq!(result, Err("bad_request"));
        } else {
            assert_eq!(result, Ok(()), "{name}");
        }
    }
}

#[test]
fn resurrect_is_read_and_refused_only_when_true() {
    let live = |resurrect: Value| {
        let mut fields = json!({
            "blob": b64url::encode(&[1, 1, 1, 9]),
            "tag": b64url::encode(&[3; 32]),
        });
        if !resurrect.is_null() {
            fields["resurrect"] = resurrect;
        }
        put_item(fields)
    };
    assert!(live(Value::Null).validate().is_ok());
    assert!(live(json!(false)).validate().is_ok());
    assert!(live(json!(true)).validate().is_err());
    // The field reads back as it came.
    let text = read("put_item_req.resurrect.json");
    let request: PutItemReq = serde_json::from_str(&text).unwrap();
    assert_eq!(request.resurrect, Some(true));
    assert_eq!(request.validate(), Err(WireError::Field("resurrect")));
}

#[test]
fn refusal_codes_come_from_the_message_prefix_only() {
    assert_eq!(
        refusal_code("malformed_ke1: expected 96 bytes, got 95"),
        "malformed_ke1"
    );
    assert_eq!(
        refusal_code("tombstone_invalid: not base64url"),
        "tombstone_invalid"
    );
    assert_eq!(refusal_code("unknown field `x`"), "bad_request");
    assert_eq!(refusal_code("nonsense: expected 96 bytes"), "bad_request");
    assert_eq!(refusal_code(""), "bad_request");
    // A value in the message after the prefix does not count.
    assert_eq!(
        refusal_code("invalid type: string \"malformed_ke1: x\""),
        "bad_request"
    );
}

// ------------------------------------------------------------ the sync shapes

/// A batch operation with the fields of `value` on top of an id, a base
/// revision and an idem.
fn batch_op(value: Value) -> BatchOpJson {
    let mut base = json!({
        "id": hex16::encode(&[9; 16]),
        "base_rev": 1,
        "idem": hex16::encode(&[7; 16]),
    });
    base.as_object_mut()
        .unwrap()
        .extend(value.as_object().unwrap().clone());
    serde_json::from_value(base).unwrap()
}

/// The names of the fields of an object.
fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

/// Whether a `null` is anywhere in `value`.
fn has_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().any(has_null),
        Value::Object(fields) => fields.values().any(has_null),
        _ => false,
    }
}

#[test]
fn m2_fixtures_roundtrip_byte_for_byte() {
    let all = fixtures();
    let m2: Vec<&(String, String)> = all
        .iter()
        .filter(|(_, shape)| M2_SHAPES.contains(&shape.as_str()))
        .collect();
    let names: BTreeSet<&str> = m2.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        BTreeSet::from([
            "batch_req.json",
            "batch_res.json",
            "checkpoint_put_req.json",
            "checkpoint_put_res.json",
            "checkpoint_stale_res.json",
            "items_res.json",
            "items_res.last.json",
            "sync_event.json",
        ])
    );
    for (name, shape) in m2 {
        let text = read(name);
        let text = text.trim_end_matches('\n');
        assert_eq!(
            round_trip(shape, text).unwrap_or_else(|e| panic!("{name}: {e}")),
            text,
            "{name} changes when it is read and written"
        );
        assert_eq!(check_step(shape, text), Ok(()), "{name}");
    }
}

#[test]
fn a_checkpoint_upload_has_whole_sorted_entries_and_the_digest_of_them() {
    let upload: CheckpointJson = parse("checkpoint_put_req.json");
    let entries = &upload.entries;
    assert_eq!(entries.len() % CHECKPOINT_ENTRY_LEN, 0);
    assert!(!entries.is_empty() && entries.len() <= MAX_CHECKPOINT_ENTRIES * CHECKPOINT_ENTRY_LEN);
    assert_eq!(upload.digest[..], Sha256::digest(entries)[..]);
    let mut last: Option<&[u8]> = None;
    for entry in entries.chunks(CHECKPOINT_ENTRY_LEN) {
        let (id, rest) = entry.split_at(16);
        assert!(last.is_none_or(|before| before < id), "ids rise strictly");
        last = Some(id);
        let rev = u64::from_be_bytes(rest[..8].try_into().unwrap());
        assert!(rev >= 1, "a revision starts at 1");
    }
    assert_eq!(
        (MAX_BATCH_OPS, MAX_BATCH_BYTES, CHECKPOINT_ENTRY_LEN),
        (100, 6 * 1024 * 1024, 56)
    );
}

#[test]
fn batch_op_resurrect_is_accepted_only_with_a_live_body() {
    let blob = b64url::encode(&[1, 1, 1, 9, 9]);
    let tag = b64url::encode(&[3; 32]);
    let tomb = b64url::encode(&[4; 40]);
    let resurrects = |op: &BatchOpJson| match op.validate().unwrap() {
        BatchOpForm::Live { resurrect, .. } => resurrect,
        BatchOpForm::Deleted { .. } => panic!("a live row is not a tombstone"),
    };
    // A live row may ask; `false` and a left-out field are the same.
    assert!(resurrects(&batch_op(
        json!({ "blob": blob, "tag": tag, "resurrect": true })
    )));
    assert!(!resurrects(&batch_op(
        json!({ "blob": blob, "tag": tag, "resurrect": false })
    )));
    assert!(!resurrects(&batch_op(json!({ "blob": blob, "tag": tag }))));
    let fixture: BatchReq = parse("batch_req.json");
    assert!(resurrects(&fixture.ops[1]));
    assert_eq!(fixture.ops[1].resurrect, Some(true));
    // A tombstone may not.
    assert_eq!(
        batch_op(json!({ "deleted": true, "tomb": tomb, "resurrect": true })).validate(),
        Err(WireError::Field("resurrect"))
    );
    match batch_op(json!({ "deleted": true, "tomb": tomb, "resurrect": false }))
        .validate()
        .unwrap()
    {
        BatchOpForm::Deleted { tomb } => assert_eq!(tomb, &[4; 40][..]),
        BatchOpForm::Live { .. } => panic!("a tombstone is not live"),
    }
    assert!(matches!(
        fixture.ops[2].validate(),
        Ok(BatchOpForm::Deleted { .. })
    ));
}

#[test]
fn batch_req_rejects_zero_and_101_ops_unknown_fields_and_an_op_with_both_forms() {
    let fixture: BatchReq = parse("batch_req.json");
    assert_eq!(fixture.validate(), Ok(()));
    assert!(fixture.ops.iter().all(|op| op.validate().is_ok()));

    // The number of operations: 1 to 100.
    let with_ops = |n: usize| BatchReq {
        ops: (0..n).map(|_| fixture.ops[0].clone()).collect(),
    };
    assert_eq!(with_ops(0).validate(), Err(WireError::Field("ops")));
    assert_eq!(with_ops(1).validate(), Ok(()));
    assert_eq!(with_ops(MAX_BATCH_OPS).validate(), Ok(()));
    assert_eq!(
        with_ops(MAX_BATCH_OPS + 1).validate(),
        Err(WireError::Field("ops"))
    );

    // Unknown fields, in the batch and in an operation.
    let base = json_of("batch_req.json");
    let mut value = base.clone();
    value["x"] = json!(1);
    assert!(serde_json::from_value::<BatchReq>(value).is_err());
    let mut value = base.clone();
    value["ops"][0]["x"] = json!(1);
    assert!(serde_json::from_value::<BatchReq>(value).is_err());
    // An operation needs its item id, its base revision and its idem.
    for field in ["id", "idem", "base_rev"] {
        let mut value = base.clone();
        value["ops"][0].as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<BatchReq>(value).is_err(),
            "{field}"
        );
    }

    // An operation with both forms, or with neither, is refused as one op.
    let blob = b64url::encode(&[1, 1, 1, 9, 9]);
    let tag = b64url::encode(&[3; 32]);
    let tomb = b64url::encode(&[4; 40]);
    for (label, fields) in [
        ("both", json!({ "blob": blob, "tag": tag, "tomb": tomb })),
        (
            "all four",
            json!({ "blob": blob, "tag": tag, "deleted": true, "tomb": tomb }),
        ),
        ("neither", json!({})),
        ("deleted only", json!({ "deleted": true })),
        ("tomb only", json!({ "tomb": tomb })),
        ("blob only", json!({ "blob": blob })),
        (
            "deleted false with a tomb",
            json!({ "deleted": false, "tomb": tomb }),
        ),
    ] {
        let op = batch_op(fields);
        assert!(op.validate().is_err(), "{label}");
        // The count is fine; the bad operation is answered in its own place.
        let request = BatchReq {
            ops: vec![fixture.ops[0].clone(), op],
        };
        assert_eq!(request.validate(), Ok(()), "{label}");
    }
}

#[test]
fn batch_result_has_exactly_one_form_and_no_null_fields() {
    let live_conflict = ConflictRes {
        current_rev: 4,
        blob: Some(vec![1, 1, 1, 9]),
        tag: Some([3; 32]),
        deleted: false,
    };
    let deleted_conflict = ConflictRes {
        current_rev: 5,
        blob: None,
        tag: None,
        deleted: true,
    };
    let stored = vec!["status", "rev", "seq", "replayed"];
    let refused = vec!["status", "error"];
    let made = [
        (BatchResultJson::stored(2, 5, false), 200, stored.clone()),
        (BatchResultJson::stored(3, 6, true), 200, stored),
        (
            BatchResultJson::conflict(live_conflict),
            409,
            vec!["status", "current_rev", "blob", "tag", "deleted"],
        ),
        (
            BatchResultJson::conflict(deleted_conflict),
            409,
            vec!["status", "current_rev", "deleted"],
        ),
        (BatchResultJson::refused("idem_reuse"), 422, refused.clone()),
        (
            BatchResultJson::refused("bad_request"),
            400,
            refused.clone(),
        ),
        (BatchResultJson::refused("busy"), 503, refused.clone()),
        (BatchResultJson::refused("tombstone_invalid"), 422, refused),
    ];
    for (result, status, fields) in &made {
        assert_eq!(result.validate(), Ok(()), "{status} {fields:?}");
        assert_eq!(result.status, *status);
        let value = serde_json::to_value(result).unwrap();
        assert!(!has_null(&value), "{value}");
        assert_eq!(
            keys(&value),
            fields.iter().copied().collect::<BTreeSet<&str>>(),
            "{value}"
        );
        // It reads back as it was written.
        let back: BatchResultJson = serde_json::from_value(value).unwrap();
        assert!(back == *result);
    }
    // The error of a refusal is the code.
    assert_eq!(
        BatchResultJson::refused("busy").error.as_deref(),
        Some("busy")
    );

    // The results of the fixture have one form each and no null.
    let fixture: BatchRes = parse("batch_res.json");
    assert_eq!(fixture.results.len(), 6);
    assert!(fixture.results.iter().all(|r| r.validate().is_ok()));
    assert!(!has_null(&json_of("batch_res.json")));

    // A result that mixes forms, or has a field that is not its form's, is refused.
    let bad = |value: Value| {
        serde_json::from_value::<BatchResultJson>(value)
            .unwrap()
            .validate()
            .is_err()
    };
    assert!(bad(json!({ "status": 200 })));
    assert!(bad(json!({ "status": 200, "rev": 2, "seq": 5 })));
    assert!(bad(
        json!({ "status": 409, "rev": 2, "seq": 5, "replayed": false })
    ));
    assert!(bad(
        json!({ "status": 200, "rev": 2, "seq": 5, "replayed": false, "error": "internal" })
    ));
    assert!(bad(
        json!({ "status": 409, "current_rev": 4, "deleted": false })
    ));
    assert!(bad(
        json!({ "status": 409, "current_rev": 4, "deleted": true, "blob": "AAAA" })
    ));
    assert!(bad(
        json!({ "status": 200, "current_rev": 4, "deleted": true })
    ));
    assert!(bad(json!({ "status": 200, "error": "internal" })));
    assert!(bad(json!({ "status": 422, "error": "" })));
    assert!(bad(
        json!({ "status": 422, "error": "idem_reuse", "rev": 2 })
    ));
    // A revision starts at 1.
    assert!(bad(
        json!({ "status": 200, "rev": 0, "seq": 5, "replayed": false })
    ));
    // A refusal has one of the codes and the status of that code.
    assert!(bad(json!({ "status": 400, "error": "idem_reuse" })));
    assert!(bad(json!({ "status": 422, "error": "bad_request" })));
    assert!(bad(json!({ "status": 400, "error": "not_a_code" })));
    assert!(bad(json!({ "status": 500, "error": "not_a_code" })));
    // 409 is the conflict form, so no refusal has it, whatever the code.
    assert!(bad(json!({ "status": 409, "error": "conflict" })));
    assert!(bad(json!({ "status": 409, "error": "checkpoint_stale" })));
    assert!(bad(
        json!({ "status": 409, "error": "registration_closed" })
    ));
    // Every other code is a good refusal with its own status.
    for code in ERROR_CODES {
        let status = ferret_server::error::status_of(code).as_u16();
        let refusal: BatchResultJson =
            serde_json::from_value(json!({ "status": status, "error": code })).unwrap();
        assert_eq!(refusal.validate().is_ok(), status != 409, "{code}");
    }
}

#[test]
fn batch_res_has_one_to_100_valid_results() {
    let one = BatchResultJson::stored(2, 5, false);
    let with = |n: usize| BatchRes {
        results: vec![one.clone(); n],
    };
    assert_eq!(with(0).validate(), Err(WireError::Field("results")));
    assert_eq!(with(1).validate(), Ok(()));
    assert_eq!(with(MAX_BATCH_OPS).validate(), Ok(()));
    assert_eq!(
        with(MAX_BATCH_OPS + 1).validate(),
        Err(WireError::Field("results"))
    );
    let mut mixed = with(2);
    mixed.results[1].error = Some("internal".to_owned());
    assert!(mixed.validate().is_err());
    assert_eq!(parse::<BatchRes>("batch_res.json").validate(), Ok(()));
}

#[test]
fn null_counts_as_absent_for_batch_ops() {
    let live = json!({
        "id": hex16::encode(&[9; 16]),
        "base_rev": 1,
        "blob": b64url::encode(&[1, 1, 1, 9]),
        "tag": b64url::encode(&[3; 32]),
        "deleted": null,
        "tomb": null,
        "idem": hex16::encode(&[7; 16]),
        "resurrect": null,
    });
    let op: BatchOpJson = serde_json::from_value(live).unwrap();
    assert_eq!(
        (op.deleted, op.tomb.as_ref(), op.resurrect),
        (None, None, None)
    );
    assert!(matches!(
        op.validate(),
        Ok(BatchOpForm::Live {
            resurrect: false,
            ..
        })
    ));
    // Written back, the nulls are left out.
    let text = serde_json::to_string(&op).unwrap();
    assert!(!text.contains("null"), "{text}");

    let gone = json!({
        "id": hex16::encode(&[9; 16]),
        "base_rev": 2,
        "blob": null,
        "tag": null,
        "deleted": true,
        "tomb": b64url::encode(&[4; 40]),
        "idem": hex16::encode(&[7; 16]),
        "resurrect": null,
    });
    let op: BatchOpJson = serde_json::from_value(gone).unwrap();
    assert!(matches!(op.validate(), Ok(BatchOpForm::Deleted { .. })));
    assert!(!serde_json::to_string(&op).unwrap().contains("null"));
}

#[test]
fn items_res_next_after_is_32_lower_hex_or_absent() {
    let page: ItemsRes = parse("items_res.json");
    let value = json_of("items_res.json");
    let next = value["next_after"].as_str().unwrap();
    assert_eq!(next.len(), 32);
    assert!(next.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(page.next_after, Some(hex16::decode(next).unwrap()));
    assert!(page.has_more);
    // The last page leaves it out; written back, the field is not there.
    let last: ItemsRes = parse("items_res.last.json");
    assert_eq!(last.next_after, None);
    assert!(!last.has_more);
    assert!(json_of("items_res.last.json")["next_after"].is_null());
    assert!(!serde_json::to_string(&last).unwrap().contains("next_after"));
    // Anything else is refused.
    for bad in [
        next.to_uppercase(),
        next[1..].to_string(),
        format!("{next}0"),
        String::new(),
        format!("0x{}", &next[2..]),
    ] {
        let mut changed = value.clone();
        changed["next_after"] = json!(bad);
        assert!(
            serde_json::from_value::<ItemsRes>(changed).is_err(),
            "{bad:?}"
        );
    }
    let mut number = value.clone();
    number["next_after"] = json!(5);
    assert!(serde_json::from_value::<ItemsRes>(number).is_err());
    // The page holds changes the same way /changes does.
    assert_eq!(page.items.len(), 2);
    assert!(page.items.iter().any(|row| row.deleted));
    // `next_after` is there exactly when `has_more` is true.
    assert_eq!(page.validate(), Ok(()));
    assert_eq!(last.validate(), Ok(()));
    let mut more_without_next = page.clone();
    more_without_next.next_after = None;
    assert!(more_without_next.validate().is_err());
    let mut next_on_the_last = last.clone();
    next_on_the_last.next_after = page.next_after;
    assert!(next_on_the_last.validate().is_err());
}

#[test]
fn sync_event_payload_is_seq_only() {
    let event: SyncEventJson = parse("sync_event.json");
    assert_eq!(event.seq, 7);
    assert_eq!(keys(&json_of("sync_event.json")), BTreeSet::from(["seq"]));
    assert_eq!(
        serde_json::to_string(&SyncEventJson { seq: 12 }).unwrap(),
        r#"{"seq":12}"#
    );
    for bad in [
        r#"{"seq":7,"vault":"x"}"#,
        r#"{"seq":7,"x":1}"#,
        r#"{}"#,
        r#"{"seq":"7"}"#,
        r#"{"seq":-1}"#,
        r#"{"seq":9007199254740992}"#,
        r#"{"seq":1.5}"#,
    ] {
        assert!(serde_json::from_str::<SyncEventJson>(bad).is_err(), "{bad}");
    }
}

#[test]
fn checkpoint_answers_are_the_seq_and_the_stale_code() {
    let stored: CheckpointPutRes = parse("checkpoint_put_res.json");
    assert_eq!(stored.seq, 7);
    let stale: CheckpointStaleRes = parse("checkpoint_stale_res.json");
    assert_eq!(
        (stale.error.as_str(), stale.stored_seq),
        ("checkpoint_stale", 9)
    );
    assert_eq!(CheckpointStaleRes::new(9), stale);
    assert!(ERROR_CODES.contains(&stale.error.as_str()));
    // Only that code, and only those two fields.
    for bad in [
        r#"{"error":"conflict","stored_seq":9}"#,
        r#"{"error":"","stored_seq":9}"#,
        r#"{"error":"checkpoint_stale"}"#,
        r#"{"error":"checkpoint_stale","stored_seq":9,"x":1}"#,
    ] {
        assert!(
            serde_json::from_str::<CheckpointStaleRes>(bad).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn new_codes_have_their_status() {
    let golden: serde_json::Map<String, Value> =
        serde_json::from_str(&read("error_statuses.json")).unwrap();
    for (code, status) in [
        ("busy", 503),
        ("checkpoint_stale", 409),
        ("checkpoint_invalid", 422),
    ] {
        assert!(ERROR_CODES.contains(&code), "{code}");
        assert_eq!(ferret_server::error::status_of(code).as_u16(), status);
        assert_eq!(ApiError::coded(code).status.as_u16(), status);
        assert_eq!(golden[code], status, "{code} in error_statuses.json");
    }
    // They come after the codes of the first version, so that list is unchanged.
    let at = |code: &str| ERROR_CODES.iter().position(|c| *c == code).unwrap();
    assert!(at("gone") < at("busy") && at("busy") < at("checkpoint_stale"));
    assert!(at("checkpoint_stale") < at("checkpoint_invalid"));
}

#[test]
fn invalid_cases_are_refused_the_same_way_in_rust_and_js() {
    // `web/test/unit/wire.test.mjs` runs the same cases of the same file under
    // the same name; both sides refuse each at its layer with its code.
    let cases: Vec<Invalid> = parse("invalid.json");
    let m2: Vec<&Invalid> = cases
        .iter()
        .filter(|case| M2_SHAPES.contains(&case.shape.as_str()))
        .collect();
    assert!(m2.len() >= 100, "found only {} cases", m2.len());
    for case in &m2 {
        assert_refused(case);
    }
    // Every new shape has cases, and the two with a second step have it at
    // both layers.
    for shape in M2_SHAPES {
        assert!(m2.iter().any(|case| case.shape == *shape), "{shape}");
    }
    for shape in ["batch_req", "batch_res"] {
        assert!(
            m2.iter()
                .any(|case| case.shape == shape && case.layer == "validate"),
            "{shape}"
        );
    }
    assert!(m2.iter().any(|case| case.error == "tombstone_invalid"));
}

#[test]
fn debug_of_the_new_types_is_redacted() {
    let batch: BatchReq = parse("batch_req.json");
    let result: BatchRes = parse("batch_res.json");
    let upload: CheckpointJson = parse("checkpoint_put_req.json");
    let page: ItemsRes = parse("items_res.json");
    let event: SyncEventJson = parse("sync_event.json");
    let stored: CheckpointPutRes = parse("checkpoint_put_res.json");
    let stale: CheckpointStaleRes = parse("checkpoint_stale_res.json");
    for (shown, expected) in [
        (format!("{batch:?}"), "BatchReq([redacted])"),
        (format!("{:?}", batch.ops[0]), "BatchOpJson([redacted])"),
        (format!("{result:?}"), "BatchRes([redacted])"),
        (
            format!("{:?}", result.results[2]),
            "BatchResultJson([redacted])",
        ),
        (format!("{upload:?}"), "CheckpointJson([redacted])"),
        (format!("{page:?}"), "ItemsRes([redacted])"),
        (format!("{event:?}"), "SyncEventJson([redacted])"),
        (format!("{stored:?}"), "CheckpointPutRes([redacted])"),
        (format!("{stale:?}"), "CheckpointStaleRes([redacted])"),
        (
            format!("{:?}", batch.ops[0].validate().unwrap()),
            "BatchOpForm::Live([redacted])",
        ),
        (
            format!("{:?}", batch.ops[2].validate().unwrap()),
            "BatchOpForm::Deleted([redacted])",
        ),
    ] {
        assert_eq!(shown, expected);
    }
}
