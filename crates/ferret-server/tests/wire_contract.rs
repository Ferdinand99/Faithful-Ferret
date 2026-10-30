//! The wire contract: the JSON shapes of the server API, as the fixtures in
//! `tests/fixtures/wire/` write them. `web/test/unit/wire.test.mjs` reads the
//! same files.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use ferret_server::error::ApiError;
use ferret_server::wire::{
    self, ChangeJson, ChangesRes, CheckpointHeadJson, CheckpointJson, ConflictRes, ERROR_CODES,
    ErrorRes, HandoffRedeemRes, HandoffReq, HandoffRes, LoginFinishReq, LoginFinishRes,
    LoginPurposeJson, LoginStartReq, LoginStartRes, MethodsRes, PutItemForm, PutItemReq,
    PutItemRes, RedeemReq, RegisterFinishReq, RegisterStartReq, RegisterStartRes, SealedRowJson,
    SessionRes, WireError, WrapJson, b64url, hex16, parse_handoff_code,
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
const NOT_SHAPES: &[&str] = &["headers.json", "generate.mjs", "error_codes.json"];

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
    assert!(json_of("session_res.admin.json")["account_id"].is_null());
    assert!(json_of("changes_res.empty.json")["checkpoint"].is_null());
    assert!(json_of("wrap.passkey.json")["credential_id"].is_string());
    assert!(json_of("wrap.password.json")["credential_id"].is_null());
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
    // The codes that the brief and the reviews name.
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
