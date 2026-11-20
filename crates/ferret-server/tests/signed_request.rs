//! The signed body of a sensitive request: the `Ferret-Nonce` and
//! `Ferret-Proof` headers, the raw body, the proof checked only by the OPAQUE
//! library, and the body parsed only after the permit. Spec: Fase 1 § 4.6.
//!
//! The route is `support::session::signed_probe`: the extractors of
//! `http::extract`, then `Proofs::signed` (the library's `authorize_signed`),
//! then `SignedBody::parse`, behind the vault listener's layers.

mod support;

use std::io;
use std::sync::{Arc, Mutex, Once};

use axum::body::Bytes;
use axum::http::StatusCode;
use ferret_core::AuthOp;
use ferret_server::auth::session::Origin;
use ferret_server::wire::{MAX_SIGNED_BODY, b64url};
use ferret_server_auth::SessionScope;
use support::session::{
    Issued, call_probe, issue, make_fresh, nonce_for, seed_signer, sign, signed_probe,
};
use support::{Jar, Res, TestApp};
use tracing_subscriber::fmt::MakeWriter;

const BODY: &[u8] = br#"{"n":7}"#;
const OP: AuthOp = AuthOp::UnlockMethodRecoveryPut;

/// A full session of the signer that has just re-authenticated.
async fn full_session(app: &TestApp) -> Issued {
    let user = seed_signer(app).await.user_id;
    let issued = issue(app, user, Origin::Vault, SessionScope::Full, 1).await;
    make_fresh(app, issued.sid).await;
    issued
}

fn enc(bytes: &[u8]) -> String {
    b64url::encode(bytes)
}

/// Sends `body` with a proof of `op` over `signed_body` and `nonce`.
async fn send(
    app: &TestApp,
    jar: &Jar,
    nonce: &[u8; 32],
    op: AuthOp,
    signed_body: &[u8],
    body: &[u8],
) -> Res {
    let proof = sign(op, nonce, signed_body);
    call_probe(
        &signed_probe(app),
        jar,
        Some(&enc(nonce)),
        Some(&enc(&proof)),
        body.to_vec(),
    )
    .await
}

fn assert_code(res: &Res, status: StatusCode, code: &str) {
    assert_eq!(res.status, status, "{}", res.text());
    assert_eq!(res.json()["error"], code, "{}", res.text());
}

#[tokio::test]
async fn missing_or_short_nonce_or_proof_is_400_and_burns_nothing() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let nonce = nonce_for(&app, &session.jar).await;
    let proof = sign(OP, &nonce, BODY);
    let (n, p) = (enc(&nonce), enc(&proof));
    let short_nonce = enc(&nonce[..31]);
    let long_nonce = enc(&[nonce.as_slice(), &[0]].concat());
    let short_proof = enc(&proof[..63]);
    let padded_nonce = format!("{n}=");
    let standard_proof = base64_standard(&proof);
    let cases: Vec<(Option<&str>, Option<&str>, &str)> = vec![
        (None, Some(&p), "malformed_nonce"),
        (Some(""), Some(&p), "malformed_nonce"),
        (Some(&short_nonce), Some(&p), "malformed_nonce"),
        (Some(&long_nonce), Some(&p), "malformed_nonce"),
        (Some(&padded_nonce), Some(&p), "malformed_nonce"),
        (Some(&n), None, "malformed_proof"),
        (Some(&n), Some(""), "malformed_proof"),
        (Some(&n), Some(&short_proof), "malformed_proof"),
        (Some(&n), Some(&standard_proof), "malformed_proof"),
        (None, None, "malformed_nonce"),
    ];
    let probe = signed_probe(&app);
    for (nonce_header, proof_header, code) in cases {
        let res = call_probe(
            &probe,
            &session.jar,
            nonce_header,
            proof_header,
            BODY.to_vec(),
        )
        .await;
        assert_code(&res, StatusCode::BAD_REQUEST, code);
        assert_eq!(
            app.challenges().store().len(),
            1,
            "the nonce is still there"
        );
    }
    // The nonce was never touched: the full request works with it.
    let res = call_probe(&probe, &session.jar, Some(&n), Some(&p), BODY.to_vec()).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["n"], 7);
}

/// Standard base64 with padding: not what the headers take.
fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(bytes);
    assert!(
        text.contains(['+', '/', '=']),
        "the test needs a char of the other alphabet"
    );
    text
}

#[tokio::test]
async fn a_body_over_the_limit_is_413() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let nonce = nonce_for(&app, &session.jar).await;
    let big = vec![b' '; MAX_SIGNED_BODY + 1];
    let res = send(&app, &session.jar, &nonce, OP, &big, &big).await;
    assert_code(&res, StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    assert_eq!(
        app.challenges().store().len(),
        1,
        "the nonce is still there"
    );

    // Exactly the limit is read, checked, and only then parsed: white space
    // around the JSON is still JSON.
    let mut exact = vec![b' '; MAX_SIGNED_BODY - BODY.len()];
    exact.extend_from_slice(BODY);
    let res = send(&app, &session.jar, &nonce, OP, &exact, &exact).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json()["n"], 7);
}

#[tokio::test]
async fn a_body_that_breaks_off_is_400_not_413_and_burns_nothing() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let nonce = nonce_for(&app, &session.jar).await;
    let proof = sign(OP, &nonce, BODY);
    let broken = axum::body::Body::from_stream(futures_util::stream::iter(vec![
        Ok(Bytes::from_static(b"{\"n\":")),
        Err(io::Error::other("the client went away")),
    ]));
    let probe = signed_probe(&app);
    let res = call_probe(
        &probe,
        &session.jar,
        Some(&enc(&nonce)),
        Some(&enc(&proof)),
        broken,
    )
    .await;
    assert_code(&res, StatusCode::BAD_REQUEST, "bad_request");
    assert_eq!(
        app.challenges().store().len(),
        1,
        "the nonce is still there"
    );

    // Over the limit in pieces is 413, and burns nothing either.
    let pieces = axum::body::Body::from_stream(futures_util::stream::iter(
        (0..=MAX_SIGNED_BODY / 1024).map(|_| Ok::<_, io::Error>(Bytes::from(vec![b' '; 1024]))),
    ));
    let res = call_probe(
        &probe,
        &session.jar,
        Some(&enc(&nonce)),
        Some(&enc(&proof)),
        pieces,
    )
    .await;
    assert_code(&res, StatusCode::PAYLOAD_TOO_LARGE, "too_large");
    let res = call_probe(
        &probe,
        &session.jar,
        Some(&enc(&nonce)),
        Some(&enc(&proof)),
        BODY.to_vec(),
    )
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_valid_proof_over_other_bytes_is_401_denied() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, BODY, br#"{"n":8}"#).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
    // One more byte of white space is other bytes too.
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, BODY, br#"{"n":7} "#).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
    // Both nonces are spent.
    assert!(app.challenges().store().is_empty());
}

#[tokio::test]
async fn a_proof_for_another_op_is_401_denied() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    for op in [
        AuthOp::UnlockMethodAdd,
        AuthOp::UnlockMethodRemove,
        AuthOp::UnlockMethodPasswordPut,
        AuthOp::Rekey,
    ] {
        let nonce = nonce_for(&app, &session.jar).await;
        let res = send(&app, &session.jar, &nonce, op, BODY, BODY).await;
        assert_code(&res, StatusCode::UNAUTHORIZED, "denied");
    }
    // The probe's own operation goes through.
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, BODY, BODY).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn the_body_is_parsed_only_after_the_permit() {
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let junk: &[u8] = b"{not json";

    // A body that does not parse, under a wrong proof: the proof is refused,
    // and the body was never looked at (a parse first would have said 400).
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, BODY, junk).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "denied");

    // The same body under a proof over it: the permit comes first, then the
    // parse refuses it.
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, junk, junk).await;
    assert_code(&res, StatusCode::BAD_REQUEST, "bad_request");

    // An unknown field is refused after the permit as well.
    let extra: &[u8] = br#"{"n":7,"x":1}"#;
    let nonce = nonce_for(&app, &session.jar).await;
    let res = send(&app, &session.jar, &nonce, OP, extra, extra).await;
    assert_code(&res, StatusCode::BAD_REQUEST, "bad_request");

    // That `parse` takes only a permit for exactly these bytes is a unit
    // test of `http::extract`: only the extractor can make a `SignedBody`.
}

#[tokio::test]
async fn a_session_without_the_capability_never_reaches_the_body() {
    let app = TestApp::new().await;
    let user = seed_signer(&app).await.user_id;
    let full = issue(&app, user, Origin::Vault, SessionScope::Full, 1).await;
    let nonce = nonce_for(&app, &full.jar).await;
    let reset = issue(&app, user, Origin::Vault, SessionScope::AccountReset, 2).await;
    // A reset session may not write unlock methods: 403, before the headers.
    let res = call_probe(&signed_probe(&app), &reset.jar, None, None, BODY.to_vec()).await;
    assert_code(&res, StatusCode::FORBIDDEN, "forbidden");
    let res = send(&app, &reset.jar, &nonce, OP, BODY, BODY).await;
    assert_code(&res, StatusCode::FORBIDDEN, "forbidden");
    // No session at all: 401, before the headers.
    let res = send(&app, &Jar::default(), &nonce, OP, BODY, BODY).await;
    assert_code(&res, StatusCode::UNAUTHORIZED, "unauthorized");
    // The nonce of the full session was not spent by any of them.
    assert_eq!(app.challenges().store().len(), 1);
}

// ------------------------------------------------------------------ the log

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

fn log_sink() -> Sink {
    static ONCE: Once = Once::new();
    static SINK: Mutex<Option<Sink>> = Mutex::new(None);
    ONCE.call_once(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        // Tasks run on other threads, so the subscriber is the process's.
        let _ = tracing::subscriber::set_global_default(subscriber);
        *SINK.lock().expect("sink") = Some(sink);
    });
    SINK.lock().expect("sink").clone().expect("the sink")
}

#[tokio::test]
async fn proof_headers_never_reach_the_log() {
    let sink = log_sink();
    let app = TestApp::new().await;
    let session = full_session(&app).await;
    let canary: &[u8] = br#"{"n":4242424242}"#;
    let mut seen: Vec<String> = Vec::new();

    // A good request, a proof over other bytes, other bytes under the proof,
    // and below a proof of the wrong length.
    for (signed, sent) in [
        (canary, canary),
        (BODY, canary),
        (canary, &b"canary-other-bytes-5d1e"[..]),
    ] {
        let nonce = nonce_for(&app, &session.jar).await;
        let proof = sign(OP, &nonce, signed);
        seen.push(enc(&nonce));
        seen.push(enc(&proof));
        let _ = call_probe(
            &signed_probe(&app),
            &session.jar,
            Some(&enc(&nonce)),
            Some(&enc(&proof)),
            sent.to_vec(),
        )
        .await;
    }
    let nonce = nonce_for(&app, &session.jar).await;
    seen.push(enc(&nonce));
    let _ = call_probe(
        &signed_probe(&app),
        &session.jar,
        Some(&enc(&nonce)),
        Some(&enc(&[0x5c; 63])),
        canary.to_vec(),
    )
    .await;
    seen.push(enc(&[0x5c; 63]));
    seen.push("4242424242".to_string());
    seen.push("canary-other-bytes-5d1e".to_string());
    for name in ["__Host-ferret_sid", "__Host-ferret_session"] {
        seen.push(session.jar.get(name).expect("a cookie").to_string());
    }

    let log = String::from_utf8(sink.0.lock().expect("sink").clone()).expect("utf-8");
    // The canary only counts if the log is being written at all.
    assert!(
        log.contains("signed request refused"),
        "the sink got nothing: {log}"
    );
    for secret in &seen {
        assert!(!log.contains(secret.as_str()), "the log holds {secret}");
    }
}

// ------------------------------------------------------------ the verifiers

#[test]
fn clippy_toml_disallows_both_core_proof_verifiers() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("clippy.toml");
    let text = std::fs::read_to_string(&path).expect("crates/ferret-server/clippy.toml");
    // The table, outside the comments.
    let config: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(config.contains("disallowed-methods"), "{config}");
    for path in [
        "ferret_core::verify_auth_proof",
        "ferret_core::verify_recovery_proof",
    ] {
        assert!(
            config.contains(&format!("path = \"{path}\"")),
            "clippy.toml does not disallow {path}"
        );
    }
    // And nothing in the server's own sources names them.
    let mut stack = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("a directory") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let source = std::fs::read_to_string(&path).expect("a source file");
                for name in ["verify_auth_proof", "verify_recovery_proof"] {
                    let calls = source
                        .lines()
                        .filter(|l| !l.trim_start().starts_with("//"))
                        .any(|l| l.contains(name));
                    assert!(!calls, "{} names {name}", path.display());
                }
            }
        }
    }
}
