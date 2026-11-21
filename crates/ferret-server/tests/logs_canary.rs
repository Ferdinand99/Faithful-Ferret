//! A canary for the logs: a token, a DPoP proof and a refresh token that carry
//! recognizable text are sent through every route that takes them and every
//! way each of them can fail, and neither the output of `tracing` (every level,
//! every thread, the blocking pool of the database included) nor an error
//! answer may hold any of it: not the text, not a piece of it, not its
//! base64url form.
//!
//! The same is done with the real tokens and proofs of devices that signed in
//! (renewed, reused, revoked, signed out), so the lines that the server does
//! write on those paths are read too. A search of an empty log proves nothing,
//! so the test also asserts the lines the paths must leave.
//!
//! Spec: Fase 1 § 11 (no secret in a log); `Authorization` and `DPoP` are
//! never logged.

mod support;

use std::sync::OnceLock;

use axum::http::{HeaderValue, Method, StatusCode};
use ferret_server::auth::refresh::GRACE_SECS;
use ferret_server::ids::TokenSecret;
use ferret_server::wire::b64url;
use serde_json::json;
use support::accounts::{CLIENT_PASSWORD, client_account, client_session};
use support::backup::LogBuffer;
use support::device::{
    DeviceClient, LOGIN_FINISH, device_app, device_body, finish_req, login_start,
};
use support::dpop::DeviceKey;
use support::{Req, Res, TestApp, VAULT_URL, Which};

const REFRESH: &str = "/api/auth/token/refresh";
const REVOKE: &str = "/api/auth/token/revoke";
const SYNC: &str = "/api/sync/changes";

/// The text every canary carries.
const MARK: &str = "CANARY";

/// The log of the whole process, from the first call on: every level, every
/// thread.
fn log() -> &'static LogBuffer {
    static LOG: OnceLock<LogBuffer> = OnceLock::new();
    LOG.get_or_init(|| {
        let buffer = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buffer.clone())
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        buffer
    })
}

/// A token that carries `label` in its 32 bytes (padded with dots), so that
/// the text is in the raw bytes and the base64url form is a fixed string.
fn canary_token(label: &str) -> TokenSecret {
    assert!(label.len() <= 32 && label.starts_with(MARK));
    let mut bytes = [b'.'; 32];
    bytes[..label.len()].copy_from_slice(label.as_bytes());
    TokenSecret::from_wire(&b64url::encode(&bytes)).expect("a token")
}

/// Everything that must not be found: a text and the reason it is a secret.
#[derive(Default)]
struct Secrets(Vec<String>);

impl Secrets {
    fn add(&mut self, text: impl Into<String>) {
        let text = text.into();
        if text.len() >= 12 {
            self.0.push(text);
        }
    }

    /// The token, in the form it travels and as the bytes it holds.
    fn token(&mut self, token: &TokenSecret) {
        self.add(token.to_wire());
        let raw = b64url::decode(&token.to_wire()).expect("a token");
        self.add(String::from_utf8_lossy(&raw).into_owned());
    }

    /// A compact JWS: the whole, each part, and each part decoded.
    fn proof(&mut self, proof: &str) {
        self.add(proof);
        for part in proof.split('.') {
            self.add(part);
            if let Ok(bytes) = b64url::decode(part) {
                self.add(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    }

    /// The first secret that `text` holds, whole or in a piece of 24
    /// characters (a secret that is cut by a line or an ellipsis still gives
    /// itself away).
    fn found_in(&self, text: &str) -> Option<String> {
        for secret in &self.0 {
            if text.contains(secret.as_str()) {
                return Some(secret.clone());
            }
            if secret.len() > 24 {
                let bytes = secret.as_bytes();
                for start in (0..=bytes.len() - 24).step_by(8) {
                    if let Ok(piece) = std::str::from_utf8(&bytes[start..start + 24])
                        && text.contains(piece)
                    {
                        return Some(piece.to_string());
                    }
                }
            }
        }
        None
    }
}

fn email(n: u8) -> String {
    format!("client{n}@example.com")
}

/// What the test sent, and what came back, for the search.
struct Seen {
    /// The text of every answer's headers, and of every error answer's body.
    answers: Vec<String>,
    /// How many answers were refusals.
    refusals: usize,
}

impl Seen {
    fn take(&mut self, what: &str, res: &Res) {
        let mut text = format!("{what}\n");
        for (name, value) in &res.headers {
            text.push_str(&format!(
                "{name}: {}\n",
                String::from_utf8_lossy(value.as_bytes())
            ));
        }
        if res.status.as_u16() >= 400 {
            self.refusals += 1;
            text.push_str(&res.text());
        }
        self.answers.push(text);
    }
}

/// A compact JWS of the bytes of a header and claims, signed with `key`.
fn jws(key: &DeviceKey, header: serde_json::Value, claims: serde_json::Value) -> String {
    key.sign(&header, &claims)
}

/// Proofs that carry the canary and fail in every way a proof can, for
/// `method` and `path`, and, when `token` is given, with its `ath`.
fn canary_proofs(
    method: &str,
    path: &str,
    token: Option<&TokenSecret>,
    iat: i64,
    n: u64,
) -> Vec<String> {
    let key = DeviceKey::from_counter(9_000_000 + n);
    let htu = format!("{VAULT_URL}{path}");
    let jti = format!("{MARK}-JTI-{n:016}");
    let good = support::dpop::claims(method, &htu, iat, &jti, token);
    let mut proofs = Vec::new();
    // A proof of a key that is bound to nothing, in every other way good.
    proofs.push(jws(&key, key.header(), good.clone()));
    // An unsigned one.
    let mut header = key.header();
    header["alg"] = json!("none");
    proofs.push(format!(
        "{}.{}.",
        b64url::encode(header.to_string().as_bytes()),
        b64url::encode(good.to_string().as_bytes())
    ));
    // Members that are not allowed: in the header, in the claims, a private
    // key.
    let mut header = key.header();
    header["kid"] = json!(format!("{MARK}-KID-{n:016}"));
    proofs.push(jws(&key, header, good.clone()));
    let mut claims = good.clone();
    claims["sub"] = json!(format!("{MARK}-SUB-{n:016}"));
    proofs.push(jws(&key, key.header(), claims));
    let mut header = key.header();
    header["jwk"]["d"] = json!(format!("{MARK}-PRIVATE-KEY-{n:016}"));
    proofs.push(jws(&key, header, good.clone()));
    // Another method, another address, a time long ago.
    proofs.push(jws(
        &key,
        key.header(),
        support::dpop::claims("DELETE", &htu, iat, &jti, token),
    ));
    proofs.push(jws(
        &key,
        key.header(),
        support::dpop::claims(
            method,
            &format!("https://evil.example{path}/{MARK}"),
            iat,
            &jti,
            token,
        ),
    ));
    proofs.push(jws(
        &key,
        key.header(),
        support::dpop::claims(method, &htu, iat - 3_600, &jti, token),
    ));
    // A signature of another message.
    let signed = jws(&key, key.header(), good);
    let mut parts: Vec<&str> = signed.split('.').collect();
    let other = jws(
        &key,
        key.header(),
        json!({"jti": format!("{MARK}-OTHER-{n:016}")}),
    );
    parts[2] = other.rsplit('.').next().expect("a signature");
    proofs.push(parts.join("."));
    // Not a JWS at all, and one that is far too long.
    proofs.push(format!("{MARK}.{MARK}-NOT-A-PROOF-{n:016}.{MARK}"));
    proofs.push(format!("{MARK}-{}", "X".repeat(5_000)));
    proofs
}

/// Sends `request` to the vault listener.
async fn send(app: &TestApp, req: Req) -> Res {
    app.call_raw(Which::Vault, req.build()).await
}

fn token_req(method: Method, path: &str, token: &TokenSecret, proof: &str) -> Req {
    Req::new(method, path)
        .header("authorization", &format!("DPoP {}", token.to_wire()))
        .header("dpop", proof)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
}

fn body_req(path: &str, token: &str, proof: &str) -> Req {
    Req::post(path)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https")
        .header("dpop", proof)
        .json(&json!({ "refresh_token": token }))
}

#[tokio::test]
async fn tokens_and_proofs_never_reach_the_logs() {
    let log = log();
    let app = device_app().await;
    let account = client_account(&app, 1).await;
    let browser = client_session(&app, &account, ferret_server_auth::SessionScope::Full, 1).await;
    let mut secrets = Secrets::default();
    let mut seen = Seen {
        answers: Vec::new(),
        refusals: 0,
    };
    let now = support::device::now(&app);

    // ---- real devices: a sign-in, a renewal, a reuse, another key, a sign-out
    let mut first = DeviceClient::new(1);
    let res = first.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let mut second = DeviceClient::new(2);
    let res = second.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let mut third = DeviceClient::new(3);
    let res = third.sign_in(&app, &email(1), CLIENT_PASSWORD).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    for device in [&first, &second, &third] {
        secrets.token(device.access.as_ref().expect("signed in"));
        secrets.token(device.refresh.as_ref().expect("signed in"));
        secrets.add(device.key.x.clone());
        secrets.add(device.key.y.clone());
        // The private key (the scalar the key signs with) is the most secret of all.
        secrets.add(device.key.secret_b64());
        secrets.add(device.key.secret_hex());
    }
    let old_refresh = TokenSecret::from_wire(&first.refresh.as_ref().expect("signed in").to_wire())
        .expect("a token");
    let old_access = TokenSecret::from_wire(&first.access.as_ref().expect("signed in").to_wire())
        .expect("a token");

    // A renewal that works, and the proofs of every real request are secrets.
    let proof = first.proof(&app, "POST", REFRESH, None);
    secrets.proof(&proof);
    let res = send(&app, body_req(REFRESH, &old_refresh.to_wire(), &proof)).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let body = res.json();
    for name in ["access_token", "refresh_token"] {
        secrets.add(body[name].as_str().expect("a token"));
    }
    // The same proof again (a replay).
    let res = send(&app, body_req(REFRESH, &old_refresh.to_wire(), &proof)).await;
    seen.take("a replayed proof", &res);
    // The old token after the grace period: a reuse, which revokes.
    app.clock
        .advance(u64::try_from(GRACE_SECS + 1).expect("seconds"));
    let proof = first.proof(&app, "POST", REFRESH, None);
    secrets.proof(&proof);
    let res = send(&app, body_req(REFRESH, &old_refresh.to_wire(), &proof)).await;
    assert_eq!(
        (res.status.as_u16(), res.json()["error"].as_str()),
        (401, Some("token_reused"))
    );
    seen.take("a reuse", &res);
    // The revoked device's tokens.
    let proof = first.proof(&app, "POST", REFRESH, None);
    secrets.proof(&proof);
    let res = send(&app, body_req(REFRESH, &old_refresh.to_wire(), &proof)).await;
    seen.take("a revoked device renews", &res);
    let proof = first.proof(&app, "GET", SYNC, Some(&old_access));
    secrets.proof(&proof);
    let res = send(&app, token_req(Method::GET, SYNC, &old_access, &proof)).await;
    assert_eq!(res.json()["error"], "device_revoked");
    seen.take("a revoked device syncs", &res);
    // The second device's refresh token with a proof of another key.
    let theirs = second.refresh.as_ref().expect("signed in");
    let proof = third.proof(&app, "POST", REFRESH, None);
    secrets.proof(&proof);
    let res = send(&app, body_req(REFRESH, &theirs.to_wire(), &proof)).await;
    assert_eq!(res.json()["error"], "token_reused");
    seen.take("a proof of another key", &res);
    // The third device signs out, and then signs out again.
    let mine = third.refresh.as_ref().expect("signed in");
    let proof = third.proof(&app, "POST", REVOKE, None);
    secrets.proof(&proof);
    let res = send(&app, body_req(REVOKE, &mine.to_wire(), &proof)).await;
    assert_eq!(res.status, StatusCode::NO_CONTENT);
    seen.take("a sign-out", &res);
    // A wrong password, with a good proof.
    let proof = DeviceKey::from_counter(9_100_000).proof(
        "POST",
        &format!("{VAULT_URL}{LOGIN_FINISH}"),
        now + GRACE_SECS + 1,
        None,
    );
    secrets.proof(&proof);
    let half = login_start(&app, &email(1), "not the master password").await;
    let res = send(&app, finish_req(&device_body(&half), Some(&proof))).await;
    seen.take("a wrong password", &res);
    // A key that a device already has: one key is one device.
    let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
    let proof = second.login_proof(&app);
    secrets.proof(&proof);
    let res = send(&app, finish_req(&device_body(&half), Some(&proof))).await;
    assert_eq!(res.status, StatusCode::BAD_REQUEST);
    seen.take("a key in use", &res);

    // ---- the canary: a token, a proof and a refresh token that are not real
    let canary_access = canary_token("CANARY-ACCESS-TOKEN");
    let canary_refresh = canary_token("CANARY-REFRESH-TOKEN");
    secrets.token(&canary_access);
    secrets.token(&canary_refresh);
    secrets.add("CANARY-ACCESS-TOKEN");
    secrets.add("CANARY-REFRESH-TOKEN");
    secrets.add(format!("{MARK}-JTI-"));
    secrets.add(format!("{MARK}-KID-"));
    secrets.add(format!("{MARK}-SUB-"));
    secrets.add(format!("{MARK}-PRIVATE-KEY-"));
    secrets.add(format!("{MARK}-NOT-A-PROOF-"));
    secrets.add(format!("{MARK}-NOT-A-TOKEN"));
    secrets.add(format!("{MARK}-USER:{MARK}-PASS"));
    let now = support::device::now(&app);

    let mut n = 0u64;
    let mut sends = 0usize;
    let real_access = TokenSecret::from_wire(&second.access.as_ref().expect("signed in").to_wire())
        .expect("a token");
    let routes: Vec<(Method, &str, Option<serde_json::Value>)> = vec![
        (Method::GET, SYNC, None),
        (Method::GET, "/api/vault/unlock-methods", None),
        (Method::GET, "/api/sync/checkpoint", None),
        (Method::GET, "/api/sync/items", None),
        (Method::GET, "/api/sync/restore-rows", None),
        (Method::PUT, "/api/sync/checkpoint", Some(json!({}))),
        (Method::POST, "/api/sync/batch", Some(json!({}))),
        (
            Method::PUT,
            "/api/sync/items/00000000000000000000000000000001",
            Some(json!({})),
        ),
        (Method::GET, "/api/sync/events", None),
        (Method::GET, "/api/auth/devices", None),
    ];
    for (method, path, body) in &routes {
        // The canary token and the real revoked one, with every canary proof
        // and with the proofs of the real device that fits them.
        for token in [&canary_access, &old_access, &real_access] {
            n += 1;
            let mut proofs = canary_proofs(method.as_str(), path, Some(token), now, n);
            proofs.push(second.proof(&app, method.as_str(), path, Some(token)));
            for proof in proofs {
                secrets.proof(&proof);
                let mut req = token_req(method.clone(), path, token, &proof);
                if let Some(body) = body {
                    req = req.json(body);
                }
                let res = send(&app, req).await;
                sends += 1;
                // The real token with the real proof is the one request that
                // may work; it is not a canary, and its answer is not read for
                // the canary, only for the real secrets.
                seen.take("a route that takes a token, with a bad proof", &res);
            }
        }
        // A token header and a cookie together, and on the admin listener.
        n += 1;
        let proof = canary_proofs(method.as_str(), path, Some(&canary_access), now, n).remove(0);
        secrets.proof(&proof);
        let mut req = token_req(method.clone(), path, &canary_access, &proof);
        if let Some(cookie) = browser.jar.header() {
            req = req.header("cookie", &cookie);
        }
        let res = send(&app, req).await;
        assert_eq!(
            res.status,
            StatusCode::BAD_REQUEST,
            "{method} {path}: {}",
            res.text()
        );
        seen.take("a token and a cookie", &res);
        let req = token_req(method.clone(), path, &canary_access, &proof);
        let res = app.call_raw(Which::Admin, req.build()).await;
        seen.take("a token on the admin listener", &res);
        // The `Authorization` of a proxy (Basic) with the canary as the
        // credentials, and a duplicated and an unreadable header.
        let basic = b64std(format!("{MARK}-USER:{MARK}-PASS").as_bytes());
        let res = send(
            &app,
            Req::new(method.clone(), path)
                .header("authorization", &format!("Basic {basic}"))
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https"),
        )
        .await;
        seen.take("Basic from a proxy", &res);
        let mut request = token_req(method.clone(), path, &canary_access, &proof).build();
        request.headers_mut().append(
            "dpop",
            HeaderValue::from_str(&format!("{MARK}-SECOND-PROOF.{MARK}.{MARK}")).expect("a header"),
        );
        let res = app.call_raw(Which::Vault, request).await;
        seen.take("two proofs", &res);
        let mut request = token_req(method.clone(), path, &canary_access, &proof).build();
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_bytes(format!("DPoP {MARK}-BYTES-\u{ff}\u{fe}").as_bytes())
                .expect("a header"),
        );
        let res = app.call_raw(Which::Vault, request).await;
        seen.take("a token that is not text", &res);
    }

    // The token routes: a refresh token that is the canary, one that is not a
    // token, and a real one of another key, each with every canary proof.
    for path in [REFRESH, REVOKE] {
        for text in [
            canary_refresh.to_wire(),
            format!("{MARK}-NOT-A-TOKEN"),
            "x".repeat(2_000),
            second.refresh.as_ref().expect("signed in").to_wire(),
        ] {
            n += 1;
            let mut proofs = canary_proofs("POST", path, None, now, n);
            proofs.push(String::new());
            for proof in proofs {
                secrets.proof(&proof);
                let req = if proof.is_empty() {
                    Req::post(path)
                        .header("ferret-protocol", "1")
                        .header("x-forwarded-proto", "https")
                        .json(&json!({ "refresh_token": text }))
                } else {
                    body_req(path, &text, &proof)
                };
                let res = send(&app, req).await;
                sends += 1;
                seen.take("a token route with a bad proof", &res);
            }
        }
    }

    // The sign-in: the canary proofs, and a canary in every field.
    for proof in canary_proofs("POST", LOGIN_FINISH, None, now, 777) {
        secrets.proof(&proof);
        let half = login_start(&app, &email(1), CLIENT_PASSWORD).await;
        let res = send(&app, finish_req(&device_body(&half), Some(&proof))).await;
        sends += 1;
        seen.take("a sign-in with a bad proof", &res);
        let half = login_start(&app, &email(1), "not the master password").await;
        let res = send(&app, finish_req(&device_body(&half), Some(&proof))).await;
        seen.take("a sign-in with a bad proof and a wrong password", &res);
    }

    // The proof as a canary in the text of the stream's request as well.
    let proof = canary_proofs("GET", "/api/sync/events", Some(&canary_access), now, 888).remove(0);
    secrets.proof(&proof);
    let res = send(
        &app,
        token_req(Method::GET, "/api/sync/events", &canary_access, &proof)
            .header("sec-fetch-site", "none"),
    )
    .await;
    seen.take("the stream with the canary", &res);

    // ---- what the log holds, and what the answers hold
    let text = log.text();
    assert!(
        sends > 100,
        "the canary went through many requests: {sends}"
    );
    assert!(seen.refusals > 100, "and was refused: {}", seen.refusals);
    // The lines the paths must leave: a search of an empty log proves nothing.
    for line in [
        "a device was revoked: a used refresh token came again",
        "a device was revoked",
    ] {
        assert!(
            text.contains(line),
            "the log lacks the line {line:?}:\n{text}"
        );
    }
    if let Some(found) = secrets.found_in(&text) {
        panic!("a secret reached the log: {found:?}\n{text}");
    }
    for answer in &seen.answers {
        if let Some(found) = secrets.found_in(answer) {
            panic!("a secret reached an answer: {found:?}\n{answer}");
        }
    }
    // The marker itself is nowhere in the log, whatever form it was in.
    assert!(
        !text.contains(MARK),
        "the canary's mark reached the log:\n{text}"
    );
    assert!(!text.to_ascii_lowercase().contains("authorization: dpop"));
}

/// Standard base64 (what `Authorization: Basic` carries).
fn b64std(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
