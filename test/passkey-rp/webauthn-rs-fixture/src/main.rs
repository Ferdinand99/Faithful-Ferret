// The strict relying-party fixture (webauthn-rs): a small JSON API on 127.0.0.1 that the
// fixture server (test/passkey-rp/server) puts behind /api/rs/. State is in memory only.
//
//   POST /register/start  {sid, rpId, origin, user:{name, displayName, id?}, userVerification,
//                          residentKey, attestation, algs?, excludeExisting?, authenticatorAttachment?,
//                          extensions?}  ->  {ok, options}   (options = PublicKeyCredentialCreationOptionsJSON)
//   POST /register/finish {sid, credential}              ->  {ok, credentialId, flags} or {ok:false, error}
//   POST /auth/start      {sid, rpId, origin, userVerification, allow: "all"|"none"|"unknown", extensions?}
//                                                        ->  {ok, options}
//   POST /auth/finish     {sid, credential}              ->  {ok, counter, flags} or {ok:false, error}
//   POST /reset           {sid}                          ->  {ok}
//
// Every check is the library's (signature, RP ID hash, origin, crossOrigin, flags, backup
// eligibility and state, counter). The fixture adds two on top, so that the reason of a
// refusal is plain: a clientDataJSON with `crossOrigin: true` is refused, and a discoverable
// response must carry the user handle of the credential's owner.
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::Read;
use std::sync::Mutex;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server};
use url::Url;
use webauthn_rs_core::WebauthnCore;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AuthenticationState, AuthenticatorAttachment, Credential, PublicKeyCredential,
    RegisterPublicKeyCredential, RegistrationState, UserVerificationPolicy,
};

struct Registration {
    state: RegistrationState,
    user_id: Vec<u8>,
    rp_id: String,
    origin: String,
}

struct Authentication {
    state: AuthenticationState,
    rp_id: String,
    origin: String,
}

#[derive(Default)]
struct Session {
    reg: Option<Registration>,
    auth: Option<Authentication>,
    /// Credential and the user handle of its owner.
    credentials: Vec<(Credential, Vec<u8>)>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserIn {
    name: String,
    display_name: String,
    id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterStart {
    sid: String,
    rp_id: String,
    origin: String,
    user: UserIn,
    #[serde(default = "preferred")]
    user_verification: String,
    #[serde(default = "preferred")]
    resident_key: String,
    #[serde(default = "none")]
    attestation: String,
    algs: Option<Vec<i64>>,
    #[serde(default)]
    exclude_existing: bool,
    authenticator_attachment: Option<String>,
    extensions: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthStart {
    sid: String,
    rp_id: String,
    origin: String,
    #[serde(default = "preferred")]
    user_verification: String,
    #[serde(default = "all")]
    allow: String,
    extensions: Option<Value>,
}

fn preferred() -> String {
    "preferred".into()
}
fn none() -> String {
    "none".into()
}
fn all() -> String {
    "all".into()
}

fn policy(text: &str) -> Result<UserVerificationPolicy, String> {
    match text {
        "required" => Ok(UserVerificationPolicy::Required),
        "preferred" => Ok(UserVerificationPolicy::Preferred),
        "discouraged" => Ok(UserVerificationPolicy::Discouraged_DO_NOT_USE),
        other => Err(format!("unknown userVerification {other}")),
    }
}

/// The library, set up for one RP ID and exactly one allowed origin (no subdomains, no other port).
fn core(rp_id: &str, origin: &str) -> Result<WebauthnCore, String> {
    let url = Url::parse(origin).map_err(|e| format!("origin: {e}"))?;
    Ok(WebauthnCore::new_unsafe_experts_only(
        "Ferret passkey fixture (webauthn-rs)",
        rp_id,
        vec![url],
        Duration::from_secs(120),
        Some(false),
        Some(false),
    ))
}

#[derive(Serialize)]
struct Flags {
    uv: bool,
    be: bool,
    bs: bool,
}

fn client_data_cross_origin(client_data_b64: &str) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(client_data_b64.trim_end_matches('=')) else { return false };
    let Ok(v) = serde_json::from_slice::<Value>(&bytes) else { return false };
    v.get("crossOrigin").and_then(Value::as_bool).unwrap_or(false)
}

fn err(message: impl std::fmt::Display) -> (u16, Value) {
    (400, json!({"ok": false, "error": message.to_string()}))
}

fn register_start(state: &Mutex<State>, body: &[u8]) -> (u16, Value) {
    let req: RegisterStart = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(format!("bad request: {e}")),
    };
    let uv = match policy(&req.user_verification) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let w = match core(&req.rp_id, &req.origin) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let user_id: Vec<u8> = match &req.user.id {
        Some(id) => match URL_SAFE_NO_PAD.decode(id) {
            Ok(b) => b,
            Err(e) => return err(format!("user.id: {e}")),
        },
        None => {
            // A stable handle per RP and user name.
            let mut h = [0u8; 16];
            let seed = format!("{}:{}", req.rp_id, req.user.name);
            for (i, b) in seed.bytes().enumerate() {
                h[i % 16] ^= b.wrapping_add(i as u8);
            }
            h.to_vec()
        }
    };
    let attestation = match req.attestation.as_str() {
        "none" => AttestationConveyancePreference::None,
        "indirect" => AttestationConveyancePreference::Indirect,
        "direct" | "enterprise" => AttestationConveyancePreference::Direct,
        other => return err(format!("unknown attestation {other}")),
    };
    let mut builder = match w.new_challenge_register_builder(&user_id, &req.user.name, &req.user.display_name) {
        Ok(b) => b,
        Err(e) => return err(format!("{e:?}")),
    }
    .attestation(attestation)
    .user_verification_policy(uv)
    .require_resident_key(req.resident_key == "required")
    .authenticator_attachment(match req.authenticator_attachment.as_deref() {
        Some("platform") => Some(AuthenticatorAttachment::Platform),
        Some("cross-platform") => Some(AuthenticatorAttachment::CrossPlatform),
        _ => None,
    });
    let mut st = state.lock().unwrap();
    let session = st.sessions.entry(req.sid.clone()).or_default();
    if req.exclude_existing {
        let ids: Vec<_> = session.credentials.iter().filter(|(_, h)| *h == user_id).map(|(c, _)| c.cred_id.clone()).collect();
        builder = builder.exclude_credentials(Some(ids));
    }
    let (response, reg_state) = match w.generate_challenge_register(builder) {
        Ok(x) => x,
        Err(e) => return err(format!("{e:?}")),
    };
    session.reg = Some(Registration { state: reg_state, user_id, rp_id: req.rp_id.clone(), origin: req.origin.clone() });
    let mut options = match serde_json::to_value(&response) {
        Ok(Value::Object(mut o)) => o.remove("publicKey").unwrap_or(Value::Null),
        _ => return err("options did not serialise"),
    };
    // What the library cannot express (a "preferred" resident key, "enterprise" attestation, a
    // list of algorithms of the test's choosing) is set on the options the page gets. The
    // checks stay the library's.
    patch_creation_options(&mut options, &req);
    (200, json!({"ok": true, "options": options}))
}

fn patch_creation_options(options: &mut Value, req: &RegisterStart) {
    let Some(o) = options.as_object_mut() else { return };
    let selection = o.entry("authenticatorSelection").or_insert_with(|| json!({}));
    if let Some(s) = selection.as_object_mut() {
        s.insert("residentKey".into(), json!(req.resident_key));
        s.insert("requireResidentKey".into(), json!(req.resident_key == "required"));
        s.insert("userVerification".into(), json!(req.user_verification));
        match req.authenticator_attachment.as_deref() {
            Some(a) => {
                s.insert("authenticatorAttachment".into(), json!(a));
            }
            None => {
                s.remove("authenticatorAttachment");
            }
        }
    }
    o.insert("attestation".into(), json!(req.attestation));
    if let Some(algs) = &req.algs {
        let list: Vec<Value> = algs.iter().map(|a| json!({"type": "public-key", "alg": a})).collect();
        o.insert("pubKeyCredParams".into(), Value::Array(list));
    }
    if let Some(ext) = &req.extensions {
        o.insert("extensions".into(), ext.clone());
    }
}

#[derive(Deserialize)]
struct Finish {
    sid: String,
    credential: Value,
}

fn register_finish(state: &Mutex<State>, body: &[u8]) -> (u16, Value) {
    let req: Finish = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(format!("bad request: {e}")),
    };
    if let Some(cd) = req.credential.pointer("/response/clientDataJSON").and_then(Value::as_str) {
        if client_data_cross_origin(cd) {
            return err("clientDataJSON says crossOrigin: true");
        }
    }
    // The extension outputs the library knows (credProps) are kept; the rest (prf, ...) are not
    // the relying party's business and the library does not model them.
    let mut credential = req.credential.clone();
    if let Some(o) = credential.as_object_mut() {
        o.remove("clientExtensionResults");
        if let Some(ext) = req.credential.get("clientExtensionResults").and_then(Value::as_object) {
            let kept: serde_json::Map<String, Value> =
                ext.iter().filter(|(k, _)| k.as_str() == "credProps").map(|(k, v)| (k.clone(), v.clone())).collect();
            o.insert("extensions".into(), Value::Object(kept));
        }
    }
    let parsed: RegisterPublicKeyCredential = match serde_json::from_value(credential) {
        Ok(c) => c,
        Err(e) => return err(format!("credential: {e}")),
    };
    let mut st = state.lock().unwrap();
    let Some(session) = st.sessions.get_mut(&req.sid) else { return err("no such session") };
    let Some(reg) = session.reg.take() else { return err("no registration in progress") };
    let w = match core(&reg.rp_id, &reg.origin) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    match w.register_credential(&parsed, &reg.state, None) {
        Ok(cred) => {
            let flags = Flags { uv: cred.user_verified, be: cred.backup_eligible, bs: cred.backup_state };
            let id = URL_SAFE_NO_PAD.encode(cred.cred_id.as_slice());
            session.credentials.push((cred, reg.user_id));
            (200, json!({"ok": true, "credentialId": id, "flags": flags}))
        }
        Err(e) => err(format!("{e:?}")),
    }
}

fn auth_start(state: &Mutex<State>, body: &[u8]) -> (u16, Value) {
    let req: AuthStart = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(format!("bad request: {e}")),
    };
    let uv = match policy(&req.user_verification) {
        Ok(p) => p,
        Err(e) => return err(e),
    };
    let w = match core(&req.rp_id, &req.origin) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    let mut st = state.lock().unwrap();
    let session = st.sessions.entry(req.sid.clone()).or_default();
    // "all" lists every stored credential, "none" is a discoverable request (an empty list),
    // "unknown" lists only an id that no store holds.
    let creds: Vec<Credential> = match req.allow.as_str() {
        "all" => session.credentials.iter().map(|(c, _)| c.clone()).collect(),
        _ => vec![],
    };
    let builder = match w.new_challenge_authenticate_builder(creds, Some(uv)) {
        Ok(b) => b,
        Err(e) => return err(format!("{e:?}")),
    };
    let (response, auth_state) = match w.generate_challenge_authenticate(builder) {
        Ok(x) => x,
        Err(e) => return err(format!("{e:?}")),
    };
    session.auth = Some(Authentication { state: auth_state, rp_id: req.rp_id.clone(), origin: req.origin.clone() });
    let mut options = match serde_json::to_value(&response) {
        Ok(Value::Object(mut o)) => o.remove("publicKey").unwrap_or(Value::Null),
        _ => return err("options did not serialise"),
    };
    if let Some(o) = options.as_object_mut() {
        o.insert("userVerification".into(), json!(req.user_verification));
        if req.allow == "unknown" {
            o.insert("allowCredentials".into(), json!([{"type": "public-key", "id": URL_SAFE_NO_PAD.encode([0xA5u8; 32])}]));
        }
        if let Some(ext) = &req.extensions {
            o.insert("extensions".into(), ext.clone());
        }
    }
    (200, json!({"ok": true, "options": options}))
}

fn auth_finish(state: &Mutex<State>, body: &[u8]) -> (u16, Value) {
    let req: Finish = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return err(format!("bad request: {e}")),
    };
    if let Some(cd) = req.credential.pointer("/response/clientDataJSON").and_then(Value::as_str) {
        if client_data_cross_origin(cd) {
            return err("clientDataJSON says crossOrigin: true");
        }
    }
    let mut credential = req.credential.clone();
    if let Some(o) = credential.as_object_mut() {
        o.remove("clientExtensionResults");
    }
    let parsed: PublicKeyCredential = match serde_json::from_value(credential) {
        Ok(c) => c,
        Err(e) => return err(format!("credential: {e}")),
    };
    let mut st = state.lock().unwrap();
    let Some(session) = st.sessions.get_mut(&req.sid) else { return err("no such session") };
    let Some(auth) = session.auth.take() else { return err("no authentication in progress") };
    let w = match core(&auth.rp_id, &auth.origin) {
        Ok(w) => w,
        Err(e) => return err(e),
    };
    // The credential comes from the store by the id the response names; a response that carries
    // a user handle must carry the one of the credential's owner.
    let Some(idx) = session.credentials.iter().position(|(c, _)| c.cred_id.as_slice() == parsed.raw_id.as_slice()) else {
        return err("CredentialNotFound");
    };
    if let Some(handle) = parsed.response.user_handle.as_ref() {
        if *handle != session.credentials[idx].1 {
            return err("userHandle does not name the owner of the credential");
        }
    }
    let cred = session.credentials[idx].0.clone();
    match w.authenticate_single_credential(&parsed, &auth.state, &cred) {
        Ok(result) => {
            let flags = Flags { uv: result.user_verified(), be: result.backup_eligible(), bs: result.backup_state() };
            // What a relying party must do with the answer, or the next check has nothing to compare to:
            // keep the counter (and the backup state) the authenticator reported.
            let counter: u32 = result.counter();
            session.credentials[idx].0.counter = counter;
            session.credentials[idx].0.backup_state = result.backup_state();
            session.credentials[idx].0.backup_eligible = result.backup_eligible();
            (200, json!({"ok": true, "counter": counter, "flags": flags}))
        }
        Err(e) => err(format!("{e:?}")),
    }
}

fn main() {
    let addr = std::env::var("FIXTURE_RS_ADDR").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let server = Server::http(&addr).expect("bind");
    let state = Mutex::new(State::default());
    eprintln!("webauthn-rs fixture on {addr}");
    for mut request in server.incoming_requests() {
        let mut body = Vec::new();
        let _ = request.as_reader().take(1 << 20).read_to_end(&mut body);
        let path = request.url().split('?').next().unwrap_or("").to_string();
        let (status, value) = match (request.method(), path.as_str()) {
            (Method::Get, "/healthz") => (200, json!({"ok": true})),
            (Method::Post, "/register/start") => register_start(&state, &body),
            (Method::Post, "/register/finish") => register_finish(&state, &body),
            (Method::Post, "/auth/start") => auth_start(&state, &body),
            (Method::Post, "/auth/finish") => auth_finish(&state, &body),
            (Method::Post, "/reset") => {
                if let Ok(v) = serde_json::from_slice::<Value>(&body) {
                    if let Some(sid) = v.get("sid").and_then(Value::as_str) {
                        state.lock().unwrap().sessions.remove(sid);
                    }
                }
                (200, json!({"ok": true}))
            }
            _ => (404, json!({"ok": false, "error": "not found"})),
        };
        let header = Header::from_bytes("content-type", "application/json").unwrap();
        let _ = request.respond(Response::from_string(value.to_string()).with_status_code(status).with_header(header));
    }
}
