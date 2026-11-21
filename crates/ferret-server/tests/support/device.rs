//! A device client for the tests of device tokens: it signs in for tokens
//! with a test key ([`super::dpop::DeviceKey`]) and the real OPAQUE client of
//! `ferret-core`, and sends requests with its access token and a proof.
//!
//! Requests go to the vault listener as a device client sends them: no
//! cookie, no `Origin`, `Ferret-Protocol: 1`, and over `https` through the
//! test peer, which [`device_app`] trusts as a proxy.

use axum::http::{Method, StatusCode};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{OPAQUE_CONTEXT, OsRng, PinState, opaque_login_start};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::TokenSecret;
use ferret_server::wire::b64url;
use ferret_server_auth::Clock as _;
use ferret_server_auth::testing::SMALL;
use serde_json::{Value, json};

use super::accounts::opaque_input;
use super::dpop::DeviceKey;
use super::{Builder, PEER, Req, Res, TestApp, VAULT_URL, Which};

/// The path of the sign-in's last step.
pub const LOGIN_FINISH: &str = "/api/auth/opaque/login/finish";

/// The name the device gives when a test does not say otherwise.
pub const DEVICE_NAME: &str = "Ferret for Firefox (Windows)";

/// An app builder that believes the test peer as a proxy, so requests that
/// say `x-forwarded-proto: https` count as `https`.
pub fn device_app_builder() -> Builder {
    let proxies = ProxyList::parse(&[PEER.split(':').next().expect("a host").to_string()])
        .expect("a proxy list");
    TestApp::builder().proxies(proxies)
}

/// An app for device clients: see [`device_app_builder`].
pub async fn device_app() -> TestApp {
    device_app_builder().build().await
}

/// The clock of the app now (Unix seconds).
pub fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// A sign-in half-way: the server answered `login/start`, and the client made
/// its third message. For a password that does not open the record (a wrong
/// one, or a name without an account) the client cannot make one, and `ke3`
/// is 64 bytes of junk, as an attacker would send.
pub struct HalfWay {
    /// The `login_id` the server gave.
    pub login_id: String,
    /// The client's third message.
    pub ke3: Vec<u8>,
    /// Whether the password opened the record.
    pub opened: bool,
}

/// `login/start` for `email` with `password`, and the client's third
/// message.
pub async fn login_start(app: &TestApp, email: &str, password: &str) -> HalfWay {
    let input = opaque_input(password);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).expect("a first message");
    let res = app
        .call_raw(
            Which::Vault,
            Req::post("/api/auth/opaque/login/start")
                .header("ferret-protocol", "1")
                .header("x-forwarded-proto", "https")
                .json(&json!({"email": email, "ke1": b64url::encode(&ke1)}))
                .build(),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let answer = res.json();
    let ke2 = b64url::decode(answer["ke2"].as_str().expect("a ke2")).expect("base64url");
    let finished = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    );
    let (ke3, opened) = match finished {
        Ok(done) => (done.finished.ke3, true),
        Err(_) => (vec![0x33; 64], false),
    };
    HalfWay {
        login_id: answer["login_id"].as_str().expect("a login id").to_string(),
        ke3,
        opened,
    }
}

/// The body a device client sends to finish its sign-in.
pub fn device_body(half: &HalfWay) -> Value {
    json!({
        "login_id": half.login_id,
        "ke3": b64url::encode(&half.ke3),
        "client": "device",
        "device_name": DEVICE_NAME,
        "platform": "windows",
    })
}

/// `POST /api/auth/opaque/login/finish` with `body`, and `proof` in the
/// `DPoP` header when there is one.
pub fn finish_req(body: &Value, proof: Option<&str>) -> Req {
    let mut req = Req::post(LOGIN_FINISH)
        .header("ferret-protocol", "1")
        .header("x-forwarded-proto", "https");
    if let Some(proof) = proof {
        req = req.header("dpop", proof);
    }
    req.json(body)
}

/// A device client: its key and, once it signed in, its id and tokens.
pub struct DeviceClient {
    /// The device key.
    pub key: DeviceKey,
    /// The id the server gave the device.
    pub device_id: Option<[u8; 16]>,
    /// The access token.
    pub access: Option<TokenSecret>,
    /// The refresh token.
    pub refresh: Option<TokenSecret>,
}

impl DeviceClient {
    /// A client with the test key `n` (see [`DeviceKey::new`]), not signed in.
    pub fn new(n: u8) -> Self {
        Self {
            key: DeviceKey::new(n),
            device_id: None,
            access: None,
            refresh: None,
        }
    }

    /// A good proof for `method` and `path` on the vault origin at the app's
    /// time, with the `ath` of `token` when one comes with the request.
    pub fn proof(
        &self,
        app: &TestApp,
        method: &str,
        path: &str,
        token: Option<&TokenSecret>,
    ) -> String {
        self.key
            .proof(method, &format!("{VAULT_URL}{path}"), now(app), token)
    }

    /// A good proof for the sign-in.
    pub fn login_proof(&self, app: &TestApp) -> String {
        self.proof(app, "POST", LOGIN_FINISH, None)
    }

    /// Finishes a sign-in with `body` and a good proof of this key, and keeps
    /// the id and the tokens of a `200`.
    pub async fn finish(&mut self, app: &TestApp, body: &Value) -> Res {
        let proof = self.login_proof(app);
        let res = app
            .call_raw(Which::Vault, finish_req(body, Some(&proof)).build())
            .await;
        if res.status == StatusCode::OK {
            self.keep(&res);
        }
        res
    }

    /// The whole sign-in of `email` with `password`.
    pub async fn sign_in(&mut self, app: &TestApp, email: &str, password: &str) -> Res {
        let half = login_start(app, email, password).await;
        self.finish(app, &device_body(&half)).await
    }

    /// Takes the id and the tokens of a `200` to a sign-in.
    pub fn keep(&mut self, res: &Res) {
        let body = res.json();
        let id = body["device_id"].as_str().expect("a device id");
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&id[2 * i..2 * i + 2], 16).expect("hex"))
            .collect();
        self.device_id = Some(bytes.try_into().expect("16 bytes"));
        let token = |name: &str| {
            TokenSecret::from_wire(body[name].as_str().expect("a token")).expect("a token")
        };
        self.access = Some(token("access_token"));
        self.refresh = Some(token("refresh_token"));
    }

    /// A request with the access token and a proof for it, as a device client
    /// sends it.
    pub fn token_req(&self, app: &TestApp, method: Method, path: &str) -> Req {
        let access = self.access.as_ref().expect("signed in");
        let proof = self.proof(app, method.as_str(), path, Some(access));
        Req::new(method, path)
            .header("authorization", &format!("DPoP {}", access.to_wire()))
            .header("dpop", &proof)
            .header("ferret-protocol", "1")
            .header("x-forwarded-proto", "https")
    }

    /// Sends a request to the vault listener as it is, with no cookie.
    pub async fn send(&self, app: &TestApp, req: Req) -> Res {
        app.call_raw(Which::Vault, req.build()).await
    }
}
