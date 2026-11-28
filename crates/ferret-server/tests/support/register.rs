//! A registration through the routes, as the web vault makes it: the client of
//! `ferret-core` (with the small test key stretching) sends `register/start`
//! and `register/finish`, with the setup token, an invitation or neither.
//!
//! What the client made is kept, so a test can go on as that account: sign in,
//! recover with its recovery key, sign in a device ([`Registered::client`]
//! gives the [`super::accounts::Client`] the other helpers take).

use axum::http::StatusCode;
use ferret_core::testing::opaque::{TestKsf, register_finish_with};
use ferret_core::{
    KsfProfile, MethodId, NewAccount, NewAccountIds, NewPassword, OpaqueInput, RegistrationState,
    SecureRng as _, TestRng, opaque_register_start,
};
use ferret_server::ids::{AccountId, DeviceId, VaultId};
use ferret_server::wire::{b64url, hex16};
use ferret_server_auth::testing::SMALL;
use serde_json::{Value, json};

use super::accounts::{CLIENT_PASSWORD, Client, TestAccount, opaque_input};
use super::{Req, Res, TestApp, VAULT_URL, Which};

/// The path of the first step.
pub const START: &str = "/api/auth/opaque/register/start";
/// The path of the second step.
pub const FINISH: &str = "/api/auth/opaque/register/finish";
/// The device id the client sends in `finish`.
pub const DEVICE: [u8; 16] = [0x5d; 16];

/// A request the way the web vault sends it through the trusted proxy.
pub fn post(uri: &str, body: &Value) -> Req {
    Req::post(uri)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .header("sec-fetch-site", "same-origin")
        .json(body)
}

/// Sends `body` to `uri` on the vault listener, with no cookie.
pub async fn call(app: &TestApp, uri: &str, body: &Value) -> Res {
    app.call_raw(Which::Vault, post(uri, body).build()).await
}

/// The error code of an answer, `""` for none.
pub fn error_of(res: &Res) -> String {
    serde_json::from_slice::<Value>(&res.body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The client side of one registration with [`CLIENT_PASSWORD`].
pub struct Registrant {
    input: OpaqueInput,
    state: RegistrationState,
    request: Vec<u8>,
    rng: TestRng,
}

/// A registrant whose random bytes follow from `seed`.
pub fn registrant(seed: &str) -> Registrant {
    let mut rng = TestRng::new(format!("registrant {seed}").as_bytes());
    let input = opaque_input(CLIENT_PASSWORD);
    let (request, state) = opaque_register_start(&mut rng, &input).expect("a first message");
    Registrant {
        input,
        state,
        request,
        rng,
    }
}

/// A finished registration as the client holds it.
pub struct Registered {
    /// The answer to `start`.
    pub started: Value,
    /// The body of `finish`.
    pub finish: Value,
    /// What the client made.
    pub account: NewAccount,
    /// Where the client's random bytes come from.
    pub rng: TestRng,
}

impl Registrant {
    /// The body of `start` for `email`, with an invitation token when given.
    pub fn start_body(&self, email: &str, invite: Option<&str>) -> Value {
        let mut body = json!({ "email": email, "request": b64url::encode(&self.request) });
        if let Some(invite) = invite {
            body["invite"] = json!(invite);
        }
        body
    }

    /// `start` for `email` with `invite`.
    pub async fn start(&self, app: &TestApp, email: &str, invite: Option<&str>) -> Res {
        call(app, START, &self.start_body(email, invite)).await
    }

    /// Everything the client sends in `finish`, made from the server's answer
    /// to `start`, with the secret key bit `sk_bit`.
    pub fn finished(mut self, started: &Value, sk_bit: bool) -> Registered {
        let response =
            b64url::decode(started["response"].as_str().expect("a response")).expect("base64url");
        let registration = register_finish_with(
            &mut self.rng,
            self.state,
            &self.input,
            &response,
            &TestKsf::new(SMALL),
        )
        .expect("the client finishes");
        let mut method_ids = [0u8; 32];
        self.rng.fill(&mut method_ids);
        let (password_id, recovery_id) = method_ids.split_at(16);
        let ids = NewAccountIds {
            account_id: AccountId::from_bytes(decode_id(&started["account_id"])),
            vault_id: VaultId::from_bytes(decode_id(&started["vault_id"])),
            password_method_id: MethodId::from_bytes(password_id.try_into().expect("16")),
            recovery_method_id: MethodId::from_bytes(recovery_id.try_into().expect("16")),
        };
        let account = ferret_core::create_account(
            &mut self.rng,
            &ids,
            NewPassword {
                input: &self.input,
                registration,
                profile: KsfProfile::P1,
            },
            None,
        )
        .expect("the client makes the account");
        let wraps: Vec<Value> = account
            .wraps
            .iter()
            .map(|w| {
                json!({
                    "method_id": hex16::encode(w.method_id.as_bytes()),
                    "method_type": w.method.type_code(),
                    "kek_generation": w.kek_generation,
                    "wrap": b64url::encode(&w.wrap),
                })
            })
            .collect();
        let finish = json!({
            "registration_id": started["registration_id"],
            "device_id": hex16::encode(&DEVICE),
            "device_name": "Test browser",
            "record": b64url::encode(&account.registration_record),
            "ksf_profile": account.ksf_profile.number(),
            "sk_bit": sk_bit,
            "wraps": wraps,
            "manifest": {
                "rev": account.manifest.rev,
                "envelope": b64url::encode(&account.manifest.envelope),
                "tag": b64url::encode(&account.manifest.tag),
            },
            "checkpoint": {
                "seq": account.checkpoint.seq,
                "digest": b64url::encode(&account.checkpoint.digest),
                "mac": b64url::encode(&account.checkpoint.mac),
                "entries": b64url::encode(&account.checkpoint.entries),
            },
            "pk_a": b64url::encode(&account.pk_a),
            "pk_r": b64url::encode(&account.pk_r),
        });
        Registered {
            started: started.clone(),
            finish,
            account,
            rng: self.rng,
        }
    }

    /// `start` for `email` with `invite`, which must answer `200`, and the
    /// finish the client makes from it (not sent yet).
    pub async fn started(
        self,
        app: &TestApp,
        email: &str,
        invite: Option<&str>,
        sk_bit: bool,
    ) -> Registered {
        let res = self.start(app, email, invite).await;
        assert_eq!(res.status, StatusCode::OK, "{}", res.text());
        self.finished(&res.json(), sk_bit)
    }
}

impl Registered {
    /// Sends the finish, keeping the cookies of the answer in the app's jar of
    /// the vault listener.
    pub async fn send(&self, app: &TestApp) -> Res {
        app.call(Which::Vault, post(FINISH, &self.finish).build())
            .await
    }

    /// Sends the finish with no jar in and none out.
    pub async fn send_raw(&self, app: &TestApp) -> Res {
        call(app, FINISH, &self.finish).await
    }

    /// The account id the server gave.
    pub fn account_id(&self) -> AccountId {
        AccountId::from_bytes(decode_id(&self.started["account_id"]))
    }

    /// The vault id the server gave.
    pub fn vault_id(&self) -> VaultId {
        VaultId::from_bytes(decode_id(&self.started["vault_id"]))
    }

    /// The account as the helpers of `accounts` take it, for kit user
    /// `user_id`.
    pub fn client(self, user_id: i64) -> Client {
        let ids = TestAccount {
            user_id,
            account_id: self.account_id(),
            vault_id: self.vault_id(),
            device: DeviceId(DEVICE),
        };
        let pinned = self.account.pinned(VAULT_URL).expect("a pinned record");
        let mut wraps = self.account.wraps.into_iter();
        let password_wrap = wraps.next().expect("the password wrap");
        let recovery_wrap = wraps.next().expect("the recovery wrap");
        Client {
            ids,
            password: CLIENT_PASSWORD.to_string(),
            vault: self.account.vault,
            recovery_key: self.account.recovery_key,
            pinned,
            password_wrap,
            recovery_wrap,
            manifest: self.account.manifest,
            rng: self.rng,
        }
    }
}

/// An id of an answer.
pub fn decode_id(value: &Value) -> [u8; 16] {
    hex16::decode(value.as_str().expect("an id")).expect("hex")
}
