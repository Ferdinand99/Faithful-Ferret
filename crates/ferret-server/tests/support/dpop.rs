//! DPoP proofs for the tests of device tokens: a device key, and proofs signed
//! with it for a method, a URL and a token, good ones and wrong ones.
//!
//! The key is a P-256 key from a fixed scalar (RustCrypto's `p256`, which
//! signs deterministically), so the tests are repeatable. The server checks
//! with another implementation (the JOSE library over aws-lc-rs), so a proof
//! that passes is a proof two implementations agree on.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::{HeaderMap, HeaderValue};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferret_server::auth::tokens::{DeviceAuth, Htu};
use ferret_server::ids::TokenSecret;
use ferret_server::state::VaultDb;
use ferret_server_auth::{Clock, ManualClock};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// A handle for the vault origin of the tests, over a database that is never
/// opened: for the tests that check proofs without a running app.
pub fn device_auth() -> DeviceAuth {
    let pool = deadpool_sqlite::Config::new("/ferret-no-such-directory/none.db")
        .create_pool(deadpool_sqlite::Runtime::Tokio1)
        .expect("a pool");
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(super::START));
    DeviceAuth::new(VaultDb::new(pool), clock, super::VAULT_URL)
}

/// The `htu` of `path` on the vault origin of the tests.
pub fn vault_htu(path: &str) -> Htu {
    device_auth().htu(path)
}

/// base64url without padding.
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A device key: a P-256 key pair and its public coordinates in base64url.
pub struct DeviceKey {
    signing: SigningKey,
    /// The x coordinate, 43 characters.
    pub x: String,
    /// The y coordinate, 43 characters.
    pub y: String,
}

impl DeviceKey {
    /// The key whose secret scalar is 32 bytes of `n` (`n` from 1 to 0x7f, so
    /// the scalar is below the group order); keys with another `n` differ.
    pub fn new(n: u8) -> Self {
        assert!((1..=0x7f).contains(&n), "a scalar below the group order");
        let signing = SigningKey::from_slice(&[n; 32]).expect("a P-256 scalar");
        let point = signing.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
        Self {
            x: b64(&bytes[1..33]),
            y: b64(&bytes[33..65]),
            signing,
        }
    }

    /// A key for a long run of tests, from a number: every number gives
    /// another key (the scalar is the SHA-256 of a label and the number, so
    /// any `u64` will do, where [`DeviceKey::new`] has 127 keys).
    pub fn from_counter(counter: u64) -> Self {
        for salt in 0u8..=255 {
            let mut hasher = Sha256::new();
            hasher.update(b"ferret test device key");
            hasher.update(counter.to_be_bytes());
            hasher.update([salt]);
            let scalar: [u8; 32] = hasher.finalize().into();
            if let Ok(signing) = SigningKey::from_slice(&scalar) {
                let point = signing.verifying_key().to_sec1_point(false);
                let bytes = point.as_bytes();
                return Self {
                    x: b64(&bytes[1..33]),
                    y: b64(&bytes[33..65]),
                    signing,
                };
            }
        }
        unreachable!("a scalar below the group order is found at once");
    }

    /// The public JWK: exactly `kty`, `crv`, `x` and `y`.
    pub fn jwk(&self) -> Value {
        json!({"kty": "EC", "crv": "P-256", "x": self.x, "y": self.y})
    }

    /// The RFC 7638 thumbprint, computed here from the coordinates.
    pub fn jkt(&self) -> [u8; 32] {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            self.x, self.y
        );
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(canonical.as_bytes()));
        out
    }

    /// The good header: `typ`, `alg` and this key.
    pub fn header(&self) -> Value {
        json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk()})
    }

    /// A compact JWS over the exact bytes of a header and claims, signed with
    /// this key (ES256, `r ‖ s`).
    pub fn sign_bytes(&self, header: &[u8], claims: &[u8]) -> String {
        let input = format!("{}.{}", b64(header), b64(claims));
        let signature: Signature = self.signing.sign(input.as_bytes());
        format!("{input}.{}", b64(&signature.to_bytes()))
    }

    /// A compact JWS of a header and claims written as JSON.
    pub fn sign(&self, header: &Value, claims: &Value) -> String {
        self.sign_bytes(
            serde_json::to_string(header).expect("json").as_bytes(),
            serde_json::to_string(claims).expect("json").as_bytes(),
        )
    }

    /// A good proof for `method` and `htu` at `iat`, with a fresh `jti`, and
    /// with the `ath` of `token` when one comes with the request.
    pub fn proof(&self, method: &str, htu: &str, iat: i64, token: Option<&TokenSecret>) -> String {
        self.sign(
            &self.header(),
            &claims(method, htu, iat, &fresh_jti(), token),
        )
    }
}

/// The claims of a proof.
pub fn claims(method: &str, htu: &str, iat: i64, jti: &str, token: Option<&TokenSecret>) -> Value {
    let mut claims = json!({"jti": jti, "htm": method, "htu": htu, "iat": iat});
    if let Some(token) = token {
        claims["ath"] = Value::String(ath(token));
    }
    claims
}

/// The `ath` of a token: base64url of SHA-256 of its 43 ASCII characters.
pub fn ath(token: &TokenSecret) -> String {
    b64(&Sha256::digest(token.to_wire().as_bytes()))
}

/// A `jti` no other call returns in this process: 24 characters.
pub fn fresh_jti() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    format!("jti-{:020}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Headers with one `DPoP` header.
pub fn headers_with(proof: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "dpop",
        HeaderValue::from_str(proof).expect("a header value"),
    );
    headers
}

/// The three segments of a compact JWS.
pub fn segments(proof: &str) -> (String, String, String) {
    let mut parts = proof.split('.').map(str::to_string);
    let header = parts.next().expect("a header");
    let claims = parts.next().expect("claims");
    let signature = parts.next().expect("a signature");
    (header, claims, signature)
}

/// Lower-case hexadecimal to bytes.
pub fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "an even number of digits");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("a hex digit pair"))
        .collect()
}
