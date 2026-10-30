//! The JSON shapes shared with the web vault, and the rules for how bytes and
//! ids are written in them.
//!
//! * Ids are 32 lower-case hexadecimal characters ([`hex16`]).
//! * Other bytes are base64url without padding, strict: no `=`, no `+` or `/`,
//!   no white space, no spare bits ([`b64url`]).
//! * Integers are whole numbers no larger than [`MAX_JSON_INT`], the largest
//!   one a JavaScript number holds exactly. A larger one is refused on input.
//! * Times are Unix seconds.
//! * A shape that comes from a client refuses unknown fields. Optional fields
//!   are left out when empty, so a shape written back is the text it came from.
//!
//! `tests/fixtures/wire/` holds one example of every shape. The Rust tests in
//! `tests/wire_contract.rs` and the web tests in `web/test/unit/wire.test.mjs`
//! read the same files, so the two sides cannot drift apart.
//!
//! The types that carry ciphertext, tags, OPAQUE messages or codes have a
//! `Debug` that prints `[redacted]`, so a stray `{:?}` in a log line shows no
//! bytes.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Why a value from the wire was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    /// Not strict base64url without padding.
    Base64,
    /// Not 32 lower-case hexadecimal characters.
    Hex,
    /// Decoded to the wrong number of bytes.
    Length {
        /// What the field must have.
        expected: usize,
        /// What it had.
        got: usize,
    },
    /// A field that is missing, repeated or not allowed with the others.
    Field(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Base64 => f.write_str("not base64url without padding"),
            WireError::Hex => f.write_str("not 32 lower-case hexadecimal characters"),
            WireError::Length { expected, got } => {
                write!(f, "expected {expected} bytes, got {got}")
            }
            WireError::Field(name) => write!(f, "field {name} is wrong"),
        }
    }
}

impl std::error::Error for WireError {}

/// The largest integer on the wire: 2^53 - 1, the largest whole number a
/// JavaScript number holds exactly. A client that sends more is refused.
pub const MAX_JSON_INT: u64 = (1 << 53) - 1;

/// The longest device name, in characters.
pub const DEVICE_NAME_MAX_CHARS: usize = 64;

/// The length of a hand-over code as text: 32 bytes in base64url.
pub const HANDOFF_CODE_CHARS: usize = 43;

/// The length of a hand-over code in bytes.
pub const HANDOFF_CODE_BYTES: usize = 32;

/// Strict base64url without padding.
pub mod b64url {
    use super::WireError;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// Writes `bytes` as base64url without padding.
    pub fn encode(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Reads base64url without padding. Padding, the standard alphabet (`+`
    /// and `/`), white space and non-zero spare bits are all refused.
    pub fn decode(text: &str) -> Result<Vec<u8>, WireError> {
        URL_SAFE_NO_PAD.decode(text).map_err(|_| WireError::Base64)
    }
}

/// An id as 32 lower-case hexadecimal characters.
pub mod hex16 {
    use super::WireError;

    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    /// Writes an id as 32 lower-case hexadecimal characters.
    pub fn encode(id: &[u8; 16]) -> String {
        let mut out = String::with_capacity(32);
        for byte in id {
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        out
    }

    fn nibble(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }

    /// Reads an id. Exactly 32 lower-case hexadecimal characters; upper case,
    /// white space, a prefix and any other length are refused.
    pub fn decode(text: &str) -> Result<[u8; 16], WireError> {
        let bytes = text.as_bytes();
        if bytes.len() != 32 {
            return Err(WireError::Hex);
        }
        let mut out = [0u8; 16];
        let (pairs, _) = bytes.as_chunks::<2>();
        for (slot, pair) in out.iter_mut().zip(pairs) {
            let high = nibble(pair[0]).ok_or(WireError::Hex)?;
            let low = nibble(pair[1]).ok_or(WireError::Hex)?;
            *slot = (high << 4) | low;
        }
        Ok(out)
    }
}

/// Decodes base64url that must hold exactly `N` bytes.
fn fixed<const N: usize>(text: &str) -> Result<[u8; N], WireError> {
    let bytes = b64url::decode(text)?;
    let got = bytes.len();
    <[u8; N]>::try_from(bytes).map_err(|_| WireError::Length { expected: N, got })
}

/// `#[serde(with = "serde_b64")]` for `Vec<u8>`: base64url.
pub mod serde_b64 {
    use super::{Deserialize, Deserializer, Serializer, b64url, de};

    /// Writes bytes as base64url.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64url::encode(bytes))
    }

    /// Reads strict base64url.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        b64url::decode(&text).map_err(de::Error::custom)
    }
}

/// `#[serde(with = "serde_b64_opt")]` for `Option<Vec<u8>>`. Pair it with
/// `default` and `skip_serializing_if = "Option::is_none"`.
pub mod serde_b64_opt {
    use super::{Deserialize, Deserializer, Serializer, b64url, de};

    /// Writes bytes as base64url, or `null`.
    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_str(&b64url::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    /// Reads strict base64url, or `null`.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| b64url::decode(&text).map_err(de::Error::custom))
            .transpose()
    }
}

/// `#[serde(with = "serde_b32")]` for `[u8; 32]`: base64url of exactly 32
/// bytes.
pub mod serde_b32 {
    use super::{Deserialize, Deserializer, Serializer, b64url, de, fixed};

    /// Writes 32 bytes as base64url.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&b64url::encode(bytes))
    }

    /// Reads strict base64url that decodes to 32 bytes.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        fixed::<32>(&text).map_err(de::Error::custom)
    }
}

/// `#[serde(with = "serde_b32_opt")]` for `Option<[u8; 32]>`.
pub mod serde_b32_opt {
    use super::{Deserialize, Deserializer, Serializer, b64url, de, fixed};

    /// Writes 32 bytes as base64url, or `null`.
    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_str(&b64url::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    /// Reads strict base64url that decodes to 32 bytes, or `null`.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| fixed::<32>(&text).map_err(de::Error::custom))
            .transpose()
    }
}

/// `#[serde(with = "serde_hex16")]` for `[u8; 16]`: an id.
pub mod serde_hex16 {
    use super::{Deserialize, Deserializer, Serializer, de, hex16};

    /// Writes an id as 32 lower-case hexadecimal characters.
    pub fn serialize<S: Serializer>(id: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex16::encode(id))
    }

    /// Reads an id.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 16], D::Error> {
        let text = String::deserialize(deserializer)?;
        hex16::decode(&text).map_err(de::Error::custom)
    }
}

/// `#[serde(with = "serde_hex16_opt")]` for `Option<[u8; 16]>`.
pub mod serde_hex16_opt {
    use super::{Deserialize, Deserializer, Serializer, de, hex16};

    /// Writes an id, or `null`.
    pub fn serialize<S: Serializer>(
        id: &Option<[u8; 16]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match id {
            Some(id) => serializer.serialize_str(&hex16::encode(id)),
            None => serializer.serialize_none(),
        }
    }

    /// Reads an id, or `null`.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 16]>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| hex16::decode(&text).map_err(de::Error::custom))
            .transpose()
    }
}

/// `deserialize_with = "u53::deserialize"` for integers: a whole number no
/// larger than [`MAX_JSON_INT`].
pub mod u53 {
    use super::{Deserialize, Deserializer, MAX_JSON_INT, de};

    /// Reads an integer and refuses one a JavaScript number cannot hold.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value > MAX_JSON_INT {
            return Err(de::Error::custom("integer larger than 2^53 - 1"));
        }
        Ok(value)
    }
}

/// `deserialize_with = "device_name::deserialize"`: an optional name of at most
/// [`DEVICE_NAME_MAX_CHARS`] characters with no control characters.
pub mod device_name {
    use super::{DEVICE_NAME_MAX_CHARS, Deserialize, Deserializer, de};

    /// Reads an optional device name and refuses a long one.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<String>, D::Error> {
        let name = Option::<String>::deserialize(deserializer)?;
        if let Some(name) = &name
            && (name.chars().count() > DEVICE_NAME_MAX_CHARS || name.chars().any(char::is_control))
        {
            return Err(de::Error::custom(
                "device name is too long or has control characters",
            ));
        }
        Ok(name)
    }
}

macro_rules! redacted_debug {
    ($($ty:ident),+ $(,)?) => {$(
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "([redacted])"))
            }
        }
    )+};
}

/// A sealed row: the manifest as it is sent and stored.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedRowJson {
    /// The revision of the row.
    #[serde(deserialize_with = "u53::deserialize")]
    pub rev: u64,
    /// The envelope.
    #[serde(with = "serde_b64")]
    pub envelope: Vec<u8>,
    /// The tag over the row.
    #[serde(with = "serde_b32")]
    pub tag: [u8; 32],
}

/// An unlock method: the vault key wrapped for one way of unlocking.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapJson {
    /// The id of the method.
    #[serde(with = "serde_hex16")]
    pub method_id: [u8; 16],
    /// 1 password, 2 recovery, 3 passkey.
    pub method_type: u8,
    /// The generation of the key-encryption key.
    #[serde(deserialize_with = "u53::deserialize")]
    pub kek_generation: u64,
    /// The wrap: 104 bytes for a password, 72 for recovery.
    #[serde(with = "serde_b64")]
    pub wrap: Vec<u8>,
    /// The passkey credential, for a passkey.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub credential_id: Option<Vec<u8>>,
    /// The PRF salt, for a passkey.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b32_opt"
    )]
    pub prf_salt: Option<[u8; 32]>,
}

/// A checkpoint as it is uploaded with the first row of a vault.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointJson {
    /// The sequence number the checkpoint covers.
    #[serde(deserialize_with = "u53::deserialize")]
    pub seq: u64,
    /// The digest of `entries`.
    #[serde(with = "serde_b32")]
    pub digest: [u8; 32],
    /// The MAC over the checkpoint.
    #[serde(with = "serde_b32")]
    pub mac: [u8; 32],
    /// The entries: 56 bytes for each row.
    #[serde(with = "serde_b64")]
    pub entries: Vec<u8>,
}

/// The head of a checkpoint as `/changes` reports it: no entries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointHeadJson {
    /// The sequence number the checkpoint covers.
    #[serde(deserialize_with = "u53::deserialize")]
    pub seq: u64,
    /// The digest of the entries.
    #[serde(with = "serde_b32")]
    pub digest: [u8; 32],
    /// The MAC over the checkpoint.
    #[serde(with = "serde_b32")]
    pub mac: [u8; 32],
}

/// `POST /api/auth/opaque/register/start`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartReq {
    /// The setup token, when the server asks for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_token: Option<String>,
    /// The login name.
    pub email: String,
    /// The OPAQUE registration request.
    #[serde(with = "serde_b64")]
    pub request: Vec<u8>,
}

/// The answer to [`RegisterStartReq`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterStartRes {
    /// Names this registration in `register/finish`.
    #[serde(with = "serde_hex16")]
    pub registration_id: [u8; 16],
    /// The id of the new account.
    #[serde(with = "serde_hex16")]
    pub account_id: [u8; 16],
    /// The id of the new vault.
    #[serde(with = "serde_hex16")]
    pub vault_id: [u8; 16],
    /// The OPAQUE registration response.
    #[serde(with = "serde_b64")]
    pub response: Vec<u8>,
    /// The key-stretching profile the client must use.
    pub ksf_profile: u8,
}

/// `POST /api/auth/opaque/register/finish`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishReq {
    /// From [`RegisterStartRes`].
    #[serde(with = "serde_hex16")]
    pub registration_id: [u8; 16],
    /// The device that registers (required).
    #[serde(with = "serde_hex16")]
    pub device_id: [u8; 16],
    /// A name for the device, at most 64 characters.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "device_name::deserialize"
    )]
    pub device_name: Option<String>,
    /// The OPAQUE registration record (192 bytes).
    #[serde(with = "serde_b64")]
    pub record: Vec<u8>,
    /// The key-stretching profile the client used.
    pub ksf_profile: u32,
    /// Whether the account has a secret key.
    pub sk_bit: bool,
    /// The two unlock methods: password and recovery.
    pub wraps: Vec<WrapJson>,
    /// The manifest, as the first row of the vault.
    pub manifest: SealedRowJson,
    /// The first checkpoint.
    pub checkpoint: CheckpointJson,
    /// The public key that checks the password proofs.
    #[serde(with = "serde_b32")]
    pub pk_a: [u8; 32],
    /// The public key that checks the recovery proofs.
    #[serde(with = "serde_b32")]
    pub pk_r: [u8; 32],
}

/// What a sign-in is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LoginPurposeJson {
    /// A new session (the default).
    Login,
    /// A fresh check of the password inside a session.
    Reauth,
}

/// `POST /api/auth/opaque/login/start`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartReq {
    /// The login name.
    pub email: String,
    /// The first OPAQUE message (96 bytes).
    #[serde(with = "serde_b64")]
    pub ke1: Vec<u8>,
    /// What the sign-in is for; `login` when left out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<LoginPurposeJson>,
}

/// The answer to [`LoginStartReq`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStartRes {
    /// Names this sign-in in `login/finish`.
    #[serde(with = "serde_hex16")]
    pub login_id: [u8; 16],
    /// The second OPAQUE message (320 bytes).
    #[serde(with = "serde_b64")]
    pub ke2: Vec<u8>,
    /// The key-stretching profile the client must use.
    pub ksf_profile: u8,
    /// Whether the account has a secret key.
    pub sk_hint: bool,
}

/// `POST /api/auth/opaque/login/finish`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishReq {
    /// From [`LoginStartRes`].
    #[serde(with = "serde_hex16")]
    pub login_id: [u8; 16],
    /// The third OPAQUE message (64 bytes).
    #[serde(with = "serde_b64")]
    pub ke3: Vec<u8>,
    /// The device that signs in (required).
    #[serde(with = "serde_hex16")]
    pub device_id: [u8; 16],
    /// A name for the device, at most 64 characters.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "device_name::deserialize"
    )]
    pub device_name: Option<String>,
}

/// The answer to [`LoginFinishReq`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRes {
    /// The account.
    #[serde(with = "serde_hex16")]
    pub account_id: [u8; 16],
    /// The vault.
    #[serde(with = "serde_hex16")]
    pub vault_id: [u8; 16],
    /// The epoch of the vault key.
    #[serde(deserialize_with = "u53::deserialize")]
    pub vk_epoch: u64,
}

/// What a hand-over to the admin origin is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandoffPurposeJson {
    /// A new admin session.
    Login,
    /// A fresh password check, used up on the admin origin.
    Reauth,
}

/// `POST /api/auth/handoff`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffReq {
    /// What the hand-over is for.
    pub purpose: HandoffPurposeJson,
    /// Where to go on the admin origin; the server cleans it.
    pub next: String,
    /// `SHA-256` of the verifier the admin origin holds.
    #[serde(with = "serde_b32")]
    pub challenge: [u8; 32],
}

/// The answer to [`HandoffReq`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRes {
    /// The code: base64url of 32 bytes, 43 characters.
    pub code: String,
    /// Seconds until the code expires.
    #[serde(deserialize_with = "u53::deserialize")]
    pub expires_in: u64,
}

/// `POST /api/auth/handoff/redeem`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemReq {
    /// The code from [`HandoffRes`].
    pub code: String,
}

/// The answer to [`RedeemReq`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoffRedeemRes {
    /// Where to go on the admin origin.
    pub next: String,
}

/// Reads a hand-over code: exactly 43 characters of strict base64url that
/// decode to 32 bytes. The caller answers every failure alike.
pub fn parse_handoff_code(code: &str) -> Result<[u8; HANDOFF_CODE_BYTES], WireError> {
    if code.len() != HANDOFF_CODE_CHARS {
        return Err(WireError::Length {
            expected: HANDOFF_CODE_CHARS,
            got: code.len(),
        });
    }
    fixed::<HANDOFF_CODE_BYTES>(code)
}

/// `GET /api/auth/session`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRes {
    /// The account, when the session belongs to one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_hex16_opt"
    )]
    pub account_id: Option<[u8; 16]>,
    /// The login name.
    pub email: String,
    /// The scope of the session.
    pub scope: String,
    /// `vault` or `admin`.
    pub origin: String,
}

/// `GET /api/vault/unlock-methods`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MethodsRes {
    /// The unlock methods.
    pub methods: Vec<WrapJson>,
    /// The public key that checks the password proofs.
    #[serde(with = "serde_b32")]
    pub pk_a: [u8; 32],
    /// The epoch of the vault key.
    #[serde(deserialize_with = "u53::deserialize")]
    pub vk_epoch: u64,
    /// The manifest row.
    pub manifest: SealedRowJson,
}

/// One row in `/changes`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeJson {
    /// The item.
    #[serde(with = "serde_hex16")]
    pub id: [u8; 16],
    /// The revision.
    #[serde(deserialize_with = "u53::deserialize")]
    pub rev: u64,
    /// The sequence number of the change.
    #[serde(deserialize_with = "u53::deserialize")]
    pub seq: u64,
    /// Whether the row is a tombstone.
    pub deleted: bool,
    /// The envelope, for a live row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub blob: Option<Vec<u8>>,
    /// The tag, for a live row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b32_opt"
    )]
    pub tag: Option<[u8; 32]>,
    /// The tombstone (40 bytes), for a deleted row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub tomb: Option<Vec<u8>>,
}

/// `GET /api/sync/changes`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangesRes {
    /// The rows after `since`, oldest first.
    pub changes: Vec<ChangeJson>,
    /// The newest sequence number of the vault.
    #[serde(deserialize_with = "u53::deserialize")]
    pub latest_seq: u64,
    /// The epoch of the vault key.
    #[serde(deserialize_with = "u53::deserialize")]
    pub vk_epoch: u64,
    /// Changes when the vault is restored.
    #[serde(deserialize_with = "u53::deserialize")]
    pub restore_epoch: u64,
    /// The head of the newest checkpoint, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointHeadJson>,
    /// Whether more rows follow.
    pub has_more: bool,
}

/// `PUT /api/sync/items/{id}`: a live row (`blob` and `tag`) or a tombstone
/// (`deleted: true` and `tomb`), never both. Call [`PutItemReq::validate`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutItemReq {
    /// The revision the client built on; 0 for a new item.
    #[serde(deserialize_with = "u53::deserialize")]
    pub base_rev: u64,
    /// The envelope, for a live row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub blob: Option<Vec<u8>>,
    /// The tag, for a live row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b32_opt"
    )]
    pub tag: Option<[u8; 32]>,
    /// `true` for a tombstone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// The tombstone (40 bytes), for a deleted row.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub tomb: Option<Vec<u8>>,
    /// Makes a retry of this request safe.
    #[serde(with = "serde_hex16")]
    pub idem: [u8; 16],
}

/// The one form a [`PutItemReq`] has.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PutItemForm<'a> {
    /// A live row.
    Live {
        /// The envelope.
        blob: &'a [u8],
        /// The tag.
        tag: &'a [u8; 32],
    },
    /// A tombstone.
    Deleted {
        /// The tombstone.
        tomb: &'a [u8],
    },
}

impl fmt::Debug for PutItemForm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PutItemForm::Live { .. } => "PutItemForm::Live([redacted])",
            PutItemForm::Deleted { .. } => "PutItemForm::Deleted([redacted])",
        })
    }
}

impl PutItemReq {
    /// Checks that the request has exactly one form: `blob` and `tag` (and
    /// neither `tomb` nor `deleted: true`), or `deleted: true` and `tomb` (and
    /// neither `blob` nor `tag`). Lengths are the caller's to check.
    pub fn validate(&self) -> Result<PutItemForm<'_>, WireError> {
        match (&self.blob, &self.tag, self.deleted, &self.tomb) {
            (Some(blob), Some(tag), None | Some(false), None) => {
                Ok(PutItemForm::Live { blob, tag })
            }
            (None, None, Some(true), Some(tomb)) => Ok(PutItemForm::Deleted { tomb }),
            _ => Err(WireError::Field("blob, tag, deleted, tomb")),
        }
    }
}

/// The answer to a stored [`PutItemReq`].
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutItemRes {
    /// The new revision.
    #[serde(deserialize_with = "u53::deserialize")]
    pub rev: u64,
    /// The sequence number of the change.
    #[serde(deserialize_with = "u53::deserialize")]
    pub seq: u64,
    /// Whether this answer repeats an earlier one for the same `idem`.
    pub replayed: bool,
}

/// The `409` answer: the row as it is now.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConflictRes {
    /// The revision on the server.
    #[serde(deserialize_with = "u53::deserialize")]
    pub current_rev: u64,
    /// The envelope, when the row is live.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b64_opt"
    )]
    pub blob: Option<Vec<u8>>,
    /// The tag, when the row is live.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_b32_opt"
    )]
    pub tag: Option<[u8; 32]>,
    /// Whether the row is a tombstone.
    pub deleted: bool,
}

/// The body of every error: `{"error":"<code>"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorRes {
    /// One of [`ERROR_CODES`].
    pub error: String,
}

redacted_debug!(
    SealedRowJson,
    WrapJson,
    CheckpointJson,
    CheckpointHeadJson,
    RegisterStartReq,
    RegisterStartRes,
    RegisterFinishReq,
    LoginStartReq,
    LoginStartRes,
    LoginFinishReq,
    LoginFinishRes,
    HandoffReq,
    HandoffRes,
    RedeemReq,
    HandoffRedeemRes,
    SessionRes,
    MethodsRes,
    ChangeJson,
    ChangesRes,
    PutItemReq,
    PutItemRes,
    ConflictRes,
);

/// Every code an error body can carry. The list is stable: the web vault
/// switches on these strings, and `tests/fixtures/wire/error_codes.json` is the
/// golden copy both sides check.
pub const ERROR_CODES: &[&str] = &[
    "unauthorized",
    "denied",
    "forbidden",
    "insecure_transport",
    "handoff_invalid",
    "manifest_not_writable",
    "malformed_registration_request",
    "malformed_registration_record",
    "malformed_ke1",
    "malformed_ke3",
    "malformed_login_id",
    "malformed_nonce",
    "malformed_proof",
    "malformed_login_name",
    "malformed_recovery_key",
    "registration_closed",
    "throttled",
    "profile_rejected",
    "unsupported_envelope",
    "tombstone_invalid",
    "too_large",
    "quota_exceeded",
    "idem_reuse",
    "conflict",
    "protocol_header_missing",
    "forbidden_origin",
    "not_found",
    "bad_request",
    "internal",
];
