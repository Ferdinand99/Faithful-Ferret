//! The part of the DPoP check that needs no state and no key: the size and the
//! three segments of the compact JWS, the strict reading of its header and its
//! claims, the RFC 7638 thumbprint of the key and the checks of the claims.
//! Spec: Fase 1 § 7.6; RFC 9449 § 4.2, § 4.3.
//!
//! The signature is not checked here: the caller hands [`signing_input`],
//! [`signature_b64`] and the key of the header to the JOSE library. This is the
//! only reader of a proof's header and claims; the library never parses them,
//! so there is one reader and no difference between two.
//!
//! The file stands alone: it uses `serde`, `serde_json`, `base64` and `sha2`
//! and nothing of the crate, so the fuzz target can take it in as it is.
//!
//! What is accepted, and nothing else:
//!
//! ```text
//! header: {"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":<43>,"y":<43>}}
//! claims: {"jti":<16-64 visible ASCII>,"htm":<method>,"htu":<URL>,"iat":<seconds>,"ath"?:<43>}
//! ```
//!
//! Every member is required except `ath`; an unknown member (`d`, `kid`, `jku`,
//! `x5c`, `nonce`, ...) and a member given twice are refused, and so are a JSON
//! array in place of an object and anything after the object.

#![deny(clippy::arithmetic_side_effects)]

use std::fmt;
use std::marker::PhantomData;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use sha2::{Digest as _, Sha256};

/// The longest proof, in bytes. A longer one is refused before anything is
/// decoded.
pub const MAX_PROOF_LEN: usize = 4_096;

/// How far `iat` may be from the server's clock, either way, in seconds.
///
/// RFC 9449 § 4.3 (`iat` within an acceptable window).
pub const IAT_WINDOW_SECS: i64 = 60;

/// The shortest `jti`, in characters: 16 characters give at least 96 bits of
/// a random value written in base64url.
pub const JTI_MIN_LEN: usize = 16;

/// The longest `jti`, in characters.
pub const JTI_MAX_LEN: usize = 64;

/// The one accepted `typ`.
///
/// RFC 9449 § 4.2.
pub const TYP: &str = "dpop+jwt";

/// The one accepted `alg`: ECDSA over P-256 with SHA-256.
pub const ALG: &str = "ES256";

/// The length of `x`, `y` and `ath` in base64url: 32 bytes.
const B64_32: usize = 43;

/// The length of an ES256 signature in base64url: 64 bytes (`r ‖ s`, RFC 7518
/// § 3.4).
const B64_64: usize = 86;

/// The header of a proof.
///
/// RFC 9449 § 4.2.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopHeader {
    /// `dpop+jwt`.
    pub typ: String,
    /// `ES256`.
    pub alg: String,
    /// The public key that signed the proof.
    #[serde(deserialize_with = "object")]
    pub jwk: PublicJwk,
}

/// The public key of a proof: a P-256 point and nothing else, so a private
/// member (`d`) can never come with it.
///
/// RFC 9449 § 4.2; RFC 7518 § 6.2.1.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicJwk {
    /// `EC`.
    pub kty: String,
    /// `P-256`.
    pub crv: String,
    /// The x coordinate: 32 bytes in canonical base64url.
    pub x: String,
    /// The y coordinate: 32 bytes in canonical base64url.
    pub y: String,
}

/// The claims of a proof.
///
/// RFC 9449 § 4.2.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DpopClaims {
    /// A value the key never uses twice.
    pub jti: String,
    /// The method of the request.
    pub htm: String,
    /// The URL of the request, without query and fragment.
    pub htu: String,
    /// When the proof was made (Unix seconds).
    pub iat: i64,
    /// The hash of the access token that comes with the proof, if one does.
    #[serde(default, deserialize_with = "some_string")]
    pub ath: Option<String>,
}

impl fmt::Debug for DpopHeader {
    /// The kind of proof and of key only: the key itself stays out of a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopHeader")
            .field("typ", &self.typ)
            .field("alg", &self.alg)
            .field("jwk", &self.jwk)
            .finish()
    }
}

impl fmt::Debug for PublicJwk {
    /// The kind of key only, never its coordinates.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicJwk")
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DpopClaims {
    /// The method and the time only: the `jti`, the URL and `ath` stay out of
    /// a log.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DpopClaims")
            .field("htm", &self.htm)
            .field("iat", &self.iat)
            .finish_non_exhaustive()
    }
}

/// A proof cut in its three segments, with its header read and checked.
pub struct Parts<'a> {
    /// The header, checked: `typ`, `alg` and a public P-256 key.
    pub header: DpopHeader,
    /// The whole proof as it came.
    pub compact: &'a str,
}

impl fmt::Debug for Parts<'_> {
    /// The header's kinds only, never the proof.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Parts")
            .field("header", &self.header)
            .finish_non_exhaustive()
    }
}

/// Why a proof was refused here. The answer to the client never says which.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// Longer than [`MAX_PROOF_LEN`].
    TooLong,
    /// Not three non-empty segments of base64url characters.
    Segments,
    /// A segment that is not canonical base64url, or a signature that is not
    /// 64 bytes.
    Encoding,
    /// A header that is not the one accepted form, or whose `typ` or `alg` is
    /// another.
    Header,
    /// A key that is not a public P-256 key in canonical form.
    Key,
    /// Claims that are not the one accepted form, or whose `jti`, `htm`,
    /// `htu` or `ath` is not what the request needs.
    Claims,
    /// `iat` outside the window.
    Clock,
}

/// Reads a JSON object (never an array) into `T`, so a derived struct is read
/// from the one form JOSE has; the duplicate and unknown members are refused
/// by `T` itself.
fn object<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ObjectOnly<T>(PhantomData<T>);

    impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectOnly<T> {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }

    deserializer.deserialize_map(ObjectOnly(PhantomData))
}

/// `ath` when it is there: a string, never `null`.
fn some_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).map(Some)
}

/// Reads one JSON object from `bytes`, and nothing after it.
fn read_object<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = object(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

/// Whether `text` holds base64url characters only (no `=`, no white space).
fn is_b64url(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Decodes canonical base64url: no padding, no spare bits.
fn decode(text: &str) -> Result<Vec<u8>, ProofError> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| ProofError::Encoding)
}

/// Whether `text` is exactly 32 bytes in canonical base64url.
fn is_b64url_32(text: &str) -> bool {
    text.len() == B64_32 && matches!(URL_SAFE_NO_PAD.decode(text), Ok(bytes) if bytes.len() == 32)
}

/// The three segments of a compact JWS, or `None`.
fn segments(proof: &str) -> Option<(&str, &str, &str)> {
    let mut parts = proof.split('.');
    let header = parts.next()?;
    let claims = parts.next()?;
    let signature = parts.next()?;
    if parts.next().is_some() || header.is_empty() || claims.is_empty() || signature.is_empty() {
        return None;
    }
    if !(is_b64url(header) && is_b64url(claims) && is_b64url(signature)) {
        return None;
    }
    Some((header, claims, signature))
}

/// Cuts a proof in its segments and reads its header strictly: at most
/// [`MAX_PROOF_LEN`] bytes; three non-empty segments of base64url without `=`,
/// each canonical; a signature of 64 bytes; a header with `typ` `dpop+jwt`,
/// `alg` `ES256` and a `jwk` with `kty` `EC`, `crv` `P-256` and `x` and `y` of
/// 32 bytes each in canonical base64url (so one key has one thumbprint).
///
/// Spec: Fase 1 § 7.6; RFC 9449 § 4.2–4.3.
pub fn split(proof: &str) -> Result<Parts<'_>, ProofError> {
    if proof.len() > MAX_PROOF_LEN {
        return Err(ProofError::TooLong);
    }
    let (header, claims, signature) = segments(proof).ok_or(ProofError::Segments)?;
    let header_bytes = decode(header)?;
    // The claims are read only after the signature holds (`claims`), but they
    // must be canonical base64url from the start.
    decode(claims)?;
    if signature.len() != B64_64 || decode(signature)?.len() != 64 {
        return Err(ProofError::Encoding);
    }

    let header: DpopHeader = read_object(&header_bytes).map_err(|_| ProofError::Header)?;
    if header.typ != TYP || header.alg != ALG {
        return Err(ProofError::Header);
    }
    let jwk = &header.jwk;
    if jwk.kty != "EC" || jwk.crv != "P-256" || !is_b64url_32(&jwk.x) || !is_b64url_32(&jwk.y) {
        return Err(ProofError::Key);
    }
    Ok(Parts {
        header,
        compact: proof,
    })
}

/// The bytes the signature is over: the header and the claims segments with
/// the `.` between them, exactly as they came.
///
/// RFC 7515 § 5.2.
pub fn signing_input<'a>(p: &Parts<'a>) -> &'a str {
    p.compact
        .rsplit_once('.')
        .map_or(p.compact, |(input, _)| input)
}

/// The signature segment, in base64url, exactly as it came.
pub fn signature_b64<'a>(p: &Parts<'a>) -> &'a str {
    p.compact
        .rsplit_once('.')
        .map_or("", |(_, signature)| signature)
}

/// Reads the claims strictly. Call it only after the signature holds.
///
/// RFC 9449 § 4.2.
pub fn claims(p: &Parts<'_>) -> Result<DpopClaims, ProofError> {
    let segment = signing_input(p)
        .split_once('.')
        .map(|(_, claims)| claims)
        .ok_or(ProofError::Segments)?;
    let bytes = decode(segment)?;
    read_object(&bytes).map_err(|_| ProofError::Claims)
}

/// The RFC 7638 thumbprint of a key that [`split`] accepted: SHA-256 of
/// `{"crv":"P-256","kty":"EC","x":…,"y":…}`, the required members in lexical
/// order with no white space. The members of an accepted key are fixed words
/// and base64url, so nothing in them needs escaping.
///
/// RFC 7638 § 3; RFC 9449 § 6.1.
pub fn jkt(jwk: &PublicJwk) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in [
        "{\"crv\":\"",
        jwk.crv.as_str(),
        "\",\"kty\":\"",
        jwk.kty.as_str(),
        "\",\"x\":\"",
        jwk.x.as_str(),
        "\",\"y\":\"",
        jwk.y.as_str(),
        "\"}",
    ] {
        hash.update(part.as_bytes());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash.finalize());
    out
}

/// Whether `jti` is 16 to 64 visible ASCII characters.
fn jti_is_valid(jti: &str) -> bool {
    (JTI_MIN_LEN..=JTI_MAX_LEN).contains(&jti.len()) && jti.bytes().all(|b| b.is_ascii_graphic())
}

/// Checks the claims against the request at `now` (Unix seconds): `jti` is 16
/// to 64 visible ASCII characters; `htm` is the method; `htu` is exactly the
/// expected URL (the configured vault origin and the path, without query and
/// fragment); `iat` is at most [`IAT_WINDOW_SECS`] from `now`, either way;
/// `ath` is there exactly when an access token comes with the request, and is
/// then the hash of that token in canonical base64url.
///
/// `ath` and the token's hash are both what the client sent, so comparing
/// them reveals nothing that the client does not have.
///
/// RFC 9449 § 4.3 (checks 8, 9, 11 and 12).
pub fn check_claims(
    c: &DpopClaims,
    method: &str,
    htu: &str,
    ath: Option<&[u8; 32]>,
    now: i64,
) -> Result<(), ProofError> {
    if !jti_is_valid(&c.jti) || c.htm != method || c.htu != htu {
        return Err(ProofError::Claims);
    }
    match (ath, c.ath.as_deref()) {
        (None, None) => {}
        (Some(expected), Some(text)) => {
            if text.len() != B64_32 {
                return Err(ProofError::Claims);
            }
            let given = URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|_| ProofError::Claims)?;
            if given.as_slice() != expected.as_slice() {
                return Err(ProofError::Claims);
            }
        }
        _ => return Err(ProofError::Claims),
    }
    let earliest = now.saturating_sub(IAT_WINDOW_SECS);
    let latest = now.saturating_add(IAT_WINDOW_SECS);
    if c.iat < earliest || c.iat > latest {
        return Err(ProofError::Clock);
    }
    Ok(())
}
