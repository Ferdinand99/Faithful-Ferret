//! `clientDataJSON` (WebAuthn Level 3 § 5.8.1.1).
//!
//! Spec: Fase 1 § 9.3 and WebAuthn L3 § 5.8.1.1. The JSON is written byte by
//! byte as the specification prescribes, not through a JSON library:
//!
//! ```text
//! {"type":"webauthn.create","challenge":"<base64url>","origin":"<origin>","crossOrigin":false}
//! ```
//!
//! `crossOrigin` is always `false` and `topOrigin` is never written, because
//! a request from another origin than the top one is refused before this point
//! (Fase 1 § 9.2). A string is written with a code point verbatim when it is
//! in {U+0020, U+0021, U+0023 to U+005B, U+005D to U+10FFFF}, `\"` for U+0022,
//! `\\` for U+005C, and `\u` and four lower-case hex digits otherwise.

use super::origin::CanonicalOrigin;

/// The two ceremonies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ceremony {
    /// `navigator.credentials.create`.
    Create,
    /// `navigator.credentials.get`.
    Get,
}

impl Ceremony {
    /// The `type` member of the client data.
    pub const fn type_text(self) -> &'static str {
        match self {
            Ceremony::Create => "webauthn.create",
            Ceremony::Get => "webauthn.get",
        }
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Base64url without padding (RFC 4648 § 5). For the public challenge only.
pub(crate) fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sextets = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        // 1 byte gives 2 characters, 2 bytes give 3, 3 bytes give 4.
        let keep = chunk.len().saturating_add(1);
        for s in sextets.iter().take(keep) {
            let idx = usize::try_from(*s).unwrap_or(0);
            out.push(char::from(B64URL.get(idx).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// `CCDToString`: a string as the client data serialization writes it.
fn push_ccd_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match u32::from(c) {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x20 | 0x21 | 0x23..=0x5b | 0x5d..=0x10_ffff => out.push(c),
            other => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push_str("\\u");
                for shift in [12u32, 8, 4, 0] {
                    let nibble = usize::try_from((other >> shift) & 0xf).unwrap_or(0);
                    out.push(char::from(HEX.get(nibble).copied().unwrap_or(b'0')));
                }
            }
        }
    }
    out.push('"');
}

/// The client data JSON for `origin_text`, which is written as given.
pub(crate) fn client_data_json_raw(
    ceremony: Ceremony,
    challenge: &[u8],
    origin_text: &str,
) -> String {
    let mut out = String::from("{\"type\":");
    push_ccd_string(&mut out, ceremony.type_text());
    out.push_str(",\"challenge\":");
    push_ccd_string(&mut out, &base64url(challenge));
    out.push_str(",\"origin\":");
    push_ccd_string(&mut out, origin_text);
    out.push_str(",\"crossOrigin\":false}");
    out
}

/// The client data JSON of a request from `origin`.
pub(crate) fn client_data_json(
    ceremony: Ceremony,
    challenge: &[u8],
    origin: &CanonicalOrigin,
) -> String {
    client_data_json_raw(ceremony, challenge, origin.as_str())
}
