//! Identifiers, the session secret and the device tokens.
//!
//! The account, vault, item and unlock method ids are the core's. The device id,
//! the session types and the token types are the server's.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use ferret_core::SecureRng;
pub use ferret_core::{AccountId, ItemId, MethodId, VaultId};

use crate::wire::WireError;

/// The `item_id` of the manifest row: 16 zero bytes. The row is an ordinary row
/// in `/changes`; the web vault never shows it as an item.
pub const MANIFEST_ITEM_ID: ItemId = ItemId::MANIFEST;

/// Identifies a device (a browser profile). 16 random bytes, made once by the
/// client; a device that signs in for tokens gets one from the server instead.
/// Not secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DeviceId(pub [u8; 16]);

/// Length of the session secret in bytes.
const SECRET_LEN: usize = 32;

/// Domain label of the hash that keys a session row.
const SID_LABEL: &[u8] = b"ferret/v1/sid";

/// The random value in the `__Host-ferret_sid` cookie. Only the hash of it is
/// stored ([`SidHash`]), so a copy of the database holds no usable cookie.
///
/// Never `Clone`, and its `Debug` shows nothing.
pub struct SessionSecret(Zeroizing<[u8; SECRET_LEN]>);

impl SessionSecret {
    /// A new secret: 32 bytes from `rng`.
    pub fn random<R: SecureRng>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        rng.fill(bytes.as_mut_slice());
        Self(bytes)
    }

    /// The cookie value: base64url without padding (43 characters).
    pub fn to_cookie(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_slice())
    }

    /// Reads a cookie value. Anything but exactly 43 characters of strict
    /// base64url without padding, decoding to 32 bytes, is refused.
    pub fn from_cookie(value: &str) -> Result<Self, WireError> {
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value)
                .map_err(|_| WireError::Base64)?,
        );
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        if decoded.len() != SECRET_LEN {
            return Err(WireError::Length {
                expected: SECRET_LEN,
                got: decoded.len(),
            });
        }
        bytes.as_mut_slice().copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    /// The key of the session row: SHA-256 of the label and the secret.
    pub fn hash(&self) -> SidHash {
        let mut hasher = Sha256::new();
        hasher.update(SID_LABEL);
        hasher.update(self.0.as_slice());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        SidHash(out)
    }
}

impl fmt::Debug for SessionSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionSecret([redacted])")
    }
}

/// `SHA-256("ferret/v1/sid" ‖ secret)`: the key of a row in `ferret_sessions`.
/// A hash of a 256-bit random value, not a secret in itself; compared in
/// SQL by equality only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SidHash(pub [u8; 32]);

/// Domain label of the hash that keys a token row.
///
/// Spec: Fase 1 § 7.6 (tokens are stored as hashes only).
const TOKEN_LABEL: &[u8] = b"ferret/v1/token";

/// The length of a token on the wire: 32 bytes as base64url without padding.
const TOKEN_TEXT_LEN: usize = 43;

/// A device token, access or refresh: 32 random bytes. Only the hash of it is
/// stored ([`TokenHash`]), so a copy of the database holds no usable token.
///
/// Never `Clone`, zeroed when dropped, and its `Debug` shows nothing.
///
/// Spec: Fase 1 § 7.6; RFC 9449 § 4.2 for [`TokenSecret::ath`].
pub struct TokenSecret(Zeroizing<[u8; SECRET_LEN]>);

impl TokenSecret {
    /// A new token: 32 bytes from `rng`.
    pub fn random<R: SecureRng>(rng: &mut R) -> Self {
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        rng.fill(bytes.as_mut_slice());
        Self(bytes)
    }

    /// The token as it travels: base64url without padding (43 characters).
    pub fn to_wire(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_slice())
    }

    /// Reads a token. Anything but exactly 43 characters of strict base64url
    /// without padding (no `=`, no `+` or `/`, no spare bits), decoding to 32
    /// bytes, is refused.
    pub fn from_wire(text: &str) -> Result<Self, WireError> {
        if text.len() != TOKEN_TEXT_LEN {
            return Err(WireError::Length {
                expected: TOKEN_TEXT_LEN,
                got: text.len(),
            });
        }
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(text)
                .map_err(|_| WireError::Base64)?,
        );
        if decoded.len() != SECRET_LEN {
            return Err(WireError::Length {
                expected: SECRET_LEN,
                got: decoded.len(),
            });
        }
        let mut bytes = Zeroizing::new([0u8; SECRET_LEN]);
        bytes.as_mut_slice().copy_from_slice(&decoded);
        Ok(Self(bytes))
    }

    /// The key of the token row: SHA-256 of the label `ferret/v1/token` and
    /// the 32 bytes of the token.
    pub fn hash(&self) -> TokenHash {
        let mut hasher = Sha256::new();
        hasher.update(TOKEN_LABEL);
        hasher.update(self.0.as_slice());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        TokenHash(out)
    }

    /// The `ath` of a DPoP proof that comes with this token: SHA-256 of the
    /// token as it travels (the 43 ASCII characters), with no label.
    ///
    /// RFC 9449 § 4.2 (`ath`: the hash of the ASCII encoding of the access
    /// token's value).
    pub fn ath(&self) -> [u8; 32] {
        let text = Zeroizing::new(self.to_wire());
        let digest = Sha256::digest(text.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

impl fmt::Debug for TokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenSecret([redacted])")
    }
}

/// `SHA-256("ferret/v1/token" ‖ token)`: the key of a row in `ferret_access`
/// or `ferret_refresh`. A hash of a 256-bit random value, not a secret in
/// itself; compared in SQL by equality only.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct TokenHash(pub [u8; 32]);

#[cfg(test)]
mod tests {
    use super::*;
    use ferret_core::TestRng;

    fn secret() -> SessionSecret {
        SessionSecret::random(&mut TestRng::new(b"session secret seed"))
    }

    #[test]
    fn the_manifest_item_is_sixteen_zero_bytes() {
        assert_eq!(MANIFEST_ITEM_ID.as_bytes(), &[0u8; 16]);
    }

    #[test]
    fn a_cookie_value_is_43_characters_and_round_trips() {
        let s = secret();
        let cookie = s.to_cookie();
        assert_eq!(cookie.len(), 43);
        assert_eq!(
            SessionSecret::from_cookie(&cookie).unwrap().hash(),
            s.hash()
        );
    }

    #[test]
    fn a_cookie_value_must_be_strict() {
        let cookie = secret().to_cookie();
        for bad in [
            format!("{cookie}="),
            format!(" {cookie}"),
            format!("+{}", &cookie[1..]),
            cookie[..42].to_string(),
            format!("{cookie}A"),
            String::new(),
        ] {
            assert!(SessionSecret::from_cookie(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_hash_is_a_domain_separated_sha256() {
        let s = secret();
        let mut hasher = Sha256::new();
        hasher.update(b"ferret/v1/sid");
        hasher.update(s.0.as_slice());
        assert_eq!(s.hash().0.as_slice(), hasher.finalize().as_slice());
        assert_ne!(
            s.hash().0.as_slice(),
            Sha256::digest(s.0.as_slice()).as_slice()
        );
    }

    #[test]
    fn debug_shows_nothing_of_the_secret() {
        let s = secret();
        let shown = format!("{s:?}");
        assert!(shown.contains("redacted") && !shown.contains(&s.to_cookie()));
    }

    fn token(seed: &[u8]) -> TokenSecret {
        TokenSecret::random(&mut TestRng::new(seed))
    }

    #[test]
    fn token_secret_round_trips_43_chars_and_refuses_other_lengths_and_padding() {
        let t = token(b"token seed");
        let text = t.to_wire();
        assert_eq!(text.len(), 43);
        assert_eq!(TokenSecret::from_wire(&text).unwrap().hash(), t.hash());
        assert_eq!(TokenSecret::from_wire(&text).unwrap().to_wire(), text);
        // The last character carries 2 bits of the token and 4 spare bits,
        // which must be zero.
        let last = text.chars().last().unwrap();
        let spare = if last == 'B' { 'C' } else { 'B' };
        for bad in [
            text[..42].to_string(),
            format!("{text}A"),
            format!("{}=", &text[..42]),
            format!("{text}="),
            format!("{}{spare}", &text[..42]),
            format!("+{}", &text[1..]),
            format!("/{}", &text[1..]),
            format!(" {}", &text[1..]),
            format!("{}\n", &text[..42]),
            "A".repeat(44),
            String::new(),
        ] {
            assert!(TokenSecret::from_wire(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            TokenSecret::from_wire(&text[..42]).unwrap_err(),
            WireError::Length {
                expected: 43,
                got: 42
            }
        );
        // Two tokens are two different rows.
        assert_ne!(token(b"another seed").hash(), t.hash());
    }

    #[test]
    fn ath_is_over_the_ascii_and_the_row_hash_over_the_bytes() {
        let t = token(b"ath seed");
        // `ath`: SHA-256 of the 43 ASCII characters, no label (RFC 9449 § 4.2).
        assert_eq!(
            t.ath().as_slice(),
            Sha256::digest(t.to_wire().as_bytes()).as_slice()
        );
        // The row: SHA-256 of the label and the 32 bytes.
        let mut hasher = Sha256::new();
        hasher.update(b"ferret/v1/token");
        hasher.update(t.0.as_slice());
        assert_eq!(t.hash().0.as_slice(), hasher.finalize().as_slice());
        // Neither is the other, nor the hash of the bytes alone, nor the
        // session hash of the same bytes.
        assert_ne!(t.hash().0, t.ath());
        assert_ne!(
            t.hash().0.as_slice(),
            Sha256::digest(t.0.as_slice()).as_slice()
        );
        let mut session = Sha256::new();
        session.update(b"ferret/v1/sid");
        session.update(t.0.as_slice());
        assert_ne!(t.hash().0.as_slice(), session.finalize().as_slice());
        // A known value: the token of 32 zero bytes is 43 times `A`.
        let zero = TokenSecret::from_wire(&"A".repeat(43)).unwrap();
        assert_eq!(zero.0.as_slice(), &[0u8; 32]);
        assert_eq!(
            zero.ath().as_slice(),
            Sha256::digest("A".repeat(43).as_bytes()).as_slice()
        );
    }

    #[test]
    fn debug_shows_nothing_of_a_token() {
        let t = token(b"debug seed");
        let shown = format!("{t:?}");
        assert_eq!(shown, "TokenSecret([redacted])");
        assert!(!shown.contains(&t.to_wire()));
    }
}
