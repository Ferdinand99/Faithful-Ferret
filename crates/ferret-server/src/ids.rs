//! Identifiers and the session secret.
//!
//! The account, vault, item and unlock method ids are the core's. The device id
//! and the session types are the server's.

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
/// client. Not secret.
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
}
