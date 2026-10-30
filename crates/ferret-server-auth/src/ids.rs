//! Identifiers of the server side: the credential id that OPAQUE binds a
//! record to, the id of a login in progress, and the binding to a session.
//!
//! None of these types derives `Debug`: a login id is a bearer value for the
//! 60 seconds it lives, and a credential id of a made-up account must not be
//! told apart from a real one in a log. Their `Debug` writes `[redacted]`.

use core::fmt::{self, Write as _};

use ferret_core::{AccountId, SecureRng};
use sha2::{Digest, Sha256};

/// Label of the key under which a login state is stored.
///
/// The store never sees the login id, only this hash of it, so
/// a dump of the store holds no value a client can present.
// Used by `store_key`, whose first caller is the login state store.
#[allow(dead_code)]
const STATE_KEY_LABEL: &[u8] = b"ferret/v1/server/login-state-key";

/// The identifier OPAQUE binds a record to (`credential_identifier`). It is
/// the `account_id` for a real account, and an HMAC-derived value for a
/// made-up one, so both have the same shape.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredentialId([u8; 16]);

impl CredentialId {
    /// Wraps 16 raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<&AccountId> for CredentialId {
    fn from(account: &AccountId) -> Self {
        Self(*account.as_bytes())
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialId([redacted])")
    }
}

/// The id of a login between `login_start` and `login_finish`: 128 random
/// bits, on the wire 32 lower-case hexadecimal characters.
///
/// The id is a bearer value for the minute it lives, but it is not a
/// credential on its own: the server stores only a hash of it (see
/// [`StateKey`]), and `login_finish` also needs the client's third OPAQUE
/// message. The type is `Copy`, so it cannot wipe itself on drop.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoginId([u8; 16]);

impl LoginId {
    /// Length of the wire form in characters.
    pub const HEX_LEN: usize = 32;

    /// A fresh id from the caller's random source.
    ///
    /// 128 bits, drawn in one call.
    pub fn random<R: SecureRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill(&mut bytes);
        Self(bytes)
    }

    /// Reads the wire form: exactly 32 characters from `0-9a-f`. Upper case,
    /// white space, a `0x` prefix and every other length are malformed. The
    /// answer depends on the bytes given and on nothing else.
    pub fn parse(text: &[u8]) -> Result<Self, crate::AuthError> {
        let malformed = crate::AuthError::Malformed(crate::Malformed::LoginId);
        if text.len() != Self::HEX_LEN {
            return Err(malformed);
        }
        let mut bytes = [0u8; 16];
        let (pairs, _) = text.as_chunks::<2>();
        for (slot, [high, low]) in bytes.iter_mut().zip(pairs) {
            let (Some(high), Some(low)) = (nibble(*high), nibble(*low)) else {
                return Err(malformed);
            };
            *slot = high.wrapping_shl(4) | low;
        }
        Ok(Self(bytes))
    }

    /// The wire form: 32 lower-case hexadecimal characters.
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(Self::HEX_LEN);
        for byte in self.0 {
            // Writing to a String cannot fail.
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// The key under which the state of this login is stored:
    /// `SHA-256(label ‖ login_id)`.
    ///
    /// A label and a hash are used so that a dump of the store holds no id.
    #[allow(dead_code)]
    pub(crate) fn store_key(&self) -> StateKey {
        let mut hash = Sha256::new();
        hash.update(STATE_KEY_LABEL);
        hash.update(self.0);
        StateKey(hash.finalize().into())
    }
}

impl fmt::Debug for LoginId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LoginId([redacted])")
    }
}

/// The key of a login state in a store: the hash of the login id, never the
/// id itself.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateKey([u8; 32]);

impl StateKey {
    /// The 32 bytes, for a store to use as its key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateKey([redacted])")
    }
}

/// SHA-256 of the server's internal session id. The caller chooses the
/// session id and how to bind to it; the library only compares bindings.
#[derive(Clone, Copy)]
pub struct SessionBinding(pub [u8; 32]);

impl fmt::Debug for SessionBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionBinding([redacted])")
    }
}

/// One lower-case hexadecimal digit.
const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthError, Malformed};
    use ferret_core::testing::TestRng;

    const BYTES: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const HEX: &str = "000102030405060708090a0b0c0d0e0f";

    fn bad() -> Result<LoginId, AuthError> {
        Err(AuthError::Malformed(Malformed::LoginId))
    }

    #[test]
    fn login_id_parse_is_strict() {
        assert_eq!(LoginId::parse(HEX.as_bytes()).unwrap().0, BYTES);
        assert_eq!(
            LoginId::parse(b"ffffffffffffffffffffffffffffffff")
                .unwrap()
                .0,
            [0xff; 16]
        );
        for text in [
            // upper case, whole and in part
            "000102030405060708090A0B0C0D0E0F",
            "00010203040506070809Aa0b0c0d0e0f",
            // 31 and 33 characters, empty, double
            &HEX[..31],
            format!("{HEX}0").as_str(),
            "",
            format!("{HEX}{HEX}").as_str(),
            // white space, in the middle and at the ends
            "000102030405060708090a0b0c0d0e 0",
            " 00102030405060708090a0b0c0d0e0f",
            "00102030405060708090a0b0c0d0e0f ",
            "00102030405060708090a0b0c0d0e0f\n",
            // prefix, sign, other digits
            "0x0102030405060708090a0b0c0d0e0f",
            "+00102030405060708090a0b0c0d0e0f",
            "g00102030405060708090a0b0c0d0e0f",
            "000102030405060708090a0b0c0d0e0\u{0}",
            // a multi-byte character that makes 32 bytes
            "\u{e9}00102030405060708090a0b0c0d0e0",
        ] {
            assert_eq!(LoginId::parse(text.as_bytes()), bad(), "{text:?}");
        }
        // Not valid UTF-8 at all.
        assert_eq!(LoginId::parse(&[0xff; 32]), bad());
    }

    #[test]
    fn login_id_hex_round_trips() {
        let id = LoginId(BYTES);
        assert_eq!(id.to_hex(), HEX);
        assert_eq!(LoginId::parse(id.to_hex().as_bytes()).unwrap(), id);
        let mut rng = TestRng::new(b"login id");
        for _ in 0..50 {
            let id = LoginId::random(&mut rng);
            let hex = id.to_hex();
            assert_eq!(hex.len(), 32);
            assert!(
                hex.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            );
            assert_eq!(LoginId::parse(hex.as_bytes()).unwrap(), id);
        }
    }

    #[test]
    fn login_id_random_takes_sixteen_bytes_from_the_rng() {
        use ferret_core::testing::ReplayRng;
        let mut rng = ReplayRng::new(vec![BYTES.to_vec()]);
        assert_eq!(LoginId::random(&mut rng).0, BYTES);
        rng.finish().unwrap();
    }

    #[test]
    fn login_id_store_key_hides_the_id() {
        // SHA-256("ferret/v1/server/login-state-key" ‖ 00 01 .. 0f), computed
        // with sha256sum.
        let expected = "6ee67712148049d3d0510146605c0ee9c665a176fad735c4aa9aab256aa6d2c8";
        let key = LoginId(BYTES).store_key();
        let hex: String = key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        // The key neither contains the id nor equals a plain hash of it.
        assert!(!key.as_bytes().windows(16).any(|w| w == BYTES));
        let plain: [u8; 32] = Sha256::digest(BYTES).into();
        assert_ne!(key.as_bytes(), &plain);
        // Different ids give different keys.
        let mut other = BYTES;
        other[15] ^= 1;
        assert_ne!(LoginId(other).store_key(), key);
    }

    #[test]
    fn credential_id_comes_from_the_account_id() {
        let account = AccountId::from_bytes(BYTES);
        let id = CredentialId::from(&account);
        assert_eq!(id.as_bytes(), &BYTES);
        assert_eq!(CredentialId::from_bytes(BYTES), id);
    }

    #[test]
    fn debug_hides_the_value() {
        let shown = format!(
            "{:?} {:?} {:?} {:?}",
            LoginId(BYTES),
            CredentialId::from_bytes(BYTES),
            LoginId(BYTES).store_key(),
            SessionBinding([0x5a; 32])
        );
        assert_eq!(
            shown,
            "LoginId([redacted]) CredentialId([redacted]) StateKey([redacted]) SessionBinding([redacted])"
        );
    }
}
