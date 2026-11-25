//! Import of a passkey that another password manager made.
//!
//! Spec: Fase 1 § 9.1, § 9.6. The file of the other program holds the private
//! key in the clear (an unencrypted export). It goes from the bytes of the
//! file straight into [`passkey_import`], which checks it, writes it in the
//! one PKCS#8 form the core uses and returns a [`PasskeyRecord`] to seal. The
//! key is never returned as bytes and never leaves the core except inside the
//! sealed envelope, as for a passkey Ferret made itself.
//!
//! * The key is P-256 (ES256) only: PKCS#8 DER ([`ImportKey::Pkcs8Der`], the
//!   form Bitwarden writes) or a JWK ([`ImportKey::JwkJson`], the form
//!   AliasVault writes). Other curves, RSA and Ed25519 are
//!   [`Error::Unsupported`].
//! * The RP ID is read as a host and written in canonical form (lower case,
//!   A-labels, no trailing dot); an address or a public suffix is
//!   `malformed_rp_id`. The texts a site chose (user name, site name, display
//!   name) lose the characters [`site_text`] drops, as for a passkey Ferret
//!   made.
//! * Ferret's counter is always 0 (Fase 1 § 9.3). A passkey that comes with a
//!   counter above 0 is imported with 0, and [`ImportNotes::register_again`]
//!   says that a site which tracks the counter may refuse it: the user
//!   should register the passkey again on that site.
//! * The PRF seeds are imported only when the caller has them in Ferret's own
//!   formula ([`ImportPrf::Seeds`]); a source with another formula, or
//!   with none, is [`ImportPrf::None`] and the passkey has no PRF.
//!
//! The private scalar of a JWK is text. Its symbols are turned into bytes with
//! the table-free base64url code of `ct/harness/base64url.rs` (the file the
//! constant-time analyzer reads), so no memory lookup or branch of that step
//! depends on their values. The reader that finds the end of the quoted text
//! tests each character only against the quote, the backslash and the control
//! characters, which a valid text never holds, so it goes the same way for
//! every key.

use super::origin::canonical_rp_id;
use super::{
    MAX_CREDENTIAL_ID, MAX_NAME, MAX_USER_HANDLE, PasskeyRecord, optional_site_text, site_text,
};
use crate::cbor::redacted_debug;
use crate::error::{Error, MalformedKind};
use crate::passkey::cose::PasskeyPrivateKey;
use crate::secret::PrfSeed;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{DecodePrivateKey, ObjectIdentifier, PrivateKeyInfoRef};
use zeroize::Zeroizing;

/// The table-free base64url reading, included from `ct/harness/`.
mod b64 {
    include!("../../../../ct/harness/base64url.rs");
}

/// The longest PKCS#8 document accepted, in bytes. A P-256 key is 138 bytes
/// with the public key; the bound is for refusing a file that is something
/// else, before it is parsed.
const MAX_PKCS8: usize = 1024;
/// The longest JWK text accepted, in bytes.
const MAX_JWK: usize = 4096;
/// How deep a member that is skipped may nest.
const MAX_JSON_DEPTH: u32 = 8;
/// The length of a P-256 scalar or coordinate, in bytes.
const COORD: usize = 32;
/// The latest creation time accepted, in unix milliseconds: 2^53 - 1, the
/// largest whole number that JavaScript holds exactly (the item view gives the
/// time as a number).
const MAX_CREATED: u64 = (1 << 53) - 1;

/// `id-ecPublicKey` (RFC 5480).
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1`, the P-256 curve (RFC 5480).
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The private key of an imported passkey, as it is in the file.
pub enum ImportKey<'a> {
    /// A PKCS#8 `PrivateKeyInfo` in DER (with or without the public key).
    Pkcs8Der(&'a [u8]),
    /// A JSON Web Key (RFC 7517, RFC 7518 § 6.2): `{"kty":"EC","crv":"P-256",
    /// "d":…}` with `x` and `y` when the source wrote them. A missing `kty`
    /// is read as `EC`.
    JwkJson(&'a str),
}

/// The PRF seeds of an imported passkey.
pub enum ImportPrf<'a> {
    /// No PRF: the source has none, or has one that is not Ferret's formula.
    None,
    /// The two seeds of Ferret's formula (`HMAC-SHA-256(seed,
    /// SHA-256("WebAuthn PRF" ‖ 0x00 ‖ salt))`), 32 bytes each: one for an
    /// answer with user verification and one for an answer without. A source
    /// with one secret for both gives it twice.
    Seeds {
        /// The seed used when the user verified.
        uv: &'a [u8],
        /// The seed used when the user did not verify.
        nouv: &'a [u8],
    },
}

redacted_debug!(ImportKey<'_>, ImportPrf<'_>);

/// A passkey as the file of another program describes it, after the
/// interface has decoded the text of the file (ids and handles as bytes).
pub struct ImportedPasskeyInput<'a> {
    /// The credential id, 1 to 1 023 bytes.
    pub cred_id: &'a [u8],
    /// The RP ID as the file has it; it is made canonical.
    pub rp_id: &'a str,
    /// The user handle, 1 to 64 bytes. A passkey without one is not
    /// discoverable and is not imported.
    pub user_handle: &'a [u8],
    /// The user name.
    pub user_name: &'a str,
    /// The name the site gave itself, if the file has it.
    pub rp_name: Option<&'a str>,
    /// The display name of the account, if the file has it.
    pub user_display_name: Option<&'a str>,
    /// When the passkey was made, unix milliseconds.
    pub created: u64,
    /// The private key.
    pub key: ImportKey<'a>,
    /// The PRF seeds, when the source has Ferret's formula.
    pub prf: ImportPrf<'a>,
    /// The signature counter the source had (0 if it has none).
    pub counter: u32,
}

redacted_debug!(ImportedPasskeyInput<'_>);

/// What the user should be told about an imported passkey.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ImportNotes {
    /// The source had a counter above 0, and Ferret's is always 0: a site
    /// that compares counters (most libraries do when one of them is above 0)
    /// will refuse this passkey. The user registers it again on that site.
    pub register_again: bool,
    /// The counter of the source.
    pub counter: u32,
    /// The passkey has PRF seeds.
    pub prf: bool,
}

const fn bad_key() -> Error {
    Error::Malformed(MalformedKind::ItemBody)
}

fn bad_input() -> Error {
    Error::Malformed(MalformedKind::WebauthnOptions)
}

// ------------------------------------------------------------------ JSON

/// The members of a JWK that are read. The values borrow from the text.
#[derive(Default)]
struct Jwk<'a> {
    kty: Option<&'a str>,
    crv: Option<&'a str>,
    alg: Option<&'a str>,
    x: Option<&'a str>,
    y: Option<&'a str>,
    d: Option<&'a str>,
}

/// A reader over the bytes of a JSON text. It reads what a JWK needs: one
/// object whose known members are strings, and any other member skipped.
struct Scan<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> Scan<'a> {
    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.peek() == Some(byte) {
            self.pos = self.pos.saturating_add(1);
            Ok(())
        } else {
            Err(bad_key())
        }
    }

    /// A string: the text between the quotes as it is written, and whether it
    /// has an escape. A control character is refused, as JSON says.
    fn string(&mut self) -> Result<(&'a str, bool), Error> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut escaped = false;
        loop {
            match self.peek() {
                None => return Err(bad_key()),
                Some(b'"') => break,
                Some(b'\\') => {
                    escaped = true;
                    // The escaped byte is not looked at: a quote after a
                    // backslash does not end the string.
                    self.pos = self.pos.saturating_add(2);
                }
                Some(c) if c < 0x20 => return Err(bad_key()),
                Some(_) => self.pos = self.pos.saturating_add(1),
            }
        }
        // The quotes are ASCII, so both ends are on a character boundary.
        let s = self.text.get(start..self.pos).ok_or_else(bad_key)?;
        self.pos = self.pos.saturating_add(1);
        Ok((s, escaped))
    }

    /// Skips one value of any kind.
    fn skip_value(&mut self, depth: u32) -> Result<(), Error> {
        if depth > MAX_JSON_DEPTH {
            return Err(bad_key());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'"') => self.string().map(|_| ()),
            Some(b'{') => {
                self.pos = self.pos.saturating_add(1);
                self.members(depth, &mut |scan, _key, _escaped| {
                    scan.skip_value(depth.saturating_add(1))
                })
            }
            Some(b'[') => {
                self.pos = self.pos.saturating_add(1);
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(());
                }
                loop {
                    self.skip_value(depth.saturating_add(1))?;
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.pos = self.pos.saturating_add(1),
                        Some(b']') => {
                            self.pos = self.pos.saturating_add(1);
                            return Ok(());
                        }
                        _ => return Err(bad_key()),
                    }
                }
            }
            // A number, `true`, `false` or `null`: a run of letters, digits and
            // the signs of a number. A skipped value is checked for its
            // structure (quotes, brackets, commas), not for every rule of
            // JSON's numbers; the members that are read are checked fully.
            Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z') => {
                while matches!(
                    self.peek(),
                    Some(b'-' | b'+' | b'.' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
                ) {
                    self.pos = self.pos.saturating_add(1);
                }
                Ok(())
            }
            _ => Err(bad_key()),
        }
    }

    /// The members of an object whose `{` has been read: for each, `member`
    /// is called with the key (as written, and whether it has an escape) and
    /// must read the value.
    fn members(
        &mut self,
        depth: u32,
        member: &mut dyn FnMut(&mut Self, &'a str, bool) -> Result<(), Error>,
    ) -> Result<(), Error> {
        if depth > MAX_JSON_DEPTH {
            return Err(bad_key());
        }
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos = self.pos.saturating_add(1);
            return Ok(());
        }
        loop {
            self.skip_ws();
            let (key, escaped) = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            member(self, key, escaped)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos = self.pos.saturating_add(1),
                Some(b'}') => {
                    self.pos = self.pos.saturating_add(1);
                    return Ok(());
                }
                _ => return Err(bad_key()),
            }
        }
    }
}

/// A member that must be a string without an escape, and appear once.
fn text_member<'a>(scan: &mut Scan<'a>, slot: &mut Option<&'a str>) -> Result<(), Error> {
    if slot.is_some() {
        return Err(bad_key());
    }
    let (value, escaped) = scan.string()?;
    if escaped {
        return Err(bad_key());
    }
    *slot = Some(value);
    Ok(())
}

fn parse_jwk(text: &str) -> Result<Jwk<'_>, Error> {
    if text.len() > MAX_JWK {
        return Err(Error::TooLarge);
    }
    let mut jwk = Jwk::default();
    let mut scan = Scan { text, pos: 0 };
    scan.skip_ws();
    scan.expect(b'{')?;
    scan.members(0, &mut |s, key, escaped| {
        if escaped {
            return s.skip_value(1);
        }
        match key {
            "kty" => text_member(s, &mut jwk.kty),
            "crv" => text_member(s, &mut jwk.crv),
            "alg" => text_member(s, &mut jwk.alg),
            "x" => text_member(s, &mut jwk.x),
            "y" => text_member(s, &mut jwk.y),
            "d" => text_member(s, &mut jwk.d),
            _ => s.skip_value(1),
        }
    })?;
    scan.skip_ws();
    if scan.peek().is_some() {
        return Err(bad_key());
    }
    Ok(jwk)
}

// ----------------------------------------------------------------- base64

/// `N` bytes from unpadded base64url text of exactly the length that `N`
/// bytes have, with the spare bits zero (the canonical text). Up to two
/// trailing `=` are accepted and ignored. The bytes are wiped when dropped.
fn decode_b64url<const N: usize>(text: &str) -> Result<Zeroizing<[u8; N]>, Error> {
    let unpadded = text.strip_suffix('=').unwrap_or(text);
    let unpadded = unpadded.strip_suffix('=').unwrap_or(unpadded);
    let symbols = unpadded.as_bytes();
    // 6 bits a symbol: the number of symbols that N bytes need.
    if symbols.len() != N.saturating_mul(8).div_ceil(6) {
        return Err(bad_key());
    }
    let mut out = Zeroizing::new([0u8; N]);
    let found = b64::decode(symbols, out.as_mut_slice());
    if found.all_valid && found.spare == 0 {
        Ok(out)
    } else {
        Err(bad_key())
    }
}

// -------------------------------------------------------------------- keys

fn key_from_jwk(text: &str) -> Result<PasskeyPrivateKey, Error> {
    let jwk = parse_jwk(text)?;
    // A key of another kind or curve is not a broken one: it is not for
    // Ferret.
    if jwk.kty.is_some_and(|k| k != "EC") {
        return Err(Error::Unsupported);
    }
    match jwk.crv {
        Some("P-256") => {}
        Some(_) => return Err(Error::Unsupported),
        None => return Err(bad_key()),
    }
    if jwk.alg.is_some_and(|a| a != "ES256") {
        return Err(Error::Unsupported);
    }
    let d = decode_b64url::<COORD>(jwk.d.ok_or_else(bad_key)?)?;
    let key = SigningKey::from_slice(d.as_slice()).map_err(|_| bad_key())?;
    drop(d);
    // The public coordinates are optional; when they are there they must be
    // the key's own, so that a file that has been edited by hand is not read
    // as a key the site never saw.
    match (jwk.x, jwk.y) {
        (None, None) => {}
        (Some(x), Some(y)) => {
            let x = decode_b64url::<COORD>(x)?;
            let y = decode_b64url::<COORD>(y)?;
            let point = key.verifying_key().to_sec1_point(false);
            let same = point.x().is_some_and(|px| px.as_slice() == x.as_slice())
                && point.y().is_some_and(|py| py.as_slice() == y.as_slice());
            if !same {
                return Err(bad_key());
            }
        }
        _ => return Err(bad_key()),
    }
    PasskeyPrivateKey::from_signing_key(&key)
}

/// What a document that `p256` did not read is: `Unsupported` when it is a
/// well-formed PKCS#8 document for something Ferret does not do (another
/// curve, RSA, Ed25519), and broken when it is not PKCS#8 at all or is a P-256
/// key that does not read (a scalar that is not valid, a public key that is
/// not the key's own).
fn refused_pkcs8(der: &[u8]) -> Error {
    match PrivateKeyInfoRef::try_from(der) {
        Ok(info)
            if info.algorithm.oid != OID_EC_PUBLIC_KEY
                || info
                    .algorithm
                    .parameters
                    .is_none_or(|p| p.value() != OID_P256.as_bytes()) =>
        {
            Error::Unsupported
        }
        _ => bad_key(),
    }
}

fn key_from_pkcs8(der: &[u8]) -> Result<PasskeyPrivateKey, Error> {
    if der.len() > MAX_PKCS8 {
        return Err(Error::TooLarge);
    }
    match SigningKey::from_pkcs8_der(der) {
        Ok(key) => PasskeyPrivateKey::from_signing_key(&key),
        Err(_) => Err(refused_pkcs8(der)),
    }
}

fn prf_seed(bytes: &[u8]) -> Result<PrfSeed, Error> {
    let mut arr: [u8; 32] = bytes.try_into().map_err(|_| bad_key())?;
    Ok(PrfSeed::from_array_wiping(&mut arr))
}

// ------------------------------------------------------------------ import

/// Reads a passkey of another program into a record, ready to be put into an
/// item body (`PasskeyRecord::attach_to`) and sealed.
///
/// The checks run in this order, and the first that fails is the error: the
/// credential id (`malformed_webauthn_options` for no bytes, `too_large` for
/// more than 1 023), the user handle (`malformed_webauthn_options` unless it
/// is 1 to 64 bytes), the texts and the RP ID (`too_large` for more than 1 KiB
/// each) and the creation time (`too_large` above 2^53 - 1), the RP ID
/// (`malformed_rp_id` for one that is not a host or is a public suffix), the
/// key (`unsupported` for one that is not P-256, `too_large` for a document
/// that is too long, `malformed_item_body` for one that does not read) and the
/// PRF seeds (`malformed_item_body` unless both are 32 bytes).
///
/// The private key and the seeds are copied into the record, which wipes them
/// when it is dropped. The caller wipes its own copies (the input holds
/// borrows, and takes no ownership).
///
/// Spec: Fase 1 § 9.1, § 9.6.
pub fn passkey_import(
    input: &ImportedPasskeyInput<'_>,
) -> Result<(PasskeyRecord, ImportNotes), Error> {
    if input.cred_id.is_empty() {
        return Err(bad_input());
    }
    if input.cred_id.len() > MAX_CREDENTIAL_ID {
        return Err(Error::TooLarge);
    }
    if input.user_handle.is_empty() || input.user_handle.len() > MAX_USER_HANDLE {
        return Err(bad_input());
    }
    let long = [
        Some(input.user_name),
        input.rp_name,
        input.user_display_name,
    ]
    .into_iter()
    .flatten()
    .chain(core::iter::once(input.rp_id))
    .any(|s| s.len() > MAX_NAME);
    if long || input.created > MAX_CREATED {
        return Err(Error::TooLarge);
    }
    let rp_id = canonical_rp_id(input.rp_id)?;
    let key = match &input.key {
        ImportKey::Pkcs8Der(der) => key_from_pkcs8(der)?,
        ImportKey::JwkJson(text) => key_from_jwk(text)?,
    };
    let (prf_seed_uv, prf_seed_nouv) = match &input.prf {
        ImportPrf::None => (None, None),
        ImportPrf::Seeds { uv, nouv } => (Some(prf_seed(uv)?), Some(prf_seed(nouv)?)),
    };
    let notes = ImportNotes {
        register_again: input.counter > 0,
        counter: input.counter,
        prf: prf_seed_uv.is_some(),
    };
    let record = PasskeyRecord {
        cred_id: input.cred_id.to_vec(),
        rp_id: rp_id.as_str().to_owned(),
        user_handle: input.user_handle.to_vec(),
        user_name: site_text(input.user_name),
        rp_name: input.rp_name.and_then(optional_site_text),
        user_display_name: input.user_display_name.and_then(optional_site_text),
        created: input.created,
        key,
        prf_seed_uv,
        prf_seed_nouv,
    };
    Ok((record, notes))
}
