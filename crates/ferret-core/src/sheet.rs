//! The content of the emergency sheet and the payload of its QR code.
//!
//! Spec: Fase 1 § 6.1 (F-21, "Nødark"), § 6.2 and § 4.2 ("Pinning og
//! SK-bit"); plan U17 and U19. The core makes the text. The PDF, the layout
//! and the printing are the client's.
//!
//! # The two pages
//!
//! The sheet is two separate pages so that the two can be stored apart:
//!
//! * [`AccessPage`] (page 1): server address, e-mail, account id, KSF
//!   profile, the secret key (when the account has one) and the QR code;
//! * [`RecoveryPage`] (page 2): the recovery key and nothing else. The
//!   recovery key opens the vault alone, so it must not sit next to page 1.
//!
//! The codes are [`Zeroizing`] strings. Neither page has `Clone` or `Debug`.
//!
//! # The QR payload
//!
//! ```text
//! ferret-setup:v1?u=<server_url>&a=<account_id>&k=<ksf_profile>&s=<0|1>&o=<server_key>
//! ```
//!
//! * `u` is the server address, at most 512 bytes of printable ASCII that
//!   starts with `https://` (or `http://` for `localhost` and IP literals),
//!   with a plain host and no `user@`, `%` or `\` ([`parse_server_address`]),
//!   percent-encoded: everything except
//!   `A-Z a-z 0-9 - . _ ~` is `%XX` with **upper-case** hex;
//! * `a` is the account id, 32 lower-case hex digits;
//! * `k` is the number of the KSF profile (decimal, no leading zero);
//! * `s` is `1` when the account has a secret key and `0` when it has not;
//! * `o` is the OPAQUE server public key, 64 lower-case hex digits (U19).
//!
//! The five parameters come once each, in this order. The writer and the
//! reader agree on one spelling, so a payload that is read and written
//! again gives the same text. Anything else is `malformed_setup_qr`; another
//! version (`ferret-setup:v2?`) is `unsupported`; a server address over 512
//! bytes (or a payload no valid address can fit in) is `too_large`; a profile
//! this build does not know is `kdf_profile_unknown`. The reader
//! allocates a bounded amount and never panics.

use crate::codes::{encode_recovery_key, encode_secret_key};
use crate::error::{Error, MalformedKind};
use crate::ids::AccountId;
use crate::ksf_profile::KsfProfile;
use crate::pinning::MAX_URL_LEN;
use crate::secret::{RecoveryKey, SecretKey};
use zeroize::Zeroizing;

/// The start of every payload of version 1.
pub const SETUP_QR_PREFIX: &str = "ferret-setup:v1?";
/// The scheme that all versions share.
const SETUP_QR_SCHEME: &str = "ferret-setup:";
/// The longest server address, in bytes (plan U17). The same limit as the
/// pinned record's.
pub const MAX_SETUP_URL_LEN: usize = MAX_URL_LEN;
/// The longest e-mail address the sheet shows, in bytes (RFC 5321).
pub const MAX_SHEET_EMAIL_LEN: usize = 320;
/// The longest payload the reader looks at: the prefix, an address that is
/// all `%XX`, and the other four parameters.
const MAX_PAYLOAD_LEN: usize = 1_700;

fn bad() -> Error {
    Error::Malformed(MalformedKind::SetupQr)
}

/// What the QR code of the sheet states.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SetupQr {
    /// The server address, exactly as it was written.
    pub server_url: String,
    /// The account.
    pub account_id: AccountId,
    /// The KSF profile of the password.
    pub ksf_profile: KsfProfile,
    /// Whether the account has a secret key.
    pub sk_bit: bool,
    /// The OPAQUE server public key, to pin (U19).
    pub server_public_key: [u8; 32],
}

/// The parts of a server address that matter for where a client connects.
///
/// Made by [`parse_server_address`] with the rules of a browser, so that the
/// host a user is asked to confirm is the host the client talks to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ServerAddress {
    /// `true` for `https`, `false` for `http`.
    pub https: bool,
    /// The host in lower case; an IPv6 literal keeps its brackets.
    pub host: String,
    /// The port, when the address has one.
    pub port: Option<u16>,
}

/// Whether `host` is exactly four labels of canonical decimal (`0` to `255`,
/// no leading zero).
fn is_canonical_ipv4(host: &str) -> bool {
    let mut parts = 0usize;
    for part in host.split('.') {
        parts = parts.saturating_add(1);
        let digits =
            !part.is_empty() && part.len() <= 3 && part.bytes().all(|b| b.is_ascii_digit());
        let leading_zero = part.len() > 1 && part.starts_with('0');
        if !digits || leading_zero || part.parse::<u16>().map_or(true, |n| n > 255) {
            return false;
        }
    }
    parts == 4
}

/// Whether a browser would read `host` as an IPv4 address: its last label
/// (a trailing dot is ignored) is all digits or starts with `0x`. Such a
/// host may be written in octal, hex or a short form (`010.0.0.1` is
/// `8.0.0.1`, `127.1` and `2130706433` are `127.0.0.1`), so only the canonical
/// dotted decimal is accepted for it.
fn looks_like_ipv4(host: &str) -> bool {
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    let last = trimmed.rsplit('.').next().unwrap_or("");
    let hex = last.len() >= 2 && last.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("0x"));
    hex || (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
}

/// Reads a server address for the sheet and for the pinned record.
///
/// * 1 to 512 bytes of printable ASCII (over 512 is `too_large`);
/// * starts with `https://`, or `http://` for `localhost`, an IPv4 literal
///   or an IPv6 literal (a LAN server);
/// * the authority (up to the first `/`, `?` or `#`) is a host and an
///   optional port and nothing else: no `user@`, no `%` escape, no `\` (a
///   browser reads `\` as `/`, which would move the host), at most the
///   characters `A-Z a-z 0-9 - . _ ~ : [ ]`. An IPv6 literal is in brackets;
/// * the port, when there is one, is 1 to 5 digits from 1 to 65535;
/// * a host that a browser would read as an IPv4 address (its last label is
///   all digits or starts with `0x`) must be canonical dotted decimal: four
///   labels from `0` to `255` without a leading zero, and no trailing dot,
///   so `010.0.0.1`, `0x7f.0.0.1`, `127.1` and `2130706433` are refused;
/// * the scheme is lower case (`HTTPS://` is refused), and a trailing dot on a
///   name (`a.example.`) is kept as written;
/// * the host is lower-cased in the result. The address itself is kept as it
///   was written everywhere else.
///
/// Anything else is `malformed_setup_qr`.
///
/// Spec: Fase 1 § 6.1 (F-21); plan U17.
pub fn parse_server_address(url: &str) -> Result<ServerAddress, Error> {
    if url.len() > MAX_SETUP_URL_LEN {
        return Err(Error::TooLarge);
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) || url.contains('\\') {
        return Err(bad());
    }
    let (https, rest) = match url.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (false, url.strip_prefix("http://").ok_or_else(bad)?),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = rest.get(..end).ok_or_else(bad)?;
    if !authority
        .bytes()
        .all(|b| is_unreserved(b) || matches!(b, b':' | b'[' | b']'))
    {
        return Err(bad());
    }
    let (host, port_text) = if let Some(inner_and_rest) = authority.strip_prefix('[') {
        let (inner, after) = inner_and_rest.split_once(']').ok_or_else(bad)?;
        let hex_only = inner
            .bytes()
            .all(|b| b.is_ascii_hexdigit() || matches!(b, b':' | b'.'));
        if inner.is_empty() || !hex_only {
            return Err(bad());
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':').ok_or_else(bad)?),
        };
        (
            authority
                .get(..inner.len().saturating_add(2))
                .ok_or_else(bad)?,
            port,
        )
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || (!host.starts_with('[') && host.contains(['[', ']'])) {
        return Err(bad());
    }
    let port = match port_text {
        None => None,
        Some(text) => {
            if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(bad());
            }
            // Port 0 is no port a server listens on.
            match text.parse::<u16>().map_err(|_| bad())? {
                0 => return Err(bad()),
                n => Some(n),
            }
        }
    };
    let host = host.to_ascii_lowercase();
    let ipv4 = looks_like_ipv4(&host);
    if ipv4 && !is_canonical_ipv4(&host) {
        return Err(bad());
    }
    let local = host == "localhost" || host.starts_with('[') || ipv4;
    if !https && !local {
        return Err(bad());
    }
    Ok(ServerAddress { https, host, port })
}

/// Checks a server address for the sheet (see [`parse_server_address`]).
fn check_server_url(url: &str) -> Result<(), Error> {
    parse_server_address(url).map(drop)
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The digit for the low four bits of `n`.
fn hex_digit(table: &[u8; 16], n: u8) -> char {
    char::from(table.get(usize::from(n & 15)).copied().unwrap_or(b'0'))
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    for b in bytes {
        out.push(hex_digit(HEX_LOWER, b >> 4));
        out.push(hex_digit(HEX_LOWER, *b));
    }
}

fn percent_encode(out: &mut String, text: &str) {
    for b in text.bytes() {
        if is_unreserved(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(hex_digit(HEX_UPPER, b >> 4));
            out.push(hex_digit(HEX_UPPER, b));
        }
    }
}

/// Reads the canonical percent-encoding: raw bytes only for the unreserved
/// set, `%XX` with upper-case hex for everything else, and no `%XX` for a
/// byte that must be written raw.
fn percent_decode(text: &str) -> Result<String, Error> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
            b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len());
    let mut bytes = text.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(nibble).ok_or_else(bad)?;
            let lo = bytes.next().and_then(nibble).ok_or_else(bad)?;
            let decoded = (hi << 4) | lo;
            if is_unreserved(decoded) {
                return Err(bad());
            }
            out.push(decoded);
        } else if is_unreserved(b) {
            out.push(b);
        } else {
            return Err(bad());
        }
    }
    String::from_utf8(out).map_err(|_| bad())
}

/// Reads exactly `N` lower-case hex bytes.
fn hex_lower<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    fn nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
            b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() != N.saturating_mul(2) {
        return Err(bad());
    }
    let mut out = [0u8; N];
    let (pairs, _) = bytes.as_chunks::<2>();
    for (slot, [hi, lo]) in out.iter_mut().zip(pairs) {
        let hi = nibble(*hi).ok_or_else(bad)?;
        let lo = nibble(*lo).ok_or_else(bad)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

/// The text of the QR code of the emergency sheet.
///
/// The server address is checked first (see the module documentation); the
/// profile is typed, so a number this build does not know cannot be written.
///
/// Spec: Fase 1 § 6.1 (F-21); plan U17 and U19.
pub fn setup_qr_payload(
    server_url: &str,
    account_id: &AccountId,
    ksf_profile: KsfProfile,
    sk_bit: bool,
    server_public_key: &[u8; 32],
) -> Result<String, Error> {
    check_server_url(server_url)?;
    let mut out = String::with_capacity(MAX_PAYLOAD_LEN);
    out.push_str(SETUP_QR_PREFIX);
    out.push_str("u=");
    percent_encode(&mut out, server_url);
    out.push_str("&a=");
    push_hex(&mut out, account_id.as_bytes());
    out.push_str("&k=");
    out.push_str(&ksf_profile.number().to_string());
    out.push_str("&s=");
    out.push(if sk_bit { '1' } else { '0' });
    out.push_str("&o=");
    push_hex(&mut out, server_public_key);
    Ok(out)
}

/// The value of the parameter `name` in `part` (`name=value`).
fn field<'a>(part: Option<&'a str>, name: &str) -> Result<&'a str, Error> {
    part.and_then(|p| p.strip_prefix(name))
        .and_then(|p| p.strip_prefix('='))
        .ok_or_else(bad)
}

/// Reads the text of a QR code of the emergency sheet. See the module
/// documentation for the exact format and the errors.
///
/// Spec: Fase 1 § 6.1 (F-21); plan U17 and U19.
pub fn parse_setup_qr(s: &str) -> Result<SetupQr, Error> {
    if s.len() > MAX_PAYLOAD_LEN {
        return Err(Error::TooLarge);
    }
    let rest = s.strip_prefix(SETUP_QR_SCHEME).ok_or_else(bad)?;
    let (version, query) = rest.split_once('?').ok_or_else(bad)?;
    if version != "v1" {
        // `v` and a number: another version of the format, which this one
        // does not read.
        let number = version.strip_prefix('v').unwrap_or("");
        return if !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()) {
            Err(Error::Unsupported)
        } else {
            Err(bad())
        };
    }
    let mut parts = query.split('&');
    let url = field(parts.next(), "u")?;
    let account = field(parts.next(), "a")?;
    let profile = field(parts.next(), "k")?;
    let sk = field(parts.next(), "s")?;
    let key = field(parts.next(), "o")?;
    if parts.next().is_some() {
        return Err(bad());
    }

    let server_url = percent_decode(url)?;
    check_server_url(&server_url)?;
    let account_id = AccountId::from_bytes(hex_lower::<16>(account)?);
    // A decimal number without a sign or a leading zero.
    let digits_ok = !profile.is_empty()
        && profile.len() <= 3
        && profile.bytes().all(|b| b.is_ascii_digit())
        && !profile.starts_with('0');
    if !digits_ok {
        return Err(bad());
    }
    let number: u32 = profile.parse().map_err(|_| bad())?;
    let ksf_profile = KsfProfile::from_wire(number)?;
    let sk_bit = match sk {
        "0" => false,
        "1" => true,
        _ => return Err(bad()),
    };
    let server_public_key = hex_lower::<32>(key)?;
    Ok(SetupQr {
        server_url,
        account_id,
        ksf_profile,
        sk_bit,
        server_public_key,
    })
}

/// The account id as a UUID in the usual text form (`8-4-4-4-12`, lower-case
/// hex), for the sheet.
pub fn account_id_text(account_id: &AccountId) -> String {
    let mut out = String::with_capacity(36);
    for (i, chunk) in [0..4usize, 4..6, 6..8, 8..10, 10..16].iter().enumerate() {
        if i > 0 {
            out.push('-');
        }
        if let Some(bytes) = account_id.as_bytes().get(chunk.clone()) {
            push_hex(&mut out, bytes);
        }
    }
    out
}

/// Page 1 of the emergency sheet: where the account is, who it belongs to,
/// the secret key and the QR code that a new device can read.
///
/// Spec: Fase 1 § 6.1 ("Ark 1").
pub struct AccessPage {
    /// The server address, as the client states it.
    pub server_url: String,
    /// The e-mail address of the account.
    pub email: String,
    /// The account id as a UUID.
    pub account_id: String,
    /// The number of the KSF profile.
    pub ksf_profile: u8,
    /// The secret key as `FFS1-...`; `None` when the account has none.
    pub secret_key_code: Option<Zeroizing<String>>,
    /// The text of the QR code ([`setup_qr_payload`]).
    pub qr_payload: String,
}

/// Page 2 of the emergency sheet: the recovery key and nothing else. It opens
/// the vault alone, so it is kept apart from page 1.
///
/// Spec: Fase 1 § 6.1 ("Ark 2").
pub struct RecoveryPage {
    /// The recovery key as `FFR1-...`.
    pub recovery_key_code: Zeroizing<String>,
}

/// Both pages of the emergency sheet.
pub struct EmergencySheet {
    /// Page 1.
    pub access: AccessPage,
    /// Page 2.
    pub recovery: RecoveryPage,
}

/// Makes the text of the emergency sheet.
///
/// `email` is shown as it is: 1 to 320 bytes without control characters. The
/// QR code carries `sk_bit = sk.is_some()`.
///
/// Spec: Fase 1 § 6.1 (F-21), § 6.2.
pub fn emergency_sheet(
    server_url: &str,
    email: &str,
    account_id: &AccountId,
    ksf_profile: KsfProfile,
    server_public_key: &[u8; 32],
    sk: Option<&SecretKey>,
    rk: &RecoveryKey,
) -> Result<EmergencySheet, Error> {
    if email.is_empty() || email.len() > MAX_SHEET_EMAIL_LEN || email.chars().any(char::is_control)
    {
        return Err(bad());
    }
    let qr_payload = setup_qr_payload(
        server_url,
        account_id,
        ksf_profile,
        sk.is_some(),
        server_public_key,
    )?;
    Ok(EmergencySheet {
        access: AccessPage {
            server_url: server_url.to_owned(),
            email: email.to_owned(),
            account_id: account_id_text(account_id),
            ksf_profile: ksf_profile.number(),
            secret_key_code: sk.map(encode_secret_key),
            qr_payload,
        },
        recovery: RecoveryPage {
            recovery_key_code: encode_recovery_key(rk),
        },
    })
}
