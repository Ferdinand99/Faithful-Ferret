//! Time-based one-time passwords (TOTP) and strict `otpauth://` parsing.
//!
//! * RFC 4226 (HOTP): HMAC over the 8-byte big-endian counter, dynamic
//!   truncation, then the last 6 to 8 decimal digits.
//! * RFC 6238 (TOTP): the counter is `T = floor(t / period)` with `T0 = 0`;
//!   HMAC-SHA-1, HMAC-SHA-256 or HMAC-SHA-512.
//! * `otpauth://totp/...` is read with an allow-list (Fase 1 § 5.2, F-31):
//!   only the type `totp` and only the parameters `secret`, `issuer`,
//!   `algorithm`, `digits` and `period`. Everything else is refused, also
//!   `counter` and `image`, and a parameter that is given twice.
//!
//! The core never reads the clock: the caller passes the Unix time, so every
//! code can be tested. Nothing in this module logs, prints or formats a
//! secret or a code; the secret type is zeroizing and has no `Debug`,
//! `Clone`, `Display` or `PartialEq`.
//!
//! # What the parser accepts
//!
//! * The scheme and the type are exactly `otpauth` and `totp`; parameter
//!   names and the algorithm names (`SHA1`, `SHA256`, `SHA512`) are matched
//!   exactly. `digits` and `period` are plain decimal numbers without sign or
//!   leading zero. Defaults: SHA1, 6 digits, 30 s.
//! * `secret` is base32 (RFC 4648 alphabet), lower or upper case, with spaces
//!   (also as `%20` or `+`) and with the `=` fill left out or complete. A
//!   wrong fill is refused. Spare bits at the end are ignored, as every
//!   authenticator app does, so what a service shows always works. The
//!   secret is 1 to [`MAX_SECRET_LEN`] bytes.
//! * The label is `account` or `Issuer:account`. The `issuer` parameter wins
//!   over the issuer in the label when both are given.
//! * `+` means a space in a parameter value (as in Android's query parser)
//!   and stays a plus in the label.
//! * The whole address is at most [`MAX_URI_LEN`] bytes and has no control
//!   characters and no fragment.

use crate::error::{Error, MalformedKind};
use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The longest secret in bytes (after base32). Fase 1 § 5.2 (F-31), plan U14.
pub const MAX_SECRET_LEN: usize = 128;
/// The longest `otpauth://` address in bytes.
pub const MAX_URI_LEN: usize = 2048;
/// The longest issuer or label in bytes.
pub const MAX_TEXT_LEN: usize = 256;
/// The fewest digits in a code.
pub const MIN_DIGITS: u8 = 6;
/// The most digits in a code.
pub const MAX_DIGITS: u8 = 8;
/// The shortest period in seconds.
pub const MIN_PERIOD: u32 = 1;
/// The longest period in seconds.
pub const MAX_PERIOD: u32 = 120;
/// The default number of digits when the address has no `digits`.
pub const DEFAULT_DIGITS: u8 = 6;
/// The default period when the address has no `period`.
pub const DEFAULT_PERIOD: u32 = 30;

const fn bad() -> Error {
    Error::Malformed(MalformedKind::Otpauth)
}

/// The HMAC hash of a TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpAlgorithm {
    /// HMAC-SHA-1 (`SHA1`), the default.
    Sha1,
    /// HMAC-SHA-256 (`SHA256`).
    Sha256,
    /// HMAC-SHA-512 (`SHA512`).
    Sha512,
}

impl TotpAlgorithm {
    /// The name used in `otpauth://` addresses.
    pub const fn name(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA1" => Some(TotpAlgorithm::Sha1),
            "SHA256" => Some(TotpAlgorithm::Sha256),
            "SHA512" => Some(TotpAlgorithm::Sha512),
            _ => None,
        }
    }
}

/// The shared secret of a TOTP, 1 to [`MAX_SECRET_LEN`] bytes. Zeroizes on
/// drop; no `Debug`, `Display`, `Clone` or `PartialEq`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TotpSecret(Zeroizing<Vec<u8>>);

impl TotpSecret {
    /// Takes the secret from raw bytes: 1 to [`MAX_SECRET_LEN`] of them.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(bad());
        }
        if bytes.len() > MAX_SECRET_LEN {
            return Err(Error::TooLarge);
        }
        // Reserved once, so the secret is never copied to a bigger buffer.
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN));
        buf.extend_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Reads a base32 secret as an authenticator app shows it: any case,
    /// spaces and line breaks anywhere, `=` fill left out or complete.
    pub fn from_base32(text: &str) -> Result<Self, Error> {
        decode_base32(text.as_bytes())
    }

    /// The secret bytes. Never public.
    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Address and capacity of the buffer, for the wipe test.
    #[cfg(feature = "test-support")]
    pub fn test_buffer(&self) -> (*const u8, usize) {
        (self.0.as_ptr(), self.0.capacity())
    }
}

/// The settings of one TOTP: secret, hash, digits, period and the names the
/// address gave. Made by [`parse_otpauth`] or [`TotpParams::new`]. Has no
/// `Debug` output of its contents and no `Clone`.
pub struct TotpParams {
    secret: TotpSecret,
    algorithm: TotpAlgorithm,
    digits: u8,
    period: u32,
    issuer: Option<String>,
    label: String,
}

impl fmt::Debug for TotpParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpParams").finish_non_exhaustive()
    }
}

impl TotpParams {
    /// Checks the ranges (digits 6 to 8, period 1 to 120, text at most
    /// [`MAX_TEXT_LEN`] bytes without control characters) and builds the
    /// settings.
    pub fn new(
        secret: TotpSecret,
        algorithm: TotpAlgorithm,
        digits: u8,
        period: u32,
        issuer: Option<String>,
        label: String,
    ) -> Result<Self, Error> {
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits)
            || !(MIN_PERIOD..=MAX_PERIOD).contains(&period)
        {
            return Err(bad());
        }
        for text in issuer.iter().chain(core::iter::once(&label)) {
            if text.len() > MAX_TEXT_LEN {
                return Err(Error::TooLarge);
            }
            if text.chars().any(char::is_control) {
                return Err(bad());
            }
        }
        Ok(Self {
            secret,
            algorithm,
            digits,
            period,
            issuer,
            label,
        })
    }

    /// The HMAC hash.
    pub fn algorithm(&self) -> TotpAlgorithm {
        self.algorithm
    }

    /// The number of digits in a code, 6 to 8.
    pub fn digits(&self) -> u8 {
        self.digits
    }

    /// The period in seconds, 1 to 120.
    pub fn period(&self) -> u32 {
        self.period
    }

    /// The issuer (service name), if the address gave one.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// The account name from the label (without the issuer prefix).
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The secret bytes, for the vector runners.
    #[cfg(feature = "test-support")]
    pub(crate) fn secret_bytes(&self) -> &[u8] {
        self.secret.expose()
    }
}

// ----------------------------------------------------------------- codes

/// HMAC of the counter, the whole digest, wiped on drop.
///
/// Spec: RFC 4226 section 5.1 (the message is the counter as 8 bytes,
/// big-endian) with the hash of RFC 6238 section 1.2.
pub(crate) fn hotp_digest(
    algorithm: TotpAlgorithm,
    key: &[u8],
    counter: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let msg = counter.to_be_bytes();
    match algorithm {
        TotpAlgorithm::Sha1 => mac_of::<Hmac<Sha1>>(key, &msg),
        TotpAlgorithm::Sha256 => mac_of::<Hmac<Sha256>>(key, &msg),
        TotpAlgorithm::Sha512 => mac_of::<Hmac<Sha512>>(key, &msg),
    }
}

fn mac_of<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    // HMAC accepts keys of every length, so this cannot fail; the error is
    // mapped instead of unwrapped because the core never panics.
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| Error::Unsupported)?;
    mac.update(msg);
    let mut out = mac.finalize().into_bytes();
    let copy = Zeroizing::new(AsRef::<[u8]>::as_ref(&out).to_vec());
    AsMut::<[u8]>::as_mut(&mut out).zeroize();
    Ok(copy)
}

/// Dynamic truncation.
///
/// Spec: RFC 4226 section 5.3: the low four bits of the last byte are an
/// offset; four bytes from there, with the top bit cleared, are a 31-bit
/// number.
fn truncate(digest: &[u8]) -> Result<u32, Error> {
    let offset = usize::from(digest.last().copied().ok_or(Error::Unsupported)? & 0x0f);
    let end = offset.checked_add(4).ok_or(Error::Unsupported)?;
    let window: [u8; 4] = digest
        .get(offset..end)
        .and_then(|w| w.try_into().ok())
        .ok_or(Error::Unsupported)?;
    let [a, b, c, d] = window;
    Ok(u32::from_be_bytes([a & 0x7f, b, c, d]))
}

/// The last `digits` decimal digits of `number`, zero padded.
///
/// Spec: RFC 4226 section 5.3 (`Snum mod 10^Digit`). A 31-bit number has at
/// most ten digits, so the last `digits` of its ten-digit form are the same as
/// the remainder modulo `10^digits`.
fn decimal(number: u32, digits: u8) -> Result<Zeroizing<String>, Error> {
    let mut buf = Zeroizing::new([b'0'; 10]);
    let mut rest = number;
    for slot in buf.iter_mut().rev() {
        *slot = b'0'.wrapping_add(u8::try_from(rest % 10).map_err(|_| Error::Unsupported)?);
        rest /= 10;
    }
    let start = 10usize
        .checked_sub(usize::from(digits))
        .ok_or(Error::Unsupported)?;
    let mut out = Zeroizing::new(String::with_capacity(usize::from(MAX_DIGITS)));
    for byte in buf.get(start..).ok_or(Error::Unsupported)? {
        out.push(char::from(*byte));
    }
    Ok(out)
}

/// HOTP value of RFC 4226 for a counter.
pub(crate) fn hotp(
    algorithm: TotpAlgorithm,
    key: &[u8],
    counter: u64,
    digits: u8,
) -> Result<Zeroizing<String>, Error> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(bad());
    }
    let digest = hotp_digest(algorithm, key, counter)?;
    decimal(truncate(&digest)?, digits)
}

/// The code for `unix_seconds` (the clock comes from the caller).
///
/// Spec: RFC 6238 section 4: `T = floor((t - T0) / period)` with `T0 = 0`,
/// then HOTP with `T` as the counter.
pub fn totp_code(p: &TotpParams, unix_seconds: u64) -> Result<Zeroizing<String>, Error> {
    let counter = unix_seconds
        .checked_div(u64::from(p.period))
        .ok_or(Error::Unsupported)?;
    hotp(p.algorithm, p.secret.expose(), counter, p.digits)
}

/// Seconds until the code changes, from 1 to the period. At the first
/// second of a period it is the whole period.
pub fn totp_seconds_left(p: &TotpParams, unix_seconds: u64) -> u32 {
    let period = u64::from(p.period);
    let into = unix_seconds.checked_rem(period).unwrap_or(0);
    u32::try_from(period.saturating_sub(into)).unwrap_or(p.period)
}

// ---------------------------------------------------------------- base32

/// 1 if `value >= bound`, else 0. Both must be below 2^31.
#[inline(always)]
fn ge(value: u32, bound: u32) -> u32 {
    value.wrapping_sub(bound).wrapping_shr(31) ^ 1
}

/// 1 if `lo <= value <= hi`, else 0. All must be below 2^31.
#[inline(always)]
fn in_range(value: u32, lo: u32, hi: u32) -> u32 {
    ge(value, lo) & ge(hi, value)
}

/// The 5-bit value of a base32 letter (RFC 4648: `A`-`Z`, `2`-`7`, either
/// case) and 1 if the letter is valid, else 0. Arithmetic and masks, no
/// table and no branch on the letter: the secret is the input here.
fn symbol(byte: u8) -> (u32, u32) {
    let c = u32::from(byte);
    let upper = c.wrapping_sub(in_range(c, 97, 122).wrapping_mul(32));
    let letter = in_range(upper, 65, 90);
    let digit = in_range(upper, 50, 55);
    let value = letter
        .wrapping_mul(upper.wrapping_sub(65))
        .wrapping_add(digit.wrapping_mul(upper.wrapping_sub(24)));
    (value & 31, letter | digit)
}

/// Space, tab, carriage return and line feed.
fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Decodes a base32 secret. See the module documentation for what is
/// tolerated.
///
/// Spec: RFC 4648 section 6. Fase 1 § 5.2 (F-31): fill and case tolerance,
/// bounded length.
fn decode_base32(text: &[u8]) -> Result<TotpSecret, Error> {
    if text.len() > MAX_URI_LEN {
        return Err(Error::TooLarge);
    }
    // Letters without blanks, in a wiped buffer.
    let mut letters: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(text.len()));
    for &byte in text {
        if !is_blank(byte) {
            letters.push(byte);
        }
    }
    let mut fill = 0usize;
    while letters.last() == Some(&b'=') {
        letters.pop();
        fill = fill.saturating_add(1);
    }
    let n = letters.len();
    // Whole bytes in `n` letters; a lone letter or 3 or 6 letters over a
    // multiple of eight cannot come from a byte string.
    let whole = (n / 8).saturating_mul(5);
    let (bytes, expected_fill) = match n % 8 {
        0 => (whole, 0),
        2 => (whole.saturating_add(1), 6),
        4 => (whole.saturating_add(2), 4),
        5 => (whole.saturating_add(3), 3),
        7 => (whole.saturating_add(4), 1),
        _ => return Err(bad()),
    };
    if bytes == 0 {
        return Err(bad());
    }
    if bytes > MAX_SECRET_LEN {
        return Err(Error::TooLarge);
    }
    if fill != 0 && fill != expected_fill {
        return Err(bad());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN));
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut all_valid: u32 = 1;
    for &letter in letters.iter() {
        let (value, valid) = symbol(letter);
        all_valid &= valid;
        acc = (acc.wrapping_shl(5) | value) & 0x1fff;
        bits = bits.wrapping_add(5);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push((acc.wrapping_shr(bits) & 0xff) as u8);
        }
    }
    acc.zeroize();
    if all_valid != 1 {
        return Err(bad());
    }
    Ok(TotpSecret(out))
}

// --------------------------------------------------------------- otpauth

/// Replaces `%XX` by the byte, and `+` by a space when `plus_is_space`.
/// A `%` that is not followed by two hex digits is refused. The result is
/// wiped on drop because it may be the secret.
fn percent_decode(text: &str, plus_is_space: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    fn hex(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
            b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
            b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
            _ => None,
        }
    }
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        match byte {
            b'%' => {
                let hi = bytes.next().and_then(hex).ok_or_else(bad)?;
                let lo = bytes.next().and_then(hex).ok_or_else(bad)?;
                out.push(hi.wrapping_shl(4) | lo);
            }
            b'+' if plus_is_space => out.push(b' '),
            other => out.push(other),
        }
    }
    Ok(out)
}

/// A decoded component as text: UTF-8, no control characters, at most
/// [`MAX_TEXT_LEN`] bytes.
fn text_of(bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() > MAX_TEXT_LEN {
        return Err(Error::TooLarge);
    }
    let text = core::str::from_utf8(bytes).map_err(|_| bad())?;
    if text.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(text.to_owned())
}

/// A plain decimal number in `lo..=hi`: ASCII digits only, no sign, no
/// leading zero.
fn small_number(text: &str, lo: u32, hi: u32) -> Result<u32, Error> {
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 3
        || bytes.first() == Some(&b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(bad());
    }
    let n: u32 = text.parse().map_err(|_| bad())?;
    if (lo..=hi).contains(&n) {
        Ok(n)
    } else {
        Err(bad())
    }
}

/// Reads an `otpauth://totp/...` address with the allow-list.
///
/// Spec: Fase 1 § 5.2 (F-31); plan U14. The secret is at most
/// [`MAX_SECRET_LEN`] bytes; an unknown or repeated parameter, a type other
/// than `totp`, digits outside 6 to 8 and a period outside 1 to 120 are
/// [`MalformedKind::Otpauth`]; a secret or address that is too long is
/// [`Error::TooLarge`].
pub fn parse_otpauth(uri: &str) -> Result<TotpParams, Error> {
    if uri.len() > MAX_URI_LEN {
        return Err(Error::TooLarge);
    }
    if uri.chars().any(|c| c.is_control() || c == '#') {
        return Err(bad());
    }
    let rest = uri.strip_prefix("otpauth://").ok_or_else(bad)?;
    let (head, query) = rest.split_once('?').ok_or_else(bad)?;
    let (kind, raw_label) = head.split_once('/').ok_or_else(bad)?;
    if kind != "totp" {
        return Err(bad());
    }

    // `Issuer:account` or `account`.
    let label_bytes = percent_decode(raw_label, false)?;
    let full_label = text_of(&label_bytes)?;
    let (label_issuer, label) = match full_label.split_once(':') {
        Some((issuer, account)) => (
            Some(issuer.trim().to_owned()).filter(|i| !i.is_empty()),
            account.trim_start().to_owned(),
        ),
        None => (None, full_label.trim().to_owned()),
    };

    let mut secret: Option<TotpSecret> = None;
    let mut issuer: Option<String> = None;
    let mut algorithm: Option<TotpAlgorithm> = None;
    let mut digits: Option<u32> = None;
    let mut period: Option<u32> = None;
    for pair in query.split('&') {
        let (raw_name, raw_value) = pair.split_once('=').ok_or_else(bad)?;
        let name = percent_decode(raw_name, true)?;
        let value = percent_decode(raw_value, true)?;
        match name.as_slice() {
            b"secret" => {
                if secret.is_some() {
                    return Err(bad());
                }
                secret = Some(decode_base32(&value)?);
            }
            b"issuer" => {
                if issuer.is_some() {
                    return Err(bad());
                }
                issuer = Some(text_of(&value)?);
            }
            b"algorithm" => {
                if algorithm.is_some() {
                    return Err(bad());
                }
                let name = core::str::from_utf8(&value).map_err(|_| bad())?;
                algorithm = Some(TotpAlgorithm::from_name(name).ok_or_else(bad)?);
            }
            b"digits" => {
                if digits.is_some() {
                    return Err(bad());
                }
                let text = core::str::from_utf8(&value).map_err(|_| bad())?;
                digits = Some(small_number(
                    text,
                    u32::from(MIN_DIGITS),
                    u32::from(MAX_DIGITS),
                )?);
            }
            b"period" => {
                if period.is_some() {
                    return Err(bad());
                }
                let text = core::str::from_utf8(&value).map_err(|_| bad())?;
                period = Some(small_number(text, MIN_PERIOD, MAX_PERIOD)?);
            }
            _ => return Err(bad()),
        }
    }

    let secret = secret.ok_or_else(bad)?;
    let issuer = issuer.filter(|i| !i.is_empty()).or(label_issuer);
    let digits = u8::try_from(digits.unwrap_or(u32::from(DEFAULT_DIGITS))).map_err(|_| bad())?;
    TotpParams::new(
        secret,
        algorithm.unwrap_or(TotpAlgorithm::Sha1),
        digits,
        period.unwrap_or(DEFAULT_PERIOD),
        issuer,
        label,
    )
}
