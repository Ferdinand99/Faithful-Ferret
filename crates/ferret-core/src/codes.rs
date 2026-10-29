//! Recovery key and secret key codes.
//!
//! Spec: Fase 1 section 6.1 (F-26) for the recovery key (RK) and section 6.2
//! for the secret key (SK).
//!
//! * RK: 256 bits, written most significant bit first and padded with 4 zero
//!   bits to 260 bits, give 52 Crockford Base32 symbols. Four check symbols
//!   follow: the first 20 bits of `SHA-256("ferret/v1/rk-check" ‖ RK)`. That
//!   is 56 symbols, shown as 14 groups of 4, behind the prefix `FFR1-`.
//! * SK: 128 bits padded with 2 zero bits give 26 symbols, then 4 check
//!   symbols from `SHA-256("ferret/v1/sk-check" ‖ SK)`. That is 30 symbols,
//!   shown as 6 groups of 5, behind the prefix `FFS1-`.
//! * Reading: upper or lower case; `O` is `0`, `I` and `L` are `1`; separators
//!   are removed (see [`is_separator`]: `-`, ASCII whitespace including tab,
//!   CR and LF, no-break space, en dash and em dash, so that a pasted code
//!   survives line breaks and typographic dashes). A code is rejected if the prefix or length is wrong,
//!   a letter is not in the alphabet, the check symbols do not match, or the
//!   spare bits are not zero. All of this happens before any key derivation
//!   (the functions here start none).
//!
//! The symbol arithmetic lives in `ct/harness/crockford.rs`, a single file
//! without tables and without data-dependent branches that the constant-time
//! analyzer reads on its own. It is included here, so the code that runs is
//! the code that was analyzed.

use crate::error::{Error, InputError, MalformedKind};
use crate::prim::ct::ct_eq;
use crate::secret::{RecoveryKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The table-free symbol arithmetic, included from `ct/harness/`.
pub(crate) mod crockford {
    include!("../../../ct/harness/crockford.rs");
}

/// Number of check symbols (20 bits).
const CHECK_SYMBOLS: usize = 4;

/// Length of the prefix before the first dash: `FFR1` or `FFS1`.
const PREFIX_LEN: usize = 4;

/// Most letters that are read before the input is rejected as too long.
const MAX_LETTERS: usize = 64;

/// What differs between the two kinds of code.
struct Layout {
    /// The prefix, without the dash.
    prefix: &'static str,
    /// The label hashed in front of the key for the check symbols.
    label: &'static [u8],
    /// Symbols per group when the code is shown.
    group: usize,
}

const RK_LAYOUT: Layout = Layout {
    prefix: "FFR1",
    label: b"ferret/v1/rk-check",
    group: 4,
};

const SK_LAYOUT: Layout = Layout {
    prefix: "FFS1",
    label: b"ferret/v1/sk-check",
    group: 5,
};

/// The first 20 bits of `SHA-256(label ‖ key)` as three bytes, the last one
/// with its low four bits cleared.
///
/// Spec: Fase 1 section 6.1 and 6.2.
fn check_bits(label: &[u8], key: &[u8]) -> Zeroizing<[u8; 3]> {
    let mut hasher = Sha256::new();
    hasher.update(label);
    hasher.update(key);
    let digest: Zeroizing<[u8; 32]> = Zeroizing::new(hasher.finalize().into());
    let [d0, d1, d2, ..] = *digest;
    Zeroizing::new([d0, d1, d2 & 0xf0])
}

/// The code of a key: `KEY` bytes, `DATA` data symbols.
fn encode<const KEY: usize, const DATA: usize>(
    layout: &Layout,
    key: &[u8; KEY],
) -> Zeroizing<String> {
    let mut data = Zeroizing::new([0u8; DATA]);
    crockford::encode_symbols(key, &mut *data);
    let check = check_bits(layout.label, key);
    let mut check_symbols = Zeroizing::new([0u8; CHECK_SYMBOLS]);
    crockford::encode_symbols(&*check, &mut *check_symbols);

    // Prefix, dash, then the symbols with a dash before every group but the
    // first. The capacity covers the longest code, so nothing is reallocated.
    let mut out = Zeroizing::new(String::with_capacity(80));
    out.push_str(layout.prefix);
    let mut in_group = layout.group;
    for &symbol in data.iter().chain(check_symbols.iter()) {
        if in_group == layout.group {
            out.push('-');
            in_group = 0;
        }
        out.push(char::from(symbol));
        in_group = in_group.saturating_add(1);
    }
    out
}

/// True for the characters that are dropped before a code is read: `-`, ASCII
/// whitespace (space, tab, line feed, form feed, carriage return), U+00A0
/// no-break space, U+2013 en dash and U+2014 em dash.
pub fn is_separator(c: char) -> bool {
    c == '-' || c.is_ascii_whitespace() || matches!(c, '\u{00A0}' | '\u{2013}' | '\u{2014}')
}

/// Reads a code into `KEY` bytes. See the module documentation for the rules
/// and `Error` for what each failure maps to.
///
/// Order of the checks: too many letters (`input_too_long`); fewer than four
/// letters (`input_too_short`); wrong prefix (`malformed_code`); wrong total
/// length (`input_too_short` or `input_too_long`); a letter outside the
/// alphabet (`malformed_code`); wrong check symbols (`checksum`); non-zero
/// spare bits (`non_canonical`).
fn decode<const KEY: usize, const DATA: usize>(
    layout: &Layout,
    code: &str,
) -> Result<Zeroizing<[u8; KEY]>, Error> {
    // Drop the separators; keep everything else (the UTF-8 bytes of any other
    // character, which are then letters outside the alphabet or make the
    // length wrong), in a fixed buffer that is wiped afterwards.
    let mut letters = Zeroizing::new([0u8; MAX_LETTERS]);
    let mut slots = letters.iter_mut();
    let mut count = 0usize;
    let mut encoded = Zeroizing::new([0u8; 4]);
    for c in code.chars().filter(|c| !is_separator(*c)) {
        for &byte in c.encode_utf8(&mut *encoded).as_bytes() {
            let Some(slot) = slots.next() else {
                return Err(Error::InvalidInput(InputError::TooLong));
            };
            *slot = byte;
            count = count.saturating_add(1);
        }
    }
    let Some(read) = letters.get(..count) else {
        return Err(Error::Malformed(MalformedKind::Code));
    };
    let Some((prefix, rest)) = read.split_at_checked(PREFIX_LEN) else {
        return Err(Error::InvalidInput(InputError::TooShort));
    };
    // The prefix is public; `1` may have been typed as `I` or `L`.
    if !prefix
        .iter()
        .map(|&b| crockford::normalize_byte(b))
        .eq(layout.prefix.bytes())
    {
        return Err(Error::Malformed(MalformedKind::Code));
    }
    match rest.len().cmp(&DATA.saturating_add(CHECK_SYMBOLS)) {
        core::cmp::Ordering::Less => return Err(Error::InvalidInput(InputError::TooShort)),
        core::cmp::Ordering::Greater => return Err(Error::InvalidInput(InputError::TooLong)),
        core::cmp::Ordering::Equal => {}
    }
    let Some((data_symbols, check_symbols)) = rest.split_at_checked(DATA) else {
        return Err(Error::Malformed(MalformedKind::Code));
    };

    let mut key = Zeroizing::new([0u8; KEY]);
    let data = crockford::decode_symbols(data_symbols, &mut *key);
    let mut check_read = Zeroizing::new([0u8; 2]);
    let check = crockford::decode_symbols(check_symbols, &mut *check_read);
    if !(data.all_valid & check.all_valid) {
        return Err(Error::Malformed(MalformedKind::Code));
    }

    // Constant-time comparison of the 20 check bits: two bytes and the high
    // nibble of the third, which the decoder returns as the 4 leftover bits.
    let expected = check_bits(layout.label, &*key);
    let [c0, c1] = *check_read;
    let nibble = u8::try_from(check.spare & 0x0f).unwrap_or(0);
    let got = Zeroizing::new([c0, c1, nibble.wrapping_shl(4)]);
    if !ct_eq(&*expected, &*got) {
        return Err(Error::Checksum);
    }
    if data.spare != 0 {
        return Err(Error::NonCanonical);
    }
    Ok(key)
}

/// The code of a recovery key: `FFR1-` and 14 groups of 4 symbols, 56 symbols
/// in all, the last four being the check.
///
/// Spec: Fase 1 section 6.1 (F-26).
pub fn encode_recovery_key(rk: &RecoveryKey) -> Zeroizing<String> {
    encode::<32, 52>(&RK_LAYOUT, rk.expose())
}

/// Reads a recovery key code. Rejects a wrong prefix, wrong length, letters
/// outside the alphabet, a wrong check (`checksum`) and non-zero spare bits
/// (`non_canonical`), all before the key is used for anything.
///
/// Spec: Fase 1 section 6.1 (F-26): "Lesing".
pub fn decode_recovery_key(s: &str) -> Result<RecoveryKey, Error> {
    decode::<32, 52>(&RK_LAYOUT, s).map(|mut key| RecoveryKey::from_array_wiping(&mut key))
}

/// The code of a secret key: `FFS1-` and 6 groups of 5 symbols, 30 symbols in
/// all, the last four being the check.
///
/// Spec: Fase 1 section 6.2.
pub fn encode_secret_key(sk: &SecretKey) -> Zeroizing<String> {
    encode::<16, 26>(&SK_LAYOUT, sk.expose())
}

/// Reads a secret key code, with the same rules as [`decode_recovery_key`].
///
/// Spec: Fase 1 section 6.2 ("Lesing som for RK").
pub fn decode_secret_key(s: &str) -> Result<SecretKey, Error> {
    decode::<16, 26>(&SK_LAYOUT, s).map(|mut key| SecretKey::from_array_wiping(&mut key))
}

#[cfg(test)]
mod tests {
    use super::crockford::{
        decode_symbol, decode_symbols, encode_symbol, encode_symbols, normalize_byte,
    };

    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    #[test]
    fn encode_symbol_matches_the_alphabet_for_every_value() {
        for v in 0..=255u8 {
            assert_eq!(encode_symbol(v), ALPHABET[usize::from(v & 31)], "{v}");
        }
    }

    /// The reference reading with a table and branches: what a person would
    /// write. The table-free code must agree on every byte.
    fn reference_symbol(byte: u8) -> Option<u8> {
        let c = match byte.to_ascii_uppercase() {
            b'O' => b'0',
            b'I' | b'L' => b'1',
            other => other,
        };
        ALPHABET
            .iter()
            .position(|&a| a == c)
            .map(|p| u8::try_from(p).unwrap())
    }

    #[test]
    fn decode_symbol_matches_the_reference_for_every_byte() {
        for byte in 0..=255u8 {
            let (value, valid) = decode_symbol(normalize_byte(byte));
            match reference_symbol(byte) {
                Some(want) => assert_eq!((value, valid), (want, 1), "byte {byte:#04x}"),
                None => assert_eq!((value, valid), (0, 0), "byte {byte:#04x}"),
            }
        }
    }

    #[test]
    fn normalize_byte_folds_exactly_the_documented_letters() {
        for byte in 0..=255u8 {
            let want = match byte {
                b'a'..=b'z' => {
                    let up = byte - 32;
                    match up {
                        b'O' => b'0',
                        b'I' | b'L' => b'1',
                        other => other,
                    }
                }
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            assert_eq!(normalize_byte(byte), want, "byte {byte:#04x}");
        }
    }

    /// Reference packing: a string of '0' and '1', chunks of five.
    fn reference_encode(data: &[u8], symbols: usize) -> Vec<u8> {
        let mut bits: Vec<u8> = data
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i) & 1))
            .collect();
        bits.resize(symbols * 5, 0);
        bits.chunks(5)
            .map(|c| ALPHABET[usize::from(c.iter().fold(0u8, |a, b| (a << 1) | b))])
            .collect()
    }

    #[test]
    fn symbol_packing_matches_the_reference_for_all_lengths() {
        let data: Vec<u8> = (0..40u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        for len in 0..=40usize {
            for symbols in 0..=70usize {
                let want = reference_encode(&data[..len], symbols);
                let mut got = vec![0u8; symbols];
                encode_symbols(&data[..len], &mut got);
                assert_eq!(got, want, "len {len}, symbols {symbols}");
            }
        }
    }

    #[test]
    fn symbol_unpacking_inverts_the_packing() {
        for len in 1..=40usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i).unwrap().wrapping_mul(91).wrapping_add(5))
                .collect();
            let symbols = (len * 8).div_ceil(5);
            let mut text = vec![0u8; symbols];
            encode_symbols(&data, &mut text);
            let mut back = vec![0u8; len];
            let decoded = decode_symbols(&text, &mut back);
            assert!(decoded.all_valid);
            assert_eq!(back, data);
            assert_eq!(decoded.spare, 0, "the padding bits are zero");
        }
    }
}
