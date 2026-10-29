//! An independent TOTP: HMAC built by hand from the plain hash functions
//! (RFC 2104), the truncation of RFC 4226 with plain integers, and base32
//! with a lookup table. Shared by `totp.rs` and `props_totp.rs`; it uses
//! nothing of the core's TOTP code.
#![allow(dead_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::TotpAlgorithm;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

fn hash(alg: TotpAlgorithm, data: &[u8]) -> Vec<u8> {
    match alg {
        TotpAlgorithm::Sha1 => Sha1::digest(data).to_vec(),
        TotpAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        TotpAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// HMAC (RFC 2104) with the block size of the hash.
pub fn ref_hmac(alg: TotpAlgorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let block = match alg {
        TotpAlgorithm::Sha1 | TotpAlgorithm::Sha256 => 64,
        TotpAlgorithm::Sha512 => 128,
    };
    let mut k = if key.len() > block {
        hash(alg, key)
    } else {
        key.to_vec()
    };
    k.resize(block, 0);
    let mut inner: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.extend_from_slice(msg);
    let mut outer: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.extend_from_slice(&hash(alg, &inner));
    hash(alg, &outer)
}

/// RFC 4226 for a counter.
pub fn ref_hotp(alg: TotpAlgorithm, key: &[u8], counter: u64, digits: u32) -> String {
    let h = ref_hmac(alg, key, &counter.to_be_bytes());
    let off = (h[h.len() - 1] & 15) as usize;
    let bin = (u64::from(h[off] & 0x7f) << 24)
        | (u64::from(h[off + 1]) << 16)
        | (u64::from(h[off + 2]) << 8)
        | u64::from(h[off + 3]);
    format!(
        "{:0width$}",
        bin % 10u64.pow(digits),
        width = digits as usize
    )
}

/// RFC 6238 for a time.
pub fn ref_totp(alg: TotpAlgorithm, key: &[u8], t: u64, period: u64, digits: u32) -> String {
    ref_hotp(alg, key, t / period, digits)
}

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32, with the fill when `pad`.
pub fn ref_base32(data: &[u8], pad: bool) -> String {
    let mut bits = String::new();
    for b in data {
        bits.push_str(&format!("{b:08b}"));
    }
    while !bits.len().is_multiple_of(5) {
        bits.push('0');
    }
    let mut out: String = bits
        .as_bytes()
        .chunks(5)
        .map(|c| {
            let v = c
                .iter()
                .fold(0usize, |a, b| (a << 1) | usize::from(*b - b'0'));
            char::from(ALPHABET[v])
        })
        .collect();
    if pad {
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
    }
    out
}
