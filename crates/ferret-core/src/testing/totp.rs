//! Access to the TOTP internals for tests and vector runners. Behind
//! `test-support`; never part of a release.

use crate::error::Error;
use crate::totp::{self, TotpAlgorithm, TotpParams};

/// The secret bytes of a parsed address.
pub fn secret_bytes(p: &TotpParams) -> Vec<u8> {
    p.secret_bytes().to_vec()
}

/// The whole HMAC digest of the counter (RFC 4226 section 5.1).
pub fn hotp_digest(algorithm: TotpAlgorithm, key: &[u8], counter: u64) -> Result<Vec<u8>, Error> {
    totp::hotp_digest(algorithm, key, counter).map(|d| d.to_vec())
}

/// The HOTP value of RFC 4226 for a counter.
pub fn hotp(
    algorithm: TotpAlgorithm,
    key: &[u8],
    counter: u64,
    digits: u8,
) -> Result<String, Error> {
    totp::hotp(algorithm, key, counter, digits).map(|c| c.to_string())
}
