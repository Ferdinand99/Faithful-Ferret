//! Access for the passkey tests and vector runners: the scalar of a key, the
//! client data serializer with a free origin text, and the Public Suffix List
//! snapshot's internals. Behind `test-support`; never part of a release.

use crate::passkey::{self, Ceremony, PasskeyRecord};
use p256::ecdsa::SigningKey;
use p256::pkcs8::DecodePrivateKey;

/// The private scalar `d` of the record's key (32 bytes, big-endian).
pub fn private_scalar(record: &PasskeyRecord) -> Option<[u8; 32]> {
    let item = record.to_item();
    let key = SigningKey::from_pkcs8_der(&item.private_key).ok()?;
    let bytes = key.to_bytes();
    <[u8; 32]>::try_from(bytes.as_slice()).ok()
}

/// The client data JSON as the core writes it, for `origin_text` taken as it
/// is (so that the escaping of characters that cannot be in a canonical origin
/// can be tested).
pub fn client_data_json(create: bool, challenge: &[u8], origin_text: &str) -> String {
    let ceremony = if create {
        Ceremony::Create
    } else {
        Ceremony::Get
    };
    passkey::client_data_json_raw(ceremony, challenge, origin_text)
}

/// `(exact, wildcard, exception)`: how many rules of each kind the snapshot
/// holds after conversion to A-labels.
pub fn psl_rule_counts() -> (usize, usize, usize) {
    passkey::rule_counts()
}

/// How many rule lines the snapshot file has.
pub fn psl_rule_lines() -> usize {
    passkey::rule_lines()
}

/// Whether `domain` (canonical, A-label) is a public suffix.
pub fn is_public_suffix(domain: &str) -> bool {
    passkey::is_public_suffix(domain)
}

/// The bytes of a PRF output.
pub fn reveal_prf_output(out: &crate::PrfOutput) -> &[u8; 32] {
    out.expose()
}
