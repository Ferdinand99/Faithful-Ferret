//! HMAC-SHA256.

use crate::error::Error;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// Length of an HMAC-SHA256 tag in bytes.
pub(crate) const HMAC_SHA256_LEN: usize = 32;

/// HMAC-SHA256 of `msg` under `key` (any key length).
///
/// Compare tags with [`super::ct::ct_eq`], never with `==`.
///
/// Spec: Fase 1 § 3 (HMAC-SHA256 for item tags and checkpoints).
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<[u8; HMAC_SHA256_LEN], Error> {
    // HMAC accepts keys of every length, so this cannot fail; the error is
    // mapped instead of unwrapped because the core never panics.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|_| Error::Unsupported)?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().into())
}
