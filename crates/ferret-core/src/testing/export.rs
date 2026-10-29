//! The export file with Argon2id parameters below the floor, and its
//! intermediate values, for tests and vector runners. Behind `test-support`;
//! never part of a release.
//!
//! The functions here are the production ones with one change: the floor and
//! ceiling check is skipped, so that a test can use a few MiB instead of 64.
//! Nothing else differs, and the production functions cannot be made to skip
//! the check.

use crate::error::Error;
use crate::export::{
    ExportItem, KdfRunner, SALT_LEN, aad_body, aad_ek, decrypt_with, derive_k_exp, encrypt_with,
    parse_export_header, seal_file,
};
use crate::prim::{self, KdfParams};
use crate::rng::SecureRng;
use crate::text::ExportPassword;

fn unchecked_gate(p: KdfParams) -> Result<KdfParams, Error> {
    Ok(p)
}

fn unchecked_run(pwd: &[u8], salt: &[u8], p: KdfParams, out: &mut [u8]) -> Result<(), Error> {
    prim::argon2::argon2id_unchecked(pwd, salt, &[], &[], p, out)
}

const UNCHECKED: KdfRunner = KdfRunner {
    gate: unchecked_gate,
    run: unchecked_run,
};

/// [`crate::export_encrypt`] without the floor and ceiling.
pub fn export_encrypt_unchecked<R: SecureRng>(
    rng: &mut R,
    pw: &ExportPassword,
    kdf: KdfParams,
    created_at: u64,
    items: &[ExportItem],
) -> Result<Vec<u8>, Error> {
    encrypt_with(UNCHECKED, rng, pw, kdf, created_at, items)
}

/// An export file whose body is `plain`, as it is: not read as items, so a
/// body of the wrong shape can be made authentic. No floor and ceiling.
pub fn export_encrypt_raw_unchecked<R: SecureRng>(
    rng: &mut R,
    pw: &ExportPassword,
    kdf: KdfParams,
    created_at: u64,
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    seal_file(UNCHECKED, rng, pw, kdf, created_at, plain)
}

/// [`crate::import_decrypt`] without the floor and ceiling.
pub fn import_decrypt_unchecked(
    pw: &ExportPassword,
    file: &[u8],
) -> Result<Vec<ExportItem>, Error> {
    decrypt_with(UNCHECKED, pw, file)
}

/// The values between the password and the file, for a vector.
pub struct ExportIntermediate {
    /// The header bytes, as they stand in the file.
    pub header: Vec<u8>,
    /// `K_exp`.
    pub k_exp: [u8; 32],
    /// The AAD of `ek_wrap`.
    pub aad_ek: Vec<u8>,
    /// The AAD of the body.
    pub aad_body: Vec<u8>,
}

/// Derives the intermediate values of `file` for `pw`, with the bounds
/// skipped. Runs Argon2id once.
pub fn intermediate_unchecked(
    pw: &ExportPassword,
    file: &[u8],
) -> Result<ExportIntermediate, Error> {
    let (header, used) = parse_export_header(file)?;
    let header_bytes = file.get(..used).ok_or(Error::Decrypt)?.to_vec();
    let salt: [u8; SALT_LEN] = header.salt;
    let k_exp = derive_k_exp(UNCHECKED, pw, &salt, header.kdf)?;
    Ok(ExportIntermediate {
        aad_ek: aad_ek(&header_bytes)?,
        aad_body: aad_body(&header_bytes)?,
        header: header_bytes,
        k_exp: *k_exp,
    })
}
