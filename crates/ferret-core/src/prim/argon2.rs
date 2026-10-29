//! Argon2id with a fixed floor and ceiling for its parameters.

use crate::error::{Error, InputError};
use ::argon2::{Algorithm, Argon2, AssociatedData, Block, ParamsBuilder, Version};
use zeroize::Zeroizing;

/// Argon2id parameters: memory in KiB, passes, lanes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Number of passes.
    pub t: u32,
    /// Number of lanes (parallelism).
    pub p: u32,
}

/// The lowest parameters ever accepted: 64 MiB, 3 passes, 1 lane. Raised in
/// later releases, never lowered, and not switchable at run time.
///
/// Spec: Fase 1 § 4.1 point 5 (floor: `m ≥ 64 MiB`, `t ≥ 3`, `p` from 1).
pub const KDF_FLOOR: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

/// The highest parameters ever accepted: 512 MiB, 16 passes, 4 lanes.
///
/// The memory ceiling is 512 MiB, not the 1 GiB of the design text: the
/// plan's clarification of 29 October (U15) lowers it, so that a hostile
/// export file cannot make the WASM heap (limit 1 GiB) run out of memory.
///
/// Spec: Fase 1 § 4.1 point 5 (ceiling: `t ≤ 16`, `p ≤ 4`) with the
/// clarified memory ceiling of 512 MiB.
pub const KDF_CEIL: KdfParams = KdfParams {
    m_kib: 524_288,
    t: 16,
    p: 4,
};

/// Checks `p` against [`KDF_FLOOR`] and [`KDF_CEIL`]: `m` and `t` between
/// floor and ceiling, `p` from 1 to 4. Nothing is computed.
///
/// Fails with [`Error::KdfOutOfRange`] ("the server states unsafe
/// parameters").
///
/// Spec: Fase 1 § 4.1 point 5.
pub fn check_kdf_params(p: KdfParams) -> Result<KdfParams, Error> {
    let within = (KDF_FLOOR.m_kib..=KDF_CEIL.m_kib).contains(&p.m_kib)
        && (KDF_FLOOR.t..=KDF_CEIL.t).contains(&p.t)
        && (KDF_FLOOR.p..=KDF_CEIL.p).contains(&p.p);
    if within {
        Ok(p)
    } else {
        Err(Error::KdfOutOfRange)
    }
}

#[cfg(feature = "test-support")]
std::thread_local! {
    /// Number of Argon2 computations started on this thread. Lets a test
    /// prove that out-of-range parameters compute nothing, without other
    /// tests running in parallel disturbing the count.
    pub(crate) static RUNS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Argon2id v1.3 of `pwd` and `salt` into `out`, after
/// [`check_kdf_params`]. Out-of-range parameters fail with
/// [`Error::KdfOutOfRange`] before any memory is allocated.
///
/// `salt` must be at least 8 bytes and `out` at least 4 bytes
/// ([`InputError::TooShort`] otherwise). Running out of memory is
/// [`Error::KdfOutOfMemory`].
///
/// Spec: Fase 1 § 3 and § 4.1 (Argon2id v1.3, RFC 9106) with the bounds of
/// § 4.1 point 5.
pub(crate) fn argon2id(pwd: &[u8], salt: &[u8], p: KdfParams, out: &mut [u8]) -> Result<(), Error> {
    let p = check_kdf_params(p)?;
    derive(pwd, salt, None, &[], p, out)
}

/// Argon2id without the floor and ceiling, and with a secret and associated
/// data. Only for `test-support` (the RFC 9106 vector uses 32 KiB).
#[cfg(feature = "test-support")]
pub(crate) fn argon2id_unchecked(
    pwd: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    p: KdfParams,
    out: &mut [u8],
) -> Result<(), Error> {
    derive(pwd, salt, Some(secret), ad, p, out)
}

/// [`argon2id_unchecked`] without secret and associated data: the shape of
/// the OPAQUE key stretching function. Only for `test-support`.
#[cfg(feature = "test-support")]
pub(crate) fn argon2id_unchecked_plain(
    pwd: &[u8],
    salt: &[u8],
    p: KdfParams,
    out: &mut [u8],
) -> Result<(), Error> {
    derive(pwd, salt, None, &[], p, out)
}

/// Shared by the checked and unchecked paths.
///
/// The memory blocks are allocated here, not inside the `argon2` crate, so
/// that an allocation failure is an error rather than an abort, and so that
/// the blocks are wiped before they are freed (the `argon2` crate wipes its
/// small buffers with the `zeroize` feature but not the memory matrix).
fn derive(
    pwd: &[u8],
    salt: &[u8],
    secret: Option<&[u8]>,
    ad: &[u8],
    p: KdfParams,
    out: &mut [u8],
) -> Result<(), Error> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(p.m_kib)
        .t_cost(p.t)
        .p_cost(p.p)
        .output_len(out.len());
    if !ad.is_empty() {
        builder.data(AssociatedData::new(ad).map_err(map_error)?);
    }
    let params = builder.build().map_err(map_error)?;
    let argon2 = match secret {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
                .map_err(map_error)?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
    };

    let blocks_len = argon2.params().block_count();
    let mut blocks: Zeroizing<Vec<Block>> = Zeroizing::new(Vec::new());
    blocks
        .try_reserve_exact(blocks_len)
        .map_err(|_| Error::KdfOutOfMemory)?;
    blocks.resize(blocks_len, Block::new());

    #[cfg(feature = "test-support")]
    RUNS.set(RUNS.get().saturating_add(1));

    argon2
        .hash_password_into_with_memory(pwd, salt, out, blocks.as_mut_slice())
        .map_err(map_error)
}

/// Maps an `argon2` error to ours. After the range check only input lengths
/// and memory can fail.
fn map_error(e: ::argon2::Error) -> Error {
    use ::argon2::Error as E;
    match e {
        E::SaltTooShort | E::OutputTooShort => Error::InvalidInput(InputError::TooShort),
        E::SaltTooLong
        | E::OutputTooLong
        | E::PwdTooLong
        | E::SecretTooLong
        | E::AdTooLong
        | E::KeyIdTooLong => Error::InvalidInput(InputError::TooLong),
        E::OutOfMemory => Error::KdfOutOfMemory,
        E::MemoryTooLittle
        | E::MemoryTooMuch
        | E::ThreadsTooFew
        | E::ThreadsTooMany
        | E::TimeTooSmall => Error::KdfOutOfRange,
        _ => Error::Unsupported,
    }
}
