//! The WebAuthn `prf` extension as Ferret answers it.
//!
//! Spec: Fase 1 § 9.5 (WebAuthn L3 `prf` over CTAP `hmac-secret`):
//!
//! ```text
//! prf_out = HMAC-SHA256(prf_seed, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))
//! ```
//!
//! A passkey made with `prf` has two seeds of 32 random bytes, `prf_seed_uv`
//! and `prf_seed_nouv` (CTAP `CredRandomWithUV` and `CredRandomWithoutUV`).
//! The seed is chosen by whether user verification was actually performed in
//! the request. `eval.first` and `eval.second` give up to two outputs;
//! `evalByCredential` follows WebAuthn L3 § 10.1.4: it needs a
//! non-empty `allowCredentials` (otherwise `NotSupportedError`, here
//! [`Error::Unsupported`]), every key must be in that list (otherwise
//! `SyntaxError`), the entry of the credential in use is evaluated, and `eval`
//! is the fallback.

use crate::error::{Error, MalformedKind};
use crate::prim::mac::hmac_sha256;
use crate::secret::{PrfOutput, PrfSeed};
use core::fmt;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// The longest PRF input accepted, in bytes.
pub const MAX_PRF_INPUT: usize = 1024;

/// The most `evalByCredential` entries accepted.
pub const MAX_EVAL_BY_CREDENTIAL: usize = 200;

/// The context string of the PRF salt (WebAuthn L3 § 10.1.4).
const PRF_CONTEXT: &[u8] = b"WebAuthn PRF";

/// One or two PRF inputs (`eval`).
#[derive(Clone, PartialEq, Eq)]
pub struct PrfEval {
    /// `first`.
    pub first: Vec<u8>,
    /// `second`.
    pub second: Option<Vec<u8>>,
}

/// The `prf` member of a `create` request: it turns the extension on, and
/// may ask for outputs at once.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct PrfCreate {
    /// `eval`, if the site wants outputs already at creation.
    pub eval: Option<PrfEval>,
}

/// The `prf` member of a `get` request.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct PrfRequest {
    /// `eval`.
    pub eval: Option<PrfEval>,
    /// `evalByCredential`: `(credential id, inputs)`.
    pub eval_by_credential: Vec<(Vec<u8>, PrfEval)>,
}

/// The outputs of the extension. They are secrets and are shown by neither
/// `Debug` nor `Clone`.
pub struct PrfResults {
    first: PrfOutput,
    second: Option<PrfOutput>,
}

impl PrfResults {
    /// The output for `first`. Reaches the page in
    /// `clientExtensionResults.prf.results`, and nowhere else.
    pub fn reveal_first(&self) -> &[u8; 32] {
        self.first.expose()
    }

    /// The output for `second`, if it was asked for.
    pub fn reveal_second(&self) -> Option<&[u8; 32]> {
        self.second.as_ref().map(PrfOutput::expose)
    }
}

impl fmt::Debug for PrfResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrfResults").finish_non_exhaustive()
    }
}

/// `SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input)`.
///
/// Spec: Fase 1 § 9.5.
pub fn prf_salt(input: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PRF_CONTEXT);
    h.update([0u8]);
    h.update(input);
    h.finalize().into()
}

/// `HMAC-SHA256(seed, SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input))`.
///
/// Spec: Fase 1 § 9.5.
pub fn prf_output(seed: &PrfSeed, input: &[u8]) -> Result<PrfOutput, Error> {
    let mut salt = prf_salt(input);
    let mac = hmac_sha256(seed.expose(), &salt);
    salt.zeroize();
    let mut bytes = mac?;
    Ok(PrfOutput::from_array_wiping(&mut bytes))
}

/// The outputs for `eval` under `seed`.
pub(crate) fn evaluate(seed: &PrfSeed, eval: &PrfEval) -> Result<PrfResults, Error> {
    let first = prf_output(seed, &eval.first)?;
    let second = eval
        .second
        .as_deref()
        .map(|input| prf_output(seed, input))
        .transpose()?;
    Ok(PrfResults { first, second })
}

fn bad_options() -> Error {
    Error::Malformed(MalformedKind::WebauthnOptions)
}

impl PrfEval {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let too_long = self.first.len() > MAX_PRF_INPUT
            || self
                .second
                .as_ref()
                .is_some_and(|s| s.len() > MAX_PRF_INPUT);
        if too_long {
            return Err(Error::TooLarge);
        }
        Ok(())
    }
}

impl PrfCreate {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        self.eval.as_ref().map_or(Ok(()), PrfEval::validate)
    }
}

impl PrfRequest {
    /// Checks the request against `allow` (the `allowCredentials` ids).
    pub(crate) fn validate(&self, allow: &[Vec<u8>]) -> Result<(), Error> {
        if let Some(e) = &self.eval {
            e.validate()?;
        }
        if self.eval_by_credential.is_empty() {
            return Ok(());
        }
        if self.eval_by_credential.len() > MAX_EVAL_BY_CREDENTIAL {
            return Err(Error::TooLarge);
        }
        if allow.is_empty() {
            return Err(Error::Unsupported);
        }
        for (id, e) in &self.eval_by_credential {
            e.validate()?;
            if !allow.contains(id) {
                return Err(bad_options());
            }
        }
        Ok(())
    }

    /// The inputs that apply to the credential `cred_id`.
    pub(crate) fn select(&self, cred_id: &[u8]) -> Option<&PrfEval> {
        self.eval_by_credential
            .iter()
            .find(|(id, _)| id.as_slice() == cred_id)
            .map(|(_, e)| e)
            .or(self.eval.as_ref())
    }
}
