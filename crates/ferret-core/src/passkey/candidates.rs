//! Which stored passkeys may answer a request, and the site as the chooser
//! shows it.
//!
//! Spec: Fase 1 § 9.2 ("Ved signering"), § 9.3 ("Personvern"). The core
//! decides, so that no other code has a second reading of the rule:
//!
//! * a passkey answers a `get` only when its RP ID is **exactly** the RP ID
//!   the request resolves to (no suffix logic: a passkey of `example.com` does
//!   not answer a request for `login.example.com` and the other way round);
//! * when `allowCredentials` is not empty, the credential id must be in it.
//!
//! The result goes to Ferret's own windows only. The page never learns from it
//! whether the user has a passkey for the site; the chooser is shown in every
//! case (Fase 1 § 9.3).

use super::{
    CallerContext, GetRequest, MAX_NAME, check_id_list, require_same_origin, resolve_rp_id,
};
use crate::error::Error;
use crate::item::display_host;

/// A stored passkey as far as the choice of candidates is concerned: the two
/// things the rule looks at. Take them from the open items (`rp_id` and
/// `cred_id` of an item's passkey).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StoredPasskeyRef<'a> {
    /// The RP ID it was made for, in canonical form (lower case, A-labels). A
    /// value that is not canonical never matches.
    pub rp_id: &'a str,
    /// The credential id.
    pub cred_id: &'a [u8],
}

/// The stored passkeys that may answer a `get`: `rp_id` exactly the RP ID the
/// request resolves to, and, when `allow` is not empty, `cred_id` in `allow`.
/// Returns indexes into `stored`, in the order of `stored`.
///
/// `rp_id` is the `rpId` of the request (`None` for the host of the origin).
/// The request is judged as `passkey_get` judges it: a cross-origin caller is
/// `NotAllowed`, an RP ID the origin may not use is `malformed_rp_id`, and the
/// limits of the request are those of Fase 1 § 9.2. An empty result is not an
/// error.
///
/// This checks only what it uses (`allow`, `rp_id`, the origin); call
/// [`passkey_candidates_for`] to check the whole request.
///
/// Spec: Fase 1 § 9.2, § 9.3.
pub fn passkey_candidates(
    ctx: &CallerContext,
    rp_id: Option<&str>,
    allow: &[Vec<u8>],
    stored: &[StoredPasskeyRef<'_>],
) -> Result<Vec<usize>, Error> {
    check_id_list(allow)?;
    if rp_id.is_some_and(|s| s.len() > MAX_NAME) {
        return Err(Error::TooLarge);
    }
    require_same_origin(ctx)?;
    let rp = resolve_rp_id(ctx, rp_id)?;
    Ok(stored
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            s.rp_id == rp.as_str()
                && (allow.is_empty() || allow.iter().any(|id| id.as_slice() == s.cred_id))
        })
        .map(|(i, _)| i)
        .collect())
}

/// [`passkey_candidates`] for a whole `get` request: the request is checked
/// first as `passkey_get` checks it (`GetRequest::validate`: challenge size,
/// lists, `prf` input), so that a request that cannot be answered gives its
/// error before a chooser is shown and not after the user has clicked.
///
/// Spec: Fase 1 § 9.2, § 9.3.
pub fn passkey_candidates_for(
    ctx: &CallerContext,
    req: &GetRequest,
    stored: &[StoredPasskeyRef<'_>],
) -> Result<Vec<usize>, Error> {
    req.validate()?;
    passkey_candidates(ctx, req.rp_id.as_deref(), &req.allow, stored)
}

/// The site of a request as Ferret's chooser shows it.
///
/// The A-label forms are what is compared and what goes into
/// `clientDataJSON`; the Unicode forms are for reading. A label that mixes
/// scripts, or cannot be converted back, stays in its A-label form (as for
/// page addresses, `display_host`), so the window can show both forms side by
/// side when they differ.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PasskeySite {
    /// The canonical origin of the calling frame.
    pub origin: String,
    /// The host of the origin in Unicode form.
    pub host_unicode: String,
    /// The RP ID the request resolves to: canonical, as A-labels.
    pub rp_id: String,
    /// The RP ID in Unicode form.
    pub rp_id_unicode: String,
}

/// Resolves and checks the RP ID of a request, for the chooser: the canonical
/// origin, the RP ID (A-label) and the Unicode form of both names.
///
/// The same checks as `passkey_get` and `passkey_create`: cross-origin is
/// `NotAllowed`, and an RP ID the origin may not use (not the host or a
/// suffix of it, a public suffix, an address) is `Malformed(RpId)`, which the
/// caller gives the page as `SecurityError`.
///
/// Spec: Fase 1 § 9.2.
pub fn passkey_site(ctx: &CallerContext, rp_id: Option<&str>) -> Result<PasskeySite, Error> {
    if rp_id.is_some_and(|s| s.len() > MAX_NAME) {
        return Err(Error::TooLarge);
    }
    require_same_origin(ctx)?;
    let rp = resolve_rp_id(ctx, rp_id)?;
    Ok(PasskeySite {
        origin: ctx.origin.as_str().to_owned(),
        host_unicode: unicode_of(ctx.origin.host()),
        rp_id: rp.as_str().to_owned(),
        rp_id_unicode: unicode_of(rp.as_str()),
    })
}

/// The Unicode form of a canonical host, or the host itself when it cannot be
/// made.
fn unicode_of(host: &str) -> String {
    display_host(&format!("https://{host}")).map_or_else(|_| host.to_owned(), |h| h.unicode)
}
