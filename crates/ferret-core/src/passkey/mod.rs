//! The passkey provider: a WebAuthn authenticator in the core.
//!
//! Spec: Fase 1 § 9 (F-12, F-13, F-29). The core makes the keys, builds
//! `authenticatorData` and `clientDataJSON`, and signs. Nothing about a
//! passkey is computed outside the core, and the private key never leaves it
//! except inside the encrypted item body.
//!
//! * [`origin`]: canonical origins, RP IDs and the Public Suffix List.
//! * [`passkey_create`] and [`passkey_get`]: the two ceremonies.
//! * [`prf`]: the two PRF seeds and the `prf` extension.
//!
//! # What the caller must have done
//!
//! The core is given facts and decides on them. The extension (or the mobile
//! provider) is responsible for the facts being true:
//!
//! * `ctx.origin` is the origin of the **calling frame** as the browser or the
//!   operating system reports it, never a value from the page.
//! * `ctx.top_origin_is_same` is `false` when the calling frame is not of the
//!   same origin as the top-level document. Cross-origin requests are
//!   refused in v1 (`NotAllowed`).
//! * `uv.user_present` is `true` only after a click in Ferret's own UI.
//!   `uv.user_verified` is `true` only when the user verified **in this
//!   request** (master password, PIN, PRF or biometrics; or a recent unlock if
//!   the user has switched that on). The core sets the `UV` flag from it and
//!   from nothing else.
//!
//! # Errors
//!
//! A cancelled request, a missing user verification where the site requires
//! it, a credential that does not exist for the RP, a wrong RP ID at signing
//! time and a cross-origin request all give the one value
//! [`Error::NotAllowed`], so the page cannot tell them apart (Fase 1 § 9.3,
//! "Personvern"). The one exception is `create` with a credential from
//! `excludeCredentials` that is already stored for the RP: that is
//! [`Error::InvalidState`] (WebAuthn's `InvalidStateError`, which sites use
//! for "already registered"), given only after the user has consented, and
//! only for credentials of the same RP ID. A request that is wrong in itself
//! (an origin that cannot be one, an RP ID the origin may not use, limits
//! exceeded) has its own code.

mod authdata;
mod client_data;
mod cose;
pub mod origin;
mod prf;
mod psl;

pub use authdata::{AAGUID, FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV};
pub use client_data::Ceremony;
pub use cose::{COSE_ALG_ES256, PasskeyPrivateKey};
pub use origin::{CanonicalOrigin, RpId, canonical_origin, validate_rp_id};
pub use prf::{
    MAX_EVAL_BY_CREDENTIAL, MAX_PRF_INPUT, PrfCreate, PrfEval, PrfRequest, PrfResults, prf_output,
    prf_salt,
};
pub use psl::{snapshot_commit, snapshot_date};

#[cfg(any(test, feature = "test-support"))]
pub(crate) use client_data::client_data_json_raw;
#[cfg(any(test, feature = "test-support"))]
pub(crate) use psl::{
    is_public_suffix, public_suffix_labels, rule_counts, rule_lines, snapshot_text,
};

use crate::cbor::redacted_debug;
use crate::envelope::{SealedItem, encrypt_item};
use crate::error::{Error, MalformedKind};
use crate::ids::ItemId;
use crate::item::{ItemBody, ItemType, Passkey, UrlEntry, UrlMatch};
use crate::keys::UnlockedVault;
use crate::rng::SecureRng;
use crate::secret::PrfSeed;
use authdata::{Attested, authenticator_data};
use client_data::{base64url, client_data_json};
use cose::{attestation_object_none, cose_key_es256};

/// The largest challenge accepted, in bytes (Fase 1 § 9.2).
pub const MAX_CHALLENGE: usize = 1024;
/// The most entries in `allowCredentials` or `excludeCredentials`.
pub const MAX_CREDENTIAL_LIST: usize = 200;
/// The longest credential id in a list, in bytes (WebAuthn § 5.8.3).
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// The longest user handle, in bytes (WebAuthn § 5.4.3).
pub const MAX_USER_HANDLE: usize = 64;
/// The longest name or display name, in bytes.
pub const MAX_NAME: usize = 1024;
/// The length of a credential id made by Ferret (plan U13).
pub const CREDENTIAL_ID_LEN: usize = 32;

fn bad_options() -> Error {
    Error::Malformed(MalformedKind::WebauthnOptions)
}

/// `userVerification` of the request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UserVerification {
    /// The site requires it: without UV the answer is `NotAllowed`.
    Required,
    /// The site would like it; the flag says whether it happened.
    Preferred,
    /// The site does not want it; the flag says whether it happened.
    Discouraged,
}

/// What the user did in this request (Fase 1 § 9.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UvOutcome {
    /// The user clicked in Ferret's own UI.
    pub user_present: bool,
    /// The user verified in this request.
    pub user_verified: bool,
}

/// Who is asking.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CallerContext {
    /// The origin of the calling frame.
    pub origin: CanonicalOrigin,
    /// `false` when the calling frame is not same-origin with the top frame.
    pub top_origin_is_same: bool,
}

/// A request to make a passkey (`navigator.credentials.create`).
#[derive(Clone, PartialEq, Eq)]
pub struct CreateRequest {
    /// `challenge`.
    pub challenge: Vec<u8>,
    /// `rp.id`; the host of the origin when absent.
    pub rp_id: Option<String>,
    /// `rp.name`.
    pub rp_name: String,
    /// `user.id`, 1 to 64 bytes.
    pub user_id: Vec<u8>,
    /// `user.name`.
    pub user_name: String,
    /// `user.displayName`.
    pub user_display_name: String,
    /// The `alg` of `pubKeyCredParams`. Empty means the default (ES256);
    /// otherwise -7 must be among them.
    pub algorithms: Vec<i64>,
    /// `excludeCredentials` ids.
    pub exclude: Vec<Vec<u8>>,
    /// `authenticatorSelection.userVerification`.
    pub user_verification: UserVerification,
    /// The `prf` extension input; its presence makes the passkey a PRF one.
    pub prf: Option<PrfCreate>,
}

/// A request to sign in (`navigator.credentials.get`).
#[derive(Clone, PartialEq, Eq)]
pub struct GetRequest {
    /// `challenge`.
    pub challenge: Vec<u8>,
    /// `rpId`; the host of the origin when absent.
    pub rp_id: Option<String>,
    /// `allowCredentials` ids; empty means any.
    pub allow: Vec<Vec<u8>>,
    /// `userVerification`.
    pub user_verification: UserVerification,
    /// The `prf` extension input.
    pub prf: Option<PrfRequest>,
}

fn check_challenge(challenge: &[u8]) -> Result<(), Error> {
    if challenge.len() > MAX_CHALLENGE {
        return Err(Error::TooLarge);
    }
    Ok(())
}

fn check_id_list(list: &[Vec<u8>]) -> Result<(), Error> {
    if list.len() > MAX_CREDENTIAL_LIST || list.iter().any(|id| id.len() > MAX_CREDENTIAL_ID) {
        return Err(Error::TooLarge);
    }
    Ok(())
}

impl CreateRequest {
    /// Checks the limits of the request: challenge at most 1 KiB, lists at
    /// most 200 entries, user handle 1 to 64 bytes, names at most 1 KiB, and
    /// an algorithm list that allows ES256.
    ///
    /// Spec: Fase 1 § 9.2 ("Grenser").
    pub fn validate(&self) -> Result<(), Error> {
        check_challenge(&self.challenge)?;
        check_id_list(&self.exclude)?;
        if self.user_id.is_empty() || self.user_id.len() > MAX_USER_HANDLE {
            return Err(bad_options());
        }
        let long = [&self.rp_name, &self.user_name, &self.user_display_name]
            .iter()
            .any(|s| s.len() > MAX_NAME)
            || self.rp_id.as_ref().is_some_and(|s| s.len() > MAX_NAME);
        if long {
            return Err(Error::TooLarge);
        }
        if !self.algorithms.is_empty() && !self.algorithms.contains(&COSE_ALG_ES256) {
            return Err(Error::Unsupported);
        }
        if let Some(p) = &self.prf {
            p.validate()?;
        }
        Ok(())
    }
}

impl GetRequest {
    /// Checks the limits of the request: challenge at most 1 KiB, the id list
    /// at most 200 entries, and the `prf` input as the extension requires
    /// (`evalByCredential` needs `allowCredentials` and names only credentials
    /// in it).
    ///
    /// Spec: Fase 1 § 9.2 ("Grenser"), § 9.5 and plan U20.
    pub fn validate(&self) -> Result<(), Error> {
        check_challenge(&self.challenge)?;
        check_id_list(&self.allow)?;
        if self.rp_id.as_ref().is_some_and(|s| s.len() > MAX_NAME) {
            return Err(Error::TooLarge);
        }
        if let Some(p) = &self.prf {
            p.validate(&self.allow)?;
        }
        Ok(())
    }
}

/// A passkey as Ferret stores it: the fields of the `passkey` member of the
/// item body (plan Appendix B).
///
/// There is no `Clone`, no `PartialEq` and the `Debug` shows nothing. The
/// `signCount` is not a field: it is always 0.
pub struct PasskeyRecord {
    /// The credential id (32 random bytes).
    pub cred_id: Vec<u8>,
    /// The RP ID, canonical.
    pub rp_id: String,
    /// The user handle.
    pub user_handle: Vec<u8>,
    /// The user name, shown to the user.
    pub user_name: String,
    /// When the passkey was made, unix milliseconds.
    pub created: u64,
    key: PasskeyPrivateKey,
    prf_seed_uv: Option<PrfSeed>,
    prf_seed_nouv: Option<PrfSeed>,
}

redacted_debug!(PasskeyRecord);

fn seed_from(bytes: Option<&Vec<u8>>) -> Result<Option<PrfSeed>, Error> {
    bytes
        .map(|b| {
            let mut arr: [u8; 32] = b
                .as_slice()
                .try_into()
                .map_err(|_| Error::Malformed(MalformedKind::ItemBody))?;
            Ok(PrfSeed::from_array_wiping(&mut arr))
        })
        .transpose()
}

impl PasskeyRecord {
    /// Reads the record from the `passkey` member of an item body. Fails with
    /// `malformed_item_body` when the private key is not a P-256 PKCS#8 key
    /// or a seed is not 32 bytes.
    pub fn from_item(p: &Passkey) -> Result<Self, Error> {
        Ok(Self {
            cred_id: p.cred_id.clone(),
            rp_id: p.rp_id.clone(),
            user_handle: p.user_handle.clone(),
            user_name: p.user_name.clone(),
            created: p.created,
            key: PasskeyPrivateKey::from_pkcs8_der(&p.private_key)?,
            prf_seed_uv: seed_from(p.prf_seed_uv.as_ref())?,
            prf_seed_nouv: seed_from(p.prf_seed_nouv.as_ref())?,
        })
    }

    /// The `passkey` member of an item body. Crate-private: it holds the
    /// PKCS#8 key and the PRF seeds as plain bytes, which leave the core only
    /// inside a sealed envelope ([`seal_passkey_item`]). `scripts/check-passkey-api.sh`
    /// fails the build if a public item of this module returns such bytes.
    pub(crate) fn to_item(&self) -> Passkey {
        Passkey {
            cred_id: self.cred_id.clone(),
            rp_id: self.rp_id.clone(),
            user_handle: self.user_handle.clone(),
            user_name: self.user_name.clone(),
            private_key: self.key.der().to_vec(),
            sign_count: 0,
            created: self.created,
            prf_seed_uv: self.prf_seed_uv.as_ref().map(|s| s.expose().to_vec()),
            prf_seed_nouv: self.prf_seed_nouv.as_ref().map(|s| s.expose().to_vec()),
            extra: Vec::new(),
        }
    }

    /// Puts the passkey into `body`, replacing the one it had. Nothing else
    /// of the body is touched, so a login keeps its name, addresses, fields,
    /// notes and everything this version does not know. The key and the seeds
    /// go into the body and leave the core only inside a sealed envelope.
    ///
    /// Add the site to the addresses of a new item yourself (see
    /// [`seal_passkey_item`], which does it for the item it makes).
    pub fn attach_to(&self, body: &mut ItemBody) {
        body.passkey = Some(self.to_item());
    }

    /// True when the passkey was made with `prf`, so it has both seeds.
    pub fn has_prf(&self) -> bool {
        self.prf_seed_uv.is_some() && self.prf_seed_nouv.is_some()
    }
}

/// The answer to `create`.
#[derive(Debug)]
pub struct CreateResponse {
    /// The credential id (`rawId`).
    pub id: Vec<u8>,
    /// `attestationObject`, format `none`.
    pub attestation_object: Vec<u8>,
    /// `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// `authenticatorData` (also inside the attestation object).
    pub authenticator_data: Vec<u8>,
    /// `getPublicKey()`: SubjectPublicKeyInfo DER.
    pub public_key_spki: Vec<u8>,
    /// `getPublicKeyAlgorithm()`, -7.
    pub alg: i64,
    /// `clientExtensionResults.prf`, when the request had `prf`.
    pub prf: Option<CreatePrfResponse>,
}

/// `clientExtensionResults.prf` of `create`.
#[derive(Debug)]
pub struct CreatePrfResponse {
    /// `enabled`: always true here.
    pub enabled: bool,
    /// `results`, when the request had `eval`.
    pub results: Option<PrfResults>,
}

/// The answer to `get`.
#[derive(Debug)]
pub struct GetResponse {
    /// The credential id (`rawId`).
    pub id: Vec<u8>,
    /// `authenticatorData`.
    pub authenticator_data: Vec<u8>,
    /// `clientDataJSON`.
    pub client_data_json: Vec<u8>,
    /// The ES256 signature, ASN.1 DER.
    pub signature: Vec<u8>,
    /// `userHandle`.
    pub user_handle: Vec<u8>,
    /// `clientExtensionResults.prf.results`, when asked for and available.
    pub prf: Option<PrfResults>,
}

/// A passkey that Ferret already stores, as far as `excludeCredentials` is
/// concerned.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExistingCredential {
    /// The RP ID it was made for, in canonical form (a canonical origin's
    /// host, lower-case, IDNA A-labels). A value that is not canonical never
    /// matches the RP ID of a request, so the credential is not counted for
    /// `excludeCredentials`; canonicalize it first.
    pub rp_id: String,
    /// The credential id.
    pub cred_id: Vec<u8>,
}

/// A new passkey and the answer to the page. Store `record`; give `response`
/// to the page.
pub struct CreatedPasskey {
    /// The passkey to store.
    pub record: PasskeyRecord,
    /// The answer to the page.
    pub response: CreateResponse,
}

redacted_debug!(CreatedPasskey);

fn require_same_origin(ctx: &CallerContext) -> Result<(), Error> {
    if ctx.top_origin_is_same {
        Ok(())
    } else {
        Err(Error::NotAllowed)
    }
}

/// UP only after a click; UV only when performed; `required` without UV is
/// `NotAllowed`. A claim of UV without UP is not a state that can exist.
fn require_user(uv: UvOutcome, wanted: UserVerification) -> Result<(), Error> {
    if !uv.user_present {
        return Err(Error::NotAllowed);
    }
    if wanted == UserVerification::Required && !uv.user_verified {
        return Err(Error::NotAllowed);
    }
    Ok(())
}

fn resolve_rp_id(ctx: &CallerContext, requested: Option<&str>) -> Result<RpId, Error> {
    match requested {
        Some(id) => validate_rp_id(&ctx.origin, id),
        None => origin::default_rp_id(&ctx.origin),
    }
}

/// Makes a passkey.
///
/// Draws from `rng`, in this order: the credential id (32 bytes), the private
/// key scalar (32 bytes; again only if the draw is not a valid scalar), and,
/// when the request has `prf`, `prf_seed_uv` and `prf_seed_nouv` (32 bytes
/// each).
///
/// `existing` lists the passkeys Ferret already stores, each with its RP ID.
/// Only those for the RP ID of this request are compared with
/// `req.exclude`; a hit is [`Error::InvalidState`] (WebAuthn's
/// `InvalidStateError`). It comes after the presence check, so the user has
/// consented before the page learns that the credential exists.
///
/// Spec: Fase 1 § 9.1 to § 9.3, § 9.5; plan U13.
pub fn passkey_create<R: SecureRng>(
    rng: &mut R,
    req: &CreateRequest,
    ctx: &CallerContext,
    uv: UvOutcome,
    existing: &[ExistingCredential],
    created_ms: u64,
) -> Result<CreatedPasskey, Error> {
    req.validate()?;
    require_same_origin(ctx)?;
    let rp_id = resolve_rp_id(ctx, req.rp_id.as_deref())?;
    require_user(uv, req.user_verification)?;
    // Only credentials for this RP ID count: an id stored for another RP must
    // not tell the page anything (a cross-RP existence oracle).
    if existing
        .iter()
        .any(|e| e.rp_id == rp_id.as_str() && req.exclude.contains(&e.cred_id))
    {
        return Err(Error::InvalidState);
    }

    let mut cred_id = vec![0u8; CREDENTIAL_ID_LEN];
    rng.fill(&mut cred_id);
    let key = PasskeyPrivateKey::generate(rng)?;
    let (prf_seed_uv, prf_seed_nouv) = if req.prf.is_some() {
        (Some(PrfSeed::random(rng)), Some(PrfSeed::random(rng)))
    } else {
        (None, None)
    };

    let (x, y) = key.public_xy()?;
    let cose_key = cose_key_es256(&x, &y);
    let attested = Attested {
        credential_id: &cred_id,
        cose_key: &cose_key,
        hmac_secret: req.prf.is_some(),
    };
    let auth_data = authenticator_data(&rp_id.hash(), uv.user_verified, Some(&attested))?;
    let attestation_object = attestation_object_none(&auth_data)?;
    let client_data = client_data_json(Ceremony::Create, &req.challenge, &ctx.origin);

    let prf = match &req.prf {
        None => None,
        Some(p) => {
            // The seed follows the user verification that actually happened.
            let seed = if uv.user_verified {
                prf_seed_uv.as_ref()
            } else {
                prf_seed_nouv.as_ref()
            };
            let results = match (p.eval.as_ref(), seed) {
                (Some(eval), Some(seed)) => Some(prf::evaluate(seed, eval)?),
                _ => None,
            };
            Some(CreatePrfResponse {
                enabled: true,
                results,
            })
        }
    };

    let response = CreateResponse {
        id: cred_id.clone(),
        attestation_object,
        client_data_json: client_data.into_bytes(),
        authenticator_data: auth_data,
        public_key_spki: key.public_spki()?,
        alg: COSE_ALG_ES256,
        prf,
    };
    let record = PasskeyRecord {
        cred_id,
        rp_id: rp_id.as_str().to_owned(),
        user_handle: req.user_id.clone(),
        user_name: req.user_name.clone(),
        created: created_ms,
        key,
        prf_seed_uv,
        prf_seed_nouv,
    };
    Ok(CreatedPasskey { record, response })
}

/// Signs in with a stored passkey.
///
/// The caller has chosen `record` (by RP ID and `allowCredentials`); the
/// function checks that it is the right one: the RP ID of the request must be
/// **exactly** the stored one (no suffix logic here), and a non-empty
/// `allow` must contain the credential id. A mismatch is `NotAllowed`, the
/// same as a cancelled request.
///
/// Spec: Fase 1 § 9.2 ("Ved signering"), § 9.3, § 9.5.
pub fn passkey_get(
    record: &PasskeyRecord,
    req: &GetRequest,
    ctx: &CallerContext,
    uv: UvOutcome,
) -> Result<GetResponse, Error> {
    req.validate()?;
    require_same_origin(ctx)?;
    let rp_id = resolve_rp_id(ctx, req.rp_id.as_deref())?;
    if rp_id.as_str() != record.rp_id {
        return Err(Error::NotAllowed);
    }
    if !req.allow.is_empty() && !req.allow.contains(&record.cred_id) {
        return Err(Error::NotAllowed);
    }
    require_user(uv, req.user_verification)?;

    let auth_data = authenticator_data(&rp_id.hash(), uv.user_verified, None)?;
    let client_data = client_data_json(Ceremony::Get, &req.challenge, &ctx.origin);
    let signature = record
        .key
        .sign_assertion(&auth_data, client_data.as_bytes())?;

    let seed = if uv.user_verified {
        record.prf_seed_uv.as_ref()
    } else {
        record.prf_seed_nouv.as_ref()
    };
    let prf = match (&req.prf, seed) {
        (Some(p), Some(seed)) => p
            .select(&record.cred_id)
            .map(|eval| prf::evaluate(seed, eval))
            .transpose()?,
        _ => None,
    };

    Ok(GetResponse {
        id: record.cred_id.clone(),
        authenticator_data: auth_data,
        client_data_json: client_data.into_bytes(),
        signature,
        user_handle: record.user_handle.clone(),
        prf,
    })
}

/// Seals a passkey into an item envelope, as a **new** login item named
/// `name`, with the site of the passkey (`https://` and its RP ID) as its
/// address.
///
/// This is the one way a record leaves the core for storage: the PKCS#8 key
/// and the PRF seeds go into the body and the body into the encrypted
/// envelope; no plain bytes are returned.
///
/// `existing` is the current envelope of the item and only lets the item key
/// be kept. The body is built from the passkey alone, so **it replaces
/// everything else the item had** (other fields, notes, addresses). To add a
/// passkey to a login that exists, change its body with
/// [`PasskeyRecord::attach_to`] and seal it with `encrypt_item`.
///
/// Spec: Fase 1 § 9.1.
#[allow(clippy::too_many_arguments)]
pub fn seal_passkey_item<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    item_id: ItemId,
    rev: u64,
    record: &PasskeyRecord,
    name: &str,
    now_ms: u64,
    existing: Option<&[u8]>,
) -> Result<SealedItem, Error> {
    let mut body = ItemBody::new(ItemType::Login, name, now_ms);
    body.urls.push(UrlEntry {
        url: format!("https://{}", record.rp_id),
        matching: UrlMatch::Host,
        extra: Vec::new(),
    });
    record.attach_to(&mut body);
    encrypt_item(rng, vault, item_id, rev, &body, existing)
}

/// The base64url form of a credential id, as it is shown to a page (`id`).
pub fn credential_id_text(id: &[u8]) -> String {
    base64url(id)
}
