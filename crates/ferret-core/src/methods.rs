//! Adding and removing an unlock method, and comparing the server's list of
//! methods with the manifest.
//!
//! Spec: Fase 1 § 4.3 ("Fjerne en metode", "Mottaker sjekker") and § 4.6
//! (the proofs `unlock-method.add` and `unlock-method.remove`).
//!
//! # Changing the list
//!
//! [`manifest_add_method`] and [`manifest_remove_method`] take the manifest
//! row the server holds (it is opened first) and give back the next manifest,
//! sealed one revision up, and the **body of the request** as one byte
//! string. The proof of the request is made over exactly those bytes
//! ([`MethodChange::sign`] cannot sign anything else), so the manifest the
//! server stores is bound to the proof. The caller sends the bytes as they
//! are:
//!
//! ```text
//! add    {"method_type":3,"method_id":"<hex>","wrap":"<hex>",
//!         "kek_generation":N,"credential_id":"<hex>","prf_salt":"<hex>",
//!         "manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! remove {"method_id":"<hex>","manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! ```
//!
//! (compact, no spaces, in this key order, lowercase hex). The `remove` body
//! names the method, which the design sends only in the URL: without it the
//! proof would not say which wrap is meant.
//!
//! The rules are those of the design: only a passkey (PRF) wrap is added with
//! this call (the password and the recovery wrap are replaced by their own
//! requests, and the PIN and device wraps never leave the device); a method
//! id or a credential id is listed once; the last `password` and the last
//! `recovery` method cannot be removed ([`InputError::LastMethod`]).
//!
//! The draw is the nonce of the new manifest (24 bytes). The wrap is made by
//! the caller with [`crate::UnlockedVault::wrap_for_method`].
//!
//! # Comparing the lists
//!
//! [`check_server_methods`] compares the server's list of methods with the
//! authenticated manifest after each unlock. The two must agree on every
//! `method_type`, `method_id` and `kek_generation`, and neither may hold
//! anything the other does not.

use crate::envelope::{SealedItem, decrypt_manifest, encrypt_manifest};
use crate::error::{Error, InputError, MalformedKind, MethodListFailure};
use crate::ids::MethodId;
use crate::integrity::{AuthOp, auth_sign};
use crate::item::{Manifest, ManifestEntry};
use crate::keys::UnlockedVault;
use crate::pinning::{MAX_CREDENTIAL_ID_LEN, MAX_FLOORS, MAX_GENERATION};
use crate::rng::SecureRng;
use crate::wrap::{Method, TYPE_PASSWORD, TYPE_RECOVERY, WRAP_LEN, WrapRecord};

/// The most methods one manifest lists.
pub const MAX_METHODS: usize = MAX_FLOORS;

fn entries_error() -> Error {
    Error::Malformed(MalformedKind::Entries)
}

/// The manifest row the server holds. Opened and verified before it is used.
#[derive(Clone, Copy, Debug)]
pub struct CurrentManifest<'a> {
    /// Its current revision.
    pub rev: u64,
    /// The envelope.
    pub envelope: &'a [u8],
    /// The tag the server stores with it.
    pub tag: &'a [u8; 32],
}

/// A change of the list of unlock methods, ready to be sent. Public data
/// only.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MethodChange {
    /// The operation of the request's proof: `unlock-method.add` or
    /// `unlock-method.remove`.
    pub op: AuthOp,
    /// The new wrap (`add` only).
    pub wrap: Option<WrapRecord>,
    /// The next manifest, in the clear.
    pub manifest: Manifest,
    /// The next manifest, sealed one revision up.
    pub sealed: SealedItem,
    /// The exact bytes of the request body, as in the module documentation.
    /// The proof is made over these.
    pub body: Vec<u8>,
    /// `pk_a` of the vault the change was made for. [`MethodChange::sign`]
    /// signs only with the vault that has this key.
    pub pk_a: [u8; 32],
}

impl MethodChange {
    /// Signs the request body with `sk_a` of `vault` for [`MethodChange::op`].
    /// `vault` must be the vault the change was made for; another vault is
    /// `pinned_auth_key`.
    ///
    /// Spec: Fase 1 § 4.6.
    pub fn sign(&self, vault: &UnlockedVault, nonce: &[u8; 32]) -> Result<[u8; 64], Error> {
        if vault.auth_public_key() != self.pk_a {
            return Err(Error::Pinned(crate::error::PinnedField::AuthKey));
        }
        auth_sign(vault, self.op, nonce, &self.body)
    }
}

impl Manifest {
    /// The manifest with one more method: a passkey (PRF) wrap. The new
    /// entry carries the wrap's id, `kek_generation` and credential id; the
    /// other entries and the unknown keys stay as they are.
    ///
    /// Refused: any other kind of wrap (`unsupported`), a wrap of the wrong
    /// length, an empty or over-long credential id or an all-zero PRF salt
    /// (`input_*`), a method id or credential id that the manifest lists
    /// already, a generation above `2^32 - 1`, and a manifest that would
    /// list more than [`MAX_METHODS`] (all `malformed_entries`).
    pub fn with_method(&self, wrap: &WrapRecord) -> Result<Manifest, Error> {
        let Method::Prf {
            credential_id,
            prf_salt,
        } = &wrap.method
        else {
            return Err(Error::Unsupported);
        };
        if wrap.wrap.len() != WRAP_LEN {
            return Err(Error::Malformed(MalformedKind::Envelope));
        }
        if credential_id.is_empty() {
            return Err(Error::InvalidInput(InputError::TooShort));
        }
        if credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::InvalidInput(InputError::TooLong));
        }
        if prf_salt.iter().all(|b| *b == 0) {
            return Err(Error::InvalidInput(InputError::AllZero));
        }
        if wrap.kek_generation > MAX_GENERATION {
            return Err(entries_error());
        }
        if self.methods.len() >= MAX_METHODS
            || self.methods.iter().any(|m| {
                m.method_id == wrap.method_id
                    || (m.method_type == wrap.method.type_code()
                        && m.credential_id.as_deref() == Some(credential_id.as_slice()))
            })
        {
            return Err(entries_error());
        }
        let mut next = self.clone();
        next.methods.push(ManifestEntry::passkey(
            wrap.method_id,
            wrap.kek_generation,
            credential_id.clone(),
        ));
        Ok(next)
    }

    /// The manifest without the method `method_id`. A method the manifest
    /// does not list is `malformed_entries`; the only `password` and the only
    /// `recovery` method are `input_last_method`.
    pub fn without_method(&self, method_id: &MethodId) -> Result<Manifest, Error> {
        let index = self
            .methods
            .iter()
            .position(|m| m.method_id == *method_id)
            .ok_or_else(entries_error)?;
        let kind = self
            .methods
            .get(index)
            .map(|m| m.method_type)
            .ok_or_else(entries_error)?;
        if matches!(kind, TYPE_PASSWORD | TYPE_RECOVERY)
            && self
                .methods
                .iter()
                .filter(|m| m.method_type == kind)
                .count()
                <= 1
        {
            return Err(Error::InvalidInput(InputError::LastMethod));
        }
        let mut next = self.clone();
        if index < next.methods.len() {
            next.methods.remove(index);
        }
        Ok(next)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            out.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    out
}

/// `{"rev":N,"envelope":"<hex>","tag":"<hex>"}`.
fn manifest_json(sealed: &SealedItem) -> String {
    format!(
        "{{\"rev\":{},\"envelope\":\"{}\",\"tag\":\"{}\"}}",
        sealed.rev,
        hex(&sealed.envelope),
        hex(&sealed.tag)
    )
}

/// Opens the current manifest and checks that it is this vault's.
fn open_current(vault: &UnlockedVault, current: &CurrentManifest<'_>) -> Result<Manifest, Error> {
    let old = decrypt_manifest(vault, current.rev, current.envelope, current.tag)?;
    if old.vk_epoch != vault.context().vk_epoch {
        return Err(entries_error());
    }
    Ok(old)
}

/// Seals the next manifest one revision up and checks that it opens.
fn seal_next<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    current: &CurrentManifest<'_>,
    next: &Manifest,
) -> Result<SealedItem, Error> {
    let rev = current.rev.checked_add(1).ok_or_else(entries_error)?;
    let sealed = encrypt_manifest(rng, vault, rev, next)?;
    if decrypt_manifest(vault, sealed.rev, &sealed.envelope, &sealed.tag)? != *next {
        return Err(Error::Decrypt);
    }
    Ok(sealed)
}

/// Adds a passkey (PRF) wrap to the list of unlock methods. `wrap` is the
/// record from [`crate::UnlockedVault::wrap_for_method`]; `current` is the
/// manifest row the server holds. Draws the nonce of the new manifest.
///
/// Spec: Fase 1 § 4.3 and § 4.6 (`POST /api/vault/unlock-methods`).
pub fn manifest_add_method<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    current: &CurrentManifest<'_>,
    wrap: WrapRecord,
) -> Result<MethodChange, Error> {
    let old = open_current(vault, current)?;
    let next = old.with_method(&wrap)?;
    let Method::Prf {
        credential_id,
        prf_salt,
    } = &wrap.method
    else {
        return Err(Error::Unsupported);
    };
    let sealed = seal_next(rng, vault, current, &next)?;
    let body = format!(
        "{{\"method_type\":{},\"method_id\":\"{}\",\"wrap\":\"{}\",\"kek_generation\":{},\"credential_id\":\"{}\",\"prf_salt\":\"{}\",\"manifest\":{}}}",
        wrap.method.type_code(),
        hex(wrap.method_id.as_bytes()),
        hex(&wrap.wrap),
        wrap.kek_generation,
        hex(credential_id),
        hex(prf_salt),
        manifest_json(&sealed)
    )
    .into_bytes();
    Ok(MethodChange {
        op: AuthOp::UnlockMethodAdd,
        wrap: Some(wrap),
        manifest: next,
        sealed,
        body,
        pk_a: vault.auth_public_key(),
    })
}

/// Removes an unlock method from the list. The last `password` and the last
/// `recovery` method are refused (`input_last_method`). `current` is the
/// manifest row the server holds. Draws the nonce of the new manifest.
///
/// Spec: Fase 1 § 4.3 and § 4.6 (`DELETE /api/vault/unlock-methods/{id}`).
pub fn manifest_remove_method<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    current: &CurrentManifest<'_>,
    method_id: &MethodId,
) -> Result<MethodChange, Error> {
    let old = open_current(vault, current)?;
    let next = old.without_method(method_id)?;
    let sealed = seal_next(rng, vault, current, &next)?;
    let body = format!(
        "{{\"method_id\":\"{}\",\"manifest\":{}}}",
        hex(method_id.as_bytes()),
        manifest_json(&sealed)
    )
    .into_bytes();
    Ok(MethodChange {
        op: AuthOp::UnlockMethodRemove,
        wrap: None,
        manifest: next,
        sealed,
        body,
        pk_a: vault.auth_public_key(),
    })
}

/// One method as the server lists it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServerMethod {
    /// The `method_type` byte.
    pub method_type: u8,
    /// The method's id.
    pub method_id: MethodId,
    /// The `kek_generation` of its wrap.
    pub kek_generation: u64,
}

/// Compares the server's list of unlock methods with the manifest, which was
/// opened with the vault key and so is the user's own record.
///
/// The lists agree when every server method is in the manifest with the same
/// type, id and generation, and the manifest lists nothing the server lacks.
/// The first difference is returned, in this order:
///
/// 1. the server lists a method (or an id twice) that the manifest does not:
///    `method_list_unknown`;
/// 2. a method is listed with another type or generation:
///    `method_list_changed`;
/// 3. the manifest lists a method that the server does not:
///    `method_list_missing`.
///
/// The client warns on any of them. The local PIN and device wraps are in
/// neither list.
///
/// Spec: Fase 1 § 4.3 ("Etter hver opplåsing sammenligner klienten …").
pub fn check_server_methods(manifest: &Manifest, server: &[ServerMethod]) -> Result<(), Error> {
    let unknown = || Error::MethodList(MethodListFailure::Unknown);
    for (i, s) in server.iter().enumerate() {
        let repeated = server
            .iter()
            .take(i)
            .any(|earlier| earlier.method_id == s.method_id);
        if repeated || !manifest.methods.iter().any(|m| m.method_id == s.method_id) {
            return Err(unknown());
        }
    }
    for s in server {
        let same = manifest.methods.iter().any(|m| {
            m.method_id == s.method_id
                && m.method_type == s.method_type
                && m.kek_generation == s.kek_generation
        });
        if !same {
            return Err(Error::MethodList(MethodListFailure::Changed));
        }
    }
    if manifest
        .methods
        .iter()
        .any(|m| !server.iter().any(|s| s.method_id == m.method_id))
    {
        return Err(Error::MethodList(MethodListFailure::Missing));
    }
    Ok(())
}
