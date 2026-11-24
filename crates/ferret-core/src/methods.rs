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
//!         "aaguid":"<hex>",
//!         "manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! remove {"method_id":"<hex>","manifest":{"rev":N,"envelope":"<hex>","tag":"<hex>"}}
//! ```
//!
//! (compact, no spaces, in this key order, lowercase hex). The `remove` body
//! names the method, which the design sends only in the URL: without it the
//! proof would not say which wrap is meant.
//!
//! `aaguid` is the 16 bytes of the authenticator's AAGUID. It is display data:
//! it can be all zero (shown as "unknown"), nothing is decided from it, and
//! only Ferret's own AAGUID is refused, as an extra guard (the real guards are
//! that the passkey override is off on the vault's origin and that the wrap of
//! a passkey that Ferret stores is refused). The name the user gave the
//! passkey and its BE and BS flags are **not** in the body: they are in the
//! manifest, which is sealed, so the server neither sees nor can change them
//! ([`PasskeyMeta`]).
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
use crate::error::{Error, InputError, MalformedKind, MethodListFailure, MethodNameError};
use crate::ids::MethodId;
use crate::integrity::{AuthOp, auth_sign};
use crate::item::folders::{is_refused, nfc_trimmed};
use crate::item::{Manifest, ManifestEntry};
use crate::keys::UnlockedVault;
use crate::passkey::AAGUID;
use crate::pinning::{MAX_CREDENTIAL_ID_LEN, MAX_FLOORS, MAX_GENERATION};
use crate::rng::SecureRng;
use crate::wrap::{Method, TYPE_PASSWORD, TYPE_RECOVERY, WRAP_LEN, WrapRecord};

/// The most methods one manifest lists.
pub const MAX_METHODS: usize = MAX_FLOORS;

/// The most characters (Unicode scalar values) in the name of a passkey
/// method, once it is in NFC and trimmed.
pub const MAX_METHOD_NAME_CHARS: usize = 64;

/// What the registration of a passkey tells about it, besides the wrap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PasskeyMeta<'a> {
    /// The authenticator's AAGUID (16 bytes), from the registration. Display
    /// data only: all zero is accepted and shown as "unknown", and only
    /// Ferret's own AAGUID is refused (`invalid_state`).
    pub aaguid: [u8; 16],
    /// The name the user gave the passkey. It follows the rule of a folder
    /// name ([`normalize_method_name`]): put in NFC and trimmed, then 1 to 64
    /// characters, none of them a control character, separator, bidirectional
    /// mark or zero width space.
    pub name: &'a str,
    /// The BE flag of the registration: the key can be synced. It is fixed
    /// for the key's life and decides whether the list says "synced".
    pub be: bool,
    /// The BS flag at registration. For information only: it can be 0 then
    /// and 1 later. BS without BE is refused (`invalid_state`).
    pub bs: bool,
}

/// The name of a passkey method as it is stored: in NFC and trimmed, 1 to
/// [`MAX_METHOD_NAME_CHARS`] characters, and without a control character, a
/// line or paragraph separator, a bidirectional mark, embedding, override or
/// isolate, a zero width space or a byte order mark. This is the rule of a
/// folder name, so a name cannot reorder or hide text in the list. The zero
/// width joiner and non-joiner are allowed.
///
/// Spec: Fase 1 § 4.3 and Appendix B (the `n` key of a manifest entry).
pub fn normalize_method_name(raw: &str) -> Result<String, Error> {
    let name = nfc_trimmed(raw);
    if name.is_empty() {
        return Err(Error::MethodName(MethodNameError::Empty));
    }
    if name.chars().any(is_refused) {
        return Err(Error::MethodName(MethodNameError::BadCharacter));
    }
    if name.chars().nth(MAX_METHOD_NAME_CHARS).is_some() {
        return Err(Error::MethodName(MethodNameError::TooLong));
    }
    Ok(name)
}

/// A passkey method as the list shows it, read from the manifest.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrfMethod {
    /// The method's id.
    pub method_id: MethodId,
    /// The credential id of the passkey.
    pub credential_id: Vec<u8>,
    /// The current `kek_generation` of the method.
    pub kek_generation: u64,
    /// The name the user gave it, or `None` when the entry has none or the
    /// stored name breaks the rule of [`normalize_method_name`] (the list
    /// then shows it as unnamed).
    pub name: Option<String>,
    /// Whether the list says "synced passkey" (true) or "this device only"
    /// (false). It follows the BE flag, which is fixed for the key's life,
    /// never BS, which can change. An entry without the flag is device-only.
    pub synced: bool,
    /// The BS flag at registration, for information only.
    pub bs: Option<bool>,
}

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
    /// list more than [`MAX_METHODS`] (all `malformed_entries`); then Ferret's
    /// own AAGUID or BS set without BE (`invalid_state`) and a name that breaks the rule of
    /// [`normalize_method_name`] (`method_name_*`). The new entry carries the
    /// name in its stored form and the BE and BS flags of `meta`.
    pub fn with_method(
        &self,
        wrap: &WrapRecord,
        meta: &PasskeyMeta<'_>,
    ) -> Result<Manifest, Error> {
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
        // Display data, but Ferret's own AAGUID is an extra guard: such a
        // passkey lives in the vault it would have to open (Fase 1 § 9.4).
        if meta.aaguid == AAGUID {
            return Err(Error::InvalidState);
        }
        // BS says the key is backed up, which only a key that can be backed up
        // (BE) can be. An authenticator that reports BS without BE is not
        // conformant, and the list would call such a key "this device only".
        if meta.bs && !meta.be {
            return Err(Error::InvalidState);
        }
        let name = normalize_method_name(meta.name)?;
        let mut next = self.clone();
        next.methods.push(ManifestEntry::passkey_named(
            wrap.method_id,
            wrap.kek_generation,
            credential_id.clone(),
            name,
            meta.be,
            meta.bs,
        ));
        Ok(next)
    }

    /// The passkey (PRF) methods of the manifest, in the manifest's order,
    /// with their names and synced flags, for the list of unlock methods.
    ///
    /// The label follows the BE flag, not BS: BE is fixed for the key's life,
    /// BS can be 0 at registration and 1 later. An entry of `method_type` 3
    /// without a credential id is left out (it cannot be used). A stored name
    /// that does not pass [`normalize_method_name`] unchanged is given as
    /// `None`.
    pub fn prf_methods(&self) -> Vec<PrfMethod> {
        self.methods
            .iter()
            .filter(|m| m.method_type == 3)
            .filter_map(|m| {
                Some(PrfMethod {
                    method_id: m.method_id,
                    credential_id: m.credential_id.clone()?,
                    kek_generation: m.kek_generation,
                    name: m
                        .name
                        .as_deref()
                        .filter(|n| normalize_method_name(n).is_ok_and(|s| s == **n))
                        .map(str::to_owned),
                    synced: m.be == Some(true),
                    bs: m.bs,
                })
            })
            .collect()
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
/// manifest row the server holds. `meta` is what the registration told: the
/// AAGUID goes in the request body, the name and the BE and BS flags in the
/// sealed manifest only. Draws the nonce of the new manifest.
///
/// Spec: Fase 1 § 4.3 and § 4.6 (`POST /api/vault/unlock-methods`).
pub fn manifest_add_method<R: SecureRng>(
    rng: &mut R,
    vault: &UnlockedVault,
    current: &CurrentManifest<'_>,
    wrap: WrapRecord,
    meta: &PasskeyMeta<'_>,
) -> Result<MethodChange, Error> {
    let old = open_current(vault, current)?;
    let next = old.with_method(&wrap, meta)?;
    let Method::Prf {
        credential_id,
        prf_salt,
    } = &wrap.method
    else {
        return Err(Error::Unsupported);
    };
    let sealed = seal_next(rng, vault, current, &next)?;
    let body = format!(
        "{{\"method_type\":{},\"method_id\":\"{}\",\"wrap\":\"{}\",\"kek_generation\":{},\"credential_id\":\"{}\",\"prf_salt\":\"{}\",\"aaguid\":\"{}\",\"manifest\":{}}}",
        wrap.method.type_code(),
        hex(wrap.method_id.as_bytes()),
        hex(&wrap.wrap),
        wrap.kek_generation,
        hex(credential_id),
        hex(prf_salt),
        hex(&meta.aaguid),
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
