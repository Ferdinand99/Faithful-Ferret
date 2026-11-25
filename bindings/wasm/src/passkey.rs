//! The passkey provider, on the vault: a passkey is created, stored in an
//! item and used to sign without its private key or PRF seeds ever being
//! outside WASM memory.
//!
//! The values the page gets back (`id`, `attestation_object`,
//! `client_data_json`, `authenticator_data`, `public_key_spki`, the signature
//! and, when it asked for them, the PRF results) are what WebAuthn hands the
//! relying party by design; they are not the key. The PRF results are the
//! outputs of the extension for the inputs the site chose.

use crate::convert::{
    ANY, ByteBuf, SealedDto, Shape, Shaped, arr, b16, b32, bytes, from_js, from_js_list, js_time,
    js_u64, opt_bytes, secret_bytes, secret_text, to_js,
};
use crate::error::{Fail, Res, run};
use crate::item::{Bytes, DraftDto, build_body};
use crate::vault::{MAX_OPEN, OpenItem, PendingPasskey, Vault};
use ferret_core::passkey::{PrfCreate, PrfEval, PrfRequest, PrfResults};
use ferret_core::{
    CallerContext, CreateRequest, ExistingCredential, GetRequest, ImportKey, ImportPrf,
    ImportedPasskeyInput, ItemBody, ItemId, ItemType, OsRng, PasskeyRecord, StoredPasskeyRef,
    UrlEntry, UrlMatch, UserVerification, UvOutcome, canonical_origin, encrypt_item,
    passkey_candidates_for, passkey_create, passkey_get, passkey_import as core_passkey_import,
    passkey_site,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallerDto {
    /// The origin of the calling frame as the browser reports it.
    origin: String,
    top_origin_is_same: bool,
}

impl CallerDto {
    fn core(&self) -> Res<CallerContext> {
        Ok(CallerContext {
            origin: canonical_origin(&self.origin)?,
            top_origin_is_same: self.top_origin_is_same,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UvDto {
    user_present: bool,
    user_verified: bool,
}

impl UvDto {
    fn core(&self) -> UvOutcome {
        UvOutcome {
            user_present: self.user_present,
            user_verified: self.user_verified,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalDto {
    #[serde(with = "bytes")]
    first: Vec<u8>,
    #[serde(default, with = "opt_bytes")]
    second: Option<Vec<u8>>,
}

impl EvalDto {
    fn core(self) -> PrfEval {
        PrfEval {
            first: self.first,
            second: self.second,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalByCredentialDto {
    #[serde(with = "bytes")]
    id: Vec<u8>,
    #[serde(with = "bytes")]
    first: Vec<u8>,
    #[serde(default, with = "opt_bytes")]
    second: Option<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrfDto {
    #[serde(default)]
    eval: Option<EvalDto>,
    #[serde(default)]
    eval_by_credential: Vec<EvalByCredentialDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateDto {
    #[serde(with = "bytes")]
    challenge: Vec<u8>,
    #[serde(default)]
    rp_id: Option<String>,
    rp_name: String,
    #[serde(with = "bytes")]
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    #[serde(default)]
    algorithms: Vec<i64>,
    #[serde(default)]
    exclude: Vec<ByteBuf>,
    user_verification: String,
    /// Present when the site asks for the PRF extension.
    #[serde(default)]
    prf: Option<PrfDto>,
    /// Present and true when the site asks for `credProps`.
    #[serde(default)]
    cred_props: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetDto {
    #[serde(with = "bytes")]
    challenge: Vec<u8>,
    #[serde(default)]
    rp_id: Option<String>,
    #[serde(default)]
    allow: Vec<ByteBuf>,
    user_verification: String,
    #[serde(default)]
    prf: Option<PrfDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExistingDto {
    rp_id: String,
    #[serde(with = "bytes")]
    id: Vec<u8>,
}

fn user_verification(s: &str) -> Res<UserVerification> {
    match s {
        "required" => Ok(UserVerification::Required),
        "preferred" => Ok(UserVerification::Preferred),
        "discouraged" => Ok(UserVerification::Discouraged),
        _ => Err(Fail::Input),
    }
}

impl GetDto {
    /// The core's request. `passkey_get` and `passkey_candidates` read it the
    /// same way, so that both judge the same request.
    fn core(self) -> Res<GetRequest> {
        Ok(GetRequest {
            challenge: self.challenge,
            rp_id: self.rp_id,
            allow: id_list(self.allow),
            user_verification: user_verification(&self.user_verification)?,
            prf: self.prf.map(|p| PrfRequest {
                eval: p.eval.map(EvalDto::core),
                eval_by_credential: p
                    .eval_by_credential
                    .into_iter()
                    .map(|e| {
                        (
                            e.id,
                            PrfEval {
                                first: e.first,
                                second: e.second,
                            },
                        )
                    })
                    .collect(),
            }),
        })
    }
}

#[derive(Serialize)]
struct PrfResultsDto {
    #[serde(with = "b32")]
    first: [u8; 32],
    #[serde(default, with = "crate::convert::opt_b32")]
    second: Option<[u8; 32]>,
}

impl PrfResultsDto {
    fn of(r: &PrfResults) -> Self {
        Self {
            first: *r.reveal_first(),
            second: r.reveal_second().copied(),
        }
    }
}

#[derive(Serialize)]
struct CreatePrfDto {
    enabled: bool,
    results: Option<PrfResultsDto>,
}

/// `clientExtensionResults.credProps` of a registration.
#[derive(Serialize)]
struct CredPropsDto {
    rk: bool,
}

#[derive(Serialize)]
struct CreateResponseDto {
    id: Bytes,
    attestation_object: Bytes,
    client_data_json: Bytes,
    authenticator_data: Bytes,
    public_key_spki: Bytes,
    alg: i64,
    /// `authenticatorAttachment`: public text.
    authenticator_attachment: &'static str,
    /// `getTransports()`: public text, in the order the core gives.
    transports: &'static [&'static str],
    /// Present only when the site asked for `credProps`.
    cred_props: Option<CredPropsDto>,
    prf: Option<CreatePrfDto>,
}

#[derive(Serialize)]
struct GetResponseDto {
    id: Bytes,
    authenticator_attachment: &'static str,
    authenticator_data: Bytes,
    client_data_json: Bytes,
    signature: Bytes,
    user_handle: Bytes,
    prf: Option<PrfResultsDto>,
}

/// What `passkey_create` returns: the sealed item to store, and the handle of
/// the answer that is held back until `passkey_create_confirm`.
#[derive(Serialize)]
struct CreatedDto {
    item: SealedDto,
    #[serde(with = "b16")]
    item_id: [u8; 16],
    pending: u32,
}

/// What `passkey_create_confirm` returns: the answer for the page and the
/// handle of the item that now holds the passkey.
#[derive(Serialize)]
struct ConfirmedDto {
    response: CreateResponseDto,
    handle: u32,
}

/// The value of `existing` that says there are no stored passkeys. An empty
/// array is refused instead, so that "I have none" is a decision and not what
/// a forgotten argument looks like.
const NO_EXISTING: &str = "no_existing";

/// The passkeys the caller lists as stored (`{ rp_id, id }`), or none when it
/// says so with [`NO_EXISTING`].
fn existing_list(v: JsValue) -> Res<Vec<ExistingDto>> {
    if v.as_string().as_deref() == Some(NO_EXISTING) {
        return Ok(Vec::new());
    }
    let list: Vec<ExistingDto> = from_js_list(v)?;
    if list.is_empty() {
        return Err(Fail::Input);
    }
    Ok(list)
}

fn id_list(list: Vec<ByteBuf>) -> Vec<Vec<u8>> {
    list.into_iter().map(|b| b.0).collect()
}

#[wasm_bindgen]
impl Vault {
    /// Makes a passkey for a `navigator.credentials.create` request and seals
    /// it into an item. **Nothing is stored and nothing is released when it
    /// returns**: the answer for the page is held back, and the item is not
    /// open yet.
    ///
    /// 1. Upload the returned `item` (`{ rev, envelope, tag }`) to the
    ///    server.
    /// 2. Only when the server has accepted it, call
    ///    `passkey_create_confirm(pending)`. It returns the answer for the
    ///    page and the handle of the item, and the binding keeps nothing of
    ///    it.
    /// 3. If the upload fails or conflicts, call
    ///    `passkey_create_abort(pending)` (or just make the next passkey,
    ///    which replaces it). The page has not been answered, so no site has
    ///    a public key whose private key is nowhere.
    ///
    /// * `request` is `{ challenge, rp_id, rp_name, user_id, user_name,
    ///   user_display_name, algorithms, exclude, user_verification, prf }`.
    /// * `caller` is `{ origin, top_origin_is_same }`: the origin of the
    ///   calling frame as the browser reports it, never a value from the
    ///   page. `uv` is `{ user_present, user_verified }`.
    /// * `existing` lists the passkeys that are already stored as
    ///   `{ rp_id, id }` (take `rp_id` and `cred_id` from `item_view`), for
    ///   `excludeCredentials`. It must be given: a non-empty array, or the
    ///   named marker `"no_existing"` (`NO_EXISTING` in the client) when
    ///   there are none. An empty array is `invalid_input`. The passkeys of
    ///   the open items are always checked as well.
    /// * Without `attach_to`, a new login item named `name` is made, with the
    ///   site of the passkey as its address. With the handle of an open item,
    ///   the passkey is put into that item and nothing else of it changes;
    ///   `item_id` must then be its id. `rev` is the revision of the write.
    ///
    /// The PRF results, when the site asked for them, depend on user
    /// verification: the output for the same salt differs between a request
    /// with `user_verified` true and one with it false (spec § 9.3, as with
    /// the CTAP2 `hmac-secret` extension, which has two seeds). A site that
    /// uses the output as a key therefore needs user verification every time.
    ///
    /// Returns `{ item: { rev, envelope, tag }, item_id, pending }`.
    #[allow(clippy::too_many_arguments)]
    pub fn passkey_create(
        &mut self,
        item_id: Vec<u8>,
        rev: f64,
        name: &str,
        request: JsValue,
        caller: JsValue,
        uv: JsValue,
        existing: JsValue,
        now_ms: f64,
        attach_to: Option<u32>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let id = ItemId::from_bytes(arr(&item_id)?);
            let rev = js_u64(rev)?;
            let now = js_time(now_ms)?;
            let dto: CreateDto = from_js(request)?;
            let ctx = from_js::<CallerDto>(caller)?.core()?;
            let uv = from_js::<UvDto>(uv)?.core();
            let mut existing: Vec<ExistingCredential> = existing_list(existing)?
                .into_iter()
                .map(|e| ExistingCredential {
                    rp_id: e.rp_id,
                    cred_id: e.id,
                })
                .collect();
            let req = CreateRequest {
                challenge: dto.challenge,
                rp_id: dto.rp_id,
                rp_name: dto.rp_name,
                user_id: dto.user_id,
                user_name: dto.user_name,
                user_display_name: dto.user_display_name,
                algorithms: dto.algorithms,
                exclude: id_list(dto.exclude),
                user_verification: user_verification(&dto.user_verification)?,
                prf: dto.prf.map(|p| PrfCreate {
                    eval: p.eval.map(EvalDto::core),
                }),
                cred_props: dto.cred_props,
            };

            let inner = self.inner_mut()?;
            // The open items count as stored whatever the caller listed.
            existing.extend(inner.items.values().filter_map(|i| {
                i.body.passkey.as_ref().map(|p| ExistingCredential {
                    rp_id: p.rp_id.clone(),
                    cred_id: p.cred_id.clone(),
                })
            }));
            let created = passkey_create(&mut OsRng, &req, &ctx, uv, &existing, now)?;

            // The body the passkey goes into, and the envelope whose item key
            // is kept.
            let (mut body, envelope) = match attach_to {
                Some(h) => {
                    let open = inner.item(h)?;
                    if open.item_id != id || open.body.is_read_only() {
                        return Err(Fail::Input);
                    }
                    // A passkey that is there is not replaced silently: the
                    // old one would be lost for good.
                    if open.body.passkey.is_some() {
                        return Err(ferret_core::Error::InvalidState.into());
                    }
                    (open.body.clone(), Some(open.envelope.clone()))
                }
                None => {
                    let mut body = ItemBody::new(ItemType::Login, name, now);
                    body.urls.push(UrlEntry {
                        url: format!("https://{}", created.record.rp_id),
                        matching: UrlMatch::Host,
                        extra: Vec::new(),
                    });
                    (body, None)
                }
            };
            created.record.attach_to(&mut body);
            body.modified = now;
            let sealed = encrypt_item(
                &mut OsRng,
                &inner.vault,
                id,
                rev,
                &body,
                envelope.as_deref(),
            )?;
            let out_item = SealedDto::of(&sealed);

            let handle = inner.new_handle()?;
            // Which open item the passkey goes into, and the envelope that
            // item has now: if it changes before the confirmation, the sealed
            // item is out of date.
            let attach = attach_to.zip(envelope);
            inner.passkey = Some(PendingPasskey {
                handle,
                response: created.response,
                item: OpenItem {
                    item_id: id,
                    envelope: sealed.envelope,
                    body,
                },
                attach_to: attach,
            });
            to_js(&CreatedDto {
                item: out_item,
                item_id: *id.as_bytes(),
                pending: handle,
            })
        })
    }

    /// Releases the answer of `passkey_create` after the caller has stored
    /// the sealed item on the server. Opens the item (a new handle) or, for
    /// `attach_to`, updates the open item, and returns `{ response, handle }`.
    /// The binding keeps nothing of the passkey's answer afterwards.
    ///
    /// If the open item that the passkey was added to has been changed since
    /// `passkey_create` (the sealed item is then out of date), this is
    /// `invalid_state` and the answer stays held until `passkey_create_abort`.
    pub fn passkey_create_confirm(&mut self, pending: u32) -> Result<JsValue, JsValue> {
        run(|| {
            let inner = self.inner_mut()?;
            let waiting = inner
                .passkey
                .as_ref()
                .filter(|p| p.handle == pending)
                .ok_or(Fail::Handle)?;
            match &waiting.attach_to {
                Some((h, base)) => {
                    let open = inner.items.get(h).ok_or(Fail::Handle)?;
                    if open.envelope != *base {
                        return Err(ferret_core::Error::InvalidState.into());
                    }
                }
                None => {
                    if inner.items.len() >= MAX_OPEN {
                        return Err(ferret_core::Error::TooLarge.into());
                    }
                }
            }
            let done = inner.passkey.take().ok_or(Fail::Handle)?;
            let handle = match done.attach_to {
                Some((h, _)) => {
                    if let Some(slot) = inner.items.get_mut(&h) {
                        *slot = done.item;
                    }
                    h
                }
                None => inner.open(done.item)?,
            };
            let r = &done.response;
            to_js(&ConfirmedDto {
                response: CreateResponseDto {
                    id: Bytes(r.id.clone()),
                    attestation_object: Bytes(r.attestation_object.clone()),
                    client_data_json: Bytes(r.client_data_json.clone()),
                    authenticator_data: Bytes(r.authenticator_data.clone()),
                    public_key_spki: Bytes(r.public_key_spki.clone()),
                    alg: r.alg,
                    authenticator_attachment: r.authenticator_attachment,
                    transports: r.transports,
                    cred_props: r.cred_props.map(|c| CredPropsDto { rk: c.rk }),
                    prf: r.prf.as_ref().map(|p| CreatePrfDto {
                        enabled: p.enabled,
                        results: p.results.as_ref().map(PrfResultsDto::of),
                    }),
                },
                handle,
            })
        })
    }

    /// Drops a passkey that `passkey_create` made and that was not
    /// confirmed: the answer for the page is wiped and never released.
    pub fn passkey_create_abort(&mut self, pending: u32) -> Result<(), JsValue> {
        run(|| {
            let inner = self.inner_mut()?;
            if inner.passkey.as_ref().is_some_and(|p| p.handle == pending) {
                inner.passkey = None;
                Ok(())
            } else {
                Err(Fail::Handle)
            }
        })
    }

    /// Signs in with the passkey in the open item `handle`, for a
    /// `navigator.credentials.get` request. The RP ID of the request must be
    /// exactly the stored one. Match `allow` against the `cred_id` that
    /// `item_view` shows before asking the user.
    ///
    /// The PRF results depend on user verification: the passkey has two seeds
    /// (spec § 9.3, as the CTAP2 `hmac-secret` extension), and the one used
    /// follows `uv.user_verified`. The same salt gives different outputs with
    /// and without it, so a site that derives keys from the output needs user
    /// verification on every request.
    ///
    /// Returns `{ id, authenticator_attachment, authenticator_data,
    /// client_data_json, signature, user_handle, prf }`.
    pub fn passkey_get(
        &self,
        handle: u32,
        request: JsValue,
        caller: JsValue,
        uv: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let req = from_js::<GetDto>(request)?.core()?;
            let ctx = from_js::<CallerDto>(caller)?.core()?;
            let uv = from_js::<UvDto>(uv)?.core();
            let item = self.inner()?.item(handle)?;
            let passkey = item.body.passkey.as_ref().ok_or(Fail::Input)?;
            let record = PasskeyRecord::from_item(passkey)?;
            let r = passkey_get(&record, &req, &ctx, uv)?;
            to_js(&GetResponseDto {
                id: Bytes(r.id),
                authenticator_attachment: r.authenticator_attachment,
                authenticator_data: Bytes(r.authenticator_data),
                client_data_json: Bytes(r.client_data_json),
                signature: Bytes(r.signature),
                user_handle: Bytes(r.user_handle),
                prf: r.prf.as_ref().map(PrfResultsDto::of),
            })
        })
    }

    /// The open passkey items that may answer a `navigator.credentials.get`
    /// request, as item handles, in handle order. A passkey qualifies when its
    /// RP ID is exactly the RP ID the request resolves to and, when `allow` is
    /// not empty, its credential id is in `allow`. The core decides
    /// (`passkey_candidates_for`), after it has checked the whole request as
    /// `passkey_get` does.
    ///
    /// * `caller` is `{ origin, top_origin_is_same }`.
    /// * `request` is the request of `passkey_get`: `{ challenge, rp_id,
    ///   allow, user_verification, prf }`.
    ///
    /// An empty list is not an error. The errors do not depend on what the
    /// vault holds: `too_large`, `invalid_input`, `not_allowed` (a
    /// cross-origin caller) and `malformed_rp_id` (an RP ID the origin may
    /// not use, which the caller gives the page as `SecurityError`). This
    /// only reads: nothing is signed or written. The list is for the
    /// extension's own windows and must never reach the page.
    pub fn passkey_candidates(
        &self,
        caller: JsValue,
        request: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let req = from_js::<GetDto>(request)?.core()?;
            let ctx = from_js::<CallerDto>(caller)?.core()?;
            let inner = self.inner()?;
            let open: Vec<(u32, StoredPasskeyRef<'_>)> = inner
                .items
                .iter()
                .filter_map(|(h, i)| {
                    i.body.passkey.as_ref().map(|p| {
                        (
                            *h,
                            StoredPasskeyRef {
                                rp_id: &p.rp_id,
                                cred_id: &p.cred_id,
                            },
                        )
                    })
                })
                .collect();
            let refs: Vec<StoredPasskeyRef<'_>> = open.iter().map(|(_, r)| *r).collect();
            let found = passkey_candidates_for(&ctx, &req, &refs)?;
            let handles: Vec<u32> = found
                .into_iter()
                .filter_map(|i| open.get(i).map(|(h, _)| *h))
                .collect();
            to_js(&handles)
        })
    }

    /// The site of a request as the chooser shows it: `{ origin,
    /// host_unicode, rp_id, rp_id_unicode }`. The origin and the RP ID are the
    /// canonical forms (A-labels) that are compared and written into
    /// `clientDataJSON`; the Unicode forms are for reading, and a label that
    /// mixes scripts stays an A-label in them. The checks are those of
    /// `passkey_get`: `not_allowed` for a cross-origin caller and
    /// `malformed_rp_id` for an RP ID the origin may not use. It reads
    /// nothing from the vault; it is a method of it so that the check only
    /// runs while the vault is unlocked.
    pub fn passkey_site(&self, caller: JsValue, rp_id: Option<String>) -> Result<JsValue, JsValue> {
        run(|| {
            let ctx = from_js::<CallerDto>(caller)?.core()?;
            self.inner()?;
            let site = passkey_site(&ctx, rp_id.as_deref())?;
            to_js(&SiteDto {
                origin: &site.origin,
                host_unicode: &site.host_unicode,
                rp_id: &site.rp_id,
                rp_id_unicode: &site.rp_id_unicode,
            })
        })
    }

    /// Seals a passkey of another program into a **new** login item and
    /// returns `{ item: { rev, envelope, tag }, rp_id, notes }`. Nothing is
    /// stored and the item is not opened: upload `item` and open it with
    /// `open_item` when it is needed. The private key and the PRF seeds go
    /// from the arguments into the sealed item inside WASM; nothing of them
    /// is returned, and the arguments that hold them are wiped when the call
    /// ends.
    ///
    /// * `item_id` is 16 bytes of fresh randomness (`crypto.getRandomValues`),
    ///   not the manifest id; `rev` is the revision of the write (1 for a
    ///   new item).
    /// * `draft` is the draft of `encrypt_item` for a **new** item (it needs
    ///   `item_type` and `name`) and has no `passkey` and no `remove_passkey`
    ///   (`invalid_input`): the rest of the login (a user name, a password,
    ///   notes, addresses, a one-time-password address) is the importer's. If
    ///   the draft has no addresses, the item gets the site of the passkey
    ///   (`https://` and its RP ID).
    /// * `passkey` is `{ cred_id, rp_id, user_handle, user_name, rp_name?,
    ///   user_display_name?, created, key_pkcs8 | key_jwk, prf_seed_uv?,
    ///   prf_seed_nouv?, counter? }`. `cred_id` and `user_handle` are
    ///   `Uint8Array`s (1 to 1 023 and 1 to 64 bytes); `created` is unix
    ///   milliseconds; the key is `key_pkcs8` (a `Uint8Array`, PKCS#8 DER) or
    ///   `key_jwk` (the text of a JWK), exactly one of them, P-256 only.
    ///   The two seeds come together, only from a source whose PRF is
    ///   Ferret's formula (32 bytes each); a source with one secret gives it
    ///   twice. `counter` is the counter the source had.
    ///
    /// The core reads the RP ID as a host and stores it in canonical form,
    /// refuses a public suffix or an address, cleans the texts the site chose
    /// and writes the key in the one PKCS#8 form it uses. A passkey of the
    /// same RP ID and credential id that is in an open item is
    /// `invalid_state`. The errors are those of the core's `passkey_import`
    /// (`malformed_rp_id`, `unsupported` for a key that is not P-256,
    /// `malformed_item_body` for a key that does not read, `too_large`,
    /// `malformed_webauthn_options`).
    ///
    /// `notes` is `{ register_again, counter, prf }`: `register_again` is
    /// true when the source had a counter above 0, which a site that
    /// compares counters will refuse, so the user registers the passkey
    /// again there.
    ///
    /// Spec: Fase 1 § 9.1, § 9.6.
    pub fn passkey_import(
        &mut self,
        item_id: Vec<u8>,
        rev: f64,
        draft: JsValue,
        passkey: JsValue,
        now_ms: f64,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let id = ItemId::from_bytes(arr(&item_id)?);
            if id == ItemId::MANIFEST {
                return Err(Fail::Input);
            }
            let rev = js_u64(rev)?;
            let now = js_time(now_ms)?;
            let draft: DraftDto = from_js(draft)?;
            // Ferret's own passkeys are logins; so are the imported ones.
            if draft.touches_passkey() || !draft.is_login() {
                return Err(Fail::Input);
            }
            let dto: ImportDto = from_js(passkey)?;
            let created = js_u64(dto.created)?;
            let counter = u32::try_from(js_u64(dto.counter)?).map_err(|_| Fail::Input)?;
            let key = match (&dto.key_pkcs8, &dto.key_jwk) {
                (Some(der), None) => ImportKey::Pkcs8Der(der.as_slice()),
                (None, Some(text)) => ImportKey::JwkJson(text.as_str()),
                _ => return Err(Fail::Input),
            };
            let prf = match (&dto.prf_seed_uv, &dto.prf_seed_nouv) {
                (None, None) => ImportPrf::None,
                (Some(uv), Some(nouv)) => ImportPrf::Seeds {
                    uv: uv.as_slice(),
                    nouv: nouv.as_slice(),
                },
                _ => return Err(Fail::Input),
            };
            let input = ImportedPasskeyInput {
                cred_id: &dto.cred_id,
                rp_id: &dto.rp_id,
                user_handle: &dto.user_handle,
                user_name: &dto.user_name,
                rp_name: dto.rp_name.as_deref(),
                user_display_name: dto.user_display_name.as_deref(),
                created,
                key,
                prf,
                counter,
            };
            let (record, notes) = core_passkey_import(&input)?;
            drop(dto);

            let inner = self.inner_mut()?;
            // The same credential is not stored twice: the site has one
            // credential for it.
            let clash = inner.items.values().any(|i| {
                i.body
                    .passkey
                    .as_ref()
                    .is_some_and(|p| p.rp_id == record.rp_id && p.cred_id == record.cred_id)
            });
            if clash {
                return Err(ferret_core::Error::InvalidState.into());
            }
            let mut body = build_body(&draft, None, now)?;
            if body.urls.is_empty() {
                body.urls.push(UrlEntry {
                    url: format!("https://{}", record.rp_id),
                    matching: UrlMatch::Host,
                    extra: Vec::new(),
                });
            }
            record.attach_to(&mut body);
            body.modified = now;
            let sealed = encrypt_item(&mut OsRng, &inner.vault, id, rev, &body, None)?;
            to_js(&ImportedDto {
                item: SealedDto::of(&sealed),
                rp_id: record.rp_id.clone(),
                notes: ImportNotesDto {
                    register_again: notes.register_again,
                    counter: notes.counter,
                    prf: notes.prf,
                },
            })
        })
    }
}

/// The passkey of another program that is imported (`passkey_import`). The
/// key goes in as owned bytes (`key_pkcs8`) or text (`key_jwk`), exactly one
/// of them, and is wiped when the call ends, whatever it returns.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct ImportDto {
    #[serde(with = "bytes")]
    cred_id: Vec<u8>,
    rp_id: String,
    #[serde(with = "bytes")]
    user_handle: Vec<u8>,
    user_name: String,
    #[serde(default)]
    rp_name: Option<String>,
    #[serde(default)]
    user_display_name: Option<String>,
    /// When the passkey was made, unix milliseconds.
    created: f64,
    #[serde(default, deserialize_with = "secret_bytes::deserialize")]
    key_pkcs8: Option<Zeroizing<Vec<u8>>>,
    #[serde(default, deserialize_with = "secret_text::deserialize")]
    key_jwk: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize")]
    prf_seed_uv: Option<Zeroizing<Vec<u8>>>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize")]
    prf_seed_nouv: Option<Zeroizing<Vec<u8>>>,
    /// The signature counter of the source (0 when it has none).
    #[serde(default)]
    counter: f64,
}

impl Shaped for ImportDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("cred_id", &ANY),
        ("rp_id", &ANY),
        ("user_handle", &ANY),
        ("user_name", &ANY),
        ("rp_name", &ANY),
        ("user_display_name", &ANY),
        ("created", &ANY),
        ("key_pkcs8", &ANY),
        ("key_jwk", &ANY),
        ("prf_seed_uv", &ANY),
        ("prf_seed_nouv", &ANY),
        ("counter", &ANY),
    ]);
}

/// What `passkey_import` returns: the sealed item and what the user should be
/// told. Nothing in it is secret.
#[derive(Serialize)]
struct ImportedDto {
    item: SealedDto,
    /// The RP ID as it is stored (canonical).
    rp_id: String,
    notes: ImportNotesDto,
}

#[derive(Serialize)]
struct ImportNotesDto {
    /// The source had a counter above 0: the user registers the passkey again
    /// on sites that compare counters.
    register_again: bool,
    counter: u32,
    /// The passkey has PRF seeds.
    prf: bool,
}
/// The site of a request: public text.
#[derive(Serialize)]
struct SiteDto<'a> {
    origin: &'a str,
    host_unicode: &'a str,
    rp_id: &'a str,
    rp_id_unicode: &'a str,
}

impl Shaped for CallerDto {
    const SHAPE: Shape = Shape::Obj(&[("origin", &ANY), ("top_origin_is_same", &ANY)]);
}

impl Shaped for UvDto {
    const SHAPE: Shape = Shape::Obj(&[("user_present", &ANY), ("user_verified", &ANY)]);
}

impl Shaped for EvalDto {
    const SHAPE: Shape = Shape::Obj(&[("first", &ANY), ("second", &ANY)]);
}

impl Shaped for EvalByCredentialDto {
    const SHAPE: Shape = Shape::Obj(&[("id", &ANY), ("first", &ANY), ("second", &ANY)]);
}

impl Shaped for PrfDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("eval", &EvalDto::SHAPE),
        (
            "eval_by_credential",
            &Shape::List(&EvalByCredentialDto::SHAPE),
        ),
    ]);
}

impl Shaped for ExistingDto {
    const SHAPE: Shape = Shape::Obj(&[("rp_id", &ANY), ("id", &ANY)]);
}

impl Shaped for CreateDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("challenge", &ANY),
        ("rp_id", &ANY),
        ("rp_name", &ANY),
        ("user_id", &ANY),
        ("user_name", &ANY),
        ("user_display_name", &ANY),
        ("algorithms", &ANY),
        ("exclude", &ANY),
        ("user_verification", &ANY),
        ("prf", &PrfDto::SHAPE),
        ("cred_props", &ANY),
    ]);
}

impl Shaped for GetDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("challenge", &ANY),
        ("rp_id", &ANY),
        ("allow", &ANY),
        ("user_verification", &ANY),
        ("prf", &PrfDto::SHAPE),
    ]);
}
