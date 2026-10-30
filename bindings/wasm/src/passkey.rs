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
    ANY, SealedDto, Shape, Shaped, arr, b16, b32, bytes, from_js, from_js_list, js_time, js_u64,
    opt_bytes, to_js,
};
use crate::error::{Fail, Res, run};
use crate::item::Bytes;
use crate::vault::{OpenItem, Vault};
use ferret_core::passkey::{PrfCreate, PrfEval, PrfRequest, PrfResults};
use ferret_core::{
    CallerContext, CreateRequest, ExistingCredential, GetRequest, ItemBody, ItemId, ItemType,
    OsRng, PasskeyRecord, UrlEntry, UrlMatch, UserVerification, UvOutcome, canonical_origin,
    encrypt_item, passkey_create, passkey_get,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

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
struct ByteBuf(#[serde(with = "bytes")] Vec<u8>);

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

#[derive(Serialize)]
struct CreateResponseDto {
    id: Bytes,
    attestation_object: Bytes,
    client_data_json: Bytes,
    authenticator_data: Bytes,
    public_key_spki: Bytes,
    alg: i64,
    prf: Option<CreatePrfDto>,
}

#[derive(Serialize)]
struct GetResponseDto {
    id: Bytes,
    authenticator_data: Bytes,
    client_data_json: Bytes,
    signature: Bytes,
    user_handle: Bytes,
    prf: Option<PrfResultsDto>,
}

#[derive(Serialize)]
struct CreatedDto {
    response: CreateResponseDto,
    item: SealedDto,
    #[serde(with = "b16")]
    item_id: [u8; 16],
}

fn id_list(list: Vec<ByteBuf>) -> Vec<Vec<u8>> {
    list.into_iter().map(|b| b.0).collect()
}

#[wasm_bindgen]
impl Vault {
    /// Makes a passkey for a `navigator.credentials.create` request and
    /// stores it in an item, in one step: the passkey is not given to the
    /// page unless it was sealed first.
    ///
    /// * `request` is `{ challenge, rp_id, rp_name, user_id, user_name,
    ///   user_display_name, algorithms, exclude, user_verification, prf }`.
    /// * `caller` is `{ origin, top_origin_is_same }`: the origin of the
    ///   calling frame as the browser reports it, never a value from the
    ///   page. `uv` is `{ user_present, user_verified }`.
    /// * `existing` lists the passkeys that are already stored as
    ///   `{ rp_id, id }`, for `excludeCredentials`.
    /// * Without `attach_to`, a new login item named `name` is made, with the
    ///   site of the passkey as its address. With the handle of an open item,
    ///   the passkey is put into that item and nothing else of it changes;
    ///   `item_id` must then be its id. `rev` is the revision of the write.
    ///
    /// Returns `{ response, item: { rev, envelope, tag }, item_id }`.
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
            let existing: Vec<ExistingDto> = from_js_list(existing)?;
            let existing: Vec<ExistingCredential> = existing
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
            };

            let inner = self.inner_mut()?;
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

            let r = &created.response;
            let out = to_js(&CreatedDto {
                response: CreateResponseDto {
                    id: Bytes(r.id.clone()),
                    attestation_object: Bytes(r.attestation_object.clone()),
                    client_data_json: Bytes(r.client_data_json.clone()),
                    authenticator_data: Bytes(r.authenticator_data.clone()),
                    public_key_spki: Bytes(r.public_key_spki.clone()),
                    alg: r.alg,
                    prf: r.prf.as_ref().map(|p| CreatePrfDto {
                        enabled: p.enabled,
                        results: p.results.as_ref().map(PrfResultsDto::of),
                    }),
                },
                item: SealedDto::of(&sealed),
                item_id: *id.as_bytes(),
            })?;

            match attach_to {
                Some(h) => {
                    if let Some(open) = inner.items.get_mut(&h) {
                        open.envelope = sealed.envelope;
                        open.body = body;
                    }
                }
                None => {
                    inner.open(OpenItem {
                        item_id: id,
                        envelope: sealed.envelope,
                        body,
                    })?;
                }
            }
            Ok(out)
        })
    }

    /// Signs in with the passkey in the open item `handle`, for a
    /// `navigator.credentials.get` request. The RP ID of the request must be
    /// exactly the stored one. Returns `{ id, authenticator_data,
    /// client_data_json, signature, user_handle, prf }`.
    pub fn passkey_get(
        &self,
        handle: u32,
        request: JsValue,
        caller: JsValue,
        uv: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let dto: GetDto = from_js(request)?;
            let ctx = from_js::<CallerDto>(caller)?.core()?;
            let uv = from_js::<UvDto>(uv)?.core();
            let req = GetRequest {
                challenge: dto.challenge,
                rp_id: dto.rp_id,
                allow: id_list(dto.allow),
                user_verification: user_verification(&dto.user_verification)?,
                prf: dto.prf.map(|p| PrfRequest {
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
            };
            let item = self.inner()?.item(handle)?;
            let passkey = item.body.passkey.as_ref().ok_or(Fail::Input)?;
            let record = PasskeyRecord::from_item(passkey)?;
            let r = passkey_get(&record, &req, &ctx, uv)?;
            to_js(&GetResponseDto {
                id: Bytes(r.id),
                authenticator_data: Bytes(r.authenticator_data),
                client_data_json: Bytes(r.client_data_json),
                signature: Bytes(r.signature),
                user_handle: Bytes(r.user_handle),
                prf: r.prf.as_ref().map(PrfResultsDto::of),
            })
        })
    }
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
