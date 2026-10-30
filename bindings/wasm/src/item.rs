//! Items in WASM memory: the redacted view, the draft that JavaScript sends,
//! and how a draft is merged into the body that is already there.
//!
//! JavaScript never holds a decrypted body. It holds a number (the handle of
//! an open item), gets a view without secrets, and asks for one secret at a
//! time. When it saves, it sends a **draft**: only what the user changed. On
//! an edit, the binding starts from the open body and applies the draft, so a
//! private key, a PRF seed, a TOTP secret, a hidden field that was not
//! touched, and every key this version does not know, stay as they were and
//! never go through JavaScript.

use crate::convert::{ANY, Shape, Shaped, bytes};
use crate::error::{Fail, Res};
use ferret_core::item::view::ItemView;
use ferret_core::{Field, FieldKind, ItemBody, ItemType, Totp, UrlEntry, UrlMatch, parse_otpauth};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The most custom fields and addresses one draft may carry.
const MAX_FIELDS: usize = 1_000;
const MAX_URLS: usize = 100;

// ------------------------------------------------------------------ view

#[derive(Serialize)]
struct FieldViewDto<'a> {
    id: &'a str,
    label: &'a str,
    kind: &'a str,
    /// `null` for a field that is hidden by default.
    value: Option<&'a str>,
}

#[derive(Serialize)]
struct UrlViewDto<'a> {
    url: &'a str,
    matching: &'a str,
}

/// The public side of a passkey. `cred_id` and `user_handle` are not secret
/// (the relying party has both); they are what a caller needs to build
/// `excludeCredentials` and to match `allowCredentials`.
#[derive(Serialize)]
struct PasskeyViewDto<'a> {
    rp_id: &'a str,
    user_name: &'a str,
    created: u64,
    has_prf: bool,
    #[serde(with = "bytes")]
    cred_id: &'a [u8],
    #[serde(with = "bytes")]
    user_handle: &'a [u8],
}

/// What JavaScript may see of an item: no private key, no PRF seed, no TOTP
/// address, no note and no value of a hidden field.
#[derive(Serialize)]
pub(crate) struct ViewDto<'a> {
    item_type: &'a str,
    name: &'a str,
    fields: Vec<FieldViewDto<'a>>,
    urls: Vec<UrlViewDto<'a>>,
    has_totp: bool,
    passkey: Option<PasskeyViewDto<'a>>,
    has_notes: bool,
    created: u64,
    modified: u64,
    favorite: bool,
    device: Option<&'a str>,
    read_only: bool,
}

impl<'a> ViewDto<'a> {
    /// The view of `v`, the redacted view of `body`. The public ids of the
    /// passkey are read from the body, which is the only place that has them.
    pub(crate) fn of(v: &'a ItemView, body: &'a ItemBody) -> Self {
        const NONE: &[u8] = &[];
        let (cred_id, user_handle) = body.passkey.as_ref().map_or((NONE, NONE), |p| {
            (p.cred_id.as_slice(), p.user_handle.as_slice())
        });
        Self {
            item_type: &v.item_type,
            name: &v.name,
            fields: v
                .fields
                .iter()
                .map(|f| FieldViewDto {
                    id: &f.id,
                    label: &f.label,
                    kind: &f.kind,
                    value: f.value.as_deref(),
                })
                .collect(),
            urls: v
                .urls
                .iter()
                .map(|u| UrlViewDto {
                    url: &u.url,
                    matching: &u.matching,
                })
                .collect(),
            has_totp: v.has_totp,
            passkey: v.passkey.as_ref().map(|p| PasskeyViewDto {
                rp_id: &p.rp_id,
                user_name: &p.user_name,
                created: p.created,
                has_prf: p.has_prf,
                cred_id,
                user_handle,
            }),
            has_notes: v.has_notes,
            created: v.created,
            modified: v.modified,
            favorite: v.favorite,
            device: v.device.as_deref(),
            read_only: v.read_only,
        }
    }
}

// ----------------------------------------------------------------- draft

/// A custom field of a draft. On an edit, a missing `label`, `kind` or
/// `value` is what the field with the same `id` has now.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct FieldDraft {
    id: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

/// An address of a draft.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct UrlDraft {
    url: String,
    #[serde(default)]
    matching: Option<String>,
}

/// The one-time-password setup of a draft: an `otpauth://` address.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpDraft {
    uri: String,
}

/// The part of a passkey that the user may edit: its name. The key, the
/// credential id and the seeds cannot be sent in, only kept.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyDraft {
    user_name: String,
}

/// What JavaScript sends when it saves an item.
///
/// A key that is missing means "as it is now" on an edit and "empty" on a new
/// item. To remove the one-time-password setup, the notes or the passkey, set
/// `remove_totp`, `remove_notes` or `remove_passkey`. There is no key for a
/// private key, a PRF seed or a TOTP secret apart from the address.
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(crate) struct DraftDto {
    #[serde(default)]
    item_type: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    fields: Option<Vec<FieldDraft>>,
    #[serde(default)]
    urls: Option<Vec<UrlDraft>>,
    #[serde(default)]
    totp: Option<TotpDraft>,
    #[serde(default)]
    remove_totp: bool,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    remove_notes: bool,
    #[serde(default)]
    favorite: Option<bool>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    passkey: Option<PasskeyDraft>,
    #[serde(default)]
    remove_passkey: bool,
}

fn field_kind(text: Option<&String>, previous: Option<&FieldKind>) -> FieldKind {
    match (text, previous) {
        (Some(t), _) => FieldKind::from_text(t.clone()),
        (None, Some(p)) => p.clone(),
        (None, None) => FieldKind::Text,
    }
}

/// The body that results from `draft`.
///
/// * `existing` is the open body of the item being edited, or `None` for a
///   new item (then `item_type` and `name` are required). Nothing in
///   `existing` is read back by JavaScript: the starting point of an edit is
///   a copy of it inside WASM.
/// * `now_ms` is the time of the write: `created` and `modified` of a new
///   item, `modified` of an edit.
///
/// A body from a newer schema is `read_only_schema`. A TOTP address that
/// does not parse is the error of `parse_otpauth` and is refused before
/// anything is sealed.
pub(crate) fn build_body(
    draft: &DraftDto,
    existing: Option<&ItemBody>,
    now_ms: u64,
) -> Res<ItemBody> {
    let mut body = match existing {
        Some(prev) => {
            if prev.is_read_only() {
                return Err(ferret_core::Error::ReadOnlySchema.into());
            }
            prev.clone()
        }
        None => {
            let item_type = draft.item_type.as_ref().ok_or(Fail::Input)?;
            let name = draft.name.as_ref().ok_or(Fail::Input)?;
            ItemBody::new(ItemType::from_text(item_type.clone()), name.clone(), now_ms)
        }
    };
    if let Some(t) = &draft.item_type {
        body.item_type = ItemType::from_text(t.clone());
    }
    if let Some(n) = &draft.name {
        body.name.clone_from(n);
    }
    if let Some(f) = draft.favorite {
        body.favorite = f;
    }
    if let Some(d) = &draft.device {
        body.device = Some(d.clone());
    }

    if let Some(list) = &draft.fields {
        if list.len() > MAX_FIELDS {
            return Err(ferret_core::Error::TooLarge.into());
        }
        let mut fields: Vec<Field> = Vec::with_capacity(list.len());
        for f in list {
            if fields.iter().any(|g| g.id == f.id) {
                return Err(Fail::Input);
            }
            let prev = body.fields.iter().find(|g| g.id == f.id);
            fields.push(Field {
                id: f.id.clone(),
                label: f
                    .label
                    .clone()
                    .or_else(|| prev.map(|p| p.label.clone()))
                    .unwrap_or_default(),
                kind: field_kind(f.kind.as_ref(), prev.map(|p| &p.kind)),
                value: f
                    .value
                    .clone()
                    .or_else(|| prev.map(|p| p.value.clone()))
                    .unwrap_or_default(),
                extra: prev.map(|p| p.extra.clone()).unwrap_or_default(),
            });
        }
        body.fields = fields;
    }

    if let Some(list) = &draft.urls {
        if list.len() > MAX_URLS {
            return Err(ferret_core::Error::TooLarge.into());
        }
        let urls = list
            .iter()
            .map(|u| UrlEntry {
                url: u.url.clone(),
                matching: u
                    .matching
                    .as_ref()
                    .map_or(UrlMatch::Host, |m| UrlMatch::from_text(m.clone())),
                extra: body
                    .urls
                    .iter()
                    .find(|p| p.url == u.url)
                    .map(|p| p.extra.clone())
                    .unwrap_or_default(),
            })
            .collect();
        body.urls = urls;
    }

    if draft.remove_totp && draft.totp.is_some() {
        return Err(Fail::Input);
    }
    if draft.remove_totp {
        body.totp = None;
    } else if let Some(t) = &draft.totp {
        let uri = normalize_otpauth(&t.uri)?;
        parse_otpauth(&uri)?;
        let extra = body
            .totp
            .as_ref()
            .map(|p| p.extra.clone())
            .unwrap_or_default();
        body.totp = Some(Totp { uri, extra });
    }

    if draft.remove_notes && draft.notes.is_some() {
        return Err(Fail::Input);
    }
    if draft.remove_notes {
        body.notes = None;
    } else if let Some(n) = &draft.notes {
        body.notes = Some(n.clone());
    }

    if draft.remove_passkey && draft.passkey.is_some() {
        return Err(Fail::Input);
    }
    if draft.remove_passkey {
        body.passkey = None;
    } else if let Some(p) = &draft.passkey {
        // Only the name of a passkey that is there can be changed.
        let pk = body.passkey.as_mut().ok_or(Fail::Input)?;
        pk.user_name.clone_from(&p.user_name);
    }

    body.modified = now_ms;
    Ok(body)
}

// ------------------------------------------------------- otpauth address

/// Trims an `otpauth://` address and makes it acceptable to the strict
/// parser: the algorithm name may be written in any case (`sha1`), and the
/// issuer loses the spaces around it. Everything else is the parser's to
/// judge (a parameter that is not on its list, a repeated one, bad base32).
///
/// The core's rules do not change; this is the glue's reading of what a
/// user pastes.
pub(crate) fn normalize_otpauth(uri: &str) -> Res<String> {
    let uri = uri.trim();
    let Some((head, query)) = uri.split_once('?') else {
        return Ok(uri.to_owned());
    };
    let mut parts: Vec<String> = Vec::new();
    for pair in query.split('&') {
        match pair.split_once('=') {
            Some(("algorithm", value)) => {
                let upper = value.to_ascii_uppercase();
                let known = matches!(upper.as_str(), "SHA1" | "SHA256" | "SHA512");
                parts.push(format!(
                    "algorithm={}",
                    if known { upper.as_str() } else { value }
                ));
            }
            Some(("issuer", value)) => {
                let decoded = percent_decode_plus(value)?;
                parts.push(format!("issuer={}", percent_encode(decoded.trim())));
            }
            _ => parts.push(pair.to_owned()),
        }
    }
    Ok(format!("{head}?{}", parts.join("&")))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// A query value, percent-decoded, with `+` as a space. A bad escape or bytes
/// that are not UTF-8 are `invalid_input`.
fn percent_decode_plus(s: &str) -> Res<String> {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'+' => {
                out.push(b' ');
                i = i.saturating_add(1);
            }
            b'%' => {
                let hi = bytes.get(i.saturating_add(1)).copied().and_then(hex_val);
                let lo = bytes.get(i.saturating_add(2)).copied().and_then(hex_val);
                match (hi, lo) {
                    (Some(hi), Some(lo)) => out.push((hi << 4) | lo),
                    _ => return Err(Fail::Input),
                }
                i = i.saturating_add(3);
            }
            _ => {
                out.push(b);
                i = i.saturating_add(1);
            }
        }
    }
    String::from_utf8(out).map_err(|_| Fail::Input)
}

/// Everything but `A-Z a-z 0-9 - . _ ~` as `%XX` (upper-case hex).
fn percent_encode(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(
                HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
            ));
            out.push(char::from(
                HEX.get(usize::from(b & 15)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

/// A passkey record or other value that carries bytes, for the passkey
/// responses.
#[derive(Serialize)]
pub(crate) struct Bytes(#[serde(with = "bytes")] pub(crate) Vec<u8>);

impl Shaped for FieldDraft {
    const SHAPE: Shape = Shape::Obj(&[
        ("id", &ANY),
        ("label", &ANY),
        ("kind", &ANY),
        ("value", &ANY),
    ]);
}

impl Shaped for UrlDraft {
    const SHAPE: Shape = Shape::Obj(&[("url", &ANY), ("matching", &ANY)]);
}

impl Shaped for TotpDraft {
    const SHAPE: Shape = Shape::Obj(&[("uri", &ANY)]);
}

impl Shaped for PasskeyDraft {
    const SHAPE: Shape = Shape::Obj(&[("user_name", &ANY)]);
}

impl Shaped for DraftDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("item_type", &ANY),
        ("name", &ANY),
        ("fields", &Shape::List(&FieldDraft::SHAPE)),
        ("urls", &Shape::List(&UrlDraft::SHAPE)),
        ("totp", &TotpDraft::SHAPE),
        ("remove_totp", &ANY),
        ("notes", &ANY),
        ("remove_notes", &ANY),
        ("favorite", &ANY),
        ("device", &ANY),
        ("passkey", &PasskeyDraft::SHAPE),
        ("remove_passkey", &ANY),
    ]);
}
