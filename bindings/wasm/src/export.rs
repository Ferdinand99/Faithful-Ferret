//! Export and import files.
//!
//! The slow step of both, Argon2id with up to 512 MiB (plan U15), runs in a
//! short-lived **job worker** so that the vault worker's heap does not grow
//! to the size of the largest import until it is locked:
//!
//! ```text
//! export:  vault.export_begin(rows, created_at)   -> { salt, kdf }
//!          argon2_export_key(pw, salt, kdf, ...)  -> K_exp          (job worker)
//!          vault.export_finish(K_exp)             -> file
//! import:  import_header(file)                    -> { salt, kdf, created_at }
//!          argon2_export_key(pw, salt, kdf, ...)  -> K_exp          (job worker)
//!          vault.import_open(file, K_exp)         -> { count, created_at }
//!          vault.import_view(i) / vault.import_seal(i, new_id, rev)
//! ```
//!
//! `K_exp` is not a vault key: it only opens the wrapped content key of the
//! one file it was made for. It crosses JavaScript once, between the two
//! workers, and the client wipes it after it has sent it. The password goes
//! only to the job worker. The items of an import stay in WASM memory: the
//! interface gets a redacted view of each, and `import_seal` encrypts one
//! into the vault without it passing through JavaScript.

use crate::convert::{
    ANY, KdfDto, SealedDto, Shape, Shaped, arr, b16, b32, bytes, from_js, from_js_list, js_time,
    js_u64, to_js,
};
use crate::error::{Fail, Res, run};
use crate::item::ViewDto;
use crate::vault::Vault;
use ferret_core::{
    EXPORT_KDF, ExportItem, ExportPassword, ExportWrapKey, ItemId, MasterPassword, OsRng,
    PlainExportOptions, decrypt_item, encrypt_item, export_begin, export_plain_csv,
    export_plain_json, export_wrap_key, import_decrypt_with_key, import_prepare,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// A row the server holds, for an export.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRowDto {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    rev: u64,
    #[serde(with = "bytes")]
    envelope: Vec<u8>,
    #[serde(with = "b32")]
    tag: [u8; 32],
}

#[derive(Serialize)]
struct BeginDto {
    #[serde(with = "b16")]
    salt: [u8; 16],
    kdf: KdfDto,
}

#[derive(Serialize)]
struct HeaderDto {
    #[serde(with = "b16")]
    salt: [u8; 16],
    kdf: KdfDto,
    created_at: u64,
}

#[derive(Serialize)]
struct OpenedDto {
    count: usize,
    created_at: u64,
}

#[derive(Serialize)]
struct ImportViewDto<'a> {
    #[serde(with = "b16")]
    item_id: [u8; 16],
    view: ViewDto<'a>,
}

/// Opens the rows and makes them export items.
fn items_of(vault: &Vault, rows: JsValue) -> Res<Vec<ExportItem>> {
    let rows: Vec<ExportRowDto> = from_js_list(rows)?;
    let unlocked = vault.unlocked()?;
    let mut items = Vec::with_capacity(rows.len());
    for r in &rows {
        let id = ItemId::from_bytes(r.item_id);
        let decoded = decrypt_item(unlocked, id, r.rev, &r.envelope, &r.tag)?;
        items.push(ExportItem {
            item_id: id,
            body: decoded.body,
        });
    }
    Ok(items)
}

/// The slow step of an export or an import: `K_exp` for a password, the salt
/// of the file and its Argon2id parameters. It is the **only** function the
/// job worker calls, and its result is the one byte array of the binding that
/// is a key; it is listed with this reason in the export test.
///
/// * `mode` is `"write"` (an export; `master_password` is required, and an
///   export password equal to it is refused) or `"open"` (an import; no
///   minimum length and no comparison).
/// * `kdf` is checked against the floor and the 512 MiB ceiling before any
///   memory is reserved.
#[wasm_bindgen]
pub fn argon2_export_key(
    password: Vec<u8>,
    salt: Vec<u8>,
    kdf: JsValue,
    mode: &str,
    master_password: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsValue> {
    run(|| {
        let password = Zeroizing::new(password);
        let master_password = master_password.map(Zeroizing::new);
        let kdf: KdfDto = from_js(kdf)?;
        let pw = match (mode, &master_password) {
            ("write", Some(mp)) => {
                ExportPassword::new_checked(&password, &MasterPassword::for_unlock(mp)?)?
            }
            ("open", None) => ExportPassword::for_open(&password)?,
            _ => return Err(Fail::Input),
        };
        let key = export_wrap_key(&pw, &arr::<16>(&salt)?, kdf.core())?;
        Ok(key.to_bytes().to_vec())
    })
}

/// The header of an export file: its salt, Argon2id parameters and date. The
/// structure, the floor, the 512 MiB ceiling and the length of the file are
/// checked before this returns, and nothing is computed from a password.
#[wasm_bindgen]
pub fn import_header(file: &[u8]) -> Result<JsValue, JsValue> {
    run(|| {
        let h = import_prepare(file)?;
        to_js(&HeaderDto {
            salt: h.salt,
            kdf: KdfDto::of(h.kdf),
            created_at: h.created_at,
        })
    })
}

#[wasm_bindgen]
impl Vault {
    /// First half of an encrypted export. `rows` are the items to write, each
    /// `{ item_id, rev, envelope, tag }`; they are opened here. The file is
    /// written with 256 MiB, 3 passes (`kdf` may be given to write it with
    /// more). Returns `{ salt, kdf }` for `argon2_export_key`.
    pub fn export_begin(
        &mut self,
        rows: JsValue,
        created_at: f64,
        kdf: JsValue,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let created = js_time(created_at)?;
            let params = if kdf.is_undefined() || kdf.is_null() {
                EXPORT_KDF
            } else {
                from_js::<KdfDto>(kdf)?.core()
            };
            let items = items_of(self, rows)?;
            let draft = export_begin(&mut OsRng, params, created, &items)?;
            let out = BeginDto {
                salt: *draft.salt(),
                kdf: KdfDto::of(draft.kdf()),
            };
            let value = to_js(&out)?;
            self.inner_mut()?.export = Some(draft);
            Ok(value)
        })
    }

    /// Second half of an encrypted export: seals the file with the `K_exp`
    /// that the job worker made. Returns the file.
    pub fn export_finish(&mut self, wrap_key: Vec<u8>) -> Result<Vec<u8>, JsValue> {
        run(|| {
            let wrap_key = Zeroizing::new(wrap_key);
            let draft = self.inner_mut()?.export.take().ok_or(Fail::Input)?;
            let key = ExportWrapKey::from_slice(&wrap_key)?;
            Ok(draft.finish(&mut OsRng, &key)?)
        })
    }

    /// Drops an export that was begun and not finished.
    pub fn export_abort(&mut self) -> Result<(), JsValue> {
        run(|| {
            self.inner_mut()?.export = None;
            Ok(())
        })
    }

    /// A plaintext export of the rows, `"json"` or `"csv"`, on an explicit
    /// request by the user. It holds every secret in the clear. The passkey
    /// keys and PRF seeds are in the JSON only with `include_passkeys`.
    pub fn reveal_plain_export(
        &self,
        rows: JsValue,
        format: &str,
        include_passkeys: bool,
    ) -> Result<String, JsValue> {
        run(|| {
            let items = items_of(self, rows)?;
            let options = PlainExportOptions { include_passkeys };
            Ok(match format {
                "json" => export_plain_json(&items, &options)?,
                "csv" => export_plain_csv(&items, &options)?,
                _ => return Err(Fail::Input),
            })
        })
    }

    /// Second half of an import: opens `file` with the `K_exp` that the job
    /// worker made for its header and keeps the items inside WASM. Returns
    /// `{ count, created_at }`. A wrong password and any changed byte are
    /// `decrypt`.
    pub fn import_open(&mut self, file: &[u8], wrap_key: Vec<u8>) -> Result<JsValue, JsValue> {
        run(|| {
            let wrap_key = Zeroizing::new(wrap_key);
            let header = import_prepare(file)?;
            let key = ExportWrapKey::from_slice(&wrap_key)?;
            let items = import_decrypt_with_key(&key, file)?;
            let out = to_js(&OpenedDto {
                count: items.len(),
                created_at: header.created_at,
            })?;
            self.inner_mut()?.import = Some(items);
            Ok(out)
        })
    }

    /// The imported item number `index` as `{ item_id, view }`, without its
    /// secrets.
    pub fn import_view(&self, index: u32) -> Result<JsValue, JsValue> {
        run(|| {
            let items = self.inner()?.import.as_ref().ok_or(Fail::Input)?;
            let item = items
                .get(usize::try_from(index).map_err(|_| Fail::Input)?)
                .ok_or(Fail::Input)?;
            let view = item.body.view();
            to_js(&ImportViewDto {
                item_id: *item.item_id.as_bytes(),
                view: ViewDto::of(&view),
            })
        })
    }

    /// Encrypts the imported item number `index` into the vault as a new item
    /// with the id `item_id` at revision `rev`, without it passing through
    /// JavaScript. Returns `{ rev, envelope, tag }`.
    pub fn import_seal(
        &mut self,
        index: u32,
        item_id: Vec<u8>,
        rev: f64,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let id = ItemId::from_bytes(arr(&item_id)?);
            let rev = js_u64(rev)?;
            let inner = self.inner_mut()?;
            let items = inner.import.as_ref().ok_or(Fail::Input)?;
            let item = items
                .get(usize::try_from(index).map_err(|_| Fail::Input)?)
                .ok_or(Fail::Input)?;
            let sealed = encrypt_item(&mut OsRng, &inner.vault, id, rev, &item.body, None)?;
            to_js(&SealedDto::of(&sealed))
        })
    }

    /// Drops the imported items (and wipes them).
    pub fn import_close(&mut self) -> Result<(), JsValue> {
        run(|| {
            self.inner_mut()?.import = None;
            Ok(())
        })
    }
}

impl Shaped for ExportRowDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("item_id", &ANY),
        ("rev", &ANY),
        ("envelope", &ANY),
        ("tag", &ANY),
    ]);
}
