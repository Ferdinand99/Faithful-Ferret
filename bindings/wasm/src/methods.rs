//! The list of unlock methods: comparing it with the server's list, and
//! adding or removing a method.
//!
//! The manifest is the user's own record of the methods (sealed with the
//! vault key). The server also keeps a list, and a server that lies about it
//! is found by comparing the two (`check_server_methods`). A change of the
//! list is a new manifest row and a request that the vault key signs; the
//! calls here make both, and the caller sends them in one request:
//!
//! ```text
//! add:     wrap_prf(...)                       -> wrap
//!          manifest_add_method(current, wrap)  -> { op, sealed, body, pk_a }
//!          auth_sign(op, nonce, body)          -> signature
//! remove:  manifest_remove_method(current, id) -> { op, sealed, body, pk_a }
//!          auth_sign(op, nonce, body)          -> signature
//! ```
//!
//! `current` is the manifest row the server holds, `{ rev, envelope, tag }`;
//! the new row gets `rev + 1`.

use crate::convert::{ANY, RowDto, SealedDto, Shape, Shaped, WrapDto, arr, b16, b32, bytes};
use crate::convert::{from_js, from_js_list, to_js};
use crate::error::{Res, run};
use crate::vault::Vault;
use ferret_core::{
    CurrentManifest, MethodChange, MethodId, OsRng, ServerMethod, check_server_methods,
    decrypt_manifest, manifest_add_method, manifest_remove_method,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// One method as the server lists it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerMethodDto {
    method_type: u8,
    #[serde(with = "b16")]
    method_id: [u8; 16],
    kek_generation: u64,
}

/// A change of the method list: what to send and what to sign.
#[derive(Serialize)]
struct MethodChangeDto {
    /// The operation name for `auth_sign`.
    op: &'static str,
    /// The new manifest row.
    sealed: SealedDto,
    /// The body of the request, which `auth_sign` signs.
    #[serde(with = "bytes")]
    body: Vec<u8>,
    /// `pk_a`, the public key the server verifies the signature with.
    #[serde(with = "b32")]
    pk_a: [u8; 32],
}

impl MethodChangeDto {
    fn of(change: &MethodChange) -> Self {
        Self {
            op: change.op.name(),
            sealed: SealedDto::of(&change.sealed),
            body: change.body.clone(),
            pk_a: change.pk_a,
        }
    }
}

#[wasm_bindgen]
impl Vault {
    /// Compares the server's list of unlock methods with the manifest `row`
    /// (`{ rev, envelope, tag }`, opened here with the vault key). `server`
    /// is a list of `{ method_type, method_id, kek_generation }`. The lists
    /// agree when every server method is in the manifest with the same type,
    /// id and generation and the manifest lists nothing the server lacks;
    /// otherwise the first difference is `method_list_unknown`,
    /// `method_list_changed` or `method_list_missing`. Call it after every
    /// unlock and warn the user on any of them. The local PIN and device
    /// wraps are in neither list.
    pub fn check_server_methods(&self, row: JsValue, server: JsValue) -> Result<(), JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let row: RowDto = from_js(row)?;
            let list: Vec<ServerMethodDto> = from_js_list(server)?;
            let manifest = decrypt_manifest(vault, row.rev, &row.envelope, &row.tag)?;
            let server: Vec<ServerMethod> = list
                .iter()
                .map(|s| ServerMethod {
                    method_type: s.method_type,
                    method_id: MethodId::from_bytes(s.method_id),
                    kek_generation: s.kek_generation,
                })
                .collect();
            Ok(check_server_methods(&manifest, &server)?)
        })
    }

    /// Adds a passkey (PRF) wrap to the manifest. `current` is the manifest
    /// row the server holds; `wrap` is the record that `wrap_prf` returned.
    /// Returns `{ op, sealed, body, pk_a }`: send `sealed` and `body`, signed
    /// with `auth_sign(op, nonce, body)`.
    pub fn manifest_add_method(&self, current: JsValue, wrap: JsValue) -> Result<JsValue, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let row: RowDto = from_js(current)?;
            let wrap = from_js::<WrapDto>(wrap)?.core()?;
            let change = manifest_add_method(
                &mut OsRng,
                vault,
                &CurrentManifest {
                    rev: row.rev,
                    envelope: &row.envelope,
                    tag: &row.tag,
                },
                wrap,
            )?;
            to_js(&MethodChangeDto::of(&change))
        })
    }

    /// Removes an unlock method from the manifest. The last `password` and
    /// the last `recovery` method are refused (`input_last_method`).
    /// `current` is the manifest row the server holds. Returns `{ op, sealed,
    /// body, pk_a }` as `manifest_add_method` does.
    pub fn manifest_remove_method(
        &self,
        current: JsValue,
        method_id: Vec<u8>,
    ) -> Result<JsValue, JsValue> {
        run(|| {
            let vault = self.unlocked()?;
            let row: RowDto = from_js(current)?;
            let id: Res<[u8; 16]> = arr(&method_id);
            let change = manifest_remove_method(
                &mut OsRng,
                vault,
                &CurrentManifest {
                    rev: row.rev,
                    envelope: &row.envelope,
                    tag: &row.tag,
                },
                &MethodId::from_bytes(id?),
            )?;
            to_js(&MethodChangeDto::of(&change))
        })
    }
}

impl Shaped for ServerMethodDto {
    const SHAPE: Shape = Shape::Obj(&[
        ("method_type", &ANY),
        ("method_id", &ANY),
        ("kek_generation", &ANY),
    ]);
}
