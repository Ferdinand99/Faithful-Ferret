//! `GET /api/vault/unlock-methods`: the wraps of the vault key, the public key
//! `pk_a`, the key epoch and the manifest row. Spec: Fase 1 § 4.6.
//!
//! Only a full session reaches this route (the extractor refuses the others),
//! and the account is the session's own: there is no id in the path.

use axum::extract::{FromRef, State};
use axum::routing::get;
use axum::{Json, Router};

use super::store::{self, MethodRow, MethodsView};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultSession};
use crate::state::VaultDb;
use crate::wire::{MethodsRes, SealedRowJson, WrapJson};

/// The unlock methods route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
{
    Router::new().route("/api/vault/unlock-methods", get(get_methods))
}

/// The wraps, `pk_a`, the key epoch and the manifest row of the session's
/// account.
async fn get_methods(
    session: VaultSession,
    State(db): State<VaultDb>,
) -> Result<Json<MethodsRes>, ApiError> {
    let account = session.account;
    let view = db
        .with_conn(move |conn| store::methods_view(conn, &account))
        .await?;
    Ok(Json(methods_res(view)?))
}

/// The wire shape of a [`MethodsView`]. A row the store holds in a shape the
/// wire cannot carry (a manifest that is a tombstone, a PRF salt that is not 32
/// bytes) is an inconsistent database: 500, with nothing in the answer.
fn methods_res(view: MethodsView) -> Result<MethodsRes, ApiError> {
    let methods = view
        .methods
        .into_iter()
        .map(wrap_json)
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = view.manifest;
    let (Some(envelope), Some(tag), false) = (manifest.blob, manifest.tag, manifest.deleted) else {
        return Err(inconsistent("the manifest row is not live"));
    };
    Ok(MethodsRes {
        methods,
        pk_a: view.pk_a,
        vk_epoch: view.vk_epoch,
        manifest: SealedRowJson {
            rev: manifest.rev,
            envelope,
            tag,
        },
    })
}

fn wrap_json(row: MethodRow) -> Result<WrapJson, ApiError> {
    let prf_salt = row
        .prf_salt
        .map(<[u8; 32]>::try_from)
        .transpose()
        .map_err(|_| inconsistent("a PRF salt is not 32 bytes"))?;
    Ok(WrapJson {
        method_id: *row.method_id.as_bytes(),
        method_type: row.method_type,
        kek_generation: u64::from(row.kek_generation),
        wrap: row.wrap,
        credential_id: row.credential_id,
        prf_salt,
    })
}

fn inconsistent(why: &'static str) -> ApiError {
    ApiError::from(StoreError::Invalid(why))
}
