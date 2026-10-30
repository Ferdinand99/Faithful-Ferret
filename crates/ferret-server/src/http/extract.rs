//! The session extractors: the only code that knows the kit's cookie key.
//!
//! A route takes [`VaultSession`] (vault listener) or [`AdminSession`] (admin
//! listener). The extractor needs Ferret's `__Host-ferret_sid` cookie to match
//! a row that is not revoked, belongs to the listener, has the scope `full` and
//! is within its limits, and the kit's signed cookie to agree with the row's
//! user and `issued_at` and with the kit's `session_version`. Anything else is
//! the one answer `401 {"error":"unauthorized"}`.
//!
//! Not built yet: the extractors refuse every request.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::Key;
use ferret_server_auth::Clock;

use crate::error::ApiError;
use crate::ids::{AccountId, DeviceId, SidHash, VaultId};
use crate::state::VaultDb;

/// What the session extractors need and nothing more: the key that opens the
/// kit's cookie, the database and the clock.
#[derive(Clone)]
pub struct SessionAuth {
    pub key: Key,
    pub db: VaultDb,
    pub clock: Arc<dyn Clock>,
}

/// A signed-in session on the vault listener, with its account and vault.
#[derive(Debug, Clone)]
pub struct VaultSession {
    pub sid: SidHash,
    pub user_id: i64,
    pub issued_at: i64,
    pub device: DeviceId,
    pub account: AccountId,
    pub vault: VaultId,
    pub vk_epoch: u64,
}

/// A signed-in session on the admin listener.
#[derive(Debug, Clone)]
pub struct AdminSession {
    pub sid: SidHash,
    pub user_id: i64,
}

impl<S> FromRequestParts<S> for VaultSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Err(ApiError::unauthorized())
    }
}

impl<S> FromRequestParts<S> for AdminSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(_parts: &mut Parts, _state: &S) -> Result<Self, ApiError> {
        Err(ApiError::unauthorized())
    }
}
