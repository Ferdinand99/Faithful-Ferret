//! The session extractors: the only code that knows the kit's cookie key.
//!
//! A route takes [`VaultSession`] (vault listener) or [`AdminSession`] (admin
//! listener). The extractor needs Ferret's `__Host-ferret_sid` cookie to match
//! a row that is not revoked, belongs to the listener, has the scope `full` and
//! is within its limits (`auth::session::limits`), and the kit's signed cookie
//! to agree with the row's user and `issued_at` and with the kit's
//! `session_version`. The user must still be active. Anything else is the one
//! answer `401 {"error":"unauthorized"}`: the same status, headers and body for
//! every reason, so a caller learns nothing about which part failed.
//!
//! A limit is inclusive: a session that idled exactly 12 hours is still valid,
//! one second more is not. The row's `last_seen` is written at most once a
//! minute.
//!
//! The extractors are generic over the state and ask only for [`SessionAuth`]
//! through `FromRef`: the cookie key, the database and the clock. The vault
//! modules never see the key; they take the extractor.
//!
//! Spec: Fase 1 § 7.6.

use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use ferret_server_auth::{Clock, SessionScope};
use rusqlite::{OptionalExtension as _, params};
use vole_kit::auth::session::SessionClaims;

use crate::auth::session::{Origin, limits, lookup};
use crate::error::{ApiError, StoreError};
use crate::ids::{AccountId, DeviceId, SessionSecret, SidHash, VaultId};
use crate::product;
use crate::state::VaultDb;

/// `last_seen` is written when it is at least this many seconds old.
const TOUCH_AFTER_SECS: i64 = 60;

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

/// A session that passed every check.
struct Verified {
    sid: SidHash,
    user_id: i64,
    issued_at: i64,
    device: DeviceId,
    /// The account of the user, read for the vault listener only.
    account: Option<(AccountId, VaultId, u64)>,
}

impl SessionAuth {
    /// Checks the cookies of a request against the database. `Ok(None)` is
    /// every way of not being signed in.
    async fn verify(&self, parts: &Parts, origin: Origin) -> Result<Option<Verified>, StoreError> {
        let jar = SignedCookieJar::from_headers(&parts.headers, self.key.clone());
        let Some(secret) = jar
            .get(product::SID_COOKIE)
            .and_then(|c| SessionSecret::from_cookie(c.value()).ok())
        else {
            return Ok(None);
        };
        let Some(claims) = jar
            .get(product::SESSION_COOKIE)
            .and_then(|c| SessionClaims::decode(c.value()))
        else {
            return Ok(None);
        };
        drop(jar);
        // A clock that failed reads as the largest value; nothing is valid then.
        let Ok(now) = i64::try_from(self.clock.now_unix()) else {
            return Ok(None);
        };
        let sid = secret.hash();
        drop(secret);

        self.db
            .with_conn(move |conn| {
                let Some(row) = lookup(conn, &sid)? else {
                    return Ok(None);
                };
                let (idle, absolute) = limits(row.origin);
                let within_limits = now.saturating_sub(row.last_seen).max(0) <= idle
                    && now.saturating_sub(row.issued_at).max(0) <= absolute;
                if row.revoked_at.is_some()
                    || row.origin != origin
                    || row.scope != SessionScope::Full
                    || !within_limits
                    || claims.user_id != row.user_id
                    || claims.issued_at != row.issued_at
                {
                    return Ok(None);
                }
                // The kit's side: the user is active and has not bumped the
                // session version (password change, "sign out everywhere").
                let user: Option<(i64, bool)> = conn
                    .query_row(
                        "SELECT session_version, active FROM users WHERE id = ?1",
                        params![row.user_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match user {
                    Some((version, true)) if version == claims.version => {}
                    _ => return Ok(None),
                }
                let account = if origin == Origin::Vault {
                    let found: Option<(Vec<u8>, Vec<u8>, i64)> = conn
                        .query_row(
                            "SELECT a.account_id, v.vault_id, a.vk_epoch
                             FROM ferret_accounts a
                             JOIN ferret_vaults v ON v.account_id = a.account_id
                             WHERE a.user_id = ?1",
                            params![row.user_id],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .optional()?;
                    let Some((account, vault, epoch)) = found else {
                        return Ok(None);
                    };
                    let ids = <[u8; 16]>::try_from(account)
                        .and_then(|a| <[u8; 16]>::try_from(vault).map(|v| (a, v)))
                        .ok()
                        .zip(u64::try_from(epoch).ok());
                    let Some(((account, vault), epoch)) = ids else {
                        return Ok(None);
                    };
                    Some((
                        AccountId::from_bytes(account),
                        VaultId::from_bytes(vault),
                        epoch,
                    ))
                } else {
                    None
                };

                // At most once a minute; the condition makes it one statement,
                // so requests that arrive together write once. A failed write
                // only makes the idle limit bite sooner.
                if let Err(e) = conn.execute(
                    "UPDATE ferret_sessions SET last_seen = ?1
                     WHERE sid_hash = ?2 AND revoked_at IS NULL AND ?1 - last_seen >= ?3",
                    params![now, sid.0.as_slice(), TOUCH_AFTER_SECS],
                ) {
                    tracing::warn!(error = %e, "could not record the use of a session");
                }

                Ok(Some(Verified {
                    sid,
                    user_id: row.user_id,
                    issued_at: row.issued_at,
                    device: row.device,
                    account,
                }))
            })
            .await
    }
}

impl<S> FromRequestParts<S> for VaultSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth
            .verify(parts, Origin::Vault)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        let (account, vault, vk_epoch) = verified.account.ok_or_else(ApiError::unauthorized)?;
        Ok(VaultSession {
            sid: verified.sid,
            user_id: verified.user_id,
            issued_at: verified.issued_at,
            device: verified.device,
            account,
            vault,
            vk_epoch,
        })
    }
}

impl<S> FromRequestParts<S> for AdminSession
where
    S: Send + Sync,
    SessionAuth: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        let auth = SessionAuth::from_ref(state);
        let verified = auth
            .verify(parts, Origin::Admin)
            .await?
            .ok_or_else(ApiError::unauthorized)?;
        Ok(AdminSession {
            sid: verified.sid,
            user_id: verified.user_id,
        })
    }
}
