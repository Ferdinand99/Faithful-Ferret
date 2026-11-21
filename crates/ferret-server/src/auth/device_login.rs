//! The sign-in of a device client (Spec: Fase 1 § 7.6; RFC 9449 § 5).
//!
//! A device client finishes the OPAQUE sign-in on the same path as the web
//! vault, `POST /api/auth/opaque/login/finish`, with the body
//! [`crate::wire::DeviceLoginFinishReq`] (the key `client` tells it from the
//! cookie body, see [`crate::wire::LoginFinishBody`]) and a DPoP proof of its
//! new key in the `DPoP` header. Instead of a session cookie it gets a device
//! row, an access token and a refresh token
//! ([`crate::wire::DeviceLoginFinishRes`]), and no cookie at all.
//!
//! The order:
//!
//! 1. The route checked the transport and the clock before it read the body;
//!    the clock is read once more here, and that time is the one the proof
//!    and everything after it are checked against.
//! 2. The proof (`htm` `POST`, `htu` the configured vault origin and this
//!    path, no `ath`), before the sign-in state is taken and before any
//!    account is read. Every refusal of it is the one `401 dpop_invalid`, the
//!    same for an account that exists, one that does not and a disabled user;
//!    and the sign-in state is still there, so a client whose clock was off
//!    can sync to the `Date` of the answer and send the same sign-in again.
//! 3. The library's `login_finish`, as for the web vault (the throttle, the
//!    single use of the state, the proof against the record the account has
//!    now); then the account is read. A refusal is the one `401 denied`.
//! 4. One `BEGIN IMMEDIATE` transaction: the user is active with the
//!    `session_version` the account was read with, the kit's second factor is
//!    off (`403 forbidden` otherwise, as for the web vault), the account's
//!    OPAQUE record is still the one the proof was checked against
//!    (`LoginVerified::record`, the same check as `open_session_proven` in
//!    `auth::login`: a new master password that committed since refuses with
//!    `401 denied`), and the account has a vault. Then the device row
//!    (`devices::insert`: the quota, `413 quota_exceeded`, and a key that is
//!    on a device row already, `400 bad_request`), its first tokens, the time
//!    of the sign-in, the revocation of the user's pending sign-in codes, and
//!    last the `jti` of the proof, which is recorded only now that its key is
//!    bound to the new device. A replayed or a refused `jti` rolls everything
//!    back.
//! 5. `200` with the tokens, `no-store`.
//!
//! Every answer after the body was read carries a `Date` of the server's
//! clock, the clock the proofs are checked against.

use std::net::SocketAddr;

use axum::Json;
use axum::http::Method;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use ferret_core::OsRng;
use ferret_server_auth::{AuthError, DenyReason, LoginPurpose, RecordBinding};
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use vole_kit::db::{sign_in_codes, users};

use crate::auth::devices::{self, DeviceInsertError, NewDevice};
use crate::auth::dpop::{self, DpopError, Expect, VerifiedProof};
use crate::auth::login::{
    ProvenAccount, auth_refusal, clock_now, finish_blocking, no_store, read_proven_account,
    record_is_current, to_i64,
};
use crate::auth::throttle::caller_from;
use crate::auth::tokens::{DeviceAuth, IssuedTokens, issue_for_new_device, with_server_date};
use crate::error::{ApiError, StoreError};
use crate::ids::{AccountId, DeviceId};
use crate::state::FerretState;
use crate::wire::{
    DeviceLoginFinishReq, DeviceLoginFinishRes, PlatformJson, TokenJson, TokenTypeJson, hex16,
};

/// The path of the sign-in, as the `htu` of its proof names it.
pub const LOGIN_FINISH_PATH: &str = "/api/auth/opaque/login/finish";

/// Finishes the sign-in of a device client: see the module documentation.
pub(crate) async fn finish(
    state: &FerretState,
    parts: &Parts,
    peer: SocketAddr,
    req: DeviceLoginFinishReq,
) -> Result<Response, ApiError> {
    // The route refused a request without the transport before the body;
    // this read is the time of the sign-in.
    let now = to_i64(clock_now(state)?)?;
    let answer = match finish_at(state, parts, peer, req, now).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    Ok(with_server_date(answer, now))
}

async fn finish_at(
    state: &FerretState,
    parts: &Parts,
    peer: SocketAddr,
    req: DeviceLoginFinishReq,
    now: i64,
) -> Result<Response, ApiError> {
    // The proof first: nothing about an account is known or touched yet.
    let htu = state.device_auth.htu(LOGIN_FINISH_PATH);
    let proof = dpop::verify(
        &parts.headers,
        &Expect {
            method: &Method::POST,
            htu: &htu,
            access: None,
        },
        now,
    )
    .map_err(ApiError::from)?;

    let caller = caller_from(&parts.headers, Some(peer));
    let login_id = hex16::encode(&req.login_id);
    let ke3 = req.ke3;
    let worker = state.clone();
    // On a blocking thread and outside the pool, as for the web vault (see
    // `StoredRecords` in `auth::login`).
    let verified = tokio::task::spawn_blocking(move || {
        finish_blocking(&worker, caller, &login_id, &ke3, None)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(auth_refusal)?;
    if !matches!(verified.purpose, LoginPurpose::Login) {
        // No session was named, so the library finishes sign-ins only.
        return Err(auth_refusal(AuthError::Denied(DenyReason::StateInvalid)));
    }
    let account_bytes = *verified.credential.as_bytes();
    let ProvenAccount {
        user_id,
        session_version,
        account,
        vault,
        vk_epoch,
    } = state
        .vault_db
        .with_conn(move |conn| read_proven_account(conn, account_bytes))
        .await?
        .ok_or_else(|| auth_refusal(AuthError::Denied(DenyReason::StateInvalid)))?;

    let sign_in = DeviceSignIn {
        user_id,
        session_version,
        account,
        record: verified.record,
        name: req.device_name,
        platform: req.platform,
        now,
    };
    let auth = state.device_auth.clone();
    let opened = state
        .vault_db
        .with_conn(move |conn| device_login_tx(conn, &sign_in, &proof, &auth))
        .await?;
    let (device, tokens) = match opened {
        Opened::Device { device, tokens } => (device, tokens),
        Opened::Refused => {
            return Err(auth_refusal(AuthError::Denied(DenyReason::StateInvalid)));
        }
        Opened::SecondFactor => {
            tracing::info!("device sign-in refused: the kit's second factor is on");
            return Err(ApiError::coded("forbidden"));
        }
        Opened::RecordChanged => {
            return Err(auth_refusal(AuthError::Denied(DenyReason::RecordChanged)));
        }
        Opened::Quota => return Err(ApiError::coded("quota_exceeded")),
        Opened::KeyInUse => return Err(ApiError::coded("bad_request")),
        Opened::Proof(error) => return Err(ApiError::from(error)),
    };
    Ok(no_store(
        Json(DeviceLoginFinishRes {
            account_id: *account.as_bytes(),
            vault_id: *vault.as_bytes(),
            vk_epoch,
            device_id: device.0,
            access_token: TokenJson(tokens.access.to_wire()),
            refresh_token: TokenJson(tokens.refresh.to_wire()),
            token_type: TokenTypeJson::DPoP,
            expires_in: tokens.expires_in,
        })
        .into_response(),
    ))
}

/// The facts of a device sign-in after the proof, as the transaction needs
/// them.
struct DeviceSignIn {
    /// The kit user.
    user_id: i64,
    /// The user's `session_version` when the account was read after the proof.
    session_version: i64,
    /// The account the proof was for.
    account: AccountId,
    /// The record the OPAQUE proof was checked against.
    record: RecordBinding,
    /// The name the device gave.
    name: String,
    /// The platform the device gave.
    platform: PlatformJson,
    /// Now (Unix seconds).
    now: i64,
}

/// How the transaction of a device sign-in ended.
enum Opened {
    /// The device and its first tokens are written.
    Device {
        device: DeviceId,
        tokens: IssuedTokens,
    },
    /// The user is gone, was disabled or was signed out everywhere since the
    /// account was read, or the account has no vault.
    Refused,
    /// The kit's second factor is on for the user, and this server cannot ask
    /// for it yet.
    SecondFactor,
    /// The account's record is not the one the proof was checked against.
    RecordChanged,
    /// The account has the most live devices it may have.
    Quota,
    /// The proof's key is on a device row already.
    KeyInUse,
    /// The proof's `jti` was refused when it was recorded.
    Proof(DpopError),
}

/// The database side of a device sign-in, in one write transaction. Every
/// outcome but [`Opened::Device`] returns before the commit, so nothing of it
/// is kept.
fn device_login_tx(
    conn: &mut Connection,
    new: &DeviceSignIn,
    proof: &VerifiedProof,
    auth: &DeviceAuth,
) -> Result<Opened, StoreError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let user: Option<(bool, i64, bool)> = tx
        .query_row(
            "SELECT active, session_version, totp_enabled FROM users WHERE id = ?1",
            params![new.user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let totp = match user {
        Some((true, version, totp)) if version == new.session_version => totp,
        _ => return Ok(Opened::Refused),
    };
    if totp {
        return Ok(Opened::SecondFactor);
    }
    if !record_is_current(&tx, &new.account, &new.record)? {
        return Ok(Opened::RecordChanged);
    }
    let has_vault: Option<i64> = tx
        .query_row(
            "SELECT 1 FROM ferret_accounts a
             JOIN ferret_vaults v ON v.account_id = a.account_id
             WHERE a.account_id = ?1 AND a.user_id = ?2",
            params![new.account.as_bytes().as_slice(), new.user_id],
            |r| r.get(0),
        )
        .optional()?;
    if has_vault.is_none() {
        return Ok(Opened::Refused);
    }

    let device = match devices::insert(
        &tx,
        &NewDevice {
            user_id: new.user_id,
            jkt: *proof.jkt(),
            name: &new.name,
            platform: new.platform,
            session_version: new.session_version,
            now: new.now,
        },
        &mut OsRng,
    ) {
        Ok(device) => device,
        Err(DeviceInsertError::Quota) => return Ok(Opened::Quota),
        Err(DeviceInsertError::KeyInUse) => return Ok(Opened::KeyInUse),
        Err(DeviceInsertError::Store(error)) => return Err(error.into()),
    };
    let tokens = issue_for_new_device(&tx, &device, new.now, &mut OsRng)?;
    users::touch_last_login(&tx, new.user_id)?;
    sign_in_codes::revoke_for_user(&tx, new.user_id)?;
    // The key is bound to the new device now, so its `jti` may take a place
    // in the cache; a refusal rolls the device and its tokens back.
    if let Err(error) = auth.replay().record(proof, new.user_id, new.now) {
        return Ok(Opened::Proof(error));
    }
    tx.commit()?;
    Ok(Opened::Device { device, tokens })
}
