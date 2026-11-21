//! Redeeming a one-time sign-in code on the vault origin:
//! `POST /api/auth/redeem {email, code}`, without a session.
//!
//! An administrator makes the code for a user who has forgotten the master
//! password (on the Users page, or with `ferret sign-in-code issue` on the
//! server). The user types it, with the e-mail address, on the vault origin's
//! recovery page, and gets a short session of the scope `account_reset`: it
//! can ask for a nonce, read the recovery wrap, start a new registration in the
//! recovery and recover, and nothing else (no sync, no unlock methods, no
//! re-authentication). Nothing on this path asks for the master password.
//!
//! Spec: Fase 1 § 6.3 step 1 (the administrator resets the sign-in with the
//! kit's one-time code; the vault stays sealed) and § 4.2 (F-06: the answers
//! say nothing about which accounts exist).
//!
//! # The steps
//!
//! 1. The request is refused with `insecure_transport` when the vault URL is
//!    `https` and the request did not come over HTTPS. A body of more than
//!    [`MAX_BODY_BYTES`] is `413 too_large`, and one that is not the JSON of
//!    the request is `400 bad_request`; both depend on the bytes alone.
//! 2. The limit of [`RedeemLimit`]: 10 per address per minute, 5 per typed
//!    e-mail address and address per hour, `429 throttled` with a wait. The
//!    keys are built from what was typed, never from whether an account has
//!    that name.
//! 3. An e-mail address that is no login name, or a code longer than any
//!    spelling of a code ([`MAX_CODE_BYTES`]), is the common `401 denied` at
//!    once: no account can match it.
//! 4. The kit's `redeem_from` with the normalized name: its own throttle, then
//!    in one transaction the claim of the code (once: of two requests racing
//!    for it, one wins), the user's `session_version + 1` (every session and
//!    kit cookie of the user is dead from here) and the deletion of the user's
//!    API tokens. The kit runs the same two statements for every name: the
//!    lookup of the user by name, then the claim, which is one `UPDATE` keyed
//!    by the hash of the code and the user id; a name without a user takes the
//!    fixed id `-1`, which no row has. An unknown name, a wrong, used, revoked
//!    or expired code, another user's code and a disabled user therefore cost
//!    the same and give the same `401 denied`. The kit never logs the code or
//!    the typed name.
//! 5. `login::open_session` with the scope `account_reset`, the vault origin
//!    and the `session_version` of the redeemed code: a new row (never fresh,
//!    30 minutes at most) and its two cookies. The kit's password hash is not
//!    touched: the master password is not the kit's.
//! 6. In one more write transaction `session::end_all_credentials` ends every
//!    other session of the user on both origins, revokes every device of the
//!    user with tokens (and any code the user still has), and after the commit
//!    each ended session and revoked device is announced
//!    (`SyncEvents::announce_ended`), so its event streams close at once.
//!
//! The code is spent at step 4. When step 5 refuses (the kit's second factor
//! is on, which this server cannot ask for yet; the user has no vault; the
//! user changed in between), the user's sessions still end as in step 6, and
//! the answer is the same `401 denied`: the code is gone and the user is signed
//! out everywhere, which fails closed. No account can turn the kit's second
//! factor on before the server asks for it.
//!
//! What is typed is never logged here either: not the code, not the e-mail
//! address.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, FromRef, Request, State};
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use axum_extra::extract::cookie::SignedCookieJar;
use ferret_core::{OsRng, SecureRng as _};
use ferret_server_auth::{SessionScope, normalize_login_name};
use rusqlite::TransactionBehavior;
use vole_kit::auth::sign_in_codes;

use crate::auth::login::open_session;
use crate::auth::session::{Origin, end_all_credentials};
use crate::auth::throttle::{RedeemLimit, caller_from};
use crate::error::ApiError;
use crate::http::proxy_guard::request_is_https;
use crate::ids::{DeviceId, SidHash};
use crate::state::FerretState;
use crate::wire::{REDEEM_SCOPE, RedeemReq, RedeemRes};

/// The most a redeem request may carry. An e-mail address of the longest
/// length the login name allows before normalization, and a code with room
/// for spaces, fit with a wide margin.
pub const MAX_BODY_BYTES: usize = 8 * 1024;

/// The longest code that is read, in bytes. A code is 32 characters, shown in
/// eight groups of four with dashes; people may type spaces between the
/// groups. Anything longer cannot be a code.
pub const MAX_CODE_BYTES: usize = 128;

/// The device name of a recovery session.
const DEVICE_NAME: &str = "Account recovery";

/// `POST /api/auth/redeem`, with its own [`RedeemLimit`] (one per router, so
/// two servers in one process count apart).
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
        .route("/api/auth/redeem", post(redeem_route))
        .layer(Extension(Arc::new(RedeemLimit::new())))
}

/// The one answer for every reason a code does not give a session.
fn denied() -> ApiError {
    ApiError::coded("denied")
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A fresh random device id for the recovery session: it is no device of the
/// vault, and must not be taken for one.
fn recovery_device() -> DeviceId {
    let mut id = [0u8; 16];
    OsRng.fill(&mut id);
    DeviceId(id)
}

async fn redeem_route(
    State(state): State<FerretState>,
    Extension(limit): Extension<Arc<RedeemLimit>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    if state.origins.vault_is_https()
        && !request_is_https(&parts.headers, peer.ip(), &state.proxies, true)
    {
        return Err(ApiError::coded("insecure_transport"));
    }
    let now = state.clock.now_unix();
    let Ok(now_secs) = i64::try_from(now) else {
        tracing::error!("the clock failed; the redeeming of a code is refused");
        return Err(ApiError::internal());
    };
    let req = read_body(body).await?;
    let caller = caller_from(&parts.headers, Some(peer));

    if let Err(wait) = limit.admit(&caller, &req.email, now) {
        tracing::info!("a sign-in code redeem was throttled");
        return Err(ApiError::throttled(wait.secs()));
    }

    // No account can be named by a text that is no login name, and no code is
    // longer than this: refused before any work, whatever the account.
    let Ok(name) = normalize_login_name(&req.email) else {
        tracing::info!("a sign-in code was refused");
        return Err(denied());
    };
    if req.code.len() > MAX_CODE_BYTES {
        tracing::info!("a sign-in code was refused");
        return Err(denied());
    }

    let redeemed = sign_in_codes::redeem_from(&state.core, name.as_str(), &req.code, caller.ip)
        .await
        .map_err(|error| {
            tracing::error!(%error, "the redeeming of a sign-in code failed");
            ApiError::internal()
        })?;
    drop(req);
    let Ok(token) = redeemed else {
        tracing::info!("a sign-in code was refused");
        return Err(denied());
    };
    // The code is spent and the user signed out everywhere. The kit's password
    // hash is not set: the token is only read, never handed back to the kit.
    let (user_id, session_version) = (token.user_id(), token.session_version());
    drop(token);

    let jar = SignedCookieJar::from_headers(&parts.headers, state.core.session_key.clone());
    let opened = open_session(
        &state,
        jar,
        user_id,
        Origin::Vault,
        SessionScope::AccountReset,
        session_version,
        recovery_device(),
        DEVICE_NAME,
        now_secs,
    )
    .await;
    let (jar, sid) = match opened {
        Ok(opened) => opened,
        // A second factor that is on (403), or a user that changed or has no
        // vault (401): the code is spent either way, and the answer is the one
        // of every other refusal. The user was signed out by the redeem; the
        // rows end too, so their event streams close.
        Err(error)
            if error.status == StatusCode::FORBIDDEN
                || error.status == StatusCode::UNAUTHORIZED =>
        {
            tracing::info!(
                user_id,
                "a sign-in code was spent but no session was opened"
            );
            end_the_others(&state, user_id, None, now_secs).await?;
            return Err(denied());
        }
        Err(error) => return Err(error),
    };

    end_the_others(&state, user_id, Some(sid), now_secs).await?;
    tracing::info!(
        user_id,
        "a sign-in code was redeemed: recovery session opened"
    );

    Ok(no_store(
        (
            jar,
            Json(RedeemRes {
                scope: REDEEM_SCOPE.to_string(),
            }),
        )
            .into_response(),
    ))
}

/// Ends every session of the user but `keep`, on both origins, and revokes
/// every device of the user with tokens, in one write transaction, and
/// announces each after the commit. The sessions and devices are already dead
/// (the redeem moved the user's `session_version`); this ends their rows, so
/// the devices leave the list and the quota, and closes their event streams.
/// The announcement runs on the database thread right after the commit, so a
/// request whose client went away still closes the streams.
async fn end_the_others(
    state: &FerretState,
    user_id: i64,
    keep: Option<SidHash>,
    now: i64,
) -> Result<(), ApiError> {
    let events = state.events.clone();
    state
        .vault_db
        .with_conn(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let ended = end_all_credentials(&tx, user_id, keep.as_ref(), now)?;
            tx.commit()?;
            events.announce_ended(&ended);
            Ok(())
        })
        .await?;
    Ok(())
}

/// Reads the body: at most [`MAX_BODY_BYTES`], and the JSON of a
/// [`RedeemReq`].
async fn read_body(body: Body) -> Result<RedeemReq, ApiError> {
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::coded("too_large"))?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::bad_request("bad_request"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_refusal_is_the_common_401() {
        assert_eq!(denied().status, StatusCode::UNAUTHORIZED);
        assert_eq!(denied().code, "denied");
        assert_eq!(denied().retry_after, None);
    }

    #[test]
    fn a_spelled_out_code_fits_the_length_limit() {
        let code = sign_in_codes::generate();
        let spaced = code.replace('-', " - ");
        assert!(spaced.len() <= MAX_CODE_BYTES, "{}", spaced.len());
        assert!(sign_in_codes::normalize(&spaced).is_some());
    }

    #[test]
    fn every_recovery_session_has_its_own_device() {
        assert_ne!(recovery_device().0, recovery_device().0);
    }
}
