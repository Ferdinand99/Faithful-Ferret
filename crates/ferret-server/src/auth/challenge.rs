//! Nonces for signed requests: `POST /api/auth/challenge` on the vault
//! listener. Spec: Fase 1 § 4.6 (the signature, step 1).
//!
//! A session whose scope allows `Challenge` (a `full` session, and an
//! `account_reset` session for its recovery) gets `{nonce, expires_in: 300}`.
//! The nonce is 32 random bytes from the OPAQUE library's `issue_challenge`,
//! which keeps only `SHA-256(binding ‖ nonce)` in the in-memory store, where
//! the binding is the hash of this session's id (`session_binding`). A nonce is
//! therefore bound to the session it was issued to, is used once (the library
//! consumes it before it checks a proof), and expires after 300 seconds.
//!
//! The order of the checks:
//!
//! 1. The session (`ScopedSession<caps::Challenge>`): `401 unauthorized` for no
//!    valid session, `403 forbidden` for a scope without the capability.
//! 2. The clock: one that failed refuses (`500 internal`).
//! 3. The limit of the session (`auth::throttle::ChallengeLimit`, 30 per
//!    minute): `429 throttled` with `Retry-After`.
//! 4. The library: the scope again, its throttle by address and account, the
//!    nonce drawn and stored.
//!
//! The admin listener has no such route.

use std::net::SocketAddr;
use std::sync::{OnceLock, PoisonError};

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use ferret_core::OsRng;
use ferret_server_auth::{AuthContext, ProfileRules, issue_challenge};

use crate::auth::login::no_store;
use crate::auth::throttle::caller_from;
use crate::error::ApiError;
use crate::http::extract::{ScopedSession, caps};
use crate::state::FerretState;
use crate::wire::ChallengeRes;

/// The routes of the challenge: `POST /api/auth/challenge`, for the vault
/// listener only.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new().route("/api/auth/challenge", post(challenge))
}

/// The rules of the key stretching profiles. The library's context needs
/// them; issuing a nonce does not read them.
fn profiles() -> &'static ProfileRules {
    static RULES: OnceLock<ProfileRules> = OnceLock::new();
    RULES.get_or_init(ProfileRules::ferret_v1)
}

async fn challenge(
    State(state): State<FerretState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut parts: Parts,
) -> Result<Response, ApiError> {
    let scoped = ScopedSession::<caps::Challenge>::from_request_parts(&mut parts, &state).await?;
    let now = state.clock.now_unix();
    if now == u64::MAX {
        tracing::error!("the clock failed; no nonce is issued");
        return Err(ApiError::internal());
    }
    state
        .challenges
        .limit()
        .admit(&scoped.session().sid(), now)
        .map_err(|wait| ApiError::throttled(wait.secs()))?;

    let caller = caller_from(&parts.headers, Some(peer));
    let binding = scoped.binding();
    let policy = state
        .prelogin
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let cx = AuthContext::new(
        &state.secrets.keys,
        &state.secrets.prelogin,
        &state.secrets.seal,
        state.clock.as_ref(),
        state.throttle.as_ref(),
        &policy,
        profiles(),
    );
    let issued = issue_challenge(
        &cx,
        state.challenges.store(),
        &mut OsRng,
        &caller,
        scoped.scope(),
        &binding,
        &scoped.session().account(),
    )
    .map_err(|error| {
        // The reason is for this log only; the answer carries the public code.
        tracing::info!(reason = ?error, "nonce refused");
        ApiError::from(error)
    })?;
    let expires_in = u32::try_from(issued.expires_in).map_err(|_| ApiError::internal())?;
    Ok(no_store(
        Json(ChallengeRes {
            nonce: issued.nonce,
            expires_in,
        })
        .into_response(),
    ))
}
