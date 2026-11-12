//! Redeeming sign-in codes and invitations on the vault origin (a later
//! milestone).
//!
//! `POST /api/auth/redeem` takes an email address and a one-time code and opens
//! the short session that can recover the account.

use axum::Router;
use axum::extract::FromRef;

use crate::state::FerretState;

/// The routes of the redeeming. None are served yet.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    FerretState: FromRef<S>,
{
    Router::new()
}
