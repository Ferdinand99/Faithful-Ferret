//! Registration, sign-in, sessions and the hand-over to the admin origin.
//!
//! Everything here that handles integers that come from a client uses checked
//! arithmetic: with `panic = "abort"` an overflow would end both listeners.
//! The lint below is `deny`, and the tests check that nothing in `auth/` or
//! `vault/` switches it off.

#![deny(clippy::arithmetic_side_effects)]

pub mod challenge;
pub mod devices;
pub mod dpop;
pub mod email_change;
pub mod handoff;
pub mod login;
pub mod notify;
pub mod redeem;
pub mod register;
pub mod second_factor;
pub mod secrets;
pub mod session;
pub mod state_store;
pub mod throttle;
pub mod tokens;

use axum::Router;

/// The routes of the vault listener: registration, sign-in, sign-out, the
/// session info and the start of a hand-over.
pub fn routes_vault<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(register::routes())
        .merge(login::routes())
        .merge(handoff::routes())
}

/// The routes of the admin listener that are Ferret's: sign-out, the session
/// info and the redeeming of a hand-over code. The guard of `admin::guard`
/// does not wrap them.
pub fn routes_admin<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(login::admin_routes())
        .merge(handoff::admin_routes())
}
