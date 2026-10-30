//! The vault modules: the unlock methods, the changes feed and the item writes,
//! and the store behind them.
//!
//! **Narrow state.** Nothing under `vault/` names the application state, the
//! kit's core state, its cookie key or its crypto: the routes are generic over
//! the state and take the database handle (and other narrow handles) through
//! `FromRef`. The session comes from the `VaultSession` extractor of
//! `http::extract`, which is the only code that knows the cookie key.
//! `tests/arch.rs` checks the names.
//!
//! Integers that come from a client use checked arithmetic; the lint below is
//! `deny`.

#![deny(clippy::arithmetic_side_effects)]

pub mod batch;
pub mod changes;
pub mod checkpoint;
pub mod events;
pub mod idem;
pub mod items;
pub mod methods;
pub mod password;
pub mod quota;
pub mod reconcile;
pub mod recover;
pub mod recovery;
pub mod rekey;
pub mod store;

use axum::Router;

/// The vault API routes of the vault listener.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .merge(methods::routes())
        .merge(changes::routes())
        .merge(items::routes())
}
