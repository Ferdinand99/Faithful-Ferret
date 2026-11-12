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
pub mod import;
pub mod items;
pub mod methods;
pub mod notify;
pub mod password;
pub mod quota;
pub mod rate;
pub mod reconcile;
pub mod recover;
pub mod recovery;
pub mod rekey;
pub mod retention;
pub mod store;
pub mod unlock_write;
pub mod validate;

use std::sync::Arc;

use axum::Router;
use axum::extract::FromRef;
use axum::http::{HeaderValue, header};
use axum::middleware::map_response;
use axum::response::Response;
use ferret_server_auth::Clock;

use self::events::EventStreams;
use self::notify::SyncEvents;
use self::rate::{SyncLimits, WriteGate};
use crate::http::extract::SessionAuth;
use crate::state::{BackupStatus, Challenges, ImportWindows, VaultDb};

/// Marks every answer of the vault API `Cache-Control: no-store`: ciphertext
/// and wraps are not for a browser or proxy cache, and neither are the errors.
///
/// A handler that set its own `Cache-Control` keeps it: the event stream sends
/// `no-store, no-transform`, and a plain `no-store` over it would let a proxy
/// transform (buffer) the stream.
async fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

/// The vault API routes of the vault listener.
///
/// The state needs only the database handle, the session handle that the
/// `VaultSession` extractor reads (`SessionAuth: FromRef<S>` is the bound a
/// route needs to take that extractor; nothing here calls it), and the handles
/// of the sync routes: the change notifications, the rate limits, the write
/// gate and the event stream slots; and the handles of the routes that change
/// the unlock methods and import: the nonces of signed requests, the clock, the
/// import windows and the backup status.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    SyncEvents: FromRef<S>,
    Arc<SyncLimits>: FromRef<S>,
    WriteGate: FromRef<S>,
    Arc<EventStreams>: FromRef<S>,
    Challenges: FromRef<S>,
    ImportWindows: FromRef<S>,
    BackupStatus: FromRef<S>,
    Arc<dyn Clock>: FromRef<S>,
{
    Router::new()
        .merge(methods::routes())
        .merge(password::routes())
        .merge(recovery::routes())
        .merge(recover::routes())
        .merge(import::routes())
        .merge(changes::routes())
        .merge(items::routes())
        .merge(batch::routes())
        .merge(checkpoint::routes())
        .merge(events::routes())
        .merge(reconcile::routes())
        .layer(map_response(no_store))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_store_keeps_a_cache_control_that_a_handler_set() {
        let mut response = Response::new(axum::body::Body::empty());
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store, no-transform"),
        );
        let response = no_store(response).await;
        let values: Vec<_> = response
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .collect();
        assert_eq!(values, ["no-store, no-transform"]);
    }

    #[tokio::test]
    async fn no_store_is_added_when_none_is_set() {
        let response = no_store(Response::new(axum::body::Body::empty())).await;
        let values: Vec<_> = response
            .headers()
            .get_all(header::CACHE_CONTROL)
            .iter()
            .collect();
        assert_eq!(values, ["no-store"]);
    }
}
