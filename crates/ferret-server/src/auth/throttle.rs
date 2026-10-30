//! Rate limits for the sign-in and the registration, counted in memory. Spec:
//! Fase 1 § 11.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::HeaderMap;
use ferret_server_auth::{Caller, Clock, Outcome, RetryAfter, Stage, Throttle, ThrottleKey};

/// The limiter the server hands to `ferret-server-auth`. For now it admits every
/// request and counts nothing.
pub struct KitThrottle {
    _clock: Arc<dyn Clock>,
}

impl KitThrottle {
    /// A limiter that reads the time from `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self { _clock: clock }
    }
}

impl Throttle for KitThrottle {
    fn admit(&self, _stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        Ok(())
    }

    fn record(&self, _stage: Stage, _keys: &[ThrottleKey], _outcome: Outcome, _now: u64) {}
}

/// Who is calling: the address the proxy layer left in the request, else the
/// peer's. Not yet built from the headers: only the peer counts.
pub fn caller_from(_headers: &HeaderMap, peer: Option<SocketAddr>) -> Caller {
    Caller {
        ip: peer.map(|p| p.ip()),
    }
}
