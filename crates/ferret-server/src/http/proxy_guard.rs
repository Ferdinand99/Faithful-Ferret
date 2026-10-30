//! Which proxies to believe.
//!
//! `X-Forwarded-*`, `Forwarded` and `X-Real-IP` are believed only from the
//! addresses in `FERRET_TRUSTED_PROXIES`; every other peer's are removed before
//! anything else runs. Anyone who reaches the ports directly could otherwise
//! claim any address and any scheme.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::{ConfigError, NotImplemented};

/// The trusted proxy addresses and networks. For now the list can only be empty:
/// no proxy is believed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyList {}

impl ProxyList {
    /// The list from the configured items (addresses or CIDR networks). A
    /// non-empty list is not understood yet and is refused.
    pub fn parse(items: &[String]) -> Result<Self, ConfigError> {
        if items.is_empty() {
            Ok(Self {})
        } else {
            Err(ConfigError(NotImplemented("trusted proxies").to_string()))
        }
    }

    /// Whether `ip` is a trusted proxy.
    pub fn contains(&self, _ip: IpAddr) -> bool {
        false
    }
}

/// Removes the forwarding headers of a peer that is not a trusted proxy. Not
/// built yet: it passes the request on.
pub async fn proxy_guard(
    State(_proxies): State<Arc<ProxyList>>,
    ConnectInfo(_peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    next.run(request).await
}
