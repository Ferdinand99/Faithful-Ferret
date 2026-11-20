//! Device access tokens: issuing them and looking them up. Spec: Fase 1
//! § 7.6, § 8.2.
//!
//! A device client signs in with OPAQUE and gets an access token that lives
//! [`crate::wire::ACCESS_TOKEN_SECS`] and a refresh token, both 32 random bytes
//! ([`TokenSecret`]) and both bound to the device key (its RFC 7638 thumbprint,
//! `jkt`). The database holds only their hashes. A lookup goes through the
//! device row, so a token of a revoked device answers `device_revoked`, and a
//! device whose account changed its `session_version` (sign out everywhere, a
//! disabled user, a restore) is stopped as well.
//!
//! This module holds the types. Issuing and looking up come later.

use std::fmt;
use std::sync::Arc;

use ferret_server_auth::Clock;

use crate::auth::dpop::{JTI_CAPACITY, JTI_PER_KEY, JTI_PER_USER, JtiCache};
use crate::auth::refresh::{GRACE_CAPACITY, RefreshGrace};
use crate::ids::{DeviceId, TokenSecret};
use crate::state::VaultDb;

/// What the token routes and the extractor of a token request share: the
/// database, the clock, the cache of used `jti` values, the successors of the
/// grace period, and the vault origin the proofs name in `htu`. `Clone`
/// shares them.
#[derive(Clone)]
pub struct DeviceAuth {
    /// The database.
    #[expect(dead_code, reason = "read by the token routes, which come later")]
    db: VaultDb,
    /// The only source of time.
    #[expect(dead_code, reason = "read by the token routes, which come later")]
    clock: Arc<dyn Clock>,
    /// The `jti` values used in the window, for the whole process.
    replay: Arc<JtiCache>,
    /// The successors of the grace period, for the whole process.
    grace: Arc<RefreshGrace>,
    /// The configured public origin of the vault listener, without a trailing
    /// `/`.
    vault_origin: Arc<str>,
}

impl DeviceAuth {
    /// The handle over `db` and `clock`, with an empty `jti` cache and an
    /// empty store of successors, for proofs whose `htu` starts with
    /// `vault_origin` (the configured origin; a trailing `/` is dropped).
    pub fn new(db: VaultDb, clock: Arc<dyn Clock>, vault_origin: &str) -> Self {
        Self {
            db,
            clock,
            replay: Arc::new(JtiCache::new(JTI_CAPACITY, JTI_PER_KEY, JTI_PER_USER)),
            grace: Arc::new(RefreshGrace::new(GRACE_CAPACITY)),
            vault_origin: Arc::from(vault_origin.trim_end_matches('/')),
        }
    }

    /// The cache of used `jti` values, shared by every clone.
    pub fn replay(&self) -> &JtiCache {
        &self.replay
    }

    /// The successors of the grace period, shared by every clone.
    pub fn grace(&self) -> &RefreshGrace {
        &self.grace
    }

    /// The `htu` a proof for `path` must name: the vault origin and the path
    /// exactly as the request has it, without query or fragment (pass the
    /// path alone).
    ///
    /// RFC 9449 § 4.3 (the `htu` matches the URI of the request, without query
    /// and fragment).
    pub fn htu(&self, path: &str) -> String {
        format!("{}{path}", self.vault_origin)
    }
}

impl fmt::Debug for DeviceAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceAuth([redacted])")
    }
}

/// The tokens of one sign-in or one renewal, as they go to the device once.
pub struct IssuedTokens {
    /// The access token.
    pub access: TokenSecret,
    /// The refresh token.
    pub refresh: TokenSecret,
    /// Seconds until the access token expires.
    pub expires_in: u32,
}

impl fmt::Debug for IssuedTokens {
    /// The lifetime only: the tokens are secrets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedTokens")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// What an access token is, looked up through its device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessLookup {
    /// A live token of a live device.
    Live(AccessRow),
    /// No such token, or it expired (`401 token_expired`).
    Expired,
    /// The token's device was revoked (`401 device_revoked`). The hashes of
    /// a revoked device are kept for a while, so its tokens are still known.
    DeviceRevoked,
}

/// A live access token: its device, the account, the key it is bound to, when
/// it expires, and the `session_version` the device signed in under.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessRow {
    /// The device.
    pub device: DeviceId,
    /// The account's user (`users.id`).
    pub user_id: i64,
    /// The RFC 7638 thumbprint of the device key.
    pub jkt: [u8; 32],
    /// When the token expires (Unix seconds).
    pub expires_at: i64,
    /// The account's `session_version` when the device signed in.
    pub session_version: i64,
}

impl fmt::Debug for AccessRow {
    /// Everything but the key's thumbprint.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessRow")
            .field("device", &self.device)
            .field("user_id", &self.user_id)
            .field("expires_at", &self.expires_at)
            .field("session_version", &self.session_version)
            .finish_non_exhaustive()
    }
}
