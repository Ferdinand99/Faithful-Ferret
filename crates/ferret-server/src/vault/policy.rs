//! `GET /api/vault/policy`: the server's rule for quick unlock, as a client
//! reads it, and the one-row table behind it (`ferret_unlock_policy`).
//!
//! ```text
//! 200 { "pin": { "allowed": true, "after_restart": true, "min_length": 6 },
//!       "prf": { "enabled": true } }
//! ```
//!
//! A client keeps the answer and holds itself to it when a PIN is set, at every
//! unlock and at every sync. A server that has no such route (404) says "no
//! PIN" to a client.
//!
//! Only a full session or a device token reaches the route (the extractor
//! refuses the others). The rule belongs to the server, not to an account, so
//! there is no id in the path and the answer is the same for every caller; it
//! holds nothing of the account, the vault or the caller. The administrator
//! sets the rule on the admin pages (`admin::unlock`).
//!
//! Without the cargo feature `quick-unlock` the route is still there, and says
//! that no PIN is allowed and that the passkey routes are off.

use axum::extract::{FromRef, State};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{Connection, OptionalExtension as _, params};
use serde::{Deserialize, Serialize};

use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultCaller};
use crate::state::VaultDb;

/// The shortest minimum length an administrator can set: below it a PIN is no
/// lock at all, and the clients refuse such a PIN whatever the server says.
pub const MIN_LENGTH_FLOOR: u8 = 4;
/// The longest minimum length: a PIN is at most 64 characters.
pub const MIN_LENGTH_CEILING: u8 = 64;
/// The minimum length of a server that was never set up.
pub const MIN_LENGTH_DEFAULT: u8 = 6;

/// Whether this build offers quick unlock (the cargo feature `quick-unlock`).
pub const fn quick_unlock_built() -> bool {
    cfg!(feature = "quick-unlock")
}

/// The rule an administrator sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlockPolicy {
    /// A PIN may be used at all. Off is the emergency switch.
    pub pin_allowed: bool,
    /// A PIN may be kept on disk, so it works after a restart of the browser.
    pub pin_after_restart: bool,
    /// The shortest PIN, in characters ([`MIN_LENGTH_FLOOR`]..=[`MIN_LENGTH_CEILING`]).
    pub pin_min_length: u8,
}

impl Default for UnlockPolicy {
    /// What a server that was never set up has: a PIN is allowed, it survives a
    /// restart, and it has six characters at least.
    fn default() -> Self {
        Self {
            pin_allowed: true,
            pin_after_restart: true,
            pin_min_length: MIN_LENGTH_DEFAULT,
        }
    }
}

impl UnlockPolicy {
    /// Whether `self` is a harder rule than `before`: a PIN that was fine under
    /// `before` can be refused under `self`, and the clients then delete it.
    pub fn is_stricter_than(&self, before: &UnlockPolicy) -> bool {
        (before.pin_allowed && !self.pin_allowed)
            || (before.pin_after_restart && !self.pin_after_restart)
            || self.pin_min_length > before.pin_min_length
    }

    /// Whether a minimum length is one the server accepts.
    pub fn length_ok(length: i64) -> bool {
        (i64::from(MIN_LENGTH_FLOOR)..=i64::from(MIN_LENGTH_CEILING)).contains(&length)
    }
}

/// The rule as it is stored; the defaults when the row is not there (a
/// database that was edited by hand). A row the table's checks would have
/// refused is an inconsistent database and an error.
pub fn read(conn: &Connection) -> Result<UnlockPolicy, StoreError> {
    let row = conn
        .query_row(
            "SELECT pin_allowed, pin_after_restart, pin_min_length \
             FROM ferret_unlock_policy WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((allowed, after_restart, min_length)) = row else {
        return Ok(UnlockPolicy::default());
    };
    let flag = |value: i64| match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(StoreError::Invalid("a policy flag is not 0 or 1")),
    };
    let pin_min_length = u8::try_from(min_length)
        .ok()
        .filter(|n| UnlockPolicy::length_ok(i64::from(*n)))
        .ok_or(StoreError::Invalid(
            "the minimum PIN length is out of range",
        ))?;
    Ok(UnlockPolicy {
        pin_allowed: flag(allowed)?,
        pin_after_restart: flag(after_restart)?,
        pin_min_length,
    })
}

/// Stores the rule, at `now` (Unix seconds).
pub fn write(conn: &Connection, policy: &UnlockPolicy, now: i64) -> Result<(), StoreError> {
    if !UnlockPolicy::length_ok(i64::from(policy.pin_min_length)) {
        return Err(StoreError::Invalid(
            "the minimum PIN length is out of range",
        ));
    }
    conn.execute(
        "INSERT INTO ferret_unlock_policy \
             (id, pin_allowed, pin_after_restart, pin_min_length, updated_at) \
         VALUES (1, ?1, ?2, ?3, ?4) \
         ON CONFLICT(id) DO UPDATE SET \
             pin_allowed = excluded.pin_allowed, \
             pin_after_restart = excluded.pin_after_restart, \
             pin_min_length = excluded.pin_min_length, \
             updated_at = excluded.updated_at",
        params![
            i64::from(policy.pin_allowed),
            i64::from(policy.pin_after_restart),
            i64::from(policy.pin_min_length),
            now.max(0)
        ],
    )?;
    Ok(())
}

/// The PIN part of the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinPolicyJson {
    /// A PIN may be used at all.
    pub allowed: bool,
    /// A PIN may be kept on disk.
    pub after_restart: bool,
    /// The shortest PIN.
    pub min_length: u8,
}

/// The passkey part of the answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrfPolicyJson {
    /// The server has the routes for unlocking with a passkey.
    pub enabled: bool,
}

/// `GET /api/vault/policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRes {
    /// The PIN rule.
    pub pin: PinPolicyJson,
    /// The passkey switch.
    pub prf: PrfPolicyJson,
}

impl PolicyRes {
    /// The answer for the stored rule: a build without quick unlock allows no
    /// PIN and has no passkey routes, whatever the table says.
    pub fn of(policy: &UnlockPolicy, built: bool) -> Self {
        Self {
            pin: PinPolicyJson {
                allowed: built && policy.pin_allowed,
                after_restart: policy.pin_after_restart,
                min_length: policy.pin_min_length,
            },
            prf: PrfPolicyJson { enabled: built },
        }
    }
}

/// The policy route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
{
    Router::new().route("/api/vault/policy", get(get_policy))
}

/// The rule. The caller proves a full session or a device; nothing about the
/// caller goes into the answer.
async fn get_policy(
    _caller: VaultCaller,
    State(db): State<VaultDb>,
) -> Result<Json<PolicyRes>, ApiError> {
    let policy = db.with_conn(|conn| read(conn)).await?;
    Ok(Json(PolicyRes::of(&policy, quick_unlock_built())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_harder_rule_is_one_a_stored_pin_can_fail() {
        let base = UnlockPolicy::default();
        let stricter = |change: fn(&mut UnlockPolicy)| {
            let mut next = base;
            change(&mut next);
            next.is_stricter_than(&base)
        };
        assert!(stricter(|p| p.pin_allowed = false));
        assert!(stricter(|p| p.pin_after_restart = false));
        assert!(stricter(|p| p.pin_min_length = 7));
        assert!(!stricter(|p| p.pin_min_length = 5));
        assert!(!stricter(|_| {}));
        // Turning a switch on is never harder.
        let off = UnlockPolicy {
            pin_allowed: false,
            pin_after_restart: false,
            pin_min_length: 6,
        };
        assert!(!base.is_stricter_than(&off));
    }

    #[test]
    fn only_four_to_sixty_four_is_a_length() {
        for length in [-1, 0, 3, 65, 1000, i64::MAX] {
            assert!(!UnlockPolicy::length_ok(length), "{length}");
        }
        for length in [4, 6, 64] {
            assert!(UnlockPolicy::length_ok(length), "{length}");
        }
    }

    #[test]
    fn a_build_without_quick_unlock_answers_that_nothing_is_allowed() {
        let rule = UnlockPolicy::default();
        let off = PolicyRes::of(&rule, false);
        assert!(!off.pin.allowed);
        assert!(!off.prf.enabled);
        let on = PolicyRes::of(&rule, true);
        assert!(on.pin.allowed);
        assert!(on.prf.enabled);
        assert_eq!(on.pin.min_length, 6);
        // A switched-off rule stays off in a build that offers the feature.
        let stopped = UnlockPolicy {
            pin_allowed: false,
            ..rule
        };
        assert!(!PolicyRes::of(&stopped, true).pin.allowed);
    }
}
