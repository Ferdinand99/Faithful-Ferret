//! The actions on another account, each with its event in the account log,
//! and the one set of rules that says which account may be acted on.
//!
//! * [`target`] is the only place the rules live: the account exists and has
//!   a vault, and it is neither the administrator's own account nor an
//!   administrator. Only the server command ([`Actor::ServerCommand`]) may act
//!   on an administrator: it is the way back for an administrator who has
//!   forgotten the master password. What an action needs beyond that (an
//!   active account, no second factor of the kit) is asked of the
//!   [`TargetUser`] it returns.
//! * [`issue_sign_in_code`] makes a one-time sign-in code, for the Users page
//!   and for `ferret sign-in-code issue`. The kit stores the code in a
//!   transaction of its own, so the event is written right after it; if the
//!   event cannot be written, the code is revoked again and the action fails,
//!   so no code is left that the log does not show.
//!
//! Spec: Fase 1 § 11 ("The acting account and the target", "Every action on
//! another account writes its event in the same transaction as the change")
//! and § 6.3 (every code is in the account log).

use std::fmt;

use rusqlite::{Connection, OptionalExtension as _, params};
use vole_kit::auth::sign_in_codes;
use zeroize::Zeroizing;

use crate::accounts::log::{self, Actor, EventKind};
use crate::admin::codes::IssuedCode;
use crate::error::StoreError;

/// Why an action on an account was not taken.
#[derive(Debug)]
pub enum ActionError {
    /// No such account, or one without a vault.
    NotFound,
    /// The actor may not act on that account (its own, or an administrator),
    /// or may not take this action at all.
    NotAllowed,
    /// The account is disabled, and the action needs an active one.
    Disabled,
    /// The account has the kit's second factor on, which a sign-in code
    /// cannot pass yet.
    SecondFactor,
    /// No good backup set was made after the account was disabled.
    NeedsBackup,
    /// The e-mail that was typed is not the account's.
    EmailMismatch,
    /// The account is not disabled, and the action needs a disabled one.
    NotDisabled,
    /// A limit is reached (pending invitations).
    Full,
    /// The database failed.
    Store(StoreError),
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionError::NotFound => f.write_str("no such account with a vault"),
            ActionError::NotAllowed => f.write_str("that action is not allowed on that account"),
            ActionError::Disabled => f.write_str("the account is disabled"),
            ActionError::SecondFactor => f.write_str("the account has two-factor sign-in on"),
            ActionError::NeedsBackup => {
                f.write_str("no good backup was made after the account was disabled")
            }
            ActionError::EmailMismatch => f.write_str("the e-mail is not the account's"),
            ActionError::NotDisabled => f.write_str("the account is not disabled"),
            ActionError::Full => f.write_str("the limit is reached"),
            ActionError::Store(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ActionError {}

impl From<StoreError> for ActionError {
    fn from(error: StoreError) -> Self {
        ActionError::Store(error)
    }
}

impl From<rusqlite::Error> for ActionError {
    fn from(error: rusqlite::Error) -> Self {
        ActionError::Store(StoreError::Sql(error))
    }
}

/// An account that [`target`] found may be acted on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetUser {
    /// The kit user.
    pub user_id: i64,
    /// Its e-mail (the kit's username).
    pub email: String,
    /// Whether the account is active (not disabled).
    pub active: bool,
    /// Whether the kit's second factor is on.
    pub second_factor: bool,
}

impl TargetUser {
    /// The account, if it is active; else [`ActionError::Disabled`].
    pub fn require_active(self) -> Result<Self, ActionError> {
        if self.active {
            Ok(self)
        } else {
            Err(ActionError::Disabled)
        }
    }

    /// The account, if it is disabled; else [`ActionError::NotDisabled`].
    pub fn require_disabled(self) -> Result<Self, ActionError> {
        if self.active {
            Err(ActionError::NotDisabled)
        } else {
            Ok(self)
        }
    }

    /// The account, if the kit's second factor is off; else
    /// [`ActionError::SecondFactor`].
    pub fn require_no_second_factor(self) -> Result<Self, ActionError> {
        if self.second_factor {
            Err(ActionError::SecondFactor)
        } else {
            Ok(self)
        }
    }
}

/// The account `target` as `by` may act on it, or why not.
///
/// * The actor is an administrator with a known account, or the server
///   command; anyone else is [`ActionError::NotAllowed`].
/// * The account exists and has a vault, else [`ActionError::NotFound`].
/// * An administrator never acts on their own account or on another
///   administrator ([`ActionError::NotAllowed`]); the server command may.
pub fn target(conn: &Connection, by: &Actor, target: i64) -> Result<TargetUser, ActionError> {
    let acting_admin = match by {
        Actor::Admin {
            user_id: Some(id), ..
        } => Some(*id),
        Actor::ServerCommand => None,
        Actor::Admin { user_id: None, .. } | Actor::Server | Actor::Account => {
            return Err(ActionError::NotAllowed);
        }
    };
    let found: Option<(String, bool, bool, bool)> = conn
        .query_row(
            "SELECT u.username, u.role = 'admin', u.active, u.totp_enabled
             FROM users u
             JOIN ferret_accounts a ON a.user_id = u.id
             JOIN ferret_vaults v ON v.account_id = a.account_id
             WHERE u.id = ?1",
            params![target],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((email, is_admin, active, second_factor)) = found else {
        return Err(ActionError::NotFound);
    };
    if let Some(me) = acting_admin
        && (me == target || is_admin)
    {
        return Err(ActionError::NotAllowed);
    }
    Ok(TargetUser {
        user_id: target,
        email,
        active,
        second_factor,
    })
}

/// Makes a one-time sign-in code for `target`, with the kit's life (24 hours,
/// one use; a newer code revokes the older), and writes
/// `sign_in_code_issued` by `by` to the account's log.
///
/// The account must pass [`target`], be active and have no kit second
/// factor, or the code could never give a session. The kit records who made
/// the code: the administrator, or for the server command the active
/// administrator with the lowest id (with none, [`ActionError::NotAllowed`]).
///
/// The kit's `insert` commits on its own, so the event is written right
/// after it. If the event cannot be written, the account's pending code is
/// revoked again (`revoke_for_user`) and the action fails with the error of
/// the event: no code is left that the log does not show.
pub fn issue_sign_in_code(
    conn: &mut Connection,
    target: i64,
    by: &Actor,
    now: i64,
) -> Result<IssuedCode, ActionError> {
    let user = self::target(conn, by, target)?
        .require_active()?
        .require_no_second_factor()?;
    let created_by = match by {
        Actor::Admin {
            user_id: Some(id), ..
        } => *id,
        _ => lowest_active_admin(conn)?.ok_or(ActionError::NotAllowed)?,
    };
    let code = Zeroizing::new(sign_in_codes::generate());
    let hash = sign_in_codes::hash(&code);
    let expires_at = vole_kit::db::sign_in_codes::insert(conn, user.user_id, &hash, created_by)?;
    if let Err(error) = log::record(conn, user.user_id, EventKind::SignInCodeIssued, by, now) {
        tracing::error!(
            user_id = user.user_id,
            %error,
            "the account log could not be written: the new sign-in code is revoked"
        );
        if let Err(revoke) = vole_kit::db::sign_in_codes::revoke_for_user(conn, user.user_id) {
            tracing::error!(
                user_id = user.user_id,
                error = %revoke,
                "the sign-in code that is not in the account log could not be revoked"
            );
            return Err(revoke.into());
        }
        return Err(error.into());
    }
    Ok(IssuedCode::new(code.to_string(), expires_at))
}

/// The active administrator with the lowest id.
fn lowest_active_admin(conn: &Connection) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM users WHERE role = 'admin' AND active = 1 ORDER BY id LIMIT 1",
        [],
        |r| r.get(0),
    )
    .optional()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(active: bool, second_factor: bool) -> TargetUser {
        TargetUser {
            user_id: 2,
            email: "user@example.com".into(),
            active,
            second_factor,
        }
    }

    #[test]
    fn the_requirements_say_what_is_missing() {
        assert!(user(true, false).require_active().is_ok());
        assert!(matches!(
            user(false, false).require_active(),
            Err(ActionError::Disabled)
        ));
        assert!(user(false, false).require_disabled().is_ok());
        assert!(matches!(
            user(true, false).require_disabled(),
            Err(ActionError::NotDisabled)
        ));
        assert!(user(true, false).require_no_second_factor().is_ok());
        assert!(matches!(
            user(true, true).require_no_second_factor(),
            Err(ActionError::SecondFactor)
        ));
    }

    #[test]
    fn only_an_admin_with_an_account_and_the_command_may_act() {
        let conn = Connection::open_in_memory().expect("a database");
        for by in [
            Actor::Admin {
                user_id: None,
                name: String::new(),
            },
            Actor::Server,
            Actor::Account,
        ] {
            assert!(
                matches!(target(&conn, &by, 1), Err(ActionError::NotAllowed)),
                "{by:?}"
            );
        }
    }
}
