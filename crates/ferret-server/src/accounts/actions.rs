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
//!   so no code is left that the log does not show. The event's transaction
//!   asks [`target`] again, so no change of the account between the first
//!   check and the kit's transaction lets a code through.
//! * [`create_invite`], [`resend_invite`] and [`revoke_invite`] are the
//!   invitations of the Users page: at most the kit's 50 pending (which the
//!   kit's `insert` does not count), "send again" as a revoke and a new one in
//!   one transaction. Each asks, in its write, that the actor is still an
//!   active administrator.
//! * [`disable`], [`enable`], [`sign_out_everywhere`] and [`delete`] are
//!   for an administrator on the Users page only: the server command makes
//!   sign-in codes and nothing else, so it is refused here, and with an
//!   administrator acting [`target`] never lets another administrator (or
//!   the administrator's own account) be touched.
//! * [`disable`], [`enable`] and [`sign_out_everywhere`] change the account
//!   and write its event in one `BEGIN IMMEDIATE`, which first asks the actor
//!   and [`target`] again; an event that cannot be written undoes the change.
//!   [`disable`] and [`sign_out_everywhere`] return what they ended, for the
//!   caller to announce after the commit.
//! * [`delete`] removes a disabled account for good, once a good backup set
//!   was made after its last `account_disabled`. It is the one action with no
//!   event: the account's log goes with it (the tables cascade), so it writes
//!   one line to the server's log instead, with the administrator's and the
//!   account's ids and the time, never the e-mail.
//!
//! Spec: Fase 1 § 11 ("The acting account and the target", "Every action on
//! another account writes its event in the same transaction as the change",
//! "Disable, enable and sign out everywhere", "Deletion") and § 6.3 (every
//! code is in the account log).

use std::fmt;

use ferret_server_auth::normalize_login_name;
use rusqlite::{Connection, OptionalExtension as _, TransactionBehavior, params};
use vole_kit::auth::{invites, sign_in_codes};
use vole_kit::db::invites::MAX_PENDING;
use zeroize::Zeroizing;

use crate::accounts::invites::INVITED_ROLE;
use crate::accounts::log::{self, Actor, EventKind};
use crate::admin::codes::IssuedCode;
use crate::auth::session::{Ended, end_all_credentials};
use crate::error::StoreError;

/// Why an action on an account was not taken.
#[derive(Debug)]
pub enum ActionError {
    /// No such account, or one without a vault; for an invitation, no such
    /// pending invitation.
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
    issue_sign_in_code_for(conn, target, by, now).map(|(code, _)| code)
}

/// [`issue_sign_in_code`], with the e-mail of the account the code is for, as
/// the rules found it (the Users page shows it next to the code, and asks the
/// database no second time).
pub fn issue_sign_in_code_for(
    conn: &mut Connection,
    target: i64,
    by: &Actor,
    now: i64,
) -> Result<(IssuedCode, String), ActionError> {
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
    if let Err(error) = log_issued(conn, target, by, now) {
        tracing::error!(
            user_id = user.user_id,
            %error,
            "the sign-in code was not logged: it is revoked"
        );
        if let Err(revoke) = vole_kit::db::sign_in_codes::revoke_for_user(conn, user.user_id) {
            tracing::error!(
                user_id = user.user_id,
                error = %revoke,
                "the sign-in code that is not in the account log could not be revoked"
            );
            return Err(revoke.into());
        }
        return Err(error);
    }
    Ok((IssuedCode::new(code.to_string(), expires_at), user.email))
}

/// The event of a sign-in code that the kit has just stored, in one short
/// write transaction that first asks [`target`] again: the account may have
/// been disabled, made an administrator or given a second factor between the
/// first check and the kit's own transaction. Whatever changed, the event is
/// written only for an account the rules still allow; otherwise the caller
/// revokes the code. A change after this commit revokes the code itself (a
/// disable, a new second factor and every other change of how the account
/// signs in revoke its pending codes).
fn log_issued(conn: &mut Connection, target: i64, by: &Actor, now: i64) -> Result<(), ActionError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    self::target(&tx, by, target)?
        .require_active()?
        .require_no_second_factor()?;
    log::record(&tx, target, EventKind::SignInCodeIssued, by, now)?;
    tx.commit()?;
    Ok(())
}

/// The account of the administrator `by`, if it is one with a known account;
/// else [`ActionError::NotAllowed`].
fn admin_of(by: &Actor) -> Result<i64, ActionError> {
    match by {
        Actor::Admin {
            user_id: Some(id), ..
        } => Ok(*id),
        _ => Err(ActionError::NotAllowed),
    }
}

/// `Ok` when `admin` is an active administrator now (asked in the caller's
/// transaction); else [`ActionError::NotAllowed`]. The page checked the role
/// before; this is the same check at the moment of the write.
fn require_active_admin(conn: &Connection, admin: i64) -> Result<(), ActionError> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM users WHERE id = ?1 AND role = 'admin' AND active = 1",
            params![admin],
            |r| r.get(0),
        )
        .optional()?;
    found.map(|_| ()).ok_or(ActionError::NotAllowed)
}

/// Adds one invitation of [`INVITED_ROLE`] by `by` in the caller's
/// transaction, if fewer than the kit's [`MAX_PENDING`] are pending (the kit's
/// `insert` does not count them); returns the token.
fn add_invite(conn: &Connection, admin: i64) -> Result<Zeroizing<String>, ActionError> {
    if vole_kit::db::invites::count_pending(conn)? >= MAX_PENDING {
        return Err(ActionError::Full);
    }
    let token = Zeroizing::new(invites::generate());
    let hash = invites::hash(&token);
    let id = vole_kit::db::invites::insert(conn, &hash, INVITED_ROLE, "", admin)?;
    tracing::info!(admin = admin, invite_id = id, "an invitation was made");
    Ok(token)
}

/// Makes an invitation by the administrator `by` (an [`Actor::Admin`] with an
/// account, which becomes the invitation's `created_by`; any other actor is
/// [`ActionError::NotAllowed`]): a new token, of which the database keeps only
/// the SHA-256, for an account of [`INVITED_ROLE`], for the kit's seven days.
/// [`ActionError::Full`] when [`MAX_PENDING`] invitations are pending. The
/// token is returned once, to show as a link; it is wiped on drop.
///
/// An invitation is not an action on an account, so it writes no event to an
/// account log (there is no account yet); the log line names the
/// administrator and the invitation's id, never the token.
pub fn create_invite(conn: &mut Connection, by: &Actor) -> Result<Zeroizing<String>, ActionError> {
    let admin = admin_of(by)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_active_admin(&tx, admin)?;
    let token = add_invite(&tx, admin)?;
    tx.commit()?;
    Ok(token)
}

/// "Send again": revokes the pending invitation `id` and makes a new one by
/// `by`, in one transaction, so the old link is dead by the time the new one
/// is shown. [`ActionError::NotFound`] when `id` is not pending (used,
/// revoked, run out or unknown); nothing changes then. Only the invitation
/// row changes: a registration that started with the old link fails at its
/// finish, and nobody else's registration is touched.
pub fn resend_invite(
    conn: &mut Connection,
    id: i64,
    by: &Actor,
) -> Result<Zeroizing<String>, ActionError> {
    let admin = admin_of(by)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_active_admin(&tx, admin)?;
    if !vole_kit::db::invites::revoke(&tx, id)? {
        return Err(ActionError::NotFound);
    }
    let token = add_invite(&tx, admin)?;
    tx.commit()?;
    tracing::info!(
        admin = admin,
        invite_id = id,
        "an invitation was revoked to send it again"
    );
    Ok(token)
}

/// Revokes the pending invitation `id` for the administrator `by`; `false`
/// when it was not pending. A protective action: it needs no fresh
/// confirmation. Only that invitation changes (the kit's `revoke` is one
/// statement by id).
pub fn revoke_invite(conn: &Connection, id: i64, by: &Actor) -> Result<bool, ActionError> {
    let admin = admin_of(by)?;
    require_active_admin(conn, admin)?;
    let revoked = vole_kit::db::invites::revoke(conn, id)?;
    if revoked {
        tracing::info!(admin = admin, invite_id = id, "an invitation was revoked");
    }
    Ok(revoked)
}

/// The administrator `by`, if it is one with a known account who is still an
/// active administrator now (asked in the caller's transaction); anyone else,
/// the server command too, is [`ActionError::NotAllowed`]. The actions of the
/// Users page take only this actor: the server command makes sign-in codes
/// and nothing else (§ 11), and with an administrator acting, [`target`]
/// refuses the administrator's own account and every other administrator.
fn require_page_admin(conn: &Connection, by: &Actor) -> Result<i64, ActionError> {
    let admin = admin_of(by)?;
    require_active_admin(conn, admin)?;
    Ok(admin)
}

/// Disables `target` for `by`: the kit's `active` goes to 0, the user's
/// `session_version` is raised (so the kit's cookies stop too) and every
/// credential of the account ends (`end_all_credentials` with nothing kept:
/// every session on both origins, every device with tokens, every pending
/// sign-in code), with `account_disabled` in the same transaction. The
/// account must pass [`target`] and be active ([`ActionError::Disabled`]
/// when it is disabled already). Returns what ended, for the caller to
/// announce after the commit; renewing the pre-login policy is the caller's.
///
/// This mirrors the kit's `db::users::set_active(.., false)`, which writes
/// the same two columns and revokes the codes, but in a transaction of its
/// own that could not hold the event. The kit's "last administrator" rule is
/// not needed: only an administrator may act ([`require_page_admin`]), and
/// for one [`target`] never lets an administrator be disabled.
pub fn disable(
    conn: &mut Connection,
    target: i64,
    by: &Actor,
    now: i64,
) -> Result<Ended, ActionError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_page_admin(&tx, by)?;
    let user = self::target(&tx, by, target)?.require_active()?;
    tx.execute(
        "UPDATE users SET active = 0, session_version = session_version + 1 WHERE id = ?1",
        params![user.user_id],
    )?;
    let ended = end_all_credentials(&tx, user.user_id, None, now)?;
    log::record(&tx, user.user_id, EventKind::AccountDisabled, by, now)?;
    tx.commit()?;
    Ok(ended)
}

/// Enables the disabled account `target` again for `by`, with
/// `account_enabled` in the same transaction. The account must pass
/// [`target`] and be disabled ([`ActionError::NotDisabled`] otherwise).
/// Nothing that the disable ended comes back: a device it revoked stays
/// revoked and signs in again with the master password. As the kit's
/// `set_active(.., true)` does, a pending sign-in code is revoked (a disabled
/// account cannot be given one, so there is none in practice). Renewing the
/// pre-login policy is the caller's.
pub fn enable(conn: &mut Connection, target: i64, by: &Actor, now: i64) -> Result<(), ActionError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_page_admin(&tx, by)?;
    let user = self::target(&tx, by, target)?.require_disabled()?;
    tx.execute(
        "UPDATE users SET active = 1 WHERE id = ?1",
        params![user.user_id],
    )?;
    vole_kit::db::sign_in_codes::revoke_for_user(&tx, user.user_id)?;
    log::record(&tx, user.user_id, EventKind::AccountEnabled, by, now)?;
    tx.commit()?;
    Ok(())
}

/// Signs `target` out everywhere for `by`: the user's `session_version` is
/// raised and every credential ends (`end_all_credentials` with nothing
/// kept), as a change of the master password does, with
/// `signed_out_everywhere` in the same transaction. The account stays as it
/// is (an active one may sign in again at once). Returns what ended, for the
/// caller to announce after the commit.
pub fn sign_out_everywhere(
    conn: &mut Connection,
    target: i64,
    by: &Actor,
    now: i64,
) -> Result<Ended, ActionError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    require_page_admin(&tx, by)?;
    let user = self::target(&tx, by, target)?;
    vole_kit::db::users::bump_session_version(&tx, user.user_id)?;
    let ended = end_all_credentials(&tx, user.user_id, None, now)?;
    log::record(&tx, user.user_id, EventKind::SignedOutEverywhere, by, now)?;
    tx.commit()?;
    Ok(ended)
}

/// The time of the last `account_disabled` event of `user_id`, if its log
/// holds one.
pub fn disabled_at(conn: &Connection, user_id: i64) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT MAX(at) FROM ferret_account_events WHERE user_id = ?1 AND kind = ?2",
        params![user_id, EventKind::AccountDisabled.as_str()],
        |r| r.get(0),
    )
}

/// Whether the last good backup run, which started at `last_good_backup`,
/// started after the disable at `disabled_at`: strictly after, since the time
/// of a set is the start of its run in whole seconds, so a set started in the
/// same second may hold the account as it was just before. `false` when
/// either is unknown.
pub fn backed_up_after(disabled_at: Option<i64>, last_good_backup: Option<i64>) -> bool {
    matches!((disabled_at, last_good_backup), (Some(disabled), Some(good)) if good > disabled)
}

/// Deletes the account `target` for good for `by`: its kit user, and with it
/// (the tables cascade) the account, its vault with every item, its unlock
/// methods, its sessions, devices and tokens, its codes and its log. Nothing
/// of another account is touched.
///
/// In one `BEGIN IMMEDIATE`, in this order, each refusal leaving everything
/// as it was:
/// * the actor is still an active administrator ([`require_page_admin`]) and
///   the account passes [`target`];
/// * the account is disabled ([`ActionError::NotDisabled`]), so its sessions
///   and devices were ended by the disable;
/// * `last_good_backup`, the start of the last good backup run, is strictly
///   after the account's last `account_disabled` ([`backed_up_after`], else
///   [`ActionError::NeedsBackup`], also when the log holds no such event), so
///   the account as it was disabled is in a set and a mistake can be undone
///   with a restore;
/// * `typed_email`, normalized as a sign-in name is, is the account's e-mail
///   ([`ActionError::EmailMismatch`]).
///
/// The one action with no event, since the log goes with the account: after
/// the commit one line goes to the server's log with the administrator's id,
/// the account's id and the time, never the e-mail.
/// Renewing the pre-login policy is the caller's.
pub fn delete(
    conn: &mut Connection,
    target: i64,
    by: &Actor,
    typed_email: &str,
    last_good_backup: Option<i64>,
    now: i64,
) -> Result<(), ActionError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let admin = require_page_admin(&tx, by)?;
    let user = self::target(&tx, by, target)?.require_disabled()?;
    if !backed_up_after(disabled_at(&tx, user.user_id)?, last_good_backup) {
        return Err(ActionError::NeedsBackup);
    }
    let typed = normalize_login_name(typed_email).map_err(|_| ActionError::EmailMismatch)?;
    if typed.as_str() != user.email {
        return Err(ActionError::EmailMismatch);
    }
    if tx.execute("DELETE FROM users WHERE id = ?1", params![user.user_id])? != 1 {
        return Err(ActionError::NotFound);
    }
    tx.commit()?;
    tracing::info!(
        admin = admin,
        user_id = user.user_id,
        at = now,
        "an account was deleted"
    );
    Ok(())
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
