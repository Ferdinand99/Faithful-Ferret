//! Making a one-time sign-in code from the command line
//! (`ferret sign-in-code issue`), for the administrator who has forgotten the
//! master password and so cannot reach the Users page that makes one. The code
//! has the kit's life: 24 hours, one use, and a newer code revokes the older
//! one. It is redeemed on the vault origin's recovery page
//! (`POST /api/auth/redeem`).
//!
//! Spec: Fase 1 § 6.3, step 1: the administrator resets a user through the
//! kit's one-time sign-in code. The command is an addition to the spec: the
//! administrator who has lost the master password cannot reach the page that
//! makes a code, so the code is made on the machine that holds the data.
//!
//! The command runs while the server runs, so it does not take the lock of
//! the data directory: it opens the database beside the server (SQLite's own
//! locking orders the writes) and writes one code with the kit's `insert`, in
//! the kit's own transaction, and then its event in the account log
//! (`sign_in_code_issued`, actor `server_command`); if the event cannot be
//! written the code is revoked again and the command fails (Spec: Fase 1
//! § 6.3, § 11). It refuses while a restore is in progress, and it never
//! makes a database.

use std::fmt;
use std::path::Path;

use ferret_server_auth::normalize_login_name;
use rusqlite::{Connection, OptionalExtension as _, params};
use zeroize::Zeroizing;

use crate::accounts::actions::{self, ActionError};
use crate::accounts::log::Actor;
use crate::backup::restore;
use crate::cli::open_migrated;
use crate::error::StartError;

/// A code that was just made. The text is shown once and never stored in the
/// clear (the database holds its hash), so it is wiped on drop and `Debug`
/// shows nothing.
pub struct IssuedCode {
    code: Zeroizing<String>,
    expires_at: String,
}

impl IssuedCode {
    /// Keeps a code and the time it stops working (UTC, as the kit writes it).
    pub fn new(code: String, expires_at: String) -> Self {
        Self {
            code: Zeroizing::new(code),
            expires_at,
        }
    }

    /// The code, to print once.
    pub fn code(&self) -> &str {
        self.code.as_str()
    }

    /// When the code stops working.
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }
}

impl fmt::Debug for IssuedCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCode")
            .field("code", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Makes a code for the user with `email` in the database of `data_dir`, with
/// the kit's life of 24 hours, through `accounts::actions::issue_sign_in_code`
/// as [`Actor::ServerCommand`]: the event `sign_in_code_issued` is written to
/// the account's log right after the code (and the code is revoked again if
/// that fails), at `now`.
///
/// The user must have a vault account, be active and have no kit second
/// factor (a code cannot pass one yet), or the code could never give a
/// session. Unlike the Users page, the command may make a code for an
/// administrator. The code is recorded as made by the active administrator
/// with the lowest id. The user's earlier pending code, if any, is revoked.
pub fn issue_sign_in_code(
    data_dir: &Path,
    email: &str,
    now: i64,
) -> Result<IssuedCode, StartError> {
    restore::refuse_if_in_progress(data_dir)?;
    let name = normalize_login_name(email)
        .map_err(|_| StartError::from("that is not an e-mail address a user can have"))?;
    let mut conn = open_migrated(data_dir)?;
    let user_id = user_named(&conn, name.as_str())?.ok_or(NO_USER)?;
    actions::issue_sign_in_code(&mut conn, user_id, &Actor::ServerCommand, now).map_err(said)
}

const NO_USER: &str = "no user with a vault has that e-mail address";

/// The kit user with this login name.
fn user_named(conn: &Connection, name: &str) -> rusqlite::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM users WHERE username = ?1",
        params![name],
        |r| r.get(0),
    )
    .optional()
}

/// What the command says when no code was made.
fn said(error: ActionError) -> StartError {
    match error {
        ActionError::NotFound => NO_USER.into(),
        ActionError::Disabled => "that user is disabled: enable the account first".into(),
        ActionError::SecondFactor => {
            "that user has two-factor sign-in on, which a sign-in code cannot pass yet".into()
        }
        // The server command passes the rules of the target; what it can lack
        // is an administrator to record the code under.
        ActionError::NotAllowed => "there is no active administrator".into(),
        ActionError::Store(error) => {
            format!("the sign-in code could not be made and logged in the account log: {error}")
                .into()
        }
        other => format!("no sign-in code was made: {other}").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_issued_code_shows_nothing_when_printed() {
        let issued = IssuedCode::new("sekrit-code".into(), "2026-11-13 10:00:00".into());
        assert_eq!(issued.code(), "sekrit-code");
        assert_eq!(issued.expires_at(), "2026-11-13 10:00:00");
        let shown = format!("{issued:?} {issued:#?}");
        assert!(!shown.contains("sekrit-code"), "{shown}");
        assert!(shown.contains("2026-11-13"), "{shown}");
    }
}
