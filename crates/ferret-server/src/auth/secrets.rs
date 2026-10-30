//! The server's secrets: the OPAQUE set-up, the secret behind the made-up
//! answers for unknown names, and the key that seals login states. Spec: Fase 1
//! § 11.
//!
//! The two files `opaque_setup` and `prelogin_secret` live in the data
//! directory with mode 0600. The database remembers a fingerprint of the
//! set-up (`ferret_meta`, key `setup_fingerprint`), so a lost or swapped file
//! is noticed instead of locking every account out or changing the made-up
//! answers without a word. Every doubt ends the start: nothing here falls back
//! to making a new file once the server has run before.

use std::fmt;
use std::path::Path;

use ferret_core::OsRng;
use ferret_server_auth::{
    CreatePolicy, PreloginSecret, ServerKeys, SetupFingerprint, StartupDecision, StartupRefusal,
    StateSealKey, load_or_create, permissions_enforced, startup_decision,
};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::StartError;

/// The `ferret_meta` key that holds the fingerprint of the OPAQUE set-up.
pub const SETUP_FINGERPRINT_KEY: &str = "setup_fingerprint";

/// What a request needs from the secret files.
pub struct Secrets {
    /// The OPAQUE set-up (`opaque_setup`).
    pub keys: ServerKeys,
    /// The pre-login secret (`prelogin_secret`).
    pub prelogin: PreloginSecret,
    /// The key that seals the state between the two sign-in steps, derived from
    /// the pre-login secret.
    pub seal: StateSealKey,
}

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secrets([redacted])")
    }
}

/// Loads (or, for a database without accounts, creates) the secret files in
/// `data_dir` and checks them against the database before the server serves.
///
/// 1. Counts the accounts and reads the stored fingerprint of the set-up
///    (`ferret_meta`, `setup_fingerprint`). A stored value that is not 32 bytes
///    ends the start.
/// 2. Chooses the policy with [`CreatePolicy::for_database`]: a database that
///    has accounts or a fingerprint never gets a new file.
/// 3. Loads or creates the files (`load_or_create`). A file that is there but
///    wrong (permissions, owner, damage) ends the start under every policy.
/// 4. Asks [`startup_decision`]: `RecordFingerprint` stores the fingerprint,
///    `Refuse(_)` is an error, so the server does not start.
///
/// A server that has accounts and lost or replaced its set-up therefore
/// refuses to start.
pub fn load_secrets(data_dir: &Path, conn: &mut Connection) -> Result<Secrets, StartError> {
    if !permissions_enforced() {
        tracing::warn!(
            "this platform does not enforce the permissions of the secret files; \
             keep the data directory private to the server's user"
        );
    }
    let accounts = has_accounts(conn)?;
    let stored = read_fingerprint(conn)?;
    let policy = CreatePolicy::for_database(accounts, stored);
    let loaded = load_or_create(data_dir, policy, &mut OsRng).map_err(|e| {
        format!(
            "can't load the secret files in {}: {e}. A file that is missing is never \
                 made again once this server has run: restore it from a backup",
            data_dir.display()
        )
    })?;
    match startup_decision(&loaded, stored, accounts) {
        StartupDecision::Proceed => {}
        StartupDecision::RecordFingerprint(fingerprint) => {
            record_fingerprint(conn, &fingerprint)?;
        }
        StartupDecision::Refuse(refusal) => return Err(refusal_text(&refusal, data_dir).into()),
    }
    let seal = StateSealKey::derive(&loaded.prelogin)
        .map_err(|e| format!("can't derive the key that seals login states: {e}"))?;
    Ok(Secrets {
        keys: loaded.keys,
        prelogin: loaded.prelogin,
        seal,
    })
}

/// Whether the database has any account.
fn has_accounts(conn: &Connection) -> Result<bool, StartError> {
    let any: i64 = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM ferret_accounts)", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("can't count the accounts: {e}"))?;
    Ok(any != 0)
}

/// The fingerprint the database remembers, if any. A value of another length
/// or type is an error: it cannot be compared, and a start that cannot
/// compare must not go on.
fn read_fingerprint(conn: &Connection) -> Result<Option<SetupFingerprint>, StartError> {
    let stored: Option<rusqlite::types::Value> = conn
        .query_row(
            "SELECT value FROM ferret_meta WHERE key = ?1",
            [SETUP_FINGERPRINT_KEY],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| format!("can't read the stored fingerprint of the OPAQUE set-up: {e}"))?;
    match stored {
        None => Ok(None),
        Some(rusqlite::types::Value::Blob(bytes)) => {
            let fingerprint: [u8; 32] = bytes.try_into().map_err(|_| {
                format!("the stored fingerprint of the OPAQUE set-up ({SETUP_FINGERPRINT_KEY} in ferret_meta) is not 32 bytes")
            })?;
            Ok(Some(SetupFingerprint(fingerprint)))
        }
        Some(_) => Err(format!(
            "the stored fingerprint of the OPAQUE set-up ({SETUP_FINGERPRINT_KEY} in ferret_meta) is not a blob"
        )
        .into()),
    }
}

/// Stores the fingerprint. If another start stored one a moment before (two
/// first starts at once, which then share one `opaque_setup`), the stored
/// value must be the same, or the start ends.
fn record_fingerprint(
    conn: &mut Connection,
    fingerprint: &SetupFingerprint,
) -> Result<(), StartError> {
    conn.execute(
        "INSERT OR IGNORE INTO ferret_meta (key, value) VALUES (?1, ?2)",
        params![SETUP_FINGERPRINT_KEY, fingerprint.0.as_slice()],
    )
    .map_err(|e| format!("can't store the fingerprint of the OPAQUE set-up: {e}"))?;
    match read_fingerprint(conn)? {
        Some(now_stored) if now_stored == *fingerprint => Ok(()),
        _ => Err("the stored fingerprint of the OPAQUE set-up changed during the start".into()),
    }
}

/// Why the start is refused and what to do about it. No secret is named.
fn refusal_text(refusal: &StartupRefusal, data_dir: &Path) -> String {
    let dir = data_dir.display();
    match refusal {
        StartupRefusal::SetupLostWhileAccountsExist => format!(
            "the OPAQUE set-up is missing from {dir}, but this server has run before: \
             a new one would lock every account out. Restore opaque_setup from a backup"
        ),
        StartupRefusal::SetupReplaced => format!(
            "the OPAQUE set-up in {dir} is not the one this database was made with: \
             every account would be locked out. Restore the right opaque_setup from a backup"
        ),
        StartupRefusal::FingerprintMissingWithAccounts => format!(
            "this database has accounts but no fingerprint of the OPAQUE set-up, so \
             the opaque_setup in {dir} can't be checked. Restore the database or the file \
             from a backup"
        ),
        StartupRefusal::PreloginSecretLost => format!(
            "prelogin_secret is missing from {dir}, but this server has accounts: a new one \
             would change the made-up answers for unknown names. Restore the file from a backup"
        ),
    }
}
