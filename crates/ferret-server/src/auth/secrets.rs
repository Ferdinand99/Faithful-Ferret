//! The server's secrets: the OPAQUE set-up, the secret behind the made-up
//! answers for unknown names, and the key that seals login states. Spec: Fase 1
//! § 11.

use std::fmt;
use std::path::Path;

use ferret_server_auth::{PreloginSecret, ServerKeys, StateSealKey};
use rusqlite::Connection;

use crate::error::{NotImplemented, StartError};

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
/// `data_dir` and checks them against the database before the server serves:
/// a server that has accounts and lost its set-up refuses to start. Not yet
/// built: it says so.
pub fn load_secrets(_data_dir: &Path, _conn: &mut Connection) -> Result<Secrets, StartError> {
    Err(NotImplemented("loading the secrets").into())
}
