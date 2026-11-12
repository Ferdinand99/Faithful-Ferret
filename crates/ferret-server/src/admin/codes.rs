//! Making a one-time sign-in code from the command line
//! (`ferret sign-in-code issue`), for the administrator who has forgotten the
//! master password and so cannot reach the Users page that makes one (a later
//! milestone). The code has the kit's life: 24 hours, one use, and a newer code
//! revokes the older one.

use std::fmt;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::{NotImplemented, StartError};

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
/// the kit's life of 24 hours (so it takes no time from the caller).
pub fn issue_sign_in_code(data_dir: &Path, email: &str) -> Result<IssuedCode, StartError> {
    let _ = (data_dir, email);
    Err(NotImplemented("issuing a sign-in code from the command line").into())
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
