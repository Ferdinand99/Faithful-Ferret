//! Text handling: Unicode normalization of passwords (NFKD, Unicode 16.0
//! tables locked for suite 1) and the rules for the master password and the
//! export password. Spec: Fase 1 section 3.1 and 4.1.

pub mod password;
pub mod pin;
pub mod unicode;

pub use password::{ExportPassword, MasterPassword, MpPolicy, OpaqueInput};
pub use pin::{PIN_MAX_DIGITS, PIN_MIN_DIGITS, Pin};
