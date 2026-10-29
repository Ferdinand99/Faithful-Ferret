//! KSF profiles: the Argon2id parameters behind the number the server states.
//!
//! Spec: Fase 1 § 4.2 (table "KSF-profiler"). The server states only the
//! number; the client looks it up in its own table. The parameters never
//! travel over the network.

use crate::error::Error;
use crate::prim::{KDF_FLOOR, KdfParams};

/// A key-stretching profile of suite 1.
///
/// Profile 1 is 64 MiB, 3 passes, 1 lane (the floor of Fase 1 § 4.1). Later
/// profiles are added here, never removed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KsfProfile {
    /// 64 MiB (65 536 KiB), `t = 3`, `p = 1`.
    P1 = 1,
}

impl KsfProfile {
    /// The profile for the number a server (or a stored record) states. An
    /// unknown number is a hard error and nothing is computed.
    ///
    /// Spec: Fase 1 § 4.2 ("Ukjent profil ... er en hard feil").
    pub fn from_wire(n: u32) -> Result<Self, Error> {
        match n {
            1 => Ok(KsfProfile::P1),
            _ => Err(Error::KdfProfileUnknown),
        }
    }

    /// The number of the profile as it is stored and pinned.
    pub const fn number(self) -> u8 {
        match self {
            KsfProfile::P1 => 1,
        }
    }

    /// The Argon2id parameters of the profile. They are also the `kdf` field
    /// of the password wrap's AAD (Fase 1 § 4.3).
    ///
    /// Spec: Fase 1 § 4.2 (table "KSF-profiler"): profile 1 is 64 MiB,
    /// `t = 3`, `p = 1`.
    pub const fn params(self) -> KdfParams {
        match self {
            KsfProfile::P1 => KDF_FLOOR,
        }
    }
}
