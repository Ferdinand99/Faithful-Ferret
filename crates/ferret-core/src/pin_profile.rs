//! The PIN profiles: the Argon2id parameters behind the number that is stored
//! with a local PIN wrap.
//!
//! Spec: Fase 1 § 7.2. A PIN has few combinations, so the cost of one guess
//! is the only thing that scales against a copy of the browser profile. The
//! profile is therefore much stronger than the sign-in profile, and its
//! number is stored with the blob and bound into the wrap's AAD (`kdf`). An
//! unknown profile is a hard error before any Argon2id is run.

use crate::error::Error;
use crate::prim::KdfParams;

/// The parameters of PIN profile 1: 256 MiB (262 144 KiB), 3 passes, 1 lane.
///
/// Why these numbers: the PIN wrap sits in a profile copy, where the guess
/// rate is limited only by the attacker's hardware. 256 MiB is the same
/// memory as the export profile, it is proven in WebAssembly, it is below the
/// 512 MiB ceiling, and the memory makes parallel guessing costly (32
/// guesses at once need 8 GiB). The profile is stored in each blob and can be
/// raised only by a new profile (which makes every stored PIN void), so the
/// number is the strongest one that still fits the time budget of a weak
/// machine.
///
/// These values are provisional: the measurements of the PIN profile
/// (256/3, 192/3 and 128/4 MiB, on a fast and on a weak machine) may lower
/// them before the first release. This constant is the one place to change.
/// Once a release has stored a PIN wrap under profile 1, the numbers never
/// change for it; a stronger or weaker choice is a new profile.
pub const PIN_PROFILE_1_PARAMS: KdfParams = KdfParams {
    m_kib: 262_144,
    t: 3,
    p: 1,
};

/// Guesses per second that one powerful machine reaches against PIN profile
/// one. It is the one number that the texts about the offline cost of a PIN
/// read (the admin page and the extension). Provisional, like
/// [`PIN_PROFILE_1_PARAMS`].
pub const PIN_OFFLINE_GUESSES_PER_SECOND: u32 = 100;

/// A PIN profile.
///
/// Later profiles are added here, never removed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PinProfile {
    /// 256 MiB, `t = 3`, `p = 1` (see [`PIN_PROFILE_1_PARAMS`]).
    P1 = 1,
}

/// The lowest profile a device accepts for a stored PIN wrap. A wrap with a
/// lower profile is refused before any Argon2id is run.
pub const PIN_PROFILE_MIN: PinProfile = PinProfile::P1;

impl PinProfile {
    /// The profile for the number a stored record states. An unknown number
    /// is a hard error and nothing is computed; so is a known profile below
    /// [`PIN_PROFILE_MIN`].
    ///
    /// Errors: [`Error::KdfProfileUnknown`], [`Error::KdfProfileDowngrade`].
    pub fn from_wire(n: u32) -> Result<Self, Error> {
        let profile = match n {
            1 => PinProfile::P1,
            _ => return Err(Error::KdfProfileUnknown),
        };
        profile.at_least_min()
    }

    /// The profile itself if it is not below [`PIN_PROFILE_MIN`], else
    /// [`Error::KdfProfileDowngrade`].
    pub fn at_least_min(self) -> Result<Self, Error> {
        if self < PIN_PROFILE_MIN {
            return Err(Error::KdfProfileDowngrade);
        }
        Ok(self)
    }

    /// The number of the profile as it is stored.
    pub const fn number(self) -> u8 {
        match self {
            PinProfile::P1 => 1,
        }
    }

    /// The Argon2id parameters of the profile. They are also the `kdf` field
    /// of the PIN wrap's AAD.
    pub const fn params(self) -> KdfParams {
        match self {
            PinProfile::P1 => PIN_PROFILE_1_PARAMS,
        }
    }
}
