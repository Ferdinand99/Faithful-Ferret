//! Limits per vault: the size of an envelope, the number of rows and the bytes
//! a vault may hold.
//!
//! The limits are checked in the same statement that moves the vault counters
//! (see `store::put_item`), so two writers cannot both pass a check that only
//! one of them fits.

/// What one vault may hold.
///
/// `max_items` counts live rows (the manifest row included), so deleting an item
/// frees its slot. A tombstone stays a row until it is purged, so tombstones have
/// a limit of their own, `max_tombstones`: creating and deleting items cannot
/// grow a vault without bound. `max_bytes` counts the stored sizes of all rows,
/// envelopes and tombstones alike (spec § 8.2, quotas per account).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The largest envelope or tombstone, in bytes.
    pub max_envelope: usize,
    /// The most live rows a vault may hold.
    pub max_items: u32,
    /// The most tombstones a vault may hold until they are purged.
    pub max_tombstones: u32,
    /// The most bytes of envelopes and tombstones a vault may hold.
    pub max_bytes: u64,
}

impl Limits {
    /// The limits of a vault: 64 KiB per envelope, 10 000 live rows, 10 000
    /// tombstones, 256 MiB.
    pub const DEFAULT: Limits = Limits {
        max_envelope: 65_536,
        max_items: 10_000,
        max_tombstones: 10_000,
        max_bytes: 256 * 1024 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Whether an envelope or a tombstone of `len` bytes is within the limit.
pub fn envelope_fits(len: usize, limits: &Limits) -> bool {
    len <= limits.max_envelope
}

/// A size or a limit as SQLite sees it: an `i64`. A value above `i64::MAX`
/// (a limit nobody can reach) is `i64::MAX`.
pub(crate) fn sql_int(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limits_are_the_documented_ones() {
        let limits = Limits::default();
        assert_eq!(limits.max_envelope, 65_536);
        assert_eq!(limits.max_items, 10_000);
        assert_eq!(limits.max_tombstones, 10_000);
        assert_eq!(limits.max_bytes, 268_435_456);
    }

    #[test]
    fn an_envelope_at_the_limit_fits_and_one_byte_more_does_not() {
        let limits = Limits {
            max_envelope: 10,
            ..Limits::DEFAULT
        };
        assert!(envelope_fits(10, &limits));
        assert!(!envelope_fits(11, &limits));
    }

    #[test]
    fn a_value_beyond_i64_saturates() {
        assert_eq!(sql_int(u64::MAX), i64::MAX);
        assert_eq!(sql_int(5), 5);
    }
}
