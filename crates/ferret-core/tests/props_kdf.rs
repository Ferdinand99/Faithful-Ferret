//! Property tests for the Argon2id parameter gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::prim::{argon2_run_count, argon2id};
use ferret_core::{Error, KDF_CEIL, KDF_FLOOR, KdfParams, check_kdf_params};
use proptest::prelude::*;

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

/// Whether `p` is inside the floor and the ceiling in every dimension.
fn inside(p: KdfParams) -> bool {
    (KDF_FLOOR.m_kib..=KDF_CEIL.m_kib).contains(&p.m_kib)
        && (KDF_FLOOR.t..=KDF_CEIL.t).contains(&p.t)
        && (KDF_FLOOR.p..=KDF_CEIL.p).contains(&p.p)
}

/// Memory, passes and lanes with a bias to the edges of the range, where an
/// off-by-one in the gate would sit.
fn params() -> impl Strategy<Value = KdfParams> {
    let m = prop_oneof![
        any::<u32>(),
        (KDF_FLOOR.m_kib - 2..=KDF_FLOOR.m_kib + 2),
        (KDF_CEIL.m_kib - 2..=KDF_CEIL.m_kib + 2),
        Just(0u32),
        Just(u32::MAX),
    ];
    let t = prop_oneof![
        any::<u32>(),
        (KDF_FLOOR.t - 2..=KDF_FLOOR.t + 2),
        (KDF_CEIL.t - 2..=KDF_CEIL.t + 2),
        Just(0u32),
        Just(u32::MAX),
    ];
    let p = prop_oneof![any::<u32>(), (0u32..=KDF_CEIL.p + 2), Just(u32::MAX),];
    (m, t, p).prop_map(|(m_kib, t, p)| KdfParams { m_kib, t, p })
}

proptest! {
    #![proptest_config(config())]

    /// Any `(m, t, p)` outside the range gives `kdf_out_of_range` before
    /// anything is computed: no Argon2 run starts and the output stays as it
    /// was. The gate agrees with the stated range on every input.
    #[test]
    fn kdf_floor_cannot_be_bypassed(p in params()) {
        prop_assert_eq!(check_kdf_params(p).is_ok(), inside(p));
        if !inside(p) {
            let before = argon2_run_count();
            let mut out = [0u8; 32];
            prop_assert_eq!(
                argon2id(b"password", b"saltsalt", p, &mut out),
                Err(Error::KdfOutOfRange)
            );
            prop_assert_eq!(check_kdf_params(p), Err(Error::KdfOutOfRange));
            prop_assert_eq!(argon2_run_count(), before);
            prop_assert_eq!(out, [0u8; 32]);
        }
    }
}
