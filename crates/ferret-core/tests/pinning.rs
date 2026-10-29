//! The pinned record and its checks (Fase 1 § 4.2 and § 4.3, plan U19).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::TestRng;
use ferret_core::{
    Error, Kek, KsfProfile, Method, Pinned, PinnedField, ServerView, UnlockedVault, VaultContext,
    WrapRecord, unwrap_vk, wrap_vk,
};

const URL: &str = "https://ferret.example";
const SERVER_KEY: [u8; 32] = [0x99; 32];

struct Fixture {
    ctx: VaultContext,
    rec: WrapRecord,
    vault: UnlockedVault,
    pinned: Pinned,
}

fn seal(
    c: &VaultContext,
    method_id_byte: u8,
    generation: u64,
    method: Method,
    vk_byte: u8,
) -> (WrapRecord, UnlockedVault) {
    let k = Kek::from_test_bytes([9; 32]);
    let mut rng = TestRng::new(b"pinning");
    let rec = wrap_vk(
        &mut rng,
        c,
        &vk(vk_byte),
        &k,
        method_id(method_id_byte),
        generation,
        method,
    )
    .unwrap();
    let vault = unwrap_vk(c, &k, &rec).unwrap();
    (rec, vault)
}

fn fixture() -> Fixture {
    let c = ctx();
    let (rec, vault) = seal(&c, 0x70, 1, password_method(), 0x5a);
    let pinned = Pinned::first_unlock(
        URL,
        KsfProfile::P1,
        true,
        Some(SERVER_KEY),
        &c,
        &rec,
        &vault,
    )
    .unwrap();
    Fixture {
        ctx: c,
        rec,
        vault,
        pinned,
    }
}

fn seen() -> ServerView<'static> {
    ServerView {
        server_url: URL,
        sk_bit: true,
        server_public_key: Some(SERVER_KEY),
    }
}

fn pinned_error(field: PinnedField) -> Error {
    Error::Pinned(field)
}

#[test]
fn first_unlock_pins_what_the_unlock_showed() {
    let f = fixture();
    assert_eq!(f.pinned.server_url, URL);
    assert_eq!(f.pinned.account_id, f.ctx.account_id);
    assert_eq!(f.pinned.ksf_profile, 1);
    assert_eq!(f.pinned.kek_generation_max, vec![(method_id(0x70), 1)]);
    assert_eq!(f.pinned.vk_epoch_max, 1);
    assert!(f.pinned.sk_bit);
    assert_eq!(f.pinned.pk_a, f.vault.auth_public_key());
    assert_eq!(f.pinned.server_public_key, Some(SERVER_KEY));
    f.pinned.check_unlock(&f.ctx, &f.rec, &seen()).unwrap();
    f.pinned.check_unlocked(&f.vault).unwrap();
}

#[test]
fn pinned_rejects_lower_generation_epoch_profile() {
    // Lower kek_generation than seen for that wrap.
    let mut f = fixture();
    f.pinned.kek_generation_max = vec![(method_id(0x70), 3)];
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &seen()),
        Err(pinned_error(PinnedField::KekGeneration))
    );
    assert_eq!(
        Error::Pinned(PinnedField::KekGeneration).code(),
        "pinned_kek_generation"
    );

    // Lower vk_epoch than seen.
    let mut f = fixture();
    f.pinned.vk_epoch_max = 2;
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &seen()),
        Err(pinned_error(PinnedField::VkEpoch))
    );
    assert_eq!(
        f.pinned.check_unlocked(&f.vault),
        Err(pinned_error(PinnedField::VkEpoch))
    );

    // KSF profile below the pinned one: a downgrade.
    let mut f = fixture();
    f.pinned.ksf_profile = 2;
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &seen()),
        Err(Error::KdfProfileDowngrade)
    );
}

#[test]
fn pinned_allows_the_upgrade_paths_only() {
    let f = fixture();

    // A higher kek_generation (a changed password) and a higher epoch (a
    // rekey) are allowed.
    let c2 = VaultContext {
        vk_epoch: 2,
        ..f.ctx
    };
    let (rec2, vault2) = seal(&c2, 0x70, 4, password_method(), 0x5b);
    f.pinned.check_unlock(&c2, &rec2, &seen()).unwrap();
    // pk_a is new in a new epoch, by design.
    assert_ne!(vault2.auth_public_key(), f.pinned.pk_a);
    f.pinned.check_unlocked(&vault2).unwrap();

    // The same wrap with an equal generation and epoch is fine, too.
    f.pinned.check_unlock(&f.ctx, &f.rec, &seen()).unwrap();

    // But within the pinned epoch another vault key (so another pk_a) is not.
    let (_, other) = seal(&f.ctx, 0x70, 1, password_method(), 0x5c);
    assert_eq!(
        f.pinned.check_unlocked(&other),
        Err(pinned_error(PinnedField::AuthKey))
    );
}

#[test]
fn pinned_sk_bit_mismatch_is_hard_error() {
    let f = fixture();
    // Pinned "SK: yes", the server says "no SK".
    let view = ServerView {
        sk_bit: false,
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::SkBit))
    );
    // And the other way round.
    let mut p = f.pinned.clone();
    p.sk_bit = false;
    assert_eq!(
        p.check_unlock(&f.ctx, &f.rec, &seen()),
        Err(pinned_error(PinnedField::SkBit))
    );
    // A hard error is not a decryption error ("wrong password").
    assert_ne!(pinned_error(PinnedField::SkBit), Error::Decrypt);
    assert_eq!(pinned_error(PinnedField::SkBit).code(), "pinned_sk_bit");
}

#[test]
fn pinned_rejects_another_account_server_or_server_key() {
    let f = fixture();

    let mut c2 = f.ctx;
    c2.account_id = account(0x12);
    assert_eq!(
        f.pinned.check_unlock(&c2, &f.rec, &seen()),
        Err(pinned_error(PinnedField::AccountId))
    );

    let view = ServerView {
        server_url: "https://ferret.example.evil",
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::ServerUrl))
    );
    // Exact comparison: not even the case of the host may differ.
    let view = ServerView {
        server_url: "https://Ferret.example",
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::ServerUrl))
    );

    // Another OPAQUE server public key, and none at all while one is pinned.
    let view = ServerView {
        server_public_key: Some([0x98; 32]),
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::ServerKey))
    );
    let view = ServerView {
        server_public_key: None,
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::ServerKey))
    );
}

#[test]
fn an_unpinned_server_key_is_filled_in_once_and_then_fixed() {
    let mut f = fixture();
    f.pinned.server_public_key = None;
    f.pinned.check_unlock(&f.ctx, &f.rec, &seen()).unwrap();
    f.pinned
        .accept_unlock(&f.ctx, &f.rec, &seen(), &f.vault)
        .unwrap();
    assert_eq!(f.pinned.server_public_key, Some(SERVER_KEY));
    let view = ServerView {
        server_public_key: Some([0x98; 32]),
        ..seen()
    };
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &view),
        Err(pinned_error(PinnedField::ServerKey))
    );
}

#[test]
fn generations_are_tracked_per_wrap() {
    // A password change raises the password wrap's generation. The recovery
    // wrap keeps its own, lower counter and must still be accepted.
    let mut f = fixture();
    let (pw3, _) = seal(&f.ctx, 0x70, 3, password_method(), 0x5a);
    f.pinned
        .accept_unlock(&f.ctx, &pw3, &seen(), &f.vault)
        .unwrap();
    assert_eq!(f.pinned.kek_generation_max, vec![(method_id(0x70), 3)]);

    let (recovery1, _) = seal(&f.ctx, 0x71, 1, Method::Recovery, 0x5a);
    f.pinned.check_unlock(&f.ctx, &recovery1, &seen()).unwrap();

    // The old password wrap is now a rollback.
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &f.rec, &seen()),
        Err(pinned_error(PinnedField::KekGeneration))
    );
    // A lower recovery generation is rejected once the recovery wrap has
    // been seen at a higher one.
    let (recovery2, _) = seal(&f.ctx, 0x71, 2, Method::Recovery, 0x5a);
    f.pinned
        .accept_unlock(&f.ctx, &recovery2, &seen(), &f.vault)
        .unwrap();
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &recovery1, &seen()),
        Err(pinned_error(PinnedField::KekGeneration))
    );
}

#[test]
fn accept_unlock_records_maxima_and_a_failed_check_changes_nothing() {
    let mut f = fixture();

    // A rekey: epoch 2, a new vault key, a higher generation.
    let c2 = VaultContext {
        vk_epoch: 2,
        ..f.ctx
    };
    let (rec2, vault2) = seal(&c2, 0x70, 2, password_method(), 0x5b);
    f.pinned
        .accept_unlock(&c2, &rec2, &seen(), &vault2)
        .unwrap();
    assert_eq!(f.pinned.vk_epoch_max, 2);
    assert_eq!(f.pinned.pk_a, vault2.auth_public_key());
    assert_eq!(f.pinned.kek_generation_max, vec![(method_id(0x70), 2)]);

    // The old epoch is now a rollback, even for a wrap whose generation is
    // not lower.
    let (old_epoch_rec, _) = seal(&f.ctx, 0x70, 2, password_method(), 0x5a);
    assert_eq!(
        f.pinned.check_unlock(&f.ctx, &old_epoch_rec, &seen()),
        Err(pinned_error(PinnedField::VkEpoch))
    );

    // A failing accept leaves the record exactly as it was.
    let before = f.pinned.clone();
    let view = ServerView {
        sk_bit: false,
        ..seen()
    };
    assert!(f.pinned.accept_unlock(&c2, &rec2, &view, &vault2).is_err());
    assert_eq!(f.pinned, before);
    assert!(
        f.pinned
            .accept_unlock(&f.ctx, &f.rec, &seen(), &f.vault)
            .is_err()
    );
    assert_eq!(f.pinned, before);

    // A vault whose context is not the one presented is refused.
    assert!(
        f.pinned
            .accept_unlock(&c2, &rec2, &seen(), &f.vault)
            .is_err()
    );
    assert_eq!(f.pinned, before);
}

#[test]
fn local_wraps_start_their_own_generation_entry() {
    // A PIN or device wrap has an id the record has never seen: accepted
    // (its generation starts a new entry), and it never lowers a profile.
    let mut f = fixture();
    let (pin_rec, pin_vault) = seal(&f.ctx, 0x78, 1, pin_method(), 0x5a);
    f.pinned.check_unlock(&f.ctx, &pin_rec, &seen()).unwrap();
    f.pinned
        .accept_unlock(&f.ctx, &pin_rec, &seen(), &pin_vault)
        .unwrap();
    assert_eq!(f.pinned.ksf_profile, 1);
    assert_eq!(f.pinned.kek_generation_max.len(), 2);
}

#[test]
fn first_unlock_refuses_a_vault_of_another_context() {
    let f = fixture();
    let other = VaultContext {
        vk_epoch: 5,
        ..f.ctx
    };
    assert!(
        Pinned::first_unlock(URL, KsfProfile::P1, true, None, &other, &f.rec, &f.vault).is_err()
    );
}
