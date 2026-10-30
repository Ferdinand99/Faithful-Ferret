//! The pinned record and its two unlock entry points (Fase 1 § 4.2 and
//! § 4.3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::pinning::{MAX_CREDENTIAL_ID_LEN, MAX_FLOORS, MAX_GENERATION, MAX_URL_LEN};
use ferret_core::testing::TestRng;
use ferret_core::testing::keys::unlocked_vault_keys;
use ferret_core::{
    Error, Kek, KsfProfile, MalformedKind, Manifest, ManifestEntry, Method, MethodFloor, MethodKey,
    MethodManifestView, Pinned, PinnedField, ServerView, UnlockedVault, VaultContext, WrapRecord,
    wrap_vk,
};

use ferret_core::testing::pinning::{seed_from_view, view_from_manifest};

/// Seeding from a view that a test made by hand (only possible with
/// `test-support`; a release seeds from a decrypted manifest).
trait SeedView {
    fn seed_from_manifest_view(&mut self, view: &MethodManifestView) -> Result<(), Error>;
}

impl SeedView for Pinned {
    fn seed_from_manifest_view(&mut self, view: &MethodManifestView) -> Result<(), Error> {
        seed_from_view(self, view)
    }
}

const URL: &str = "https://ferret.example";
const SERVER_KEY: [u8; 32] = [0x99; 32];
const KEK: [u8; 32] = [9; 32];

fn kek() -> Kek {
    Kek::from_test_bytes(KEK)
}

fn seal(
    c: &VaultContext,
    method_id_byte: u8,
    generation: u64,
    method: Method,
    vk_byte: u8,
) -> WrapRecord {
    let mut rng = TestRng::new(b"pinning");
    wrap_vk(
        &mut rng,
        c,
        &vk(vk_byte),
        &kek(),
        method_id(method_id_byte),
        generation,
        method,
    )
    .unwrap()
}

struct Fixture {
    ctx: VaultContext,
    rec: WrapRecord,
    pinned: Pinned,
}

fn fixture() -> Fixture {
    let c = ctx();
    let rec = seal(&c, 0x70, 1, password_method(), 0x5a);
    let (pinned, vault) =
        Pinned::first_unlock(URL, true, Some(SERVER_KEY), &c, &rec, &kek()).unwrap();
    assert_eq!(unlocked_vault_keys(&vault)[0], [0x5a; 32]);
    Fixture {
        ctx: c,
        rec,
        pinned,
    }
}

fn view(c: VaultContext) -> ServerView<'static> {
    ServerView {
        server_url: URL,
        context: c,
        sk_bit: true,
        server_public_key: Some(SERVER_KEY),
    }
}

fn pinned_error(field: PinnedField) -> Error {
    Error::Pinned(field)
}

fn unlock(f: &mut Fixture, rec: &WrapRecord) -> Result<UnlockedVault, Error> {
    f.pinned.unlock_server(&view(f.ctx), rec, &kek())
}

fn floor(p: &Pinned, key: &MethodKey) -> Option<u64> {
    p.kek_generation_max
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, g)| *g)
}

#[test]
fn first_unlock_pins_what_the_unlock_showed() {
    let f = fixture();
    assert_eq!(f.pinned.server_url, URL);
    assert_eq!(f.pinned.account_id, f.ctx.account_id);
    assert_eq!(f.pinned.vault_id, f.ctx.vault_id);
    assert_eq!(f.pinned.ksf_profile, 1);
    assert_eq!(f.pinned.kek_generation_max, vec![(MethodKey::Password, 1)]);
    assert_eq!(f.pinned.vk_epoch_max, 1);
    assert!(f.pinned.sk_bit);
    assert_eq!(f.pinned.server_public_key, Some(SERVER_KEY));
    let mut f = f;
    let rec = f.rec.clone();
    let vault = unlock(&mut f, &rec).unwrap();
    assert_eq!(f.pinned.pk_a, vault.auth_public_key());
}

#[test]
fn first_unlock_needs_a_server_wrap_and_a_good_kek() {
    let c = ctx();
    for method in [pin_method(), Method::Device] {
        let rec = seal(&c, 0x78, 1, method, 0x5a);
        assert_eq!(
            Pinned::first_unlock(URL, true, None, &c, &rec, &kek()).err(),
            Some(Error::Unsupported)
        );
    }
    let rec = seal(&c, 0x70, 1, password_method(), 0x5a);
    let wrong = Kek::from_test_bytes([10; 32]);
    assert_eq!(
        Pinned::first_unlock(URL, true, None, &c, &rec, &wrong).err(),
        Some(Error::Decrypt)
    );
    let long_url = "u".repeat(MAX_URL_LEN + 1);
    assert_eq!(
        Pinned::first_unlock(&long_url, true, None, &c, &rec, &kek()).err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
}

#[test]
fn pinned_rejects_lower_generation_epoch_profile() {
    // Lower kek_generation than seen for the password wrap.
    let mut f = fixture();
    f.pinned.kek_generation_max = vec![(MethodKey::Password, 3)];
    let rec = f.rec.clone();
    assert_eq!(
        unlock(&mut f, &rec).err(),
        Some(pinned_error(PinnedField::KekGeneration))
    );
    assert_eq!(
        Error::Pinned(PinnedField::KekGeneration).code(),
        "pinned_kek_generation"
    );

    // Lower vk_epoch than seen.
    let mut f = fixture();
    f.pinned.vk_epoch_max = 2;
    let rec = f.rec.clone();
    assert_eq!(
        unlock(&mut f, &rec).err(),
        Some(pinned_error(PinnedField::VkEpoch))
    );

    // KSF profile below the pinned one: a downgrade.
    let mut f = fixture();
    f.pinned.ksf_profile = 2;
    let rec = f.rec.clone();
    assert_eq!(unlock(&mut f, &rec).err(), Some(Error::KdfProfileDowngrade));
}

#[test]
fn the_password_floor_survives_a_new_method_id() {
    // Review: a password change that mints a fresh method_id must not reset
    // the floor. The floor is keyed by method type.
    let mut f = fixture();
    let gen3 = seal(&f.ctx, 0x70, 3, password_method(), 0x5a);
    unlock(&mut f, &gen3).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(3));

    // A password wrap with another id and a lower generation is a rollback.
    let other_id = seal(&f.ctx, 0x7f, 2, password_method(), 0x5a);
    assert_eq!(
        unlock(&mut f, &other_id).err(),
        Some(pinned_error(PinnedField::KekGeneration))
    );
    // With another id and a higher generation it is accepted and the single
    // password floor moves up (there is no second entry).
    let other_id4 = seal(&f.ctx, 0x7f, 4, password_method(), 0x5a);
    unlock(&mut f, &other_id4).unwrap();
    assert_eq!(f.pinned.kek_generation_max, vec![(MethodKey::Password, 4)]);
}

#[test]
fn pinned_allows_the_upgrade_paths_only() {
    let mut f = fixture();

    // A higher kek_generation and a higher epoch (a rekey, with a new vault
    // key and so a new pk_a) are allowed and advance the record.
    let c2 = VaultContext {
        vk_epoch: 2,
        ..f.ctx
    };
    let rec2 = seal(&c2, 0x70, 4, password_method(), 0x5b);
    let vault2 = f.pinned.unlock_server(&view(c2), &rec2, &kek()).unwrap();
    assert_eq!(f.pinned.vk_epoch_max, 2);
    assert_eq!(f.pinned.pk_a, vault2.auth_public_key());
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(4));

    // Within the pinned epoch another vault key (so another pk_a) is not
    // allowed, and the record stays as it was.
    let before = f.pinned.clone();
    let other = seal(&c2, 0x70, 4, password_method(), 0x5c);
    assert_eq!(
        f.pinned.unlock_server(&view(c2), &other, &kek()).err(),
        Some(pinned_error(PinnedField::AuthKey))
    );
    assert_eq!(f.pinned, before);

    // The old epoch is a rollback now, also for a wrap whose generation is
    // not lower.
    let old_epoch = seal(&f.ctx, 0x70, 4, password_method(), 0x5a);
    assert_eq!(
        f.pinned
            .unlock_server(&view(f.ctx), &old_epoch, &kek())
            .err(),
        Some(pinned_error(PinnedField::VkEpoch))
    );
}

#[test]
fn pinned_sk_bit_mismatch_is_hard_error() {
    let mut f = fixture();
    let rec = f.rec.clone();
    // Pinned "SK: yes", the server says "no SK".
    let v = ServerView {
        sk_bit: false,
        ..view(f.ctx)
    };
    assert_eq!(
        f.pinned.unlock_server(&v, &rec, &kek()).err(),
        Some(pinned_error(PinnedField::SkBit))
    );
    // And the other way round.
    f.pinned.sk_bit = false;
    assert_eq!(
        unlock(&mut f, &rec).err(),
        Some(pinned_error(PinnedField::SkBit))
    );
    // A hard error is not a decryption error ("wrong password").
    assert_ne!(pinned_error(PinnedField::SkBit), Error::Decrypt);
    assert_eq!(pinned_error(PinnedField::SkBit).code(), "pinned_sk_bit");
}

#[test]
fn pinned_rejects_another_account_vault_server_or_server_key() {
    let mut f = fixture();
    let rec = f.rec.clone();

    let c2 = VaultContext {
        account_id: account(0x12),
        ..f.ctx
    };
    assert_eq!(
        f.pinned.unlock_server(&view(c2), &rec, &kek()).err(),
        Some(pinned_error(PinnedField::AccountId))
    );
    let c2 = VaultContext {
        vault_id: vault(0x23),
        ..f.ctx
    };
    assert_eq!(
        f.pinned.unlock_server(&view(c2), &rec, &kek()).err(),
        Some(pinned_error(PinnedField::VaultId))
    );

    for url in ["https://ferret.example.evil", "https://Ferret.example"] {
        let v = ServerView {
            server_url: url,
            ..view(f.ctx)
        };
        assert_eq!(
            f.pinned.unlock_server(&v, &rec, &kek()).err(),
            Some(pinned_error(PinnedField::ServerUrl)),
            "{url}"
        );
    }

    // Another OPAQUE server public key, and none at all while one is pinned.
    for key in [Some([0x98; 32]), None] {
        let v = ServerView {
            server_public_key: key,
            ..view(f.ctx)
        };
        assert_eq!(
            f.pinned.unlock_server(&v, &rec, &kek()).err(),
            Some(pinned_error(PinnedField::ServerKey))
        );
    }
}

#[test]
fn an_unpinned_server_key_is_filled_in_once_and_then_fixed() {
    let mut f = fixture();
    f.pinned.server_public_key = None;
    let rec = f.rec.clone();
    unlock(&mut f, &rec).unwrap();
    assert_eq!(f.pinned.server_public_key, Some(SERVER_KEY));
    let v = ServerView {
        server_public_key: Some([0x98; 32]),
        ..view(f.ctx)
    };
    assert_eq!(
        f.pinned.unlock_server(&v, &rec, &kek()).err(),
        Some(pinned_error(PinnedField::ServerKey))
    );
}

#[test]
fn a_failed_unlock_changes_nothing() {
    let mut f = fixture();
    let old = f.rec.clone();
    let rec3 = seal(&f.ctx, 0x70, 3, password_method(), 0x5a);
    unlock(&mut f, &rec3).unwrap();
    let before = f.pinned.clone();

    // A wrong KEK: the pins pass, the wrap does not open.
    let rec4 = seal(&f.ctx, 0x70, 4, password_method(), 0x5a);
    assert_eq!(
        f.pinned
            .unlock_server(&view(f.ctx), &rec4, &Kek::from_test_bytes([10; 32]))
            .err(),
        Some(Error::Decrypt)
    );
    assert_eq!(f.pinned, before, "wrong KEK");

    // A tampered wrap.
    let mut bad = rec4.clone();
    bad.wrap[40] ^= 1;
    assert_eq!(unlock(&mut f, &bad).err(), Some(Error::Decrypt));
    assert_eq!(f.pinned, before, "tampered wrap");

    // A rollback.
    assert!(unlock(&mut f, &old).is_err());
    assert_eq!(f.pinned, before, "rollback");

    // Another vault key in the same epoch.
    let other = seal(&f.ctx, 0x70, 4, password_method(), 0x5c);
    assert_eq!(
        unlock(&mut f, &other).err(),
        Some(pinned_error(PinnedField::AuthKey))
    );
    assert_eq!(f.pinned, before, "pk_a mismatch");

    // A passkey wrap would create a new floor key; with the wrong KEK it
    // fails after every pin check has passed, and no floor is created.
    let prf = seal(&f.ctx, 0x75, 2, prf_method(), 0x5a);
    let Method::Prf { credential_id, .. } = prf_method() else {
        unreachable!()
    };
    assert_eq!(
        f.pinned
            .unlock_server(&view(f.ctx), &prf, &Kek::from_test_bytes([10; 32]))
            .err(),
        Some(Error::Decrypt)
    );
    assert_eq!(f.pinned, before, "failed passkey unlock");
    assert_eq!(
        floor(&f.pinned, &MethodKey::Prf(credential_id.clone())),
        None
    );
    // The same wrap made for another vault key fails on pk_a, still without a
    // new floor.
    let prf_other = seal(&f.ctx, 0x75, 2, prf_method(), 0x5c);
    assert_eq!(
        unlock(&mut f, &prf_other).err(),
        Some(pinned_error(PinnedField::AuthKey))
    );
    assert_eq!(f.pinned, before, "passkey wrap of another vault key");

    // And the good one still works afterwards.
    unlock(&mut f, &rec4).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(4));
    unlock(&mut f, &prf).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(credential_id)), Some(2));
}

#[test]
fn a_failed_unlock_does_not_pin_the_server_key() {
    let mut f = fixture();
    f.pinned.server_public_key = None;
    let before = f.pinned.clone();
    let rec = f.rec.clone();

    // A wrong KEK: the server key is shown, but nothing is pinned.
    assert_eq!(
        f.pinned
            .unlock_server(&view(f.ctx), &rec, &Kek::from_test_bytes([10; 32]))
            .err(),
        Some(Error::Decrypt)
    );
    assert_eq!(f.pinned, before, "wrong KEK");
    assert_eq!(f.pinned.server_public_key, None);

    // Another vault key in the pinned epoch: the pk_a check fails last, after
    // the wrap opened, and still nothing is pinned.
    let other = seal(&f.ctx, 0x70, 1, password_method(), 0x5c);
    assert_eq!(
        unlock(&mut f, &other).err(),
        Some(pinned_error(PinnedField::AuthKey))
    );
    assert_eq!(f.pinned, before, "pk_a mismatch");
    assert_eq!(f.pinned.server_public_key, None);

    // A rollback of the generation is refused before the wrap is opened.
    let mut ahead = fixture();
    ahead.pinned.server_public_key = None;
    ahead.pinned.kek_generation_max = vec![(MethodKey::Password, 5)];
    let before = ahead.pinned.clone();
    assert_eq!(
        unlock(&mut ahead, &rec).err(),
        Some(pinned_error(PinnedField::KekGeneration))
    );
    assert_eq!(ahead.pinned, before);
    assert_eq!(ahead.pinned.server_public_key, None);

    // The successful unlock pins the key, once.
    unlock(&mut f, &rec).unwrap();
    assert_eq!(f.pinned.server_public_key, Some(SERVER_KEY));
}

#[test]
fn recovery_and_passkey_floors_are_separate_and_keyed_by_type_and_credential() {
    let mut f = fixture();
    let rec = seal(&f.ctx, 0x71, 1, Method::Recovery, 0x5a);
    unlock(&mut f, &rec).unwrap();
    let prf = seal(&f.ctx, 0x75, 2, prf_method(), 0x5a);
    unlock(&mut f, &prf).unwrap();
    let Method::Prf { credential_id, .. } = prf_method() else {
        unreachable!()
    };
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(1));
    assert_eq!(floor(&f.pinned, &MethodKey::Recovery), Some(1));
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(credential_id)), Some(2));

    // A password change leaves the recovery floor alone.
    let pw3 = seal(&f.ctx, 0x70, 3, password_method(), 0x5a);
    unlock(&mut f, &pw3).unwrap();
    unlock(&mut f, &rec).unwrap();

    // Another passkey starts its own floor.
    let other = Method::Prf {
        credential_id: vec![7; 16],
        prf_salt: [1; 32],
    };
    let o1 = seal(&f.ctx, 0x76, 1, other.clone(), 0x5a);
    unlock(&mut f, &o1).unwrap();
    let o0 = seal(&f.ctx, 0x76, 0, other, 0x5a);
    assert_eq!(
        unlock(&mut f, &o0).err(),
        Some(pinned_error(PinnedField::KekGeneration))
    );
}

#[test]
fn local_wraps_are_never_recorded() {
    let mut f = fixture();
    let before = f.pinned.clone();
    for method in [pin_method(), Method::Device] {
        let rec = seal(&f.ctx, 0x78, u64::MAX, method, 0x5a);
        // Not a server wrap: refused, and nothing recorded.
        assert_eq!(unlock(&mut f, &rec).err(), Some(Error::Unsupported));
        assert_eq!(f.pinned, before);
        // A local unlock records nothing either, whatever the generation.
        f.pinned.unlock_local(&rec, &kek()).unwrap();
        assert_eq!(f.pinned, before);
    }
}

#[test]
fn generations_above_u32_max_are_malformed() {
    let mut f = fixture();
    let huge = seal(&f.ctx, 0x70, MAX_GENERATION + 1, password_method(), 0x5a);
    assert_eq!(
        unlock(&mut f, &huge).err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
    assert_eq!(
        Error::Malformed(MalformedKind::PinnedRecord).code(),
        "malformed_pinned_record"
    );
    let max = seal(&f.ctx, 0x70, MAX_GENERATION, password_method(), 0x5a);
    unlock(&mut f, &max).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(MAX_GENERATION));
}

#[test]
fn the_record_has_a_size_cap() {
    let mut f = fixture();
    // Floors from the manifest: fill up to the cap.
    let methods: Vec<MethodFloor> = (0..u8::try_from(MAX_FLOORS - 1).unwrap())
        .map(|i| MethodFloor {
            key: MethodKey::Prf(vec![i; 16]),
            kek_generation: 1,
        })
        .collect();
    f.pinned
        .seed_from_manifest_view(&MethodManifestView { methods })
        .unwrap();
    assert_eq!(f.pinned.kek_generation_max.len(), MAX_FLOORS);

    // One more key does not fit, and nothing is changed.
    let before = f.pinned.clone();
    let one_more = MethodManifestView {
        methods: vec![MethodFloor {
            key: MethodKey::Prf(vec![0xff; 16]),
            kek_generation: 1,
        }],
    };
    assert_eq!(
        f.pinned.seed_from_manifest_view(&one_more),
        Err(Error::Malformed(MalformedKind::PinnedRecord))
    );
    assert_eq!(f.pinned, before);

    // An unlock with a passkey wrap that would need a new entry is refused
    // before the wrap is opened.
    let prf = seal(&f.ctx, 0x75, 1, prf_method(), 0x5a);
    assert_eq!(
        unlock(&mut f, &prf).err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
    assert_eq!(f.pinned, before);

    // An existing key can still be raised at the cap.
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(vec![0; 16])), Some(1));
    f.pinned
        .seed_from_manifest_view(&MethodManifestView {
            methods: vec![MethodFloor {
                key: MethodKey::Prf(vec![0; 16]),
                kek_generation: 5,
            }],
        })
        .unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(vec![0; 16])), Some(5));
    assert_eq!(f.pinned.kek_generation_max.len(), MAX_FLOORS);
    // The others are untouched, and the password floor too.
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(vec![1; 16])), Some(1));
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(1));

    // A credential id over the limit is malformed.
    let long = MethodManifestView {
        methods: vec![MethodFloor {
            key: MethodKey::Prf(vec![0; MAX_CREDENTIAL_ID_LEN + 1]),
            kek_generation: 1,
        }],
    };
    let mut g = fixture();
    assert_eq!(
        g.pinned.seed_from_manifest_view(&long),
        Err(Error::Malformed(MalformedKind::PinnedRecord))
    );
}

#[test]
fn seed_from_manifest_sets_floors_for_wraps_never_unlocked_with() {
    let mut f = fixture();
    let view_of = |recovery: u64| MethodManifestView {
        methods: vec![
            MethodFloor {
                key: MethodKey::Password,
                kek_generation: 2,
            },
            MethodFloor {
                key: MethodKey::Recovery,
                kek_generation: recovery,
            },
        ],
    };
    f.pinned.seed_from_manifest_view(&view_of(3)).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Recovery), Some(3));
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(2));

    // The recovery wrap of an older generation (a leaked old RK) is refused,
    // although this device never unlocked with a recovery wrap.
    let old_rec = seal(&f.ctx, 0x71, 2, Method::Recovery, 0x5a);
    assert_eq!(
        unlock(&mut f, &old_rec).err(),
        Some(pinned_error(PinnedField::KekGeneration))
    );
    let cur_rec = seal(&f.ctx, 0x71, 3, Method::Recovery, 0x5a);
    unlock(&mut f, &cur_rec).unwrap();

    // Floors only go up: an older manifest does not lower them.
    f.pinned.seed_from_manifest_view(&view_of(1)).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Recovery), Some(3));
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(2));

    // A bad entry anywhere changes nothing.
    let before = f.pinned.clone();
    let bad = MethodManifestView {
        methods: vec![
            MethodFloor {
                key: MethodKey::Recovery,
                kek_generation: 9,
            },
            MethodFloor {
                key: MethodKey::Password,
                kek_generation: MAX_GENERATION + 1,
            },
        ],
    };
    assert!(f.pinned.seed_from_manifest_view(&bad).is_err());
    assert_eq!(f.pinned, before);
}

#[test]
fn unlock_local_checks_account_epoch_and_pk_a_only() {
    let mut f = fixture();
    let rec = f.rec.clone();
    unlock(&mut f, &rec).unwrap();

    // PIN and device wraps open offline, without any server view.
    for method in [pin_method(), Method::Device] {
        let local = seal(&f.ctx, 0x78, 1, method, 0x5a);
        let vault = f.pinned.unlock_local(&local, &kek()).unwrap();
        assert_eq!(unlocked_vault_keys(&vault)[0], [0x5a; 32]);
    }

    // A server wrap goes through unlock_server only.
    assert_eq!(
        f.pinned.unlock_local(&f.rec, &kek()).err(),
        Some(Error::Unsupported)
    );

    // A wrap of another epoch (for example from before a rekey) does not
    // open: the epoch is in the AAD.
    let old = seal(
        &VaultContext {
            vk_epoch: 0,
            ..f.ctx
        },
        0x78,
        1,
        pin_method(),
        0x5a,
    );
    assert_eq!(
        f.pinned.unlock_local(&old, &kek()).err(),
        Some(Error::Decrypt)
    );
    // Another account or vault: the same.
    for c in [
        VaultContext {
            account_id: account(0x12),
            ..f.ctx
        },
        VaultContext {
            vault_id: vault(0x23),
            ..f.ctx
        },
    ] {
        let other = seal(&c, 0x78, 1, pin_method(), 0x5a);
        assert_eq!(
            f.pinned.unlock_local(&other, &kek()).err(),
            Some(Error::Decrypt)
        );
    }
    // A wrap of the right epoch around another vault key: pk_a differs.
    let other_vk = seal(&f.ctx, 0x78, 1, pin_method(), 0x5c);
    assert_eq!(
        f.pinned.unlock_local(&other_vk, &kek()).err(),
        Some(pinned_error(PinnedField::AuthKey))
    );
    // A wrong KEK is the single decrypt error.
    let local = seal(&f.ctx, 0x78, 1, pin_method(), 0x5a);
    assert_eq!(
        f.pinned
            .unlock_local(&local, &Kek::from_test_bytes([10; 32]))
            .err(),
        Some(Error::Decrypt)
    );
}

// ---------------------------------------------------- the method manifest

fn manifest_with(methods: Vec<ManifestEntry>) -> Manifest {
    Manifest::new(1, methods)
}

fn entry(t: u8, id: u8, g: u64) -> ManifestEntry {
    ManifestEntry::new(t, method_id(id), g)
}

#[test]
fn seed_from_manifest_refuses_a_repeated_key() {
    let mut f = fixture();
    let before = f.pinned.clone();
    for key in [
        MethodKey::Password,
        MethodKey::Recovery,
        MethodKey::Prf(vec![1; 16]),
    ] {
        let floor_of = |g| MethodFloor {
            key: key.clone(),
            kek_generation: g,
        };
        // The same key twice is refused, whatever the generations, and the
        // record is left as it was.
        for (a, b) in [(2, 2), (2, 9), (9, 2)] {
            let view = MethodManifestView {
                methods: vec![floor_of(a), floor_of(b)],
            };
            assert_eq!(
                f.pinned.seed_from_manifest_view(&view),
                Err(Error::Malformed(MalformedKind::PinnedRecord))
            );
            assert_eq!(f.pinned, before);
        }
    }
    // A repeat that is not adjacent is found too.
    let view = MethodManifestView {
        methods: vec![
            MethodFloor {
                key: MethodKey::Recovery,
                kek_generation: 1,
            },
            MethodFloor {
                key: MethodKey::Prf(vec![2; 16]),
                kek_generation: 1,
            },
            MethodFloor {
                key: MethodKey::Recovery,
                kek_generation: 1,
            },
        ],
    };
    assert!(f.pinned.seed_from_manifest_view(&view).is_err());
    assert_eq!(f.pinned, before);
}

#[test]
fn seed_from_manifest_stops_before_scanning_a_long_view() {
    let mut f = fixture();
    let before = f.pinned.clone();
    // More entries than the record can hold: refused by length, whether the
    // keys are distinct or not, so the work stays bounded.
    let distinct: Vec<MethodFloor> = (0..=MAX_FLOORS)
        .map(|i| MethodFloor {
            key: MethodKey::Prf(i.to_be_bytes().to_vec()),
            kek_generation: 1,
        })
        .collect();
    assert_eq!(distinct.len(), MAX_FLOORS + 1);
    let huge: Vec<MethodFloor> = (0..200_000)
        .map(|_| MethodFloor {
            key: MethodKey::Recovery,
            kek_generation: 1,
        })
        .collect();
    for methods in [distinct, huge] {
        assert_eq!(
            f.pinned
                .seed_from_manifest_view(&MethodManifestView { methods }),
            Err(Error::Malformed(MalformedKind::PinnedRecord))
        );
        assert_eq!(f.pinned, before);
    }
    // MAX_FLOORS - 1 new keys fit next to the password floor.
    let fits: Vec<MethodFloor> = (0..MAX_FLOORS - 1)
        .map(|i| MethodFloor {
            key: MethodKey::Prf(i.to_be_bytes().to_vec()),
            kek_generation: 1,
        })
        .collect();
    f.pinned
        .seed_from_manifest_view(&MethodManifestView { methods: fits })
        .unwrap();
    assert_eq!(f.pinned.kek_generation_max.len(), MAX_FLOORS);
}

#[test]
fn a_passkey_floor_is_keyed_by_the_credential_id_in_the_manifest() {
    let mut f = fixture();
    let credential = vec![0xa5; 20];
    let manifest = manifest_with(vec![
        entry(1, 0x70, 2),
        entry(2, 0x71, 3),
        ManifestEntry::passkey(method_id(0x75), 6, credential.clone()),
    ]);
    let view = view_from_manifest(&manifest).unwrap();
    assert_eq!(
        view.methods,
        vec![
            MethodFloor {
                key: MethodKey::Password,
                kek_generation: 2
            },
            MethodFloor {
                key: MethodKey::Recovery,
                kek_generation: 3
            },
            MethodFloor {
                key: MethodKey::Prf(credential.clone()),
                kek_generation: 6
            },
        ]
    );
    f.pinned.seed_from_manifest_view(&view).unwrap();
    assert_eq!(
        floor(&f.pinned, &MethodKey::Prf(credential.clone())),
        Some(6)
    );

    // A passkey wrap for that credential below the floor is refused, whatever
    // `method_id` the server shows with it.
    let wrap_for = |cred: &[u8], method_byte: u8, generation: u64| {
        seal(
            &f.ctx,
            method_byte,
            generation,
            Method::Prf {
                credential_id: cred.to_vec(),
                prf_salt: [3; 32],
            },
            0x5a,
        )
    };
    let wraps: Vec<(u8, WrapRecord)> = [0x75u8, 0x76, 0x99]
        .into_iter()
        .map(|b| (b, wrap_for(&credential, b, 5)))
        .collect();
    let current = wrap_for(&credential, 0x75, 6);
    let other = wrap_for(&[0x5a; 20], 0x75, 1);
    for (method_byte, old) in &wraps {
        assert_eq!(
            unlock(&mut f, old).err(),
            Some(pinned_error(PinnedField::KekGeneration)),
            "method id {method_byte:#x}"
        );
    }
    unlock(&mut f, &current).unwrap();

    // A different credential is a different floor: the manifest, not a
    // mapping from the server, says which credential belongs to which entry.
    unlock(&mut f, &other).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(vec![0x5a; 20])), Some(1));
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(credential)), Some(6));
}

#[test]
fn from_manifest_takes_only_server_methods_with_what_it_needs() {
    // PIN, device and unknown method types have no floor.
    let m = manifest_with(vec![
        entry(1, 0x70, 2),
        entry(4, 0x78, 9),
        entry(5, 0x79, 9),
        entry(9, 0x7a, 9),
    ]);
    let view = view_from_manifest(&m).unwrap();
    assert_eq!(
        view.methods,
        vec![MethodFloor {
            key: MethodKey::Password,
            kek_generation: 2
        }]
    );
    assert!(
        view_from_manifest(&manifest_with(vec![]))
            .unwrap()
            .methods
            .is_empty()
    );

    // A passkey entry without a credential id cannot make a floor.
    let missing = manifest_with(vec![entry(3, 0x75, 1)]);
    assert_eq!(
        view_from_manifest(&missing),
        Err(Error::Malformed(MalformedKind::ItemBody))
    );
    // Two entries for one key are not guessed at.
    for pair in [
        vec![entry(1, 0x70, 1), entry(1, 0x72, 2)],
        vec![entry(2, 0x71, 1), entry(2, 0x73, 2)],
        vec![
            ManifestEntry::passkey(method_id(0x75), 1, vec![1]),
            ManifestEntry::passkey(method_id(0x76), 2, vec![1]),
        ],
    ] {
        assert_eq!(
            view_from_manifest(&manifest_with(pair)),
            Err(Error::Malformed(MalformedKind::ItemBody))
        );
    }
    // Two passkeys with different credentials are two floors.
    let two = manifest_with(vec![
        ManifestEntry::passkey(method_id(0x75), 1, vec![1]),
        ManifestEntry::passkey(method_id(0x76), 2, vec![2]),
    ]);
    assert_eq!(view_from_manifest(&two).unwrap().methods.len(), 2);
}

#[test]
fn the_manifest_entry_carries_the_credential_id() {
    let mut m = manifest_with(vec![
        entry(1, 0x70, 2),
        ManifestEntry::passkey(method_id(0x75), 6, vec![0xa5; 20]),
    ]);
    m.methods[0].extra = vec![("label".into(), ferret_core::cbor::Value::text("main"))];
    let bytes = m.to_cbor().unwrap();
    let again = Manifest::from_cbor(&bytes).unwrap();
    assert_eq!(again, m);
    assert_eq!(again.to_cbor().unwrap(), bytes);
    assert_eq!(again.methods[1].credential_id, Some(vec![0xa5; 20]));
    assert_eq!(again.methods[0].credential_id, None);
    // Without a credential id nothing extra is written: an entry that has
    // none is the same bytes as in version 1 of the format.
    let plain = manifest_with(vec![entry(1, 0x70, 2)]).to_cbor().unwrap();
    assert!(!plain.windows(2).any(|w| w == [0x61, b'c']));
    // A `c` that is not bytes is malformed.
    let mut bad = manifest_with(vec![entry(3, 0x75, 1)]);
    bad.methods[0].extra = vec![("c".into(), ferret_core::cbor::Value::text("x"))];
    let bytes = bad.to_cbor().unwrap();
    assert_eq!(
        Manifest::from_cbor(&bytes),
        Err(Error::Malformed(MalformedKind::ItemBody))
    );
}

#[test]
fn seed_from_manifest_takes_the_decrypted_manifest_only() {
    let mut f = fixture();
    let manifest = manifest_with(vec![
        entry(1, 0x70, 2),
        entry(2, 0x71, 3),
        ManifestEntry::passkey(method_id(0x75), 6, vec![0xa5; 20]),
    ]);
    f.pinned.seed_from_manifest(&manifest).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Password), Some(2));
    assert_eq!(floor(&f.pinned, &MethodKey::Recovery), Some(3));
    assert_eq!(floor(&f.pinned, &MethodKey::Prf(vec![0xa5; 20])), Some(6));

    // A floor only goes up: an older manifest changes nothing.
    let older = manifest_with(vec![entry(1, 0x70, 1), entry(2, 0x71, 1)]);
    f.pinned.seed_from_manifest(&older).unwrap();
    assert_eq!(floor(&f.pinned, &MethodKey::Recovery), Some(3));

    // A manifest from an earlier epoch than the pinned one, and one that
    // cannot make floors, leave the record as it was.
    let before = f.pinned.clone();
    f.pinned.vk_epoch_max = 3;
    let pinned_later = f.pinned.clone();
    assert_eq!(
        f.pinned.seed_from_manifest(&manifest),
        Err(Error::Pinned(PinnedField::VkEpoch))
    );
    assert_eq!(f.pinned, pinned_later);
    f.pinned.vk_epoch_max = before.vk_epoch_max;
    for bad in [
        manifest_with(vec![entry(3, 0x75, 1)]),
        manifest_with(vec![entry(1, 0x70, 1), entry(1, 0x72, 9)]),
    ] {
        assert_eq!(
            f.pinned.seed_from_manifest(&bad),
            Err(Error::Malformed(MalformedKind::ItemBody))
        );
        assert_eq!(f.pinned, before);
    }
}

#[test]
fn first_unlock_takes_the_profile_from_the_wrap() {
    // A password wrap states its profile in the AAD; the record gets that
    // one. A recovery wrap says nothing about it, so the record starts at the
    // lowest profile of the table.
    let f = fixture();
    assert_eq!(f.pinned.ksf_profile, KsfProfile::P1.number());
    let c = ctx();
    let rec = seal(&c, 0x71, 1, Method::Recovery, 0x5a);
    let (pinned, _) = Pinned::first_unlock(URL, true, None, &c, &rec, &kek()).unwrap();
    assert_eq!(pinned.ksf_profile, 1);
    assert_eq!(pinned.kek_generation_max, vec![(MethodKey::Recovery, 1)]);
}

#[test]
fn a_stored_record_is_validated() {
    let f = fixture();
    f.pinned.validate().unwrap();
    let bad = Error::Malformed(MalformedKind::PinnedRecord);

    // Two floors for one key.
    let mut p = f.pinned.clone();
    p.kek_generation_max.push((MethodKey::Password, 9));
    assert_eq!(p.validate().err(), Some(bad));
    let mut p = f.pinned.clone();
    p.kek_generation_max = vec![
        (MethodKey::Prf(vec![1, 2]), 1),
        (MethodKey::Recovery, 1),
        (MethodKey::Prf(vec![1, 2]), 2),
    ];
    assert_eq!(p.validate().err(), Some(bad));
    // Too many floors.
    let mut p = f.pinned.clone();
    p.kek_generation_max = (0..=MAX_FLOORS)
        .map(|i| (MethodKey::Prf(vec![u8::try_from(i).unwrap()]), 1))
        .collect();
    assert_eq!(p.validate().err(), Some(bad));
    // A generation above the maximum, a credential id and an address that
    // are too long.
    let mut p = f.pinned.clone();
    p.kek_generation_max = vec![(MethodKey::Password, MAX_GENERATION + 1)];
    assert_eq!(p.validate().err(), Some(bad));
    let mut p = f.pinned.clone();
    p.kek_generation_max = vec![(MethodKey::Prf(vec![0; MAX_CREDENTIAL_ID_LEN + 1]), 1)];
    assert_eq!(p.validate().err(), Some(bad));
    let mut p = f.pinned.clone();
    p.server_url = "u".repeat(MAX_URL_LEN + 1);
    assert_eq!(p.validate().err(), Some(bad));
    // The limits themselves are fine.
    let mut p = f.pinned.clone();
    p.kek_generation_max = (0..MAX_FLOORS)
        .map(|i| {
            (
                MethodKey::Prf(vec![u8::try_from(i).unwrap()]),
                MAX_GENERATION,
            )
        })
        .collect();
    p.server_url = "u".repeat(MAX_URL_LEN);
    p.validate().unwrap();
}

#[test]
fn the_unlock_entry_points_refuse_an_invalid_record() {
    let mut f = fixture();
    f.pinned.kek_generation_max.push((MethodKey::Password, 9));
    let rec = f.rec.clone();
    let bad = Error::Malformed(MalformedKind::PinnedRecord);
    assert_eq!(unlock(&mut f, &rec).err(), Some(bad));
    let local = seal(&f.ctx, 0x78, 1, Method::Device, 0x5a);
    assert_eq!(f.pinned.unlock_local(&local, &kek()).err(), Some(bad));
}
