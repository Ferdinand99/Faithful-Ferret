//! The account flows (Fase 1 § 4.2, § 4.3, § 6.1, § 6.3):
//! create, change password (and KSF upgrade), recover, and the confirmation
//! of the recovery key and the secret key.
//!
//! The OPAQUE registrations use a few KiB of Argon2id memory through
//! `testing::opaque` (the flows take the finished registration, so the
//! stretching parameters are not part of them), and the vector cases run the
//! flows on recorded registrations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::cbor::Value;
use ferret_core::testing::integrity::recovery_key_bytes as recovery_key_bytes_of;
use ferret_core::testing::keys::{derived_keys, export_key_bytes, unlocked_vault_keys};
use ferret_core::testing::opaque::{Server, TestKsf, register_finish_with};
use ferret_core::testing::prim::aead_open_count;
use ferret_core::testing::vector::Outcome;
use ferret_core::testing::{ReplayRng, TestRng};
use ferret_core::{
    AccountId, AuthOp, AuthPublicKey, Error, ExportKey, InputError, ItemBody, ItemId, ItemType,
    Kek, KsfProfile, MalformedKind, Manifest, ManifestEntry, ManifestRow, MasterPassword, Method,
    MethodId, MethodKey, MpPolicy, NewAccount, NewAccountIds, NewPassword, OpaqueInput, PinState,
    Pinned, PinnedField, RecoveryInput, RecoveryKey, RecoveryPublicKey, RegistrationFinished,
    SecretKey, ServerRow, ServerView, UnlockedVault, VaultContext, change_password, create_account,
    decrypt_item, decrypt_manifest, encode_recovery_key, encode_secret_key, encrypt_item,
    parse_setup_qr, recover, recovery_public_key, unwrap_vk, verify_auth_proof, verify_checkpoint,
    verify_recovery_proof, verify_recovery_setup, verify_secret_key_entry,
};
use serde_json::json;
use static_assertions::assert_not_impl_any;

const URL: &str = "https://ferret.example";
const SMALL: ferret_core::KdfParams = ferret_core::KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const PASSWORD: &str = "correct horse battery staple";
const PASSWORD_2: &str = "tr0ub4dor and three more words";

fn rng(seed: &str) -> TestRng {
    TestRng::new(seed.as_bytes())
}

fn ids() -> NewAccountIds {
    NewAccountIds {
        account_id: account(0x11),
        vault_id: vault(0x22),
        password_method_id: method_id(0x70),
        recovery_method_id: method_id(0x71),
    }
}

fn credential() -> [u8; 16] {
    *ids().account_id.as_bytes()
}

fn sk(b: u8) -> SecretKey {
    SecretKey::from_test_bytes([b; 16])
}

/// A password made the way creation and change make it.
fn new_input(text: &str, policy: MpPolicy, secret_key: Option<&SecretKey>) -> OpaqueInput {
    MasterPassword::new(text.as_bytes(), policy)
        .unwrap()
        .opaque_input(secret_key)
}

fn server(seed: &str) -> Server {
    Server::new(&mut rng(&format!("server/{seed}")))
}

/// Runs the OPAQUE registration of `input` against `server` with a small
/// Argon2id.
fn register(server: &Server, input: &OpaqueInput, seed: &str) -> RegistrationFinished {
    let mut r = rng(&format!("client/{seed}"));
    let (request, state) = ferret_core::opaque_register_start(&mut r, input).unwrap();
    let response = server.register_response(&credential(), &request).unwrap();
    register_finish_with(&mut r, state, input, &response, &TestKsf::new(SMALL)).unwrap()
}

fn password<'a>(
    input: &'a OpaqueInput,
    registration: RegistrationFinished,
    profile: KsfProfile,
) -> NewPassword<'a> {
    NewPassword {
        input,
        registration,
        profile,
    }
}

/// An account made through the real flow.
struct Setup {
    account: NewAccount,
    server: Server,
    /// `export_key` of the registration, to rebuild `KEK_pw`.
    export: [u8; 64],
    secret_key: Option<[u8; 16]>,
}

fn create(seed: &str, with_sk: bool) -> Setup {
    let server = server(seed);
    let secret_key = with_sk.then(|| sk(0x5a));
    let policy = if with_sk {
        MpPolicy::WithSecretKey
    } else {
        MpPolicy::WithoutSecretKey
    };
    let input = new_input(PASSWORD, policy, secret_key.as_ref());
    let registration = register(&server, &input, &format!("{seed}/create"));
    let export = export_key_bytes(&registration.export_key);
    let account = create_account(
        &mut rng(&format!("{seed}/account")),
        &ids(),
        password(&input, registration, KsfProfile::P1),
        secret_key,
    )
    .unwrap();
    Setup {
        account,
        server,
        export,
        secret_key: with_sk.then_some([0x5a; 16]),
    }
}

fn kek_pw(export: &[u8; 64]) -> Kek {
    Kek::from_export_key(&account(0x11), &ExportKey::from_test_bytes(*export)).unwrap()
}

fn kek_rk(rk: &RecoveryKey) -> Kek {
    Kek::from_recovery_key(&account(0x11), rk).unwrap()
}

fn ctx1() -> VaultContext {
    ctx()
}

fn row(account: &NewAccount) -> ManifestRow<'_> {
    ManifestRow {
        rev: account.manifest.rev,
        envelope: &account.manifest.envelope,
        tag: &account.manifest.tag,
    }
}

fn sealed_row(s: &ferret_core::SealedItem) -> ManifestRow<'_> {
    ManifestRow {
        rev: s.rev,
        envelope: &s.envelope,
        tag: &s.tag,
    }
}

fn pinned_of(setup: &Setup) -> Pinned {
    setup.account.pinned(URL).unwrap()
}

fn view(pinned: &Pinned) -> ServerView<'static> {
    ServerView {
        server_url: URL,
        context: ctx1(),
        sk_bit: pinned.sk_bit,
        server_public_key: pinned.server_public_key,
    }
}

/// A generator that fails the test when anything is drawn from it.
fn no_draws() -> ReplayRng {
    ReplayRng::new(vec![])
}

// ------------------------------------------------------------- create

#[test]
fn create_account_produces_two_wraps_and_manifest() {
    let s = create("c1", true);
    let a = &s.account;
    assert_eq!(a.wraps.len(), 2);
    let [pw, rk] = a.wraps.as_slice() else {
        panic!("two wraps")
    };
    assert_eq!(
        pw.method,
        Method::Password {
            ksf: KsfProfile::P1
        }
    );
    assert_eq!(pw.kek_generation, 1);
    assert_eq!(pw.method_id, method_id(0x70));
    assert_eq!(pw.wrap.len(), 104);
    assert_eq!(rk.method, Method::Recovery);
    assert_eq!(rk.kek_generation, 1);
    assert_eq!(rk.method_id, method_id(0x71));
    assert_eq!(rk.wrap.len(), 72);
    assert_eq!(a.vault.context().vk_epoch, 1);
    assert_eq!(a.vault.context().account_id, account(0x11));
    assert_eq!(a.vault.context().vault_id, vault(0x22));

    // The manifest names both methods, at epoch 1, revision 1.
    assert_eq!(a.manifest.rev, 1);
    let m = decrypt_manifest(&a.vault, 1, &a.manifest.envelope, &a.manifest.tag).unwrap();
    assert_eq!(m.vk_epoch, 1);
    let listed: Vec<(u8, MethodId, u64)> = m
        .methods
        .iter()
        .map(|e| (e.method_type, e.method_id, e.kek_generation))
        .collect();
    assert_eq!(
        listed,
        vec![(1, method_id(0x70), 1), (2, method_id(0x71), 1)]
    );
    assert_eq!(a.registration_record.len(), 192);
    assert_eq!(a.ksf_profile, KsfProfile::P1);
    assert!(a.secret_key.is_some());
}

#[test]
fn create_account_unlocks_with_both_methods() {
    let s = create("c2", false);
    let a = &s.account;
    let by_password = unwrap_vk(&ctx1(), &kek_pw(&s.export), &a.wraps[0]).unwrap();
    let by_recovery = unwrap_vk(&ctx1(), &kek_rk(&a.recovery_key), &a.wraps[1]).unwrap();
    assert!(by_password.same_vault_key(&a.vault));
    assert!(by_recovery.same_vault_key(&a.vault));
    assert!(by_password.same_vault_key(&by_recovery));
    // Each KEK opens only its own wrap.
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_rk(&a.recovery_key), &a.wraps[0]).err(),
        Some(Error::Decrypt)
    );
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_pw(&s.export), &a.wraps[1]).err(),
        Some(Error::Decrypt)
    );
    assert!(a.secret_key.is_none());
}

#[test]
fn create_account_keys_match_derivations() {
    let s = create("c3", true);
    let a = &s.account;
    let vk = unlocked_vault_keys(&a.vault)[0];
    let derived = derived_keys(&ctx1(), &ferret_core::VaultKey::from_test_bytes(vk)).unwrap();
    assert_eq!(a.pk_a, derived.pk_a);
    assert_eq!(a.pk_a, a.vault.auth_public_key());
    assert_eq!(
        a.pk_r,
        recovery_public_key(&a.recovery_key, &account(0x11)).unwrap()
    );
    assert_ne!(a.pk_a, a.pk_r);
    // The VK and RK are what the generator gave, in order (32 bytes each).
    let mut r = rng("c3/account");
    let mut want_vk = [0u8; 32];
    ferret_core::SecureRng::fill(&mut r, &mut want_vk);
    let mut want_rk = [0u8; 32];
    ferret_core::SecureRng::fill(&mut r, &mut want_rk);
    assert_eq!(vk, want_vk);
    assert_eq!(recovery_key_bytes_of(&a.recovery_key), want_rk);
}

#[test]
fn create_account_first_checkpoint_covers_the_manifest() {
    let s = create("c4", true);
    let a = &s.account;
    assert_eq!(a.checkpoint.seq, 1);
    assert_eq!(a.checkpoint.entries.len(), 56);
    let manifest_row = ServerRow::live(
        &a.vault,
        ItemId::MANIFEST,
        a.manifest.rev,
        &a.manifest.envelope,
        &a.manifest.tag,
    )
    .unwrap();
    verify_checkpoint(&a.vault, &a.checkpoint, &[manifest_row], 1).unwrap();
    // A server that hides the manifest is found at the top.
    assert!(verify_checkpoint(&a.vault, &a.checkpoint, &[], 1).is_err());
}

#[test]
fn create_account_draws_in_the_documented_order() {
    // VK, RK, nonce of the password wrap, of the recovery wrap, of the
    // manifest: five draws of 32, 32, 24, 24, 24 bytes, and no others.
    let server = server("c5");
    let input = new_input(PASSWORD, MpPolicy::WithoutSecretKey, None);
    let registration = register(&server, &input, "c5");
    let mut r = rng("c5/account");
    let mut draws = Vec::new();
    for len in [32usize, 32, 24, 24, 24] {
        let mut d = vec![0u8; len];
        ferret_core::SecureRng::fill(&mut r, &mut d);
        draws.push(d);
    }
    let mut replay = ReplayRng::new(draws);
    create_account(
        &mut replay,
        &ids(),
        password(&input, registration, KsfProfile::P1),
        None,
    )
    .unwrap();
    replay.finish().unwrap();
}

#[test]
fn create_account_enforces_the_password_rules_before_drawing() {
    let server = server("c6");

    // A password checked for unlock only (no creation floor) is refused.
    let weak = MasterPassword::for_unlock(PASSWORD.as_bytes())
        .unwrap()
        .opaque_input(None);
    let reg = register(&server, &weak, "c6/a");
    assert_eq!(
        create_account(
            &mut no_draws(),
            &ids(),
            password(&weak, reg, KsfProfile::P1),
            None
        )
        .err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );

    // 12 characters are enough with a secret key and not without one: the
    // input made without the key carries the policy of the key's absence.
    let twelve = "twelve chars";
    assert_eq!(twelve.chars().count(), 12);
    let mp = MasterPassword::new(twelve.as_bytes(), MpPolicy::WithSecretKey).unwrap();
    let key = sk(1);
    let with_key = mp.opaque_input(Some(&key));
    assert!(with_key.meets_creation_floor());
    let without_key = mp.opaque_input(None);
    assert!(
        !without_key.meets_creation_floor(),
        "12 characters do not meet the floor without a secret key"
    );
    let reg = register(&server, &without_key, "c6/b");
    assert_eq!(
        create_account(
            &mut no_draws(),
            &ids(),
            password(&without_key, reg, KsfProfile::P1),
            None
        )
        .err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
    // With the key it works, and 15 characters work either way.
    let reg = register(&server, &with_key, "c6/c");
    create_account(
        &mut rng("c6/d"),
        &ids(),
        password(&with_key, reg, KsfProfile::P1),
        Some(key),
    )
    .unwrap();
    let fifteen = new_input("fifteen chars!!", MpPolicy::WithoutSecretKey, None);
    assert!(fifteen.meets_creation_floor());
}

#[test]
fn create_account_checks_that_the_secret_key_is_the_one_in_the_password() {
    let server = server("c7");
    let key = sk(0x5a);
    let input = new_input(PASSWORD, MpPolicy::WithSecretKey, Some(&key));
    // Another key, none at all, and a key where the input has none.
    for given in [Some(sk(0x5b)), None] {
        let reg = register(&server, &input, "c7/a");
        assert_eq!(
            create_account(
                &mut no_draws(),
                &ids(),
                password(&input, reg, KsfProfile::P1),
                given
            )
            .err(),
            Some(Error::InvalidInput(InputError::SecretKeyMismatch))
        );
    }
    let plain = new_input(PASSWORD, MpPolicy::WithoutSecretKey, None);
    let reg = register(&server, &plain, "c7/b");
    assert_eq!(
        create_account(
            &mut no_draws(),
            &ids(),
            password(&plain, reg, KsfProfile::P1),
            Some(sk(0x5a))
        )
        .err(),
        Some(Error::InvalidInput(InputError::SecretKeyMismatch))
    );
    // The right key is accepted.
    let reg = register(&server, &input, "c7/c");
    create_account(
        &mut rng("c7/d"),
        &ids(),
        password(&input, reg, KsfProfile::P1),
        Some(key),
    )
    .unwrap();
}

#[test]
fn create_account_needs_two_different_method_ids() {
    let server = server("c8");
    let input = new_input(PASSWORD, MpPolicy::WithoutSecretKey, None);
    let reg = register(&server, &input, "c8");
    let mut same = ids();
    same.recovery_method_id = same.password_method_id;
    assert_eq!(
        create_account(
            &mut no_draws(),
            &same,
            password(&input, reg, KsfProfile::P1),
            None
        )
        .err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
}

#[test]
fn the_new_device_record_unlocks_the_account() {
    let s = create("c9", true);
    let mut pinned = pinned_of(&s);
    pinned.validate().unwrap();
    assert_eq!(pinned.server_url, URL);
    assert_eq!(pinned.ksf_profile, 1);
    assert!(pinned.sk_bit);
    assert_eq!(pinned.vk_epoch_max, 1);
    assert_eq!(pinned.pk_a, s.account.pk_a);
    assert_eq!(pinned.server_public_key, Some(s.server.public_key()));
    assert_eq!(
        pinned.kek_generation_max,
        vec![(MethodKey::Password, 1), (MethodKey::Recovery, 1)]
    );
    let seen = view(&pinned);
    let vault = pinned
        .unlock_server(&seen, &s.account.wraps[0], &kek_pw(&s.export))
        .unwrap();
    assert!(vault.same_vault_key(&s.account.vault));
    // An address over the limit is refused.
    assert_eq!(
        s.account
            .pinned(&"u".repeat(ferret_core::pinning::MAX_URL_LEN + 1))
            .err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
}

// ----------------------------------------------------- change password

/// A change of password on `s` with a new registration on the same server.
fn change(
    s: &Setup,
    pinned: &Pinned,
    text: &str,
    profile: KsfProfile,
    seed: &str,
) -> Result<(ferret_core::PasswordChange, [u8; 64]), Error> {
    let policy = if pinned.sk_bit {
        MpPolicy::WithSecretKey
    } else {
        MpPolicy::WithoutSecretKey
    };
    let key = s.secret_key.map(SecretKey::from_test_bytes);
    let input = new_input(text, policy, key.as_ref());
    let reg = register(&s.server, &input, seed);
    let export = export_key_bytes(&reg.export_key);
    change_password(
        &mut rng(&format!("{seed}/change")),
        &s.account.vault,
        password(&input, reg, profile),
        pinned,
        &s.account.wraps[0],
        &row(&s.account),
    )
    .map(|c| (c, export))
}

#[test]
fn change_password_bumps_generation_and_keeps_items() {
    let s = create("p1", true);
    let a = &s.account;
    // Items the vault already holds.
    let mut r = rng("p1/items");
    let body = ItemBody::new(ItemType::Login, "Example", 1_700_000_000_000);
    let item = encrypt_item(
        &mut r,
        &a.vault,
        ItemId::from_bytes([0x41; 16]),
        3,
        &body,
        None,
    )
    .unwrap();

    let pinned = pinned_of(&s);
    let (changed, new_export) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "p1").unwrap();

    // The wrap: same id, generation 2, the new KEK opens it.
    assert_eq!(changed.wrap.method_id, method_id(0x70));
    assert_eq!(changed.wrap.kek_generation, 2);
    assert_eq!(
        changed.wrap.method,
        Method::Password {
            ksf: KsfProfile::P1
        }
    );
    assert_eq!(changed.wrap.wrap.len(), 104);
    assert_ne!(changed.wrap.wrap, a.wraps[0].wrap);
    let reopened = unwrap_vk(&ctx1(), &kek_pw(&new_export), &changed.wrap).unwrap();
    assert!(reopened.same_vault_key(&a.vault));
    // The old export key opens neither the new wrap nor...
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_pw(&s.export), &changed.wrap).err(),
        Some(Error::Decrypt)
    );
    // ... and the new one does not open the old wrap.
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_pw(&new_export), &a.wraps[0]).err(),
        Some(Error::Decrypt)
    );

    // The items are untouched: the old envelope opens with the vault the
    // new wrap gives.
    let opened = decrypt_item(
        &reopened,
        ItemId::from_bytes([0x41; 16]),
        3,
        &item.envelope,
        &item.tag,
    )
    .unwrap();
    assert_eq!(opened.body.name, "Example");

    // The manifest is one revision up and lists generation 2; the recovery
    // entry is as it was.
    assert_eq!(changed.manifest.rev, 2);
    let m = decrypt_manifest(
        &reopened,
        2,
        &changed.manifest.envelope,
        &changed.manifest.tag,
    )
    .unwrap();
    let listed: Vec<(u8, MethodId, u64)> = m
        .methods
        .iter()
        .map(|e| (e.method_type, e.method_id, e.kek_generation))
        .collect();
    assert_eq!(
        listed,
        vec![(1, method_id(0x70), 2), (2, method_id(0x71), 1)]
    );
    assert_eq!(changed.registration_record.len(), 192);
    assert_eq!(changed.server_public_key, s.server.public_key());
    assert_eq!(changed.ksf_profile, KsfProfile::P1);
}

#[test]
fn change_password_draws_two_nonces() {
    let s = create("p2", false);
    let pinned = pinned_of(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithoutSecretKey, None);
    let reg = register(&s.server, &input, "p2");
    let mut r = rng("p2/draws");
    let draws: Vec<Vec<u8>> = [24usize, 24]
        .iter()
        .map(|n| {
            let mut d = vec![0u8; *n];
            ferret_core::SecureRng::fill(&mut r, &mut d);
            d
        })
        .collect();
    let mut replay = ReplayRng::new(draws);
    change_password(
        &mut replay,
        &s.account.vault,
        password(&input, reg, KsfProfile::P1),
        &pinned,
        &s.account.wraps[0],
        &row(&s.account),
    )
    .unwrap();
    replay.finish().unwrap();
}

#[test]
fn change_password_generation_is_above_everything_seen() {
    let s = create("p3", true);
    // The device remembers generation 7; the manifest says 1, the wrap 1.
    let mut pinned = pinned_of(&s);
    pinned.kek_generation_max = vec![(MethodKey::Password, 7), (MethodKey::Recovery, 1)];
    let (changed, _) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "p3").unwrap();
    assert_eq!(changed.wrap.kek_generation, 8);
    // A wrap the server holds with a higher generation than the manifest
    // lists also counts.
    let pinned = pinned_of(&s);
    let mut high = s.account.wraps[0].clone();
    high.kek_generation = 5;
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&sk(0x5a)));
    let reg = register(&s.server, &input, "p3/b");
    let changed = change_password(
        &mut rng("p3/c"),
        &s.account.vault,
        password(&input, reg, KsfProfile::P1),
        &pinned,
        &high,
        &row(&s.account),
    )
    .unwrap();
    assert_eq!(changed.wrap.kek_generation, 6);
    // A floor at the maximum cannot be raised.
    let mut pinned = pinned_of(&s);
    pinned.kek_generation_max = vec![
        (MethodKey::Password, ferret_core::pinning::MAX_GENERATION),
        (MethodKey::Recovery, 1),
    ];
    assert_eq!(
        change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "p3/d").err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
}

#[test]
fn change_password_rejects_lower_profile() {
    let s = create("p4", true);
    // The device has seen a profile this build does not have yet (2): the
    // build's only profile is lower, and nothing is drawn.
    let mut pinned = pinned_of(&s);
    pinned.ksf_profile = 2;
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&sk(0x5a)));
    let reg = register(&s.server, &input, "p4");
    assert_eq!(
        change_password(
            &mut no_draws(),
            &s.account.vault,
            password(&input, reg, KsfProfile::P1),
            &pinned,
            &s.account.wraps[0],
            &row(&s.account),
        )
        .err(),
        Some(Error::KdfProfileDowngrade)
    );
    // The same profile is a re-registration (an upgrade to the same
    // profile): allowed.
    let pinned = pinned_of(&s);
    change(&s, &pinned, PASSWORD, KsfProfile::P1, "p4/b").unwrap();
}

#[test]
fn change_password_compares_the_server_key_with_the_pinned_one() {
    let s = create("p5", true);
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&sk(0x5a)));

    // The server now answers with another OPAQUE key.
    let other = server("p5-other");
    assert_ne!(other.public_key(), s.server.public_key());
    let reg = register(&other, &input, "p5");
    assert_eq!(reg.server_public_key, other.public_key());
    let pinned = pinned_of(&s);
    assert_eq!(
        change_password(
            &mut no_draws(),
            &s.account.vault,
            password(&input, reg, KsfProfile::P1),
            &pinned,
            &s.account.wraps[0],
            &row(&s.account),
        )
        .err(),
        Some(Error::Pinned(PinnedField::ServerKey))
    );

    // Without a pinned key the first one is accepted and returned.
    let mut unpinned = pinned_of(&s);
    unpinned.server_public_key = None;
    let reg = register(&other, &input, "p5/b");
    let changed = change_password(
        &mut rng("p5/c"),
        &s.account.vault,
        password(&input, reg, KsfProfile::P1),
        &unpinned,
        &s.account.wraps[0],
        &row(&s.account),
    )
    .unwrap();
    assert_eq!(changed.server_public_key, other.public_key());
}

#[test]
fn change_password_checks_the_pinned_record_and_the_inputs() {
    let s = create("p6", true);
    let good = pinned_of(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&sk(0x5a)));
    let run = |pinned: &Pinned, current: &ferret_core::WrapRecord, m: ManifestRow<'_>| {
        let reg = register(&s.server, &input, "p6");
        change_password(
            &mut no_draws(),
            &s.account.vault,
            password(&input, reg, KsfProfile::P1),
            pinned,
            current,
            &m,
        )
        .err()
    };

    let mut bad = good.clone();
    bad.account_id = account(0x99);
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Pinned(PinnedField::AccountId))
    );
    let mut bad = good.clone();
    bad.vault_id = vault(0x99);
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Pinned(PinnedField::VaultId))
    );
    let mut bad = good.clone();
    bad.vk_epoch_max = 2;
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Pinned(PinnedField::VkEpoch))
    );
    let mut bad = good.clone();
    bad.pk_a = [1; 32];
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Pinned(PinnedField::AuthKey))
    );
    // The SK bit: the pinned record says "no secret key" but the input has one.
    let mut bad = good.clone();
    bad.sk_bit = false;
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Pinned(PinnedField::SkBit))
    );
    // A damaged record: duplicate floors.
    let mut bad = good.clone();
    bad.kek_generation_max.push((MethodKey::Password, 9));
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
    // No floor for the password wrap: the record has not been seeded.
    let mut bad = good.clone();
    bad.kek_generation_max = vec![(MethodKey::Recovery, 1)];
    assert_eq!(
        run(&bad, &s.account.wraps[0], row(&s.account)),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
    // The current wrap is not a password wrap.
    assert_eq!(
        run(&good, &s.account.wraps[1], row(&s.account)),
        Some(Error::Unsupported)
    );
    // The manifest lists another password wrap than the one given.
    let mut other_id = s.account.wraps[0].clone();
    other_id.method_id = method_id(0x72);
    assert_eq!(
        run(&good, &other_id, row(&s.account)),
        Some(Error::Malformed(MalformedKind::Entries))
    );
    // A manifest row with a wrong tag.
    let mut tag = s.account.manifest.tag;
    tag[0] ^= 1;
    assert_eq!(
        run(
            &good,
            &s.account.wraps[0],
            ManifestRow {
                rev: 1,
                envelope: &s.account.manifest.envelope,
                tag: &tag,
            }
        ),
        Some(Error::Decrypt)
    );
    // A password that was made for unlock cannot be set.
    let weak = MasterPassword::for_unlock(PASSWORD_2.as_bytes())
        .unwrap()
        .opaque_input(Some(&sk(0x5a)));
    let reg = register(&s.server, &weak, "p6/b");
    assert_eq!(
        change_password(
            &mut no_draws(),
            &s.account.vault,
            password(&weak, reg, KsfProfile::P1),
            &good,
            &s.account.wraps[0],
            &row(&s.account),
        )
        .err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
}

#[test]
fn change_password_proof_is_bound_to_the_operation() {
    let s = create("p7", true);
    let pinned = pinned_of(&s);
    let (changed, _) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "p7").unwrap();
    let nonce = [0x33; 32];
    let body = b"{\"registration_record\":\"...\"}";
    let proof = changed.sign(&s.account.vault, &nonce, body).unwrap();
    let pk = AuthPublicKey::new(s.account.pk_a);
    verify_auth_proof(
        &pk,
        AuthOp::UnlockMethodPasswordPut,
        &account(0x11),
        &nonce,
        1,
        body,
        &proof,
    )
    .unwrap();
    for other in [
        AuthOp::UnlockMethodAdd,
        AuthOp::UnlockMethodRemove,
        AuthOp::UnlockMethodRecoveryPut,
        AuthOp::Rekey,
    ] {
        assert_eq!(
            verify_auth_proof(&pk, other, &account(0x11), &nonce, 1, body, &proof).err(),
            Some(Error::Decrypt)
        );
    }
    // Another body or another nonce.
    assert!(
        verify_auth_proof(
            &pk,
            AuthOp::UnlockMethodPasswordPut,
            &account(0x11),
            &nonce,
            1,
            b"other",
            &proof
        )
        .is_err()
    );
    assert_eq!(
        ferret_core::PasswordChange::OP,
        AuthOp::UnlockMethodPasswordPut
    );
}

#[test]
fn a_changed_password_unlocks_with_the_pinned_record() {
    let s = create("p8", true);
    let mut pinned = pinned_of(&s);
    let (changed, export) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "p8").unwrap();
    let seen = view(&pinned);
    let vault = pinned
        .unlock_server(&seen, &changed.wrap, &kek_pw(&export))
        .unwrap();
    assert!(vault.same_vault_key(&s.account.vault));
    assert_eq!(
        pinned
            .kek_generation_max
            .iter()
            .find(|(k, _)| *k == MethodKey::Password)
            .map(|(_, g)| *g),
        Some(2)
    );
    // The old wrap is now a rollback.
    let seen = view(&pinned);
    assert_eq!(
        pinned
            .unlock_server(&seen, &s.account.wraps[0], &kek_pw(&s.export))
            .err(),
        Some(Error::Pinned(PinnedField::KekGeneration))
    );
}

// ------------------------------------------------------------- recover

/// A recovery on `s` with the recovery key `code`.
fn recover_with(
    s: &Setup,
    code: &str,
    pin: PinState<'_>,
    text: &str,
    key: Option<&SecretKey>,
    seed: &str,
) -> Result<(ferret_core::Recovered, [u8; 64]), Error> {
    let policy = if key.is_some() {
        MpPolicy::WithSecretKey
    } else {
        MpPolicy::WithoutSecretKey
    };
    let input = new_input(text, policy, key);
    let reg = register(&s.server, &input, seed);
    let export = export_key_bytes(&reg.export_key);
    let c = ctx1();
    let input_data = RecoveryInput {
        ctx: &c,
        rk_code: code,
        rk_wrap: &s.account.wraps[1],
        manifest: row(&s.account),
        new_recovery_method_id: method_id(0x73),
    };
    recover(
        &mut rng(&format!("{seed}/recover")),
        &input_data,
        password(&input, reg, KsfProfile::P1),
        pin,
    )
    .map(|r| (r, export))
}

fn rk_code(s: &Setup) -> String {
    encode_recovery_key(&s.account.recovery_key).to_string()
}

#[test]
fn recover_rotates_recovery_key() {
    let s = create("r1", true);
    let a = &s.account;
    let code = rk_code(&s);
    let key = sk(0x5a);
    let (rec, export) =
        recover_with(&s, &code, PinState::FirstUse, PASSWORD_2, Some(&key), "r1").unwrap();

    // The vault key is the same.
    assert!(rec.vault.same_vault_key(&a.vault));
    assert_eq!(rec.vault.context().vk_epoch, 1);
    // The recovery key is new, and so is pk_r.
    assert_ne!(
        recovery_key_bytes_of(&rec.recovery_key),
        recovery_key_bytes_of(&a.recovery_key)
    );
    assert_ne!(rec.pk_r, a.pk_r);
    assert_eq!(
        rec.pk_r,
        recovery_public_key(&rec.recovery_key, &account(0x11)).unwrap()
    );
    // The new recovery wrap: new id, generation 2, opens with the new key
    // and not with the old one.
    assert_eq!(rec.recovery_wrap.method, Method::Recovery);
    assert_eq!(rec.recovery_wrap.method_id, method_id(0x73));
    assert_eq!(rec.recovery_wrap.kek_generation, 2);
    let by_new = unwrap_vk(&ctx1(), &kek_rk(&rec.recovery_key), &rec.recovery_wrap).unwrap();
    assert!(by_new.same_vault_key(&a.vault));
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_rk(&a.recovery_key), &rec.recovery_wrap).err(),
        Some(Error::Decrypt)
    );
    // The new password wrap: the id is kept, generation 2, the new export
    // key opens it and the old one does not.
    assert_eq!(rec.password_wrap.method_id, method_id(0x70));
    assert_eq!(rec.password_wrap.kek_generation, 2);
    let by_pw = unwrap_vk(&ctx1(), &kek_pw(&export), &rec.password_wrap).unwrap();
    assert!(by_pw.same_vault_key(&a.vault));
    assert_eq!(
        unwrap_vk(&ctx1(), &kek_pw(&s.export), &rec.password_wrap).err(),
        Some(Error::Decrypt)
    );
    // The manifest lists both new wraps.
    assert_eq!(rec.manifest.rev, 2);
    let m = decrypt_manifest(&rec.vault, 2, &rec.manifest.envelope, &rec.manifest.tag).unwrap();
    let listed: Vec<(u8, MethodId, u64)> = m
        .methods
        .iter()
        .map(|e| (e.method_type, e.method_id, e.kek_generation))
        .collect();
    assert_eq!(
        listed,
        vec![(1, method_id(0x70), 2), (2, method_id(0x73), 2)]
    );
    assert!(rec.sk_bit);
    assert_eq!(rec.ksf_profile, KsfProfile::P1);
    assert_eq!(rec.server_public_key, s.server.public_key());
    assert_eq!(rec.registration_record.len(), 192);
}

#[test]
fn recover_proof_is_signed_with_the_old_recovery_key() {
    let s = create("r2", false);
    let code = rk_code(&s);
    let (rec, _) = recover_with(&s, &code, PinState::FirstUse, PASSWORD_2, None, "r2").unwrap();
    let nonce = [0x44; 32];
    let body = b"{\"pw_wrap\":\"..\"}";
    let proof = rec.sign(&nonce, body).unwrap();
    let old = RecoveryPublicKey::new(s.account.pk_r);
    verify_recovery_proof(&old, &account(0x11), &nonce, 1, body, &proof).unwrap();
    // Not valid for the new key, another epoch, body or nonce.
    let new = RecoveryPublicKey::new(rec.pk_r);
    assert!(verify_recovery_proof(&new, &account(0x11), &nonce, 1, body, &proof).is_err());
    assert!(verify_recovery_proof(&old, &account(0x11), &nonce, 2, body, &proof).is_err());
    assert!(verify_recovery_proof(&old, &account(0x11), &nonce, 1, b"x", &proof).is_err());
    assert!(verify_recovery_proof(&old, &account(0x11), &[0; 32], 1, body, &proof).is_err());
    // Not an `sk_a` proof either.
    assert!(
        verify_auth_proof(
            &AuthPublicKey::new(s.account.pk_r),
            AuthOp::UnlockMethodPasswordPut,
            &account(0x11),
            &nonce,
            1,
            body,
            &proof
        )
        .is_err()
    );
}

#[test]
fn recover_draws_in_the_documented_order() {
    let s = create("r3", false);
    let code = rk_code(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithoutSecretKey, None);
    let reg = register(&s.server, &input, "r3");
    let mut r = rng("r3/draws");
    let draws: Vec<Vec<u8>> = [24usize, 32, 24, 24]
        .iter()
        .map(|n| {
            let mut d = vec![0u8; *n];
            ferret_core::SecureRng::fill(&mut r, &mut d);
            d
        })
        .collect();
    let new_rk = draws[1].clone();
    let mut replay = ReplayRng::new(draws);
    let c = ctx1();
    let rec = recover(
        &mut replay,
        &RecoveryInput {
            ctx: &c,
            rk_code: &code,
            rk_wrap: &s.account.wraps[1],
            manifest: row(&s.account),
            new_recovery_method_id: method_id(0x73),
        },
        password(&input, reg, KsfProfile::P1),
        PinState::FirstUse,
    )
    .unwrap();
    replay.finish().unwrap();
    assert_eq!(recovery_key_bytes_of(&rec.recovery_key).to_vec(), new_rk);
}

#[test]
fn recover_requires_valid_rk_code_checksum_first() {
    let s = create("r4", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    // A typo: the last symbol changed. The check comes before anything else,
    // so a wrong wrap and an unusable registration make no difference, and
    // nothing is drawn.
    let mut typo = code.clone().into_bytes();
    let last = typo.len() - 1;
    typo[last] = if typo[last] == b'0' { b'1' } else { b'0' };
    let typo = String::from_utf8(typo).unwrap();
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));
    let reg = register(&s.server, &input, "r4");
    let c = ctx1();
    let mut wrong_wrap = s.account.wraps[0].clone();
    wrong_wrap.method = Method::Device;
    let before = aead_open_count();
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: &typo,
                rk_wrap: &wrong_wrap,
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err(),
        Some(Error::Checksum)
    );
    assert_eq!(aead_open_count(), before, "no key was used");

    // Garbage and a code for another kind of key.
    for bad in ["", "FFR1-", "not a key", "FFS1-0000"] {
        let reg = register(&s.server, &input, "r4/b");
        let err = recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: bad,
                rk_wrap: &s.account.wraps[1],
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err()
        .unwrap();
        assert!(
            matches!(
                err,
                Error::Malformed(MalformedKind::Code)
                    | Error::Checksum
                    | Error::InvalidInput(InputError::TooShort)
            ),
            "{bad:?}: {err:?}"
        );
    }
}

#[test]
fn recover_rejects_a_wrong_key_and_a_wrong_wrap() {
    let s = create("r5", true);
    let key = sk(0x5a);
    // A valid code of another recovery key: the wrap does not open.
    let other = encode_recovery_key(&RecoveryKey::from_test_bytes([0x66; 32])).to_string();
    assert_eq!(
        recover_with(&s, &other, PinState::FirstUse, PASSWORD_2, Some(&key), "r5").err(),
        Some(Error::Decrypt)
    );
    // The password wrap in place of the recovery wrap.
    let code = rk_code(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));
    let reg = register(&s.server, &input, "r5/b");
    let c = ctx1();
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: &code,
                rk_wrap: &s.account.wraps[0],
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err(),
        Some(Error::Unsupported)
    );
    // The wrap opened for another epoch than the context states.
    let late = VaultContext {
        vk_epoch: 2,
        ..ctx1()
    };
    let reg = register(&s.server, &input, "r5/c");
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &late,
                rk_code: &code,
                rk_wrap: &s.account.wraps[1],
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err(),
        Some(Error::Decrypt)
    );
    // A manifest that names another recovery wrap than the one given.
    let manifest = sealed_manifest(
        &s,
        4,
        vec![
            ManifestEntry::new(1, method_id(0x70), 1),
            ManifestEntry::new(2, method_id(0x79), 1),
        ],
        vec![],
    );
    let reg = register(&s.server, &input, "r5/d");
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: &code,
                rk_wrap: &s.account.wraps[1],
                manifest: sealed_row(&manifest),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err(),
        Some(Error::Malformed(MalformedKind::Entries))
    );
}

#[test]
fn recover_checks_the_pinned_record() {
    let s = create("r6", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    let good = pinned_of(&s);

    // The registration shows another server key.
    let other = server("r6-other");
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));
    let reg = register(&other, &input, "r6");
    let c = ctx1();
    let data = RecoveryInput {
        ctx: &c,
        rk_code: &code,
        rk_wrap: &s.account.wraps[1],
        manifest: row(&s.account),
        new_recovery_method_id: method_id(0x73),
    };
    assert_eq!(
        recover(
            &mut no_draws(),
            &data,
            password(&input, reg, KsfProfile::P1),
            PinState::Pinned(&good),
        )
        .err(),
        Some(Error::Pinned(PinnedField::ServerKey))
    );
    // On a new device (no record) the same registration is trust on first
    // use, and the key is handed back to compare with the sheet.
    let reg = register(&other, &input, "r6/b");
    let rec = recover(
        &mut rng("r6/c"),
        &data,
        password(&input, reg, KsfProfile::P1),
        PinState::FirstUse,
    )
    .unwrap();
    assert_eq!(rec.server_public_key, other.public_key());

    // SK bit, profile, floors, epoch and key of the record.
    let go = |pinned: &Pinned| {
        let reg = register(&s.server, &input, "r6/d");
        recover(
            &mut no_draws(),
            &data,
            password(&input, reg, KsfProfile::P1),
            PinState::Pinned(pinned),
        )
        .err()
    };
    let mut bad = good.clone();
    bad.sk_bit = false;
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::SkBit)));
    let mut bad = good.clone();
    bad.ksf_profile = 2;
    assert_eq!(go(&bad), Some(Error::KdfProfileDowngrade));
    let mut bad = good.clone();
    bad.account_id = account(0x98);
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::AccountId)));
    let mut bad = good.clone();
    bad.vault_id = vault(0x98);
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::VaultId)));
    let mut bad = good.clone();
    bad.vk_epoch_max = 2;
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::VkEpoch)));
    let mut bad = good.clone();
    bad.pk_a = [3; 32];
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::AuthKey)));
    let mut bad = good.clone();
    bad.kek_generation_max = vec![(MethodKey::Password, 1), (MethodKey::Recovery, 4)];
    assert_eq!(go(&bad), Some(Error::Pinned(PinnedField::KekGeneration)));
    let mut bad = good.clone();
    bad.kek_generation_max.push((MethodKey::Recovery, 9));
    assert_eq!(
        go(&bad),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
    // The record that agrees works.
    let reg = register(&s.server, &input, "r6/e");
    recover(
        &mut rng("r6/f"),
        &data,
        password(&input, reg, KsfProfile::P1),
        PinState::Pinned(&good),
    )
    .unwrap();
}

#[test]
fn recover_generation_is_above_the_pinned_floor() {
    let s = create("r7", true);
    let code = rk_code(&s);
    let mut pinned = pinned_of(&s);
    pinned.kek_generation_max = vec![(MethodKey::Password, 5), (MethodKey::Recovery, 1)];
    let key = sk(0x5a);
    let (rec, _) = recover_with(
        &s,
        &code,
        PinState::Pinned(&pinned),
        PASSWORD_2,
        Some(&key),
        "r7",
    )
    .unwrap();
    assert_eq!(rec.password_wrap.kek_generation, 6);
    assert_eq!(rec.recovery_wrap.kek_generation, 2);
}

#[test]
fn recover_needs_the_creation_floor() {
    let s = create("r8", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    let weak = MasterPassword::for_unlock(PASSWORD_2.as_bytes())
        .unwrap()
        .opaque_input(Some(&key));
    let reg = register(&s.server, &weak, "r8");
    let c = ctx1();
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: &code,
                rk_wrap: &s.account.wraps[1],
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&weak, reg, KsfProfile::P1),
            PinState::FirstUse,
        )
        .err(),
        Some(Error::InvalidInput(InputError::TooShort))
    );
}

#[test]
fn after_a_recovery_the_new_state_unlocks_and_the_old_does_not() {
    let s = create("r9", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    let mut pinned = pinned_of(&s);
    let (rec, export) = recover_with(
        &s,
        &code,
        PinState::Pinned(&pinned.clone()),
        PASSWORD_2,
        Some(&key),
        "r9",
    )
    .unwrap();
    // The new password wrap unlocks through the record.
    let seen = view(&pinned);
    pinned
        .unlock_server(&seen, &rec.password_wrap, &kek_pw(&export))
        .unwrap();
    // The new recovery wrap too, and the old recovery wrap is now a rollback.
    let seen = view(&pinned);
    pinned
        .unlock_server(&seen, &rec.recovery_wrap, &kek_rk(&rec.recovery_key))
        .unwrap();
    let seen = view(&pinned);
    assert_eq!(
        pinned
            .unlock_server(&seen, &s.account.wraps[1], &kek_rk(&s.account.recovery_key))
            .err(),
        Some(Error::Pinned(PinnedField::KekGeneration))
    );
    // A second recovery with the new key works from the new state.
    let new_code = encode_recovery_key(&rec.recovery_key).to_string();
    let input = new_input(
        "a third password, long",
        MpPolicy::WithSecretKey,
        Some(&key),
    );
    let reg = register(&s.server, &input, "r9/b");
    let c = ctx1();
    let again = recover(
        &mut rng("r9/c"),
        &RecoveryInput {
            ctx: &c,
            rk_code: &new_code,
            rk_wrap: &rec.recovery_wrap,
            manifest: sealed_row(&rec.manifest),
            new_recovery_method_id: method_id(0x74),
        },
        password(&input, reg, KsfProfile::P1),
        PinState::Pinned(&pinned),
    )
    .unwrap();
    assert_eq!(again.password_wrap.kek_generation, 3);
    assert_eq!(again.recovery_wrap.kek_generation, 3);
    assert_eq!(again.manifest.rev, 3);
}

// -------------------------------------------------------- confirmation

#[test]
fn verify_recovery_setup_unwraps_for_real() {
    let s = create("v1", true);
    let a = &s.account;
    let code = rk_code(&s);
    let before = aead_open_count();
    verify_recovery_setup(&code, &a.wraps[1], &a.vault).unwrap();
    assert_eq!(aead_open_count(), before + 1, "the wrap was opened");
    // Separators and case are as in the sheet.
    let spaced = code.to_lowercase().replace('-', " ");
    verify_recovery_setup(&spaced, &a.wraps[1], &a.vault).unwrap();

    // A typo is reported before any key is used.
    let mut typo = code.clone().into_bytes();
    let last = typo.len() - 1;
    typo[last] = if typo[last] == b'0' { b'1' } else { b'0' };
    let before = aead_open_count();
    assert_eq!(
        verify_recovery_setup(&String::from_utf8(typo).unwrap(), &a.wraps[1], &a.vault).err(),
        Some(Error::Checksum)
    );
    assert_eq!(aead_open_count(), before);

    // A valid code of another key opens nothing.
    let other = encode_recovery_key(&RecoveryKey::from_test_bytes([0x66; 32])).to_string();
    assert_eq!(
        verify_recovery_setup(&other, &a.wraps[1], &a.vault).err(),
        Some(Error::Decrypt)
    );
    // The right code against a wrap that is broken: a string comparison
    // would say yes, the unwrap says no.
    let mut broken = a.wraps[1].clone();
    broken.wrap[30] ^= 1;
    assert_eq!(
        verify_recovery_setup(&code, &broken, &a.vault).err(),
        Some(Error::Decrypt)
    );
    // The right code against a wrap of another vault key.
    let other_vault = unlocked(0x07);
    let mut elsewhere = a.wraps[1].clone();
    elsewhere.method_id = a.wraps[1].method_id;
    assert_eq!(
        verify_recovery_setup(&code, &elsewhere, &other_vault).err(),
        Some(Error::Decrypt)
    );
    // The password wrap is not a recovery wrap.
    assert_eq!(
        verify_recovery_setup(&code, &a.wraps[0], &a.vault).err(),
        Some(Error::Unsupported)
    );
}

#[test]
fn verify_secret_key_entry_constant_time_and_exact() {
    let key = sk(0x5a);
    let code = encode_secret_key(&key).to_string();
    verify_secret_key_entry(&code, &key).unwrap();
    verify_secret_key_entry(&code.to_lowercase().replace('-', " "), &key).unwrap();
    // Another valid key.
    let other = encode_secret_key(&sk(0x5b)).to_string();
    assert_eq!(
        verify_secret_key_entry(&other, &key).err(),
        Some(Error::Decrypt)
    );
    // A single wrong symbol is caught by the check symbols first.
    let mut typo = code.clone().into_bytes();
    typo[6] = if typo[6] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        verify_secret_key_entry(&String::from_utf8(typo).unwrap(), &key).err(),
        Some(Error::Checksum)
    );
    // Prefix, length and a recovery key code are refused.
    for bad in [
        "",
        "FFS1-",
        &code[..code.len() - 1],
        &format!("{code}0"),
        encode_recovery_key(&RecoveryKey::from_test_bytes([1; 32])).as_str(),
    ] {
        assert!(verify_secret_key_entry(bad, &key).is_err(), "{bad:?}");
    }
    // Keys that differ in a single bit are different.
    for bit in 0..16u8 {
        let mut bytes = [0x5a; 16];
        bytes[usize::from(bit)] ^= 1 << (bit % 8);
        let near = encode_secret_key(&SecretKey::from_test_bytes(bytes)).to_string();
        assert_eq!(
            verify_secret_key_entry(&near, &key).err(),
            Some(Error::Decrypt)
        );
    }
}

// --------------------------------------------------------------- types

#[test]
fn the_flow_results_hold_secrets_and_are_not_clone_or_debug() {
    assert_not_impl_any!(NewAccount: Clone, Copy, core::fmt::Debug, core::fmt::Display);
    assert_not_impl_any!(ferret_core::Recovered: Clone, Copy, core::fmt::Debug, core::fmt::Display);
    assert_not_impl_any!(ferret_core::EmergencySheet: Clone, core::fmt::Debug);
    assert_not_impl_any!(ferret_core::AccessPage: Clone, core::fmt::Debug);
    assert_not_impl_any!(ferret_core::RecoveryPage: Clone, core::fmt::Debug);
    assert_not_impl_any!(NewPassword<'static>: Clone, core::fmt::Debug);
    static_assertions::assert_impl_all!(ferret_core::PasswordChange: Clone, core::fmt::Debug);
    let _ = (AccountId::from_bytes([0; 16]), UnlockedVault::context);
}

#[test]
fn the_emergency_sheet_of_a_new_account_reads_back() {
    let s = create("e1", true);
    let a = &s.account;
    let sheet = ferret_core::emergency_sheet(
        URL,
        "ferret@example.com",
        &account(0x11),
        KsfProfile::P1,
        &a.server_public_key,
        a.secret_key.as_ref(),
        &a.recovery_key,
    )
    .unwrap();
    // Separate pages: the secret key on page 1, the recovery key alone on
    // page 2.
    let sk_code = sheet.access.secret_key_code.as_ref().unwrap();
    verify_secret_key_entry(sk_code, a.secret_key.as_ref().unwrap()).unwrap();
    verify_recovery_setup(&sheet.recovery.recovery_key_code, &a.wraps[1], &a.vault).unwrap();
    assert!(!sheet.access.qr_payload.contains(&**sk_code));
    let qr = parse_setup_qr(&sheet.access.qr_payload).unwrap();
    assert_eq!(qr.server_url, URL);
    assert_eq!(qr.account_id, account(0x11));
    assert!(qr.sk_bit);
    assert_eq!(qr.server_public_key, s.server.public_key());
    // The QR's server key is what a recovery on a new device compares.
    let _ = json!({});
}

// ------------------------------------------------------------- vectors

/// The inputs and outputs of the account vector ops, in the shape that
/// `vectors/OPS.md` describes.
fn run_vectors() -> ferret_core::testing::vector::RunReport {
    let path = vectors_dir().join("internal/account.json");
    let file = ferret_core::testing::vector::load(&path).unwrap();
    ferret_core::testing::vector::run_all(&file, |case, rng| {
        ferret_core::testing::account::run_case(&case.op, &case.input, rng).map(|output| Outcome {
            output,
            intermediate: None,
        })
    })
}

/// Every case of `vectors/internal/account.json`. The cases carry recorded
/// registrations, so no Argon2id runs.
#[test]
fn account_vectors_from_file() {
    let report = run_vectors();
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert!(report.passed >= 12, "{} cases", report.passed);
}

// ------------------------------------------------- manifests, pins and recovery

/// A manifest sealed with the account's vault, at revision `rev`.
fn sealed_manifest(
    s: &Setup,
    rev: u64,
    methods: Vec<ManifestEntry>,
    extra: Vec<(String, Value)>,
) -> ferret_core::SealedItem {
    let mut manifest = Manifest::new(1, methods);
    manifest.extra = extra;
    ferret_core::encrypt_manifest(&mut rng("manifest"), &s.account.vault, rev, &manifest).unwrap()
}

/// The SK-bit downgrade in its real direction: the device pinned an account
/// that has a secret key, the new password (15 characters, so it meets the
/// floor) has none. Nothing is drawn.
#[test]
fn change_password_refuses_dropping_the_secret_key() {
    let s = create("f1", true);
    let pinned = pinned_of(&s);
    assert!(pinned.sk_bit);
    let input = new_input(PASSWORD_2, MpPolicy::WithoutSecretKey, None);
    assert!(input.meets_creation_floor() && !input.includes_secret_key());
    let reg = register(&s.server, &input, "f1");
    assert_eq!(
        change_password(
            &mut no_draws(),
            &s.account.vault,
            password(&input, reg, KsfProfile::P1),
            &pinned,
            &s.account.wraps[0],
            &row(&s.account),
        )
        .err(),
        Some(Error::Pinned(PinnedField::SkBit))
    );
}

#[test]
fn recover_refuses_dropping_the_secret_key() {
    let s = create("f2", true);
    let code = rk_code(&s);
    let pinned = pinned_of(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithoutSecretKey, None);
    assert!(input.meets_creation_floor() && !input.includes_secret_key());
    let reg = register(&s.server, &input, "f2");
    let c = ctx1();
    assert_eq!(
        recover(
            &mut no_draws(),
            &RecoveryInput {
                ctx: &c,
                rk_code: &code,
                rk_wrap: &s.account.wraps[1],
                manifest: row(&s.account),
                new_recovery_method_id: method_id(0x73),
            },
            password(&input, reg, KsfProfile::P1),
            PinState::Pinned(&pinned),
        )
        .err(),
        Some(Error::Pinned(PinnedField::SkBit))
    );
}

#[test]
fn recover_needs_a_new_recovery_method_id() {
    let s = create("f3", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));
    let c = ctx1();
    // A manifest with a passkey as well.
    let manifest = sealed_manifest(
        &s,
        4,
        vec![
            ManifestEntry::new(1, method_id(0x70), 1),
            ManifestEntry::passkey(method_id(0x75), 3, vec![1, 2, 3]),
            ManifestEntry::new(2, method_id(0x71), 1),
        ],
        vec![],
    );
    let go = |new_id: u8, draws: bool| {
        let reg = register(&s.server, &input, "f3");
        let data = RecoveryInput {
            ctx: &c,
            rk_code: &code,
            rk_wrap: &s.account.wraps[1],
            manifest: sealed_row(&manifest),
            new_recovery_method_id: method_id(new_id),
        };
        if draws {
            recover(
                &mut rng("f3/draws"),
                &data,
                password(&input, reg, KsfProfile::P1),
                PinState::FirstUse,
            )
        } else {
            recover(
                &mut no_draws(),
                &data,
                password(&input, reg, KsfProfile::P1),
                PinState::FirstUse,
            )
        }
    };
    let entries = Error::Malformed(MalformedKind::Entries);
    // The password wrap's id, and the passkey's.
    assert_eq!(go(0x70, false).err(), Some(entries));
    assert_eq!(go(0x75, false).err(), Some(entries));
    // A fresh id, and the old recovery wrap's own id (it is replaced).
    let fresh = go(0x73, true).unwrap();
    assert_eq!(fresh.recovery_wrap.method_id, method_id(0x73));
    let same = go(0x71, true).unwrap();
    assert_eq!(same.recovery_wrap.method_id, method_id(0x71));
}

#[test]
fn a_manifest_without_exactly_one_password_and_recovery_entry_is_refused() {
    let s = create("f4", true);
    let code = rk_code(&s);
    let key = sk(0x5a);
    let pinned = pinned_of(&s);
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));
    let c = ctx1();
    let entries = Error::Malformed(MalformedKind::Entries);
    let shapes: Vec<(&str, Vec<ManifestEntry>)> = vec![
        (
            "two password entries",
            vec![
                ManifestEntry::new(1, method_id(0x70), 1),
                ManifestEntry::new(1, method_id(0x76), 1),
                ManifestEntry::new(2, method_id(0x71), 1),
            ],
        ),
        (
            "two recovery entries",
            vec![
                ManifestEntry::new(1, method_id(0x70), 1),
                ManifestEntry::new(2, method_id(0x71), 1),
                ManifestEntry::new(2, method_id(0x77), 1),
            ],
        ),
        (
            "no password entry",
            vec![ManifestEntry::new(2, method_id(0x71), 1)],
        ),
        (
            "no recovery entry",
            vec![ManifestEntry::new(1, method_id(0x70), 1)],
        ),
    ];
    for (what, methods) in shapes {
        let manifest = sealed_manifest(&s, 4, methods, vec![]);
        let reg = register(&s.server, &input, "f4/a");
        assert_eq!(
            recover(
                &mut no_draws(),
                &RecoveryInput {
                    ctx: &c,
                    rk_code: &code,
                    rk_wrap: &s.account.wraps[1],
                    manifest: sealed_row(&manifest),
                    new_recovery_method_id: method_id(0x73),
                },
                password(&input, reg, KsfProfile::P1),
                PinState::FirstUse,
            )
            .err(),
            Some(entries),
            "recover: {what}"
        );
        // A change of password reads only the password entry: a second or a
        // missing recovery entry is not its business.
        let password_shape_bad = what.contains("password");
        let reg = register(&s.server, &input, "f4/b");
        let result = change_password(
            &mut rng("f4/change"),
            &s.account.vault,
            password(&input, reg, KsfProfile::P1),
            &pinned,
            &s.account.wraps[0],
            &sealed_row(&manifest),
        );
        if password_shape_bad {
            assert_eq!(result.err(), Some(entries), "change: {what}");
        } else {
            result.unwrap();
        }
    }
}

/// A manifest with a passkey entry and unknown keys at both levels: the
/// flows change only the password and recovery entries.
#[test]
fn the_other_manifest_entries_and_unknown_keys_survive_a_change_and_a_recovery() {
    let s = create("f5", true);
    let key = sk(0x5a);
    let passkey = {
        let mut e = ManifestEntry::passkey(method_id(0x75), 4, vec![9, 8, 7]);
        e.extra = vec![("aaguid".into(), Value::text("abc"))];
        e
    };
    let mut password_entry = ManifestEntry::new(1, method_id(0x70), 1);
    password_entry.extra = vec![("note".into(), Value::uint(5))];
    let mut recovery_entry = ManifestEntry::new(2, method_id(0x71), 1);
    recovery_entry.extra = vec![("created".into(), Value::uint(77))];
    let top_extra: Vec<(String, Value)> = vec![
        ("future".into(), Value::uint(7)),
        ("label".into(), Value::text("kept")),
    ];
    let methods = vec![
        password_entry.clone(),
        passkey.clone(),
        recovery_entry.clone(),
    ];
    let manifest = sealed_manifest(&s, 4, methods, top_extra.clone());
    let input = new_input(PASSWORD_2, MpPolicy::WithSecretKey, Some(&key));

    // Change of password.
    let pinned = pinned_of(&s);
    let reg = register(&s.server, &input, "f5/a");
    let changed = change_password(
        &mut rng("f5/change"),
        &s.account.vault,
        password(&input, reg, KsfProfile::P1),
        &pinned,
        &s.account.wraps[0],
        &sealed_row(&manifest),
    )
    .unwrap();
    let after = decrypt_manifest(
        &s.account.vault,
        changed.manifest.rev,
        &changed.manifest.envelope,
        &changed.manifest.tag,
    )
    .unwrap();
    assert_eq!(changed.manifest.rev, 5);
    assert_eq!(after.extra, top_extra);
    let mut want_password = password_entry.clone();
    want_password.kek_generation = 2;
    assert_eq!(
        after.methods,
        vec![want_password, passkey.clone(), recovery_entry.clone()]
    );

    // Recovery.
    let code = rk_code(&s);
    let reg = register(&s.server, &input, "f5/b");
    let c = ctx1();
    let rec = recover(
        &mut rng("f5/recover"),
        &RecoveryInput {
            ctx: &c,
            rk_code: &code,
            rk_wrap: &s.account.wraps[1],
            manifest: sealed_row(&manifest),
            new_recovery_method_id: method_id(0x73),
        },
        password(&input, reg, KsfProfile::P1),
        PinState::FirstUse,
    )
    .unwrap();
    let after = decrypt_manifest(
        &rec.vault,
        rec.manifest.rev,
        &rec.manifest.envelope,
        &rec.manifest.tag,
    )
    .unwrap();
    assert_eq!(after.extra, top_extra);
    let mut want_password = password_entry;
    want_password.kek_generation = 2;
    let mut want_recovery = recovery_entry;
    want_recovery.method_id = method_id(0x73);
    want_recovery.kek_generation = 2;
    assert_eq!(after.methods, vec![want_password, passkey, want_recovery]);
}

#[test]
fn the_password_change_proof_is_made_only_by_its_own_vault() {
    let s = create("f6", true);
    let pinned = pinned_of(&s);
    let (changed, _) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "f6").unwrap();
    assert_eq!(changed.pk_a, s.account.pk_a);
    let nonce = [1; 32];
    changed.sign(&s.account.vault, &nonce, b"body").unwrap();
    // Another open vault (another vault key) does not sign it.
    let other = unlocked(0x07);
    assert_ne!(other.auth_public_key(), changed.pk_a);
    assert_eq!(
        changed.sign(&other, &nonce, b"body").err(),
        Some(Error::Pinned(PinnedField::AuthKey))
    );
}

// ------------------------------------------------- the pinned record after a flow

fn floor_of(pinned: &Pinned, key: MethodKey) -> Option<u64> {
    pinned
        .kek_generation_max
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, g)| *g)
}

#[test]
fn a_password_change_gives_the_pinned_record_to_store() {
    let s = create("pp1", true);
    let pinned = pinned_of(&s);
    let (changed, export) = change(&s, &pinned, PASSWORD_2, KsfProfile::P1, "pp1").unwrap();
    let mut after = changed.pinned(&pinned).unwrap();
    // The password floor is the new generation, the recovery floor is as it
    // was, and the record that was passed in is untouched.
    assert_eq!(floor_of(&after, MethodKey::Password), Some(2));
    assert_eq!(floor_of(&after, MethodKey::Recovery), Some(1));
    assert_eq!(floor_of(&pinned, MethodKey::Password), Some(1));
    assert_eq!(after.server_public_key, pinned.server_public_key);
    // The new record opens the new wrap and refuses the old one without any
    // unlock in between.
    let seen = view(&after);
    assert_eq!(
        after
            .unlock_server(&seen, &s.account.wraps[0], &kek_pw(&s.export))
            .err(),
        Some(Error::Pinned(PinnedField::KekGeneration))
    );
    let vault = after
        .unlock_server(&seen, &changed.wrap, &kek_pw(&export))
        .unwrap();
    assert!(vault.same_vault_key(&s.account.vault));
    // A record for another vault key is refused.
    let mut other = pinned.clone();
    other.pk_a = [9; 32];
    assert_eq!(
        changed.pinned(&other).err(),
        Some(Error::Pinned(PinnedField::AuthKey))
    );
}

#[test]
fn a_recovery_gives_the_pinned_record_to_store() {
    let s = create("pp2", true);
    let code = rk_code(&s);
    let key = sk(0x5a);

    // A device with a record: both floors go up.
    let pinned = pinned_of(&s);
    let (rec, export) = recover_with(
        &s,
        &code,
        PinState::Pinned(&pinned),
        PASSWORD_2,
        Some(&key),
        "pp2",
    )
    .unwrap();
    let mut after = rec.pinned(URL, Some(&pinned)).unwrap();
    assert_eq!(floor_of(&after, MethodKey::Password), Some(2));
    assert_eq!(floor_of(&after, MethodKey::Recovery), Some(2));
    assert_eq!(after.account_id, pinned.account_id);
    let seen = view(&after);
    let vault = after
        .unlock_server(&seen, &rec.password_wrap, &kek_pw(&export))
        .unwrap();
    assert!(vault.same_vault_key(&s.account.vault));
    // A record of another account is refused.
    let mut other = pinned.clone();
    other.account_id = account(0x99);
    assert_eq!(
        rec.pinned(URL, Some(&other)).err(),
        Some(Error::Pinned(PinnedField::AccountId))
    );

    // A new device (trust on first use): a new record with the server key of
    // the registration and the SK bit of the new input.
    let (rec, export) = recover_with(
        &s,
        &code,
        PinState::FirstUse,
        PASSWORD_2,
        Some(&key),
        "pp2b",
    )
    .unwrap();
    let mut fresh = rec.pinned(URL, None).unwrap();
    assert_eq!(fresh.server_url, URL);
    assert!(fresh.sk_bit);
    assert_eq!(fresh.server_public_key, Some(s.server.public_key()));
    assert_eq!(floor_of(&fresh, MethodKey::Password), Some(2));
    assert_eq!(floor_of(&fresh, MethodKey::Recovery), Some(2));
    assert_eq!(fresh.pk_a, rec.vault.auth_public_key());
    let seen = view(&fresh);
    assert!(
        fresh
            .unlock_server(&seen, &rec.password_wrap, &kek_pw(&export))
            .is_ok()
    );
    // An address that cannot be pinned is refused.
    let long = "x".repeat(600);
    assert_eq!(
        rec.pinned(&long, None).err(),
        Some(Error::Malformed(MalformedKind::PinnedRecord))
    );
}
