//! The vector groups for the account flows (`account.json`) and the setup QR
//! payload (`sheet.json`).
//!
//! The flows take a finished OPAQUE registration, so each `account.*` case
//! carries the `record`, `export_key` and `server_public_key` of one that the
//! generator made against an `opaque-ke` server with a small Argon2id (a few
//! KiB: the flows do not care which parameters made the export key, and the
//! production parameters are covered by `opaque.json`). No case runs Argon2id.
//!
//! Like `opaque.json`, the expected values are recorded from the core, with
//! two things written apart from it: the generator checks that the vault key
//! and the recovery key in an output are the first draws it recorded, that a
//! wrap begins with the nonce it drew, and that `pk_a` is the one the key
//! hierarchy vectors (`kdf.json`) derive. Every error case lists the code it
//! must give, and the generator refuses a file in which a case does not.

use crate::groups::generator;
use crate::opaque_groups::Recording;
use crate::{Error, render};
use ferret_core::testing::account::run_case;
use ferret_core::testing::opaque::{Server, TestKsf, register_finish_with};
use ferret_core::testing::vector::{Case, FORMAT, Status, Tag, VectorFile};
use ferret_core::testing::{TestRng, hex_encode};
use ferret_core::{
    KdfParams, KsfProfile, MasterPassword, RecoveryKey, SecretKey, encode_recovery_key,
    encode_secret_key,
};
use serde_json::{Value, json};

const ACCOUNT: [u8; 16] = [0x11; 16];
const VAULT: [u8; 16] = [0x22; 16];
const URL: &str = "https://ferret.example";
const SMALL: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const PASSWORD: &str = "correct horse battery staple";
const PASSWORD_2: &str = "tr0ub4dor and three more words";

fn h(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

fn sk_bytes() -> [u8; 16] {
    [0x5a; 16]
}

/// A finished OPAQUE registration of `password` (with `sk`) on `server`, as
/// the `registration` object of a case.
fn registration(
    server: &Server,
    password: &str,
    sk: Option<[u8; 16]>,
    seed: &str,
) -> Result<Value, Error> {
    let mp = MasterPassword::for_unlock(password.as_bytes()).map_err(|e| e.code())?;
    let key = sk.map(SecretKey::from_test_bytes);
    let input = mp.opaque_input(key.as_ref());
    let mut rng = TestRng::new(format!("account/{seed}/registration").as_bytes());
    let (request, state) =
        ferret_core::opaque_register_start(&mut rng, &input).map_err(|e| e.code())?;
    let response = server
        .register_response(&ACCOUNT, &request)
        .map_err(|e| e.code())?;
    let done = register_finish_with(&mut rng, state, &input, &response, &TestKsf::new(SMALL))
        .map_err(|e| e.code())?;
    Ok(json!({
        "record": h(&done.record),
        "export_key": h(&ferret_core::testing::keys::export_key_bytes(&done.export_key)),
        "server_public_key": h(&done.server_public_key),
    }))
}

/// The common fields of a vault in a case input.
fn vault_fields(vk: &str, epoch: u64) -> Value {
    json!({
        "account_id": h(&ACCOUNT),
        "vault_id": h(&VAULT),
        "vk_epoch": epoch.to_string(),
        "vk": vk,
    })
}

fn merge(base: Value, extra: Value) -> Value {
    let (Value::Object(mut a), Value::Object(b)) = (base, extra) else {
        panic!("objects expected");
    };
    a.extend(b);
    Value::Object(a)
}

struct Maker {
    cases: Vec<Case>,
}

impl Maker {
    /// Runs an op once with a recording generator.
    fn run(
        op: &str,
        input: &Value,
        seed: &str,
    ) -> (Result<Value, ferret_core::Error>, Vec<String>) {
        let mut rec = Recording::new(&format!("account/{seed}"));
        let result = run_case(op, input, &mut rec);
        (result, rec.draws)
    }

    fn base(id: &str, title: &str, op: &str, input: &Value, draws: Vec<String>) -> Case {
        Case {
            id: id.into(),
            title: title.into(),
            op: op.into(),
            status: Status::Valid,
            tags: Vec::<Tag>::new(),
            synthetic: true,
            skip_reason: None,
            rng: draws,
            input: input.clone(),
            intermediate: None,
            expect: None,
            expect_error: None,
        }
    }

    /// A case that must succeed; returns the output and the recorded draws.
    fn ok(
        &mut self,
        id: &str,
        title: &str,
        op: &str,
        input: Value,
    ) -> Result<(Value, Vec<String>), Error> {
        let (result, draws) = Self::run(op, &input, id);
        let out = result.map_err(|e| format!("{id}: expected success, got {}", e.code()))?;
        let mut case = Self::base(id, title, op, &input, draws.clone());
        case.expect = Some(out.clone());
        self.cases.push(case);
        Ok((out, draws))
    }

    /// A case that must fail with `code`.
    fn err(
        &mut self,
        id: &str,
        title: &str,
        op: &str,
        input: Value,
        code: &str,
    ) -> Result<(), Error> {
        let (result, draws) = Self::run(op, &input, id);
        match result {
            Ok(_) => return Err(format!("{id}: expected {code}, got success").into()),
            Err(e) if e.code() != code => {
                return Err(format!("{id}: expected {code}, got {}", e.code()).into());
            }
            Err(_) => {}
        }
        let mut case = Self::base(id, title, op, &input, draws);
        case.status = Status::Invalid;
        case.expect_error = Some(code.into());
        self.cases.push(case);
        Ok(())
    }
}

fn pinned_json(
    profile: u8,
    sk_bit: bool,
    key: Option<&str>,
    pk_a: &str,
    floors: (Option<u64>, Option<u64>),
) -> Value {
    json!({
        "server_url": URL,
        "ksf_profile": profile,
        "sk_bit": sk_bit,
        "server_public_key": key,
        "pk_a": pk_a,
        "vk_epoch_max": "1",
        "password_floor": floors.0.map(|g| g.to_string()),
        "recovery_floor": floors.1.map(|g| g.to_string()),
    })
}

fn check(cond: bool, what: &str) -> Result<(), Error> {
    if cond {
        Ok(())
    } else {
        Err(format!("generator check failed: {what}").into())
    }
}

pub(crate) fn account() -> Result<Vec<u8>, Error> {
    let mut m = Maker { cases: vec![] };
    let server = Server::new(&mut TestRng::new(b"account/server"));
    let other_server = Server::new(&mut TestRng::new(b"account/server-other"));
    let server_key = h(&server.public_key());
    let sk = sk_bytes();

    let reg_a = registration(&server, PASSWORD, Some(sk), "a")?;
    let reg_b = registration(&server, PASSWORD, None, "b")?;
    let ids = json!({
        "account_id": h(&ACCOUNT),
        "vault_id": h(&VAULT),
        "password_method_id": h(&[0x70; 16]),
        "recovery_method_id": h(&[0x71; 16]),
    });
    let create_input = |reg: &Value,
                        policy: &str,
                        password: &str,
                        input_sk: Option<[u8; 16]>,
                        given: Option<[u8; 16]>| {
        merge(
            ids.clone(),
            json!({
                "ksf_profile": 1,
                "password": password,
                "policy": policy,
                "input_secret_key": input_sk.map(|k| h(&k)),
                "secret_key": given.map(|k| h(&k)),
                "registration": reg,
            }),
        )
    };

    // ---- create
    let (created, draws) = m.ok(
        "account/create/001",
        "create, with a secret key",
        "account.create",
        create_input(&reg_a, "with_secret_key", PASSWORD, Some(sk), Some(sk)),
    )?;
    // Written apart from the core: the vault key and the recovery key are
    // the first two draws, a wrap starts with its nonce, `pk_a` is the one
    // derived from the vault key.
    check(created["vk"] == json!(draws[0]), "vk is the first draw")?;
    check(created["rk"] == json!(draws[1]), "rk is the second draw")?;
    for (wrap, draw) in created["wraps"]
        .as_array()
        .unwrap()
        .iter()
        .zip(&draws[2..4])
    {
        check(
            wrap["wrap"].as_str().unwrap().starts_with(draw.as_str()),
            "a wrap starts with its nonce",
        )?;
    }
    let vk_hex = created["vk"].as_str().unwrap().to_owned();
    let derived = ferret_core::testing::keys::derived_keys(
        &ferret_core::VaultContext {
            account_id: ferret_core::AccountId::from_bytes(ACCOUNT),
            vault_id: ferret_core::VaultId::from_bytes(VAULT),
            vk_epoch: 1,
        },
        &ferret_core::VaultKey::from_test_bytes(
            ferret_core::testing::hex_decode(&vk_hex)
                .unwrap()
                .try_into()
                .unwrap(),
        ),
    )
    .map_err(|e| e.code())?;
    check(
        created["pk_a"] == json!(h(&derived.pk_a)),
        "pk_a is derived from vk",
    )?;
    let (created_b, _) = m.ok(
        "account/create/002",
        "create, without a secret key (15 characters)",
        "account.create",
        create_input(&reg_b, "without_secret_key", PASSWORD, None, None),
    )?;
    let _ = created_b;
    m.err(
        "account/create/003",
        "a password made for unlock cannot be set",
        "account.create",
        create_input(&reg_a, "unlock", PASSWORD, Some(sk), Some(sk)),
        "input_too_short",
    )?;
    m.err(
        "account/create/004",
        "the secret key given is not the one in the password",
        "account.create",
        create_input(
            &reg_a,
            "with_secret_key",
            PASSWORD,
            Some(sk),
            Some([0x5b; 16]),
        ),
        "input_secret_key_mismatch",
    )?;
    m.err(
        "account/create/005",
        "the password has a secret key and none is given",
        "account.create",
        create_input(&reg_a, "with_secret_key", PASSWORD, Some(sk), None),
        "input_secret_key_mismatch",
    )?;
    m.err(
        "account/create/006",
        "12 characters meet the floor only with a secret key",
        "account.create",
        create_input(&reg_b, "with_secret_key", "twelve chars", None, None),
        "input_too_short",
    )?;
    m.err(
        "account/create/007",
        "fewer than 12 characters (the password cannot even be built)",
        "account.create",
        create_input(&reg_a, "with_secret_key", "eleven char", Some(sk), Some(sk)),
        "input_too_short",
    )?;
    let mut same_ids = create_input(&reg_a, "with_secret_key", PASSWORD, Some(sk), Some(sk));
    same_ids["recovery_method_id"] = same_ids["password_method_id"].clone();
    m.err(
        "account/create/008",
        "both wraps with one method id",
        "account.create",
        same_ids,
        "malformed_entries",
    )?;

    // ---- the account the next cases start from
    let pw_wrap =
        |w: &Value| -> Value { merge(w.clone(), json!({ "type": "password", "ksf_profile": 1 })) };
    let rk_wrap = |w: &Value| -> Value { merge(w.clone(), json!({ "type": "recovery" })) };
    let wraps = created["wraps"].as_array().unwrap().clone();
    let vault = vault_fields(&vk_hex, 1);
    let pk_a = created["pk_a"].as_str().unwrap().to_owned();
    let manifest = created["manifest"].clone();
    let rk_code = {
        let rk = RecoveryKey::from_test_bytes(
            ferret_core::testing::hex_decode(created["rk"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        encode_recovery_key(&rk).to_string()
    };
    let reg_new = registration(&server, PASSWORD_2, Some(sk), "new")?;
    let reg_new_other = registration(&other_server, PASSWORD_2, Some(sk), "new-other")?;
    let good_pin = pinned_json(1, true, Some(&server_key), &pk_a, (Some(1), Some(1)));
    let change_input = |reg: &Value, policy: &str, pinned: &Value, manifest: &Value, sign: bool| {
        merge(
            vault.clone(),
            json!({
                "ksf_profile": 1,
                "password": PASSWORD_2,
                "policy": policy,
                "input_secret_key": h(&sk),
                "registration": reg,
                "current": pw_wrap(&wraps[0]),
                "manifest": manifest,
                "pinned": pinned,
                "sign": sign.then(|| json!({ "nonce": h(&[0x33; 32]), "body": h(b"{\"put\":\"password\"}") })),
            }),
        )
    };

    // ---- change password
    let (changed, draws) = m.ok(
        "account/change-password/001",
        "change the master password, generation 1 to 2, with the proof",
        "account.change_password",
        change_input(&reg_new, "with_secret_key", &good_pin, &manifest, true),
    )?;
    check(draws.len() == 2, "two draws")?;
    check(
        changed["wrap"]["wrap"]
            .as_str()
            .unwrap()
            .starts_with(draws[0].as_str()),
        "the wrap starts with its nonce",
    )?;
    check(
        changed["wrap"]["kek_generation"] == json!("2"),
        "generation 2",
    )?;
    m.ok(
        "account/change-password/002",
        "upgrade to the same profile with the same password (a re-registration)",
        "account.change_password",
        merge(
            change_input(&reg_a, "with_secret_key", &good_pin, &manifest, true),
            json!({ "password": PASSWORD }),
        ),
    )?;
    let high = pinned_json(1, true, Some(&server_key), &pk_a, (Some(7), Some(1)));
    let (high_out, _) = m.ok(
        "account/change-password/003",
        "the device remembers generation 7: the new wrap is 8",
        "account.change_password",
        change_input(&reg_new, "with_secret_key", &high, &manifest, false),
    )?;
    check(
        high_out["wrap"]["kek_generation"] == json!("8"),
        "generation 8",
    )?;
    m.err(
        "account/change-password/004",
        "the device pinned profile 2: profile 1 is a downgrade",
        "account.change_password",
        change_input(
            &reg_new,
            "with_secret_key",
            &pinned_json(2, true, Some(&server_key), &pk_a, (Some(1), Some(1))),
            &manifest,
            false,
        ),
        "kdf_profile_downgrade",
    )?;
    m.err(
        "account/change-password/005",
        "the registration shows another OPAQUE server key than the pinned one",
        "account.change_password",
        change_input(
            &reg_new_other,
            "with_secret_key",
            &good_pin,
            &manifest,
            false,
        ),
        "pinned_server_key",
    )?;
    m.err(
        "account/change-password/006",
        "the device pinned an account without a secret key",
        "account.change_password",
        change_input(
            &reg_new,
            "with_secret_key",
            &pinned_json(1, false, Some(&server_key), &pk_a, (Some(1), Some(1))),
            &manifest,
            false,
        ),
        "pinned_sk_bit",
    )?;
    let mut bad_tag = manifest.clone();
    let tag = bad_tag["tag"].as_str().unwrap().to_owned();
    bad_tag["tag"] = json!(format!(
        "{}{}",
        if tag.starts_with('0') { "1" } else { "0" },
        &tag[1..]
    ));
    m.err(
        "account/change-password/007",
        "the manifest row has a wrong tag",
        "account.change_password",
        change_input(&reg_new, "with_secret_key", &good_pin, &bad_tag, false),
        "decrypt",
    )?;
    m.err(
        "account/change-password/008",
        "a password made for unlock cannot be set",
        "account.change_password",
        change_input(&reg_new, "unlock", &good_pin, &manifest, false),
        "input_too_short",
    )?;
    m.err(
        "account/change-password/009",
        "the pinned record is for another vault key (pk_a)",
        "account.change_password",
        change_input(
            &reg_new,
            "with_secret_key",
            &pinned_json(1, true, Some(&server_key), &h(&[9; 32]), (Some(1), Some(1))),
            &manifest,
            false,
        ),
        "pinned_auth_key",
    )?;
    m.err(
        "account/change-password/010",
        "the pinned record has no password floor (not seeded from the manifest)",
        "account.change_password",
        change_input(
            &reg_new,
            "with_secret_key",
            &pinned_json(1, true, Some(&server_key), &pk_a, (None, Some(1))),
            &manifest,
            false,
        ),
        "malformed_pinned_record",
    )?;

    // ---- recover
    let recover_input = |code: &str, reg: &Value, pinned: Option<&Value>, sign: bool| {
        merge(
            vault.clone(),
            json!({
                "ksf_profile": 1,
                "password": PASSWORD_2,
                "policy": "with_secret_key",
                "input_secret_key": h(&sk),
                "registration": reg,
                "rk_code": code,
                "rk_wrap": rk_wrap(&wraps[1]),
                "manifest": manifest,
                "new_recovery_method_id": h(&[0x73; 16]),
                "pinned": pinned,
                "sign": sign.then(|| json!({ "nonce": h(&[0x44; 32]), "body": h(b"{\"recover\":true}") })),
            }),
        )
    };
    let (recovered, draws) = m.ok(
        "account/recover/001",
        "recover on a new device: new password wrap, new recovery key, proof with the old one",
        "account.recover",
        recover_input(&rk_code, &reg_new, None, true),
    )?;
    check(draws.len() == 4, "four draws")?;
    check(
        recovered["recovery_key"] == json!(draws[1]),
        "the new recovery key is the second draw",
    )?;
    check(
        recovered["vk"] == json!(vk_hex),
        "the vault key is unchanged",
    )?;
    check(
        recovered["recovery_key"] != created["rk"],
        "the recovery key is new",
    )?;
    m.ok(
        "account/recover/002",
        "recover on a device with a pinned record that agrees",
        "account.recover",
        recover_input(&rk_code, &reg_new, Some(&good_pin), false),
    )?;
    let (floored, _) = m.ok(
        "account/recover/003",
        "recover where the device remembers password generation 5",
        "account.recover",
        recover_input(
            &rk_code,
            &reg_new,
            Some(&pinned_json(
                1,
                true,
                Some(&server_key),
                &pk_a,
                (Some(5), Some(1)),
            )),
            false,
        ),
    )?;
    check(
        floored["password_wrap"]["kek_generation"] == json!("6"),
        "generation 6",
    )?;
    // A typo in the last symbol: the check symbols come first.
    let mut typo = rk_code.clone().into_bytes();
    let last = typo.len() - 1;
    typo[last] = if typo[last] == b'0' { b'1' } else { b'0' };
    let typo = String::from_utf8(typo).unwrap();
    m.err(
        "account/recover/004",
        "a typo in the recovery key code is found before any key is used",
        "account.recover",
        recover_input(&typo, &reg_new, None, false),
        "checksum",
    )?;
    let other_rk = encode_recovery_key(&RecoveryKey::from_test_bytes([0x66; 32])).to_string();
    m.err(
        "account/recover/005",
        "a valid code of another recovery key does not open the wrap",
        "account.recover",
        recover_input(&other_rk, &reg_new, None, false),
        "decrypt",
    )?;
    m.err(
        "account/recover/006",
        "the registration shows another OPAQUE server key than the pinned one",
        "account.recover",
        recover_input(&rk_code, &reg_new_other, Some(&good_pin), false),
        "pinned_server_key",
    )?;
    m.err(
        "account/recover/007",
        "the device remembers recovery generation 4: the wrap is older",
        "account.recover",
        recover_input(
            &rk_code,
            &reg_new,
            Some(&pinned_json(
                1,
                true,
                Some(&server_key),
                &pk_a,
                (Some(1), Some(4)),
            )),
            false,
        ),
        "pinned_kek_generation",
    )?;
    m.err(
        "account/recover/008",
        "the device pinned an account without a secret key",
        "account.recover",
        recover_input(
            &rk_code,
            &reg_new,
            Some(&pinned_json(
                1,
                false,
                Some(&server_key),
                &pk_a,
                (Some(1), Some(1)),
            )),
            false,
        ),
        "pinned_sk_bit",
    )?;
    m.err(
        "account/recover/009",
        "a password made for unlock cannot be set",
        "account.recover",
        merge(
            recover_input(&rk_code, &reg_new, None, false),
            json!({ "policy": "unlock" }),
        ),
        "input_too_short",
    )?;

    // ---- confirmation at setup
    let verify_rk = |entered: &str, wrap: &Value, vk: &str| {
        merge(
            vault_fields(vk, 1),
            json!({ "entered": entered, "rk_wrap": rk_wrap(wrap) }),
        )
    };
    m.ok(
        "account/verify-recovery/001",
        "the recovery key typed in full opens the recovery wrap",
        "account.verify_recovery",
        verify_rk(&rk_code, &wraps[1], &vk_hex),
    )?;
    m.ok(
        "account/verify-recovery/002",
        "lower case and spaces for dashes, as read from the sheet",
        "account.verify_recovery",
        verify_rk(
            &rk_code.to_lowercase().replace('-', " "),
            &wraps[1],
            &vk_hex,
        ),
    )?;
    m.err(
        "account/verify-recovery/003",
        "a typo is found by the check symbols",
        "account.verify_recovery",
        verify_rk(&typo, &wraps[1], &vk_hex),
        "checksum",
    )?;
    m.err(
        "account/verify-recovery/004",
        "a valid code of another recovery key",
        "account.verify_recovery",
        verify_rk(&other_rk, &wraps[1], &vk_hex),
        "decrypt",
    )?;
    let mut broken = wraps[1].clone();
    let w = broken["wrap"].as_str().unwrap().to_owned();
    broken["wrap"] = json!(format!(
        "{}{}{}",
        &w[..60],
        if &w[60..61] == "0" { "1" } else { "0" },
        &w[61..]
    ));
    m.err(
        "account/verify-recovery/005",
        "the right code against a wrap with a changed byte: the unwrap fails",
        "account.verify_recovery",
        verify_rk(&rk_code, &broken, &h(&[0x07; 32])),
        "decrypt",
    )?;
    m.err(
        "account/verify-recovery/006",
        "the right code against another vault key",
        "account.verify_recovery",
        verify_rk(&rk_code, &wraps[1], &h(&[0x07; 32])),
        "decrypt",
    )?;
    let sk_code = encode_secret_key(&SecretKey::from_test_bytes(sk)).to_string();
    let verify_sk = |entered: &str| json!({ "entered": entered, "secret_key": h(&sk) });
    m.ok(
        "account/verify-secret-key/001",
        "the secret key typed in full matches",
        "account.verify_secret_key",
        verify_sk(&sk_code),
    )?;
    m.ok(
        "account/verify-secret-key/002",
        "lower case and spaces for dashes",
        "account.verify_secret_key",
        verify_sk(&sk_code.to_lowercase().replace('-', " ")),
    )?;
    m.err(
        "account/verify-secret-key/003",
        "a valid code of another secret key",
        "account.verify_secret_key",
        verify_sk(&encode_secret_key(&SecretKey::from_test_bytes([0x5b; 16]))),
        "decrypt",
    )?;
    let mut typo_sk = sk_code.clone().into_bytes();
    typo_sk[6] = if typo_sk[6] == b'0' { b'1' } else { b'0' };
    m.err(
        "account/verify-secret-key/004",
        "a typo is found by the check symbols",
        "account.verify_secret_key",
        verify_sk(&String::from_utf8(typo_sk).unwrap()),
        "checksum",
    )?;

    let _ = KsfProfile::P1;
    render(&VectorFile {
        format: FORMAT.into(),
        group: "account".into(),
        suite: 1,
        spec: "Fase 1 § 4.2, § 4.3, § 4.6, § 6.1 and § 6.3".into(),
        generator: generator(),
        cases: m.cases,
    })
}

// ---------------------------------------------------------------- sheet

pub(crate) fn sheet() -> Result<Vec<u8>, Error> {
    let mut m = Maker { cases: vec![] };
    let key = [0xa5u8; 32];
    let build = |url: &str, account: [u8; 16], profile: u32, sk_bit: bool, key: &[u8; 32]| {
        json!({
            "server_url": url,
            "account_id": h(&account),
            "ksf_profile": profile,
            "sk_bit": sk_bit,
            "server_public_key": h(key),
        })
    };
    let account = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ];

    // ---- build
    let (out, _) = m.ok(
        "sheet/build/001",
        "an address with a port and a path, with a secret key",
        "sheet.qr.build",
        build(
            "https://vault.example.com:8443/ferret",
            account,
            1,
            true,
            &key,
        ),
    )?;
    let payload = out["payload"].as_str().unwrap().to_owned();
    check(
        payload
            == format!(
                "ferret-setup:v1?u=https%3A%2F%2Fvault.example.com%3A8443%2Fferret&a={}&k=1&s=1&o={}",
                h(&account),
                h(&key)
            ),
        "the payload spelling",
    )?;
    let (out, _) = m.ok(
        "sheet/build/002",
        "a LAN address over http, no secret key",
        "sheet.qr.build",
        build("http://10.0.3.26:3001", account, 1, false, &[0u8; 32]),
    )?;
    let lan = out["payload"].as_str().unwrap().to_owned();
    m.ok(
        "sheet/build/003",
        "an address of exactly 512 bytes",
        "sheet.qr.build",
        build(
            &format!("https://{}", "a".repeat(504)),
            account,
            1,
            true,
            &key,
        ),
    )?;
    m.ok(
        "sheet/build/004",
        "unreserved characters stay, the rest is percent-encoded in upper case",
        "sheet.qr.build",
        build(
            "https://a-b.c_d~e.example/p?q=1&r=%7e#f",
            account,
            1,
            true,
            &key,
        ),
    )?;
    m.err(
        "sheet/build/005",
        "an address of 513 bytes",
        "sheet.qr.build",
        build(
            &format!("https://{}", "a".repeat(505)),
            account,
            1,
            true,
            &key,
        ),
        "too_large",
    )?;
    m.err(
        "sheet/build/006",
        "no http or https scheme",
        "sheet.qr.build",
        build("ftp://vault.example", account, 1, true, &key),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/build/007",
        "a space in the address",
        "sheet.qr.build",
        build("https://vault example", account, 1, true, &key),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/build/008",
        "nothing after the scheme",
        "sheet.qr.build",
        build("https://", account, 1, true, &key),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/build/009",
        "a non-ASCII address (a host is written in punycode)",
        "sheet.qr.build",
        build("https://v\u{e6}ult.example", account, 1, true, &key),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/build/010",
        "a profile number this version does not know",
        "sheet.qr.build",
        build("https://vault.example", account, 2, true, &key),
        "kdf_profile_unknown",
    )?;

    // ---- parse
    let parse = |p: &str| json!({ "payload": p });
    m.ok(
        "sheet/parse/001",
        "reads what the first case builds",
        "sheet.qr.parse",
        parse(&payload),
    )?;
    m.ok(
        "sheet/parse/002",
        "reads the LAN address, no secret key",
        "sheet.qr.parse",
        parse(&lan),
    )?;
    let good = |f: &dyn Fn(&str) -> String| parse(&f(&payload));
    m.err(
        "sheet/parse/003",
        "another version of the format",
        "sheet.qr.parse",
        good(&|p| p.replacen("v1?", "v2?", 1)),
        "unsupported",
    )?;
    m.err(
        "sheet/parse/004",
        "a version that is not a number",
        "sheet.qr.parse",
        good(&|p| p.replacen("v1?", "vx?", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/005",
        "another scheme",
        "sheet.qr.parse",
        good(&|p| p.replacen("ferret-setup:", "ferret-login:", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/006",
        "percent-encoding in lower case",
        "sheet.qr.parse",
        good(&|p| p.replace("%3A", "%3a")),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/007",
        "a character that is written as %XX although it is unreserved",
        "sheet.qr.parse",
        good(&|p| p.replacen("vault", "%76ault", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/008",
        "a character that must be encoded written raw",
        "sheet.qr.parse",
        good(&|p| p.replacen("https%3A", "https:", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/009",
        "the secret key bit is neither 0 nor 1",
        "sheet.qr.parse",
        good(&|p| p.replacen("&s=1", "&s=2", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/010",
        "a profile the client does not know",
        "sheet.qr.parse",
        good(&|p| p.replacen("&k=1", "&k=2", 1)),
        "kdf_profile_unknown",
    )?;
    m.err(
        "sheet/parse/011",
        "a profile with a leading zero",
        "sheet.qr.parse",
        good(&|p| p.replacen("&k=1", "&k=01", 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/012",
        "the server key is missing",
        "sheet.qr.parse",
        good(&|p| p[..p.find("&o=").unwrap()].to_owned()),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/013",
        "an extra parameter",
        "sheet.qr.parse",
        good(&|p| format!("{p}&x=1")),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/014",
        "the parameters in another order",
        "sheet.qr.parse",
        good(&|p| {
            let (head, tail) = p.split_once("&a=").unwrap();
            let (a, rest) = tail.split_once("&k=").unwrap();
            format!("{head}&k={rest}&a={a}")
        }),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/015",
        "an account id in upper case",
        "sheet.qr.parse",
        good(&|p| p.replacen(&h(&account), &h(&account).to_uppercase(), 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/016",
        "an account id one digit short",
        "sheet.qr.parse",
        good(&|p| p.replacen(&h(&account), &h(&account)[1..], 1)),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/017",
        "a server key that is not hex",
        "sheet.qr.parse",
        good(&|p| format!("{}zz", &p[..p.len() - 2])),
        "malformed_setup_qr",
    )?;
    m.err(
        "sheet/parse/018",
        "an address over 512 bytes inside a well-formed payload",
        "sheet.qr.parse",
        good(&|p| {
            p.replacen(
                "vault.example.com",
                &format!("{}.example.com", "a".repeat(512)),
                1,
            )
        }),
        "too_large",
    )?;
    m.err(
        "sheet/parse/019",
        "a payload longer than any valid one",
        "sheet.qr.parse",
        good(&|p| format!("{p}{}", "0".repeat(1_700))),
        "too_large",
    )?;
    m.err(
        "sheet/parse/020",
        "nothing",
        "sheet.qr.parse",
        parse(""),
        "malformed_setup_qr",
    )?;

    render(&VectorFile {
        format: FORMAT.into(),
        group: "sheet".into(),
        suite: 1,
        spec: "Fase 1 § 6.1 and plan U17, U19".into(),
        generator: generator(),
        cases: m.cases,
    })
}
