//! The vector groups for the key hierarchy: the KEK and vault key
//! derivations (added to `kdf.json`), the wraps (`wrap.json`) and opening
//! them (`unlock.json`).
//!
//! Every expected value is made here without calling the core's key
//! hierarchy: the TLV bytes are written out by hand, the HKDF, AEAD and
//! Argon2id calls go to the primitive wrappers (which have their own RFC and
//! Wycheproof vectors), and the layout of every salt, AAD and wrap follows
//! Fase 1 § 3.1, § 4.3, § 4.5, § 7.2 and § 7.4 directly. The tests of the
//! core then run its own functions against these files.

use crate::groups::{generator, invalid_case, pattern, valid_case};
use crate::{Error, render};
use ferret_core::testing::prim::{aead_seal, argon2id, ed25519_public_key, hkdf_sha256};
use ferret_core::testing::vector::{Case, FORMAT, Tag, VectorFile};
use ferret_core::testing::{ReplayRng, TestRng, hex_encode};
use ferret_core::{KdfParams, SecureRng};
use serde_json::{Value, json};

// ------------------------------------------------------------ hand-made TLV

/// `tag ‖ len(u16be) ‖ value`.
pub(crate) fn t(tag: u8, value: &[u8]) -> Vec<u8> {
    let len = u16::try_from(value.len()).unwrap_or(u16::MAX);
    let mut out = vec![tag];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
    out
}

pub(crate) fn label(s: &str) -> Vec<u8> {
    t(0x01, s.as_bytes())
}

pub(crate) fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

pub(crate) fn hk(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    hkdf_sha256(salt, ikm, info, &mut out).map_err(|e| format!("hkdf failed: {e}"))?;
    Ok(out)
}

const P1: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};

fn stretch(pin: &str, device_salt: &[u8; 16]) -> Result<[u8; 32], Error> {
    let mut out = [0u8; 32];
    argon2id(pin.as_bytes(), device_salt, P1, &mut out)
        .map_err(|e| format!("argon2id failed: {e}"))?;
    Ok(out)
}

pub(crate) fn arr<const N: usize>(start: u8) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&pattern(start, N));
    out
}

pub(crate) fn h(bytes: &[u8]) -> Value {
    json!(hex_encode(bytes))
}

// ----------------------------------------------------------- derivations

fn kek_password(account: &[u8; 16], export_key: &[u8; 64]) -> Result<[u8; 32], Error> {
    let salt = cat(&[label("ferret/v1/kek/password"), t(0x10, account)]);
    hk(&salt, export_key, b"ferret/v1/kek/password")
}

fn kek_recovery(account: &[u8; 16], rk: &[u8; 32]) -> Result<[u8; 32], Error> {
    let salt = cat(&[label("ferret/v1/recovery"), t(0x10, account)]);
    hk(&salt, rk, b"ferret/v1/kek/recovery")
}

fn seed_r(account: &[u8; 16], rk: &[u8; 32]) -> Result<[u8; 32], Error> {
    let salt = cat(&[label("ferret/v1/recovery-sign"), t(0x10, account)]);
    hk(&salt, rk, b"ferret/v1/recovery-sign")
}

fn kek_prf(credential_id: &[u8], prf_output: &[u8; 32]) -> Result<[u8; 32], Error> {
    let salt = cat(&[label("ferret/v1/prf"), t(0x31, credential_id)]);
    hk(&salt, prf_output, b"ferret/v1/kek/prf")
}

fn kek_pin_mobile(pin: &str, device_salt: &[u8; 16], dev: &[u8; 32]) -> Result<[u8; 32], Error> {
    let mut ikm = dev.to_vec();
    ikm.extend_from_slice(&stretch(pin, device_salt)?);
    let salt = cat(&[label("ferret/v1/kek/pin"), t(0x37, device_salt)]);
    hk(&salt, &ikm, b"ferret/v1/kek/pin")
}

pub(crate) struct VkKeys {
    pub(crate) k_head: [u8; 32],
    pub(crate) k_del: [u8; 32],
    pub(crate) k_meta: [u8; 32],
    pub(crate) seed_a: [u8; 32],
}

pub(crate) fn vk_derive(
    account: &[u8; 16],
    vault: &[u8; 16],
    epoch: u64,
    vk: &[u8; 32],
) -> Result<VkKeys, Error> {
    let salt = cat(&[
        label("ferret/v1/vk-derive"),
        t(0x10, account),
        t(0x11, vault),
        t(0x20, &epoch.to_be_bytes()),
    ]);
    Ok(VkKeys {
        k_head: hk(&salt, vk, b"ferret/v1/head")?,
        k_del: hk(&salt, vk, b"ferret/v1/tomb")?,
        k_meta: hk(&salt, vk, b"ferret/v1/meta")?,
        seed_a: hk(&salt, vk, b"ferret/v1/auth-sign")?,
    })
}

fn commit(kek: &[u8; 32]) -> Result<[u8; 32], Error> {
    // HKDF with no salt: RFC 5869 treats it as HashLen zero bytes.
    hk(&[0u8; 32], kek, b"ferret/v1/commit")
}

// --------------------------------------------------------------- kdf cases

fn case(
    id: &str,
    title: &str,
    op: &str,
    tags: Vec<Tag>,
    input: Value,
    expect: Result<Value, &str>,
) -> Case {
    match expect {
        Ok(value) => valid_case(id, title, op, tags, input, value),
        Err(code) => invalid_case(id, title, op, tags, input, code),
    }
}

/// The key derivation cases appended to the `kdf` group.
pub(crate) fn kdf_cases(cases: &mut Vec<Case>) -> Result<(), Error> {
    // KEK_pw
    for (n, title, account, ek) in [
        (
            1,
            "export key and account 1",
            arr::<16>(0x10),
            arr::<64>(0x20),
        ),
        (
            2,
            "other account, same export key",
            arr::<16>(0x11),
            arr::<64>(0x20),
        ),
        (
            3,
            "same account, other export key",
            arr::<16>(0x10),
            arr::<64>(0x21),
        ),
    ] {
        cases.push(case(
            &format!("kdf/kek_password/valid/{n:03}"),
            title,
            "kdf.kek.password",
            vec![],
            json!({ "account_id": h(&account), "export_key": h(&ek) }),
            Ok(json!({ "kek": h(&kek_password(&account, &ek)?) })),
        ));
    }

    // KEK_rk and seed_r
    for (n, title, account, rk) in [
        (
            1,
            "recovery key and account 1",
            arr::<16>(0x10),
            arr::<32>(0x40),
        ),
        (
            2,
            "other account, same recovery key",
            arr::<16>(0x11),
            arr::<32>(0x40),
        ),
        (
            3,
            "same account, other recovery key",
            arr::<16>(0x10),
            arr::<32>(0x41),
        ),
    ] {
        let seed = seed_r(&account, &rk)?;
        cases.push(case(
            &format!("kdf/kek_recovery/valid/{n:03}"),
            title,
            "kdf.kek.recovery",
            vec![],
            json!({ "account_id": h(&account), "rk": h(&rk) }),
            Ok(json!({
                "kek": h(&kek_recovery(&account, &rk)?),
                "seed_r": h(&seed),
                "pk_r": h(&ed25519_public_key(&seed)),
            })),
        ));
    }

    // K_head, K_del, K_meta, seed_a
    let vk = arr::<32>(0x60);
    for (n, title, account, vault, epoch) in [
        (1, "epoch 1", arr::<16>(0x10), arr::<16>(0x30), 1u64),
        (
            2,
            "epoch 2: all four keys change",
            arr::<16>(0x10),
            arr::<16>(0x30),
            2,
        ),
        (3, "other account", arr::<16>(0x11), arr::<16>(0x30), 1),
        (4, "other vault", arr::<16>(0x10), arr::<16>(0x31), 1),
        (
            5,
            "epoch above 2^32",
            arr::<16>(0x10),
            arr::<16>(0x30),
            0x1_0000_0001,
        ),
    ] {
        let k = vk_derive(&account, &vault, epoch, &vk)?;
        cases.push(case(
            &format!("kdf/vk_derive/valid/{n:03}"),
            title,
            "kdf.vk_derive",
            vec![],
            json!({
                "account_id": h(&account),
                "vault_id": h(&vault),
                "vk_epoch": epoch.to_string(),
                "vk": h(&vk),
            }),
            Ok(json!({
                "k_head": h(&k.k_head),
                "k_del": h(&k.k_del),
                "k_meta": h(&k.k_meta),
                "seed_a": h(&k.seed_a),
                "pk_a": h(&ed25519_public_key(&k.seed_a)),
            })),
        ));
    }

    // KEK_prf: the salt has the credential id and no account id.
    let prf_output = arr::<32>(0x80);
    for (n, title, cred) in [
        (1, "16-byte credential id", pattern(0xa0, 16)),
        (2, "other credential id, same PRF output", pattern(0xa1, 16)),
        (3, "32-byte credential id", pattern(0xa0, 32)),
        (4, "empty credential id", vec![]),
    ] {
        cases.push(case(
            &format!("kdf/kek_prf/valid/{n:03}"),
            title,
            "kdf.kek.prf",
            vec![],
            json!({ "credential_id": h(&cred), "prf_output": h(&prf_output) }),
            Ok(json!({ "kek": h(&kek_prf(&cred, &prf_output)?) })),
        ));
    }

    // KEK_pin, extension variant: Argon2id of the PIN alone.
    let device_salt = arr::<16>(0xc0);
    for (n, title, pin) in [(1, "six digits", "123456"), (2, "eight digits", "98765432")] {
        cases.push(case(
            &format!("kdf/kek_pin_extension/valid/{n:03}"),
            title,
            "kdf.kek.pin_extension",
            vec![Tag::Slow],
            json!({ "pin": pin, "device_salt": h(&device_salt) }),
            Ok(json!({ "kek": h(&stretch(pin, &device_salt)?) })),
        ));
    }
    for (n, title, pin, code) in [
        (1, "five digits are too few", "12345", "input_too_short"),
        (
            2,
            "a letter is not a digit",
            "12a456",
            "input_forbidden_character",
        ),
        (
            3,
            "fullwidth digits are not ASCII digits",
            "\u{ff11}\u{ff12}\u{ff13}\u{ff14}\u{ff15}\u{ff16}",
            "input_forbidden_character",
        ),
    ] {
        cases.push(case(
            &format!("kdf/kek_pin_extension/invalid/{n:03}"),
            title,
            "kdf.kek.pin_extension",
            vec![],
            json!({ "pin": pin, "device_salt": h(&device_salt) }),
            Err(code),
        ));
    }

    // KEK_pin, mobile variant.
    let dev = arr::<32>(0xd0);
    for (n, title, dev) in [
        (1, "six digits", dev),
        (2, "other hardware secret", arr::<32>(0xd1)),
    ] {
        cases.push(case(
            &format!("kdf/kek_pin_mobile/valid/{n:03}"),
            title,
            "kdf.kek.pin_mobile",
            vec![Tag::Slow],
            json!({ "pin": "123456", "device_salt": h(&device_salt), "kek_dev_pin": h(&dev) }),
            Ok(json!({ "kek": h(&kek_pin_mobile("123456", &device_salt, &dev)?) })),
        ));
    }
    cases.push(case(
        "kdf/kek_pin_mobile/invalid/001",
        "five digits are too few",
        "kdf.kek.pin_mobile",
        vec![],
        json!({ "pin": "12345", "device_salt": h(&device_salt), "kek_dev_pin": h(&dev) }),
        Err("input_too_short"),
    ));
    Ok(())
}

// ----------------------------------------------------------------- wraps

#[derive(Clone)]
enum M {
    Password,
    Recovery,
    Prf(Vec<u8>, [u8; 32]),
    Pin([u8; 16]),
    Device,
}

impl M {
    fn code(&self) -> u8 {
        match self {
            M::Password => 1,
            M::Recovery => 2,
            M::Prf(..) => 3,
            M::Pin(_) => 4,
            M::Device => 5,
        }
    }

    fn has_commit(&self) -> bool {
        matches!(self, M::Password | M::Pin(_))
    }

    fn json(&self) -> Value {
        match self {
            M::Password => json!({ "type": "password", "ksf_profile": 1 }),
            M::Recovery => json!({ "type": "recovery" }),
            M::Prf(cred, salt) => {
                json!({ "type": "prf", "credential_id": h(cred), "prf_salt": h(salt) })
            }
            M::Pin(salt) => json!({ "type": "pin", "device_salt": h(salt) }),
            M::Device => json!({ "type": "device" }),
        }
    }
}

#[derive(Clone)]
struct W {
    account: [u8; 16],
    vault: [u8; 16],
    method_id: [u8; 16],
    epoch: u64,
    generation: u64,
    m: M,
}

impl W {
    /// `aad_wrap`, or the PIN AAD of § 7.2 (same field order, no generation). `kdf` overrides the 12 `kdf`
    /// bytes of a password wrap (profile 1 otherwise).
    fn aad(&self, kdf: Option<[u8; 12]>) -> Vec<u8> {
        if let M::Pin(device_salt) = &self.m {
            return cat(&[
                label("ferret/v1/pin"),
                t(0x03, &[1]),
                t(0x10, &self.account),
                t(0x11, &self.vault),
                t(0x14, &[4]),
                t(0x13, &self.method_id),
                t(0x20, &self.epoch.to_be_bytes()),
                t(0x37, device_salt),
            ]);
        }
        let mut parts = vec![
            label("ferret/v1/wrap"),
            t(0x03, &[1]),
            t(0x10, &self.account),
            t(0x11, &self.vault),
            t(0x14, &[self.m.code()]),
            t(0x13, &self.method_id),
            t(0x20, &self.epoch.to_be_bytes()),
            t(0x21, &self.generation.to_be_bytes()),
        ];
        match &self.m {
            M::Password => {
                // m = 65 536 KiB, t = 3, p = 1, each u32be.
                let p1: [u8; 12] = [0, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1];
                parts.push(t(0x30, &kdf.unwrap_or(p1)));
            }
            M::Prf(cred, salt) => {
                parts.push(t(0x31, cred));
                parts.push(t(0x32, salt));
            }
            M::Recovery | M::Device | M::Pin(_) => {}
        }
        cat(&parts)
    }

    fn input(&self) -> Value {
        json!({
            "account_id": h(&self.account),
            "vault_id": h(&self.vault),
            "method_id": h(&self.method_id),
            "vk_epoch": self.epoch.to_string(),
            "kek_generation": self.generation.to_string(),
        })
    }
}

fn seal(
    w: &W,
    kek: &[u8; 32],
    vk: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut rng = ReplayRng::new(vec![nonce.to_vec()]);
    let mut blob = aead_seal(&mut rng, kek, aad, vk).map_err(|e| format!("seal failed: {e}"))?;
    if w.m.has_commit() {
        blob.extend_from_slice(&commit(kek)?);
    }
    Ok(blob)
}

pub(crate) fn draw<const N: usize>(seed: &str) -> [u8; N] {
    let mut rng = TestRng::new(seed.as_bytes());
    let mut out = [0u8; N];
    rng.fill(&mut out);
    out
}

/// How a case's KEK is made.
enum Source {
    Export([u8; 64]),
    Recovery([u8; 32]),
    Prf([u8; 32]),
    Pin(&'static str),
    PinMobile(&'static str, [u8; 32]),
    /// A random KEK: drawn first from the RNG, then the nonce.
    Device,
}

struct Sealed {
    case: Case,
    kek: [u8; 32],
    vk: [u8; 32],
    wrap: Vec<u8>,
    w: W,
}

fn seal_case(id: &str, title: &str, w: W, source: Source, vk: [u8; 32]) -> Result<Sealed, Error> {
    let nonce: [u8; 24] = draw(&format!("{id}/nonce"));
    let mut rng = vec![nonce.to_vec()];
    let mut slow = false;
    let (op, kek, mut input) = match (&source, &w.m) {
        (Source::Export(ek), M::Password) => {
            let mut i = w.input();
            i["ksf_profile"] = json!(1);
            i["export_key"] = h(ek);
            ("wrap.seal.password", kek_password(&w.account, ek)?, i)
        }
        (Source::Recovery(rk), M::Recovery) => {
            let mut i = w.input();
            i["rk"] = h(rk);
            ("wrap.seal.recovery", kek_recovery(&w.account, rk)?, i)
        }
        (Source::Prf(out), M::Prf(cred, salt)) => {
            let mut i = w.input();
            i["credential_id"] = h(cred);
            i["prf_salt"] = h(salt);
            i["prf_output"] = h(out);
            ("wrap.seal.prf", kek_prf(cred, out)?, i)
        }
        (Source::Pin(pin), M::Pin(salt)) => {
            slow = true;
            let mut i = w.input();
            i["device_salt"] = h(salt);
            i["pin"] = json!(pin);
            ("wrap.seal.pin", stretch(pin, salt)?, i)
        }
        (Source::PinMobile(pin, dev), M::Pin(salt)) => {
            slow = true;
            let mut i = w.input();
            i["device_salt"] = h(salt);
            i["pin"] = json!(pin);
            i["kek_dev_pin"] = h(dev);
            ("wrap.seal.pin_mobile", kek_pin_mobile(pin, salt, dev)?, i)
        }
        (Source::Device, M::Device) => {
            let kek: [u8; 32] = draw(&format!("{id}/kek"));
            rng.insert(0, kek.to_vec());
            ("wrap.seal.device", kek, w.input())
        }
        _ => return Err("source does not match the method".into()),
    };
    input["vk"] = h(&vk);
    let aad = w.aad(None);
    let wrap = seal(&w, &kek, &vk, &nonce, &aad)?;
    let mut intermediate = json!({ "kek": h(&kek), "aad": h(&aad) });
    if w.m.has_commit() {
        intermediate["commit"] = h(&commit(&kek)?);
    }
    let mut case = valid_case(
        id,
        title,
        op,
        if slow { vec![Tag::Slow] } else { vec![] },
        input,
        json!({ "wrap": h(&wrap) }),
    );
    case.rng = rng.iter().map(|d| hex_encode(d)).collect();
    case.intermediate = Some(intermediate);
    Ok(Sealed {
        case,
        kek,
        vk,
        wrap,
        w,
    })
}

fn base(method_id: u8, epoch: u64, generation: u64, m: M) -> W {
    W {
        account: arr(0x10),
        vault: arr(0x30),
        method_id: arr(method_id),
        epoch,
        generation,
        m,
    }
}

/// The wraps, in table order. Used by both `wrap.json` and `unlock.json`.
fn sealed_wraps() -> Result<Vec<Sealed>, Error> {
    let vk = arr::<32>(0x60);
    let vk2 = arr::<32>(0x61);
    let vk3 = arr::<32>(0x62);
    let cred = pattern(0xa0, 16);
    let prf_salt = arr::<32>(0xb0);
    let device_salt = arr::<16>(0xc0);
    let mut out = Vec::new();

    let mut add = |id: &str, title: &str, w: W, s: Source, vk: [u8; 32]| -> Result<(), Error> {
        out.push(seal_case(id, title, w, s, vk)?);
        Ok(())
    };
    add(
        "wrap/password/valid/001",
        "password wrap, epoch 1, generation 1",
        base(0x70, 1, 1, M::Password),
        Source::Export(arr(0x20)),
        vk,
    )?;
    add(
        "wrap/password/valid/002",
        "password wrap after a rekey and two password changes",
        base(0x71, 2, 3, M::Password),
        Source::Export(arr(0x22)),
        vk2,
    )?;
    add(
        "wrap/password/valid/003",
        "password wrap with a large epoch and generation",
        base(0x72, 0x1_0000_0001, 0x2_0000_0003, M::Password),
        Source::Export(arr(0x23)),
        vk3,
    )?;
    add(
        "wrap/recovery/valid/001",
        "recovery wrap, epoch 1",
        base(0x73, 1, 1, M::Recovery),
        Source::Recovery(arr(0x40)),
        vk,
    )?;
    add(
        "wrap/recovery/valid/002",
        "recovery wrap after a new recovery key",
        base(0x74, 2, 2, M::Recovery),
        Source::Recovery(arr(0x41)),
        vk2,
    )?;
    add(
        "wrap/prf/valid/001",
        "passkey wrap, 16-byte credential id",
        base(0x75, 1, 1, M::Prf(cred, prf_salt)),
        Source::Prf(arr(0x80)),
        vk,
    )?;
    add(
        "wrap/prf/valid/002",
        "passkey wrap, 32-byte credential id",
        base(0x76, 1, 1, M::Prf(pattern(0xa1, 32), arr(0xb1))),
        Source::Prf(arr(0x81)),
        vk,
    )?;
    add(
        "wrap/prf/valid/003",
        "passkey wrap, empty credential id",
        base(0x77, 1, 1, M::Prf(vec![], arr(0xb2))),
        Source::Prf(arr(0x82)),
        vk,
    )?;
    add(
        "wrap/pin/valid/001",
        "PIN wrap of the extension",
        base(0x78, 1, 1, M::Pin(device_salt)),
        Source::Pin("123456"),
        vk,
    )?;
    add(
        "wrap/pin/valid/002",
        "PIN wrap in epoch 2",
        base(0x79, 2, 1, M::Pin(arr(0xc1))),
        Source::Pin("98765432"),
        vk2,
    )?;
    add(
        "wrap/pin_mobile/valid/001",
        "PIN wrap of the mobile variant",
        base(0x7a, 1, 1, M::Pin(device_salt)),
        Source::PinMobile("123456", arr(0xd0)),
        vk,
    )?;
    add(
        "wrap/device/valid/001",
        "device wrap, random KEK",
        base(0x7b, 1, 1, M::Device),
        Source::Device,
        vk,
    )?;
    add(
        "wrap/device/valid/002",
        "device wrap in epoch 3",
        base(0x7c, 3, 5, M::Device),
        Source::Device,
        vk3,
    )?;
    Ok(out)
}

pub(crate) fn wrap() -> Result<Vec<u8>, Error> {
    let cases = sealed_wraps()?.into_iter().map(|s| s.case).collect();
    render(&VectorFile {
        format: FORMAT.into(),
        group: "wrap".into(),
        suite: 1,
        spec: "Fase 1 § 4.3 and § 7.2".into(),
        generator: generator(),
        cases,
    })
}

// ---------------------------------------------------------------- unlock

fn open_input(w: &W, kek: &[u8; 32], wrap: &[u8]) -> Value {
    let mut i = w.input();
    i["method"] = w.m.json();
    i["kek"] = h(kek);
    i["wrap"] = h(wrap);
    i
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    if let Some(b) = out.get_mut(at) {
        *b ^= 0x01;
    }
    out
}

fn flip32(bytes: &[u8; 32], at: usize) -> [u8; 32] {
    let mut out = *bytes;
    if let Some(b) = out.get_mut(at) {
        *b ^= 0x01;
    }
    out
}

pub(crate) fn unlock() -> Result<Vec<u8>, Error> {
    let sealed = sealed_wraps()?;
    let mut cases: Vec<Case> = Vec::new();

    // Every wrap opens, and gives the vault key and pk_a.
    for s in &sealed {
        let k = vk_derive(&s.w.account, &s.w.vault, s.w.epoch, &s.vk)?;
        cases.push(valid_case(
            &s.case.id.replacen("wrap/", "unlock/", 1),
            &format!("opens: {}", s.case.title),
            "wrap.open",
            vec![],
            open_input(&s.w, &s.kek, &s.wrap),
            json!({ "vk": h(&s.vk), "pk_a": h(&ed25519_public_key(&k.seed_a)) }),
        ));
    }

    let find = |id: &str| -> Result<&Sealed, Error> {
        sealed
            .iter()
            .find(|s| s.case.id == id)
            .ok_or_else(|| format!("missing wrap {id}").into())
    };
    let pw = find("wrap/password/valid/001")?;
    let rec = find("wrap/recovery/valid/001")?;
    let prf = find("wrap/prf/valid/001")?;
    let pin = find("wrap/pin/valid/001")?;
    let dev = find("wrap/device/valid/001")?;

    let mut bad = |name: &str, title: &str, input: Value| {
        cases.push(invalid_case(
            &format!("unlock/{name}/001"),
            title,
            "wrap.open",
            vec![],
            input,
            "decrypt",
        ));
    };

    // One AAD field changed at a time (the wrap itself is untouched).
    for (name, s) in [
        ("password", pw),
        ("recovery", rec),
        ("prf", prf),
        ("pin", pin),
        ("device", dev),
    ] {
        let mut w = s.w.clone();
        w.account[0] ^= 1;
        bad(
            &format!("aad_account_{name}"),
            &format!("{name}: another account"),
            open_input(&w, &s.kek, &s.wrap),
        );
        let mut w = s.w.clone();
        w.epoch += 1;
        bad(
            &format!("aad_epoch_{name}"),
            &format!("{name}: another vk_epoch"),
            open_input(&w, &s.kek, &s.wrap),
        );
    }
    // The PIN wrap's AAD has no kek_generation (§ 7.2), so that field is for
    // the other four only.
    for (name, s) in [
        ("password", pw),
        ("recovery", rec),
        ("prf", prf),
        ("pin", pin),
        ("device", dev),
    ] {
        let mut w = s.w.clone();
        w.vault[0] ^= 1;
        bad(
            &format!("aad_vault_{name}"),
            &format!("{name}: another vault"),
            open_input(&w, &s.kek, &s.wrap),
        );
        let mut w = s.w.clone();
        w.method_id[0] ^= 1;
        bad(
            &format!("aad_method_id_{name}"),
            &format!("{name}: another method id"),
            open_input(&w, &s.kek, &s.wrap),
        );
    }
    for (name, s) in [
        ("password", pw),
        ("recovery", rec),
        ("prf", prf),
        ("device", dev),
    ] {
        let mut w = s.w.clone();
        w.generation += 1;
        bad(
            &format!("aad_generation_{name}"),
            &format!("{name}: another kek_generation"),
            open_input(&w, &s.kek, &s.wrap),
        );
    }
    // Method type: the same wrap presented as another method.
    for (name, s, as_method) in [
        ("recovery_as_device", rec, M::Device),
        ("device_as_recovery", dev, M::Recovery),
        ("prf_as_recovery", prf, M::Recovery),
        ("password_as_pin", pw, M::Pin(arr(0xc0))),
    ] {
        let mut w = s.w.clone();
        w.m = as_method;
        bad(
            &format!("aad_method_type_{name}"),
            &format!("method type: {name}"),
            open_input(&w, &s.kek, &s.wrap),
        );
    }
    // Method-specific fields.
    if let M::Prf(cred, salt) = &prf.w.m {
        let mut w = prf.w.clone();
        w.m = M::Prf(flip(cred, 0), *salt);
        bad(
            "aad_credential_id",
            "prf: another credential id",
            open_input(&w, &prf.kek, &prf.wrap),
        );
        let mut w = prf.w.clone();
        w.m = M::Prf(cred.clone(), flip32(salt, 0));
        bad(
            "aad_prf_salt",
            "prf: another prf_salt",
            open_input(&w, &prf.kek, &prf.wrap),
        );
    }
    {
        let mut w = pin.w.clone();
        let mut salt = arr::<16>(0xc0);
        salt[0] ^= 1;
        w.m = M::Pin(salt);
        bad(
            "aad_device_salt",
            "pin: another device_salt",
            open_input(&w, &pin.kek, &pin.wrap),
        );
    }
    // The kdf field: a password wrap made with another `kdf` in its AAD.
    {
        let other_kdf: [u8; 12] = [0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 1];
        let nonce: [u8; 24] = draw("unlock/aad_kdf/nonce");
        let aad = pw.w.aad(Some(other_kdf));
        let wrap = seal(&pw.w, &pw.kek, &pw.vk, &nonce, &aad)?;
        bad(
            "aad_kdf",
            "password: wrap made with another kdf in the AAD",
            open_input(&pw.w, &pw.kek, &wrap),
        );
    }

    // The wrap changed.
    for (name, s) in [("password", pw), ("recovery", rec)] {
        bad(
            &format!("nonce_{name}"),
            &format!("{name}: nonce bit flipped"),
            open_input(&s.w, &s.kek, &flip(&s.wrap, 0)),
        );
        bad(
            &format!("ciphertext_{name}"),
            &format!("{name}: ciphertext bit flipped"),
            open_input(&s.w, &s.kek, &flip(&s.wrap, 24)),
        );
        bad(
            &format!("tag_{name}"),
            &format!("{name}: tag bit flipped"),
            open_input(&s.w, &s.kek, &flip(&s.wrap, 71)),
        );
        bad(
            &format!("truncated_{name}"),
            &format!("{name}: one byte missing"),
            open_input(&s.w, &s.kek, &s.wrap[..s.wrap.len() - 1]),
        );
        let mut longer = s.wrap.clone();
        longer.push(0);
        bad(
            &format!("extended_{name}"),
            &format!("{name}: one byte added"),
            open_input(&s.w, &s.kek, &longer),
        );
        bad(
            &format!("kek_{name}"),
            &format!("{name}: another KEK"),
            open_input(&s.w, &flip32(&s.kek, 0), &s.wrap),
        );
    }
    bad(
        "commit_password",
        "password: commit bit flipped",
        open_input(&pw.w, &pw.kek, &flip(&pw.wrap, 72)),
    );
    bad(
        "commit_last_byte_password",
        "password: last commit bit flipped",
        open_input(&pw.w, &pw.kek, &flip(&pw.wrap, 103)),
    );
    bad(
        "commit_pin",
        "pin: commit bit flipped",
        open_input(&pin.w, &pin.kek, &flip(&pin.wrap, 72)),
    );
    bad(
        "no_commit_password",
        "password: wrap without the commit",
        open_input(&pw.w, &pw.kek, &pw.wrap[..72]),
    );
    bad(
        "empty_wrap",
        "password: empty wrap",
        open_input(&pw.w, &pw.kek, &[]),
    );
    {
        // The ciphertext is intact, but the commit belongs to another KEK.
        let mut wrap = pw.wrap[..72].to_vec();
        wrap.extend_from_slice(&commit(&flip32(&pw.kek, 0))?);
        bad(
            "commit_of_another_kek",
            "password: commit of another KEK",
            open_input(&pw.w, &pw.kek, &wrap),
        );
    }

    render(&VectorFile {
        format: FORMAT.into(),
        group: "unlock".into(),
        suite: 1,
        spec: "Fase 1 § 4.3 and § 7.2".into(),
        generator: generator(),
        cases,
    })
}
