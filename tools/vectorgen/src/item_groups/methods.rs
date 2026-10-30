//! The vector group for changing the list of unlock methods
//! (`methods.json`): adding and removing a method, comparing the server's
//! list with the manifest, and the PRF salt.
//!
//! Spec: Fase 1 § 4.3 and § 4.6. The manifests are written and sealed here
//! with the hand-made CBOR and the item helpers; the request bodies are
//! spelled out as text; the proofs are signed over the TLV written out by
//! hand. The core's `methods` module is not called.

use super::*;
use ferret_core::testing::prim::{ed25519_public_key, ed25519_sign};

fn rev_s(rev: u64) -> Value {
    json!(rev.to_string())
}

fn hex(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

fn manifest_row(s: &Sealed) -> Value {
    json!({ "rev": rev_s(s.rev), "envelope": h(&s.envelope), "tag": h(&s.tag) })
}

fn manifest_json(rev: u64, envelope: &[u8], tag: &[u8; 32]) -> String {
    format!(
        "{{\"rev\":{rev},\"envelope\":\"{}\",\"tag\":\"{}\"}}",
        hex(envelope),
        hex(tag)
    )
}

/// `TLV[label, op, account_id, nonce, vk_epoch, hash = SHA-256(body)]`.
fn proof_message(op: &str, ctx: &Ctx, nonce: &[u8; 32], body: &[u8]) -> Vec<u8> {
    cat(&[
        label("ferret/v1/mutation"),
        t(0x36, op.as_bytes()),
        t(0x10, &ctx.account),
        t(0x33, nonce),
        t(0x20, &ctx.epoch.to_be_bytes()),
        t(0x35, &Sha256::digest(body)),
    ])
}

/// One entry of a manifest as the cases state it.
#[derive(Clone)]
struct Ent {
    ty: u64,
    id: u8,
    generation: u64,
    credential: Option<Vec<u8>>,
    /// An unknown key of the entry.
    extra: bool,
}

impl Ent {
    fn new(ty: u64, id: u8, generation: u64) -> Self {
        Ent {
            ty,
            id,
            generation,
            credential: None,
            extra: false,
        }
    }

    fn passkey(id: u8, generation: u64, credential: Vec<u8>) -> Self {
        Ent {
            credential: Some(credential),
            ..Ent::new(3, id, generation)
        }
    }

    fn cbor(&self) -> Vec<u8> {
        let mut extra: Vec<(&str, Vec<u8>)> = Vec::new();
        if let Some(c) = &self.credential {
            extra.push(("c", cb::bytes(c)));
        }
        if self.extra {
            extra.push(("label", cb::text("kept")));
        }
        method(self.ty, self.id, self.generation, &extra)
    }

    fn json(&self) -> Value {
        let mut v = json!({
            "type": self.ty,
            "id": h(&[self.id; 16]),
            "generation": self.generation.to_string(),
        });
        if let Some(c) = &self.credential {
            v["credential_id"] = h(c);
        }
        v
    }
}

fn manifest_plain(epoch: u64, list: &[Ent], top_extra: bool) -> Vec<u8> {
    let methods: Vec<Vec<u8>> = list.iter().map(Ent::cbor).collect();
    let extra: Vec<(&str, Vec<u8>)> = if top_extra {
        vec![("future", cb::uint(1))]
    } else {
        vec![]
    };
    manifest_cbor(1, epoch, &methods, &extra)
}

/// The wrap of a passkey method as the request carries it. The core does not
/// open it (it has no KEK), so any 72 bytes serve; these are fixed.
fn wrap_json(id: u8, generation: u64, credential: &[u8], salt: &[u8; 32], bytes: &[u8]) -> Value {
    json!({
        "method_type": 3,
        "method_id": h(&[id; 16]),
        "kek_generation": generation.to_string(),
        "wrap": h(bytes),
        "credential_id": h(credential),
        "prf_salt": h(salt),
    })
}

struct Add<'a> {
    id: u8,
    generation: u64,
    credential: &'a [u8],
    salt: [u8; 32],
    wrap: Vec<u8>,
}

fn add_body(w: &Add<'_>, rev: u64, envelope: &[u8], tag: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"method_type\":3,\"method_id\":\"{}\",\"wrap\":\"{}\",\"kek_generation\":{},\"credential_id\":\"{}\",\"prf_salt\":\"{}\",\"manifest\":{}}}",
        hex(&[w.id; 16]),
        hex(&w.wrap),
        w.generation,
        hex(w.credential),
        hex(&w.salt),
        manifest_json(rev, envelope, tag)
    )
    .into_bytes()
}

fn remove_body(id: u8, rev: u64, envelope: &[u8], tag: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"method_id\":\"{}\",\"manifest\":{}}}",
        hex(&[id; 16]),
        manifest_json(rev, envelope, tag)
    )
    .into_bytes()
}

fn sign_input(input: &mut Value, nonce: &[u8; 32]) {
    input["sign"] = json!({ "nonce": h(nonce) });
}

pub(crate) fn methods() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let c1 = ctx1();
    let c2 = ctx2();
    let nonce: [u8; 32] = arr(0xa5);

    let pw = Ent::new(1, 0x70, 3);
    let rk = Ent::new(2, 0x71, 1);
    let cred_a = pattern_bytes(0xc1, 20);
    let cred_b = pattern_bytes(0xc2, 32);
    let prf_a = Ent::passkey(0x72, 1, cred_a.clone());
    let current = |name: &str, list: &[Ent], top_extra: bool, rev: u64| -> Result<Sealed, Error> {
        seal_manifest(
            &format!("methods/current/{name}"),
            &c1,
            rev,
            &manifest_plain(1, list, top_extra),
        )
    };

    // ---- methods.add, accepted
    let base = [pw.clone(), rk.clone()];
    let cur0 = current("base", &base, false, 2)?;
    let wrap_a = Add {
        id: 0x72,
        generation: 1,
        credential: &cred_a,
        salt: arr(0xb1),
        wrap: pattern_bytes(0x5a, 72),
    };
    let mut after = base.to_vec();
    after.push(prf_a.clone());
    let new_plain = manifest_plain(1, &after, false);
    let next = seal_manifest("methods/next/add_first", &c1, 3, &new_plain)?;
    let body = add_body(&wrap_a, next.rev, &next.envelope, &next.tag);
    let mut input = c1.input();
    input["current"] = manifest_row(&cur0);
    input["wrap"] = wrap_json(
        wrap_a.id,
        wrap_a.generation,
        wrap_a.credential,
        &wrap_a.salt,
        &wrap_a.wrap,
    );
    let expect = json!({
        "manifest": h(&new_plain),
        "sealed": manifest_row(&next),
        "body": h(&body),
    });
    let mut c = valid_case(
        "methods/add/first_passkey",
        "a passkey is added to a manifest with a password and a recovery method",
        "methods.add",
        vec![],
        input.clone(),
        expect,
    );
    c.rng = vec![hex(&next.nonce)];
    cases.push(c);

    // The same, signed by sk_a.
    sign_input(&mut input, &nonce);
    let message = proof_message("unlock-method.add", &c1, &nonce, &body);
    let keys = c1.keys()?;
    let sig = ed25519_sign(&keys.seed_a, &message).map_err(|e| format!("sign failed: {e}"))?;
    let mut c = valid_case(
        "methods/add/signed",
        "the proof is made over the exact request body",
        "methods.add",
        vec![],
        input,
        json!({
            "manifest": h(&new_plain),
            "sealed": manifest_row(&next),
            "body": h(&body),
            "op": "unlock-method.add",
            "pk_a": h(&ed25519_public_key(&keys.seed_a)),
            "proof": h(&sig),
        }),
    );
    c.rng = vec![hex(&next.nonce)];
    cases.push(c);

    // A second passkey; unknown keys of the manifest and of its entries stay.
    let mut kept = base.to_vec();
    kept[0].extra = true;
    kept.push(prf_a.clone());
    let cur1 = current("kept", &kept, true, 5)?;
    let wrap_b = Add {
        id: 0x73,
        generation: 4,
        credential: &cred_b,
        salt: arr(0xb2),
        wrap: pattern_bytes(0x5b, 72),
    };
    let mut after1 = kept.clone();
    after1.push(Ent::passkey(0x73, 4, cred_b.clone()));
    let plain1 = manifest_plain(1, &after1, true);
    let next1 = seal_manifest("methods/next/add_second", &c1, 6, &plain1)?;
    let body1 = add_body(&wrap_b, next1.rev, &next1.envelope, &next1.tag);
    let mut input1 = c1.input();
    input1["current"] = manifest_row(&cur1);
    input1["wrap"] = wrap_json(
        wrap_b.id,
        wrap_b.generation,
        wrap_b.credential,
        &wrap_b.salt,
        &wrap_b.wrap,
    );
    let mut c = valid_case(
        "methods/add/second_passkey_keeps_unknown_keys",
        "a second passkey; unknown keys of the manifest and its entries are kept",
        "methods.add",
        vec![],
        input1.clone(),
        json!({ "manifest": h(&plain1), "sealed": manifest_row(&next1), "body": h(&body1) }),
    );
    c.rng = vec![hex(&next1.nonce)];
    cases.push(c);

    // ---- methods.add, refused
    let mut refused = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("methods/add_invalid/{name}"),
            title,
            "methods.add",
            vec![],
            input,
            code,
        ));
    };
    let mut dup_id = input1.clone();
    dup_id["wrap"]["method_id"] = h(&[0x72; 16]);
    refused(
        "method_id_listed",
        "the method id is already in the manifest",
        dup_id,
        "malformed_entries",
    );
    let mut dup_cred = input1.clone();
    dup_cred["wrap"]["credential_id"] = h(&cred_a);
    refused(
        "credential_listed",
        "the credential id belongs to a passkey the manifest lists",
        dup_cred,
        "malformed_entries",
    );
    let mut not_prf = input1.clone();
    not_prf["wrap"] = json!({
        "method_type": 2,
        "method_id": h(&[0x74; 16]),
        "kek_generation": "1",
        "wrap": h(&pattern_bytes(0x5c, 72)),
    });
    refused(
        "not_a_passkey",
        "only a passkey wrap is added with this call",
        not_prf,
        "unsupported",
    );
    let mut short = input1.clone();
    short["wrap"]["wrap"] = h(&pattern_bytes(0x5c, 104));
    refused(
        "wrap_length",
        "a passkey wrap is 72 bytes",
        short,
        "malformed_envelope",
    );
    let mut zero = input1.clone();
    zero["wrap"]["prf_salt"] = h(&[0u8; 32]);
    refused(
        "zero_prf_salt",
        "an all-zero PRF salt",
        zero,
        "input_all_zero",
    );
    let mut no_cred = input1.clone();
    no_cred["wrap"]["credential_id"] = h(&[]);
    refused(
        "empty_credential_id",
        "an empty credential id",
        no_cred,
        "input_too_short",
    );
    let mut bad_tag = input1.clone();
    let mut tag = cur1.tag;
    tag[0] ^= 1;
    bad_tag["current"]["tag"] = h(&tag);
    refused(
        "current_tag",
        "the current manifest row does not verify",
        bad_tag,
        "decrypt",
    );
    let other = seal_manifest(
        "methods/current/other_vault",
        &c2,
        5,
        &manifest_plain(c2.epoch, &kept, true),
    )?;
    let mut foreign = input1.clone();
    foreign["current"] = manifest_row(&other);
    refused(
        "current_of_another_vault",
        "the current manifest belongs to another vault",
        foreign,
        "decrypt",
    );
    let mut stale = input1.clone();
    stale["current"]["rev"] = rev_s(6);
    refused(
        "current_rev",
        "the revision is bound to the manifest: another one does not verify",
        stale,
        "decrypt",
    );
    drop(refused);

    // ---- methods.remove, accepted
    let cur_r = current("remove", &after, false, 3)?;
    let plain_r = manifest_plain(1, &base, false);
    let next_r = seal_manifest("methods/next/remove_passkey", &c1, 4, &plain_r)?;
    let body_r = remove_body(0x72, next_r.rev, &next_r.envelope, &next_r.tag);
    let mut input_r = c1.input();
    input_r["current"] = manifest_row(&cur_r);
    input_r["method_id"] = h(&[0x72; 16]);
    let mut c = valid_case(
        "methods/remove/passkey",
        "a passkey is removed",
        "methods.remove",
        vec![],
        input_r.clone(),
        json!({ "manifest": h(&plain_r), "sealed": manifest_row(&next_r), "body": h(&body_r) }),
    );
    c.rng = vec![hex(&next_r.nonce)];
    cases.push(c);
    sign_input(&mut input_r, &nonce);
    let message_r = proof_message("unlock-method.remove", &c1, &nonce, &body_r);
    let sig_r = ed25519_sign(&keys.seed_a, &message_r).map_err(|e| format!("sign failed: {e}"))?;
    let mut c = valid_case(
        "methods/remove/signed",
        "the proof names the method and the manifest it removes",
        "methods.remove",
        vec![],
        input_r,
        json!({
            "manifest": h(&plain_r),
            "sealed": manifest_row(&next_r),
            "body": h(&body_r),
            "op": "unlock-method.remove",
            "pk_a": h(&ed25519_public_key(&keys.seed_a)),
            "proof": h(&sig_r),
        }),
    );
    c.rng = vec![hex(&next_r.nonce)];
    cases.push(c);

    // A method of a type this version does not know can be removed, and the
    // rest is untouched.
    let mut with_future = base.to_vec();
    with_future.push(Ent::new(9, 0x75, 2));
    let cur_f = current("future_type", &with_future, true, 7)?;
    let plain_f = manifest_plain(1, &base, true);
    let next_f = seal_manifest("methods/next/remove_future", &c1, 8, &plain_f)?;
    let mut input_f = c1.input();
    input_f["current"] = manifest_row(&cur_f);
    input_f["method_id"] = h(&[0x75; 16]);
    let mut c = valid_case(
        "methods/remove/unknown_type",
        "a method of an unknown type is removed; the unknown manifest key stays",
        "methods.remove",
        vec![],
        input_f,
        json!({
            "manifest": h(&plain_f),
            "sealed": manifest_row(&next_f),
            "body": h(&remove_body(0x75, next_f.rev, &next_f.envelope, &next_f.tag)),
        }),
    );
    c.rng = vec![hex(&next_f.nonce)];
    cases.push(c);

    // ---- methods.remove, refused
    let mut refused = |name: &str, title: &str, input: Value, code: &str| {
        cases.push(invalid_case(
            &format!("methods/remove_invalid/{name}"),
            title,
            "methods.remove",
            vec![],
            input,
            code,
        ));
    };
    let mut last_pw = c1.input();
    last_pw["current"] = manifest_row(&cur0);
    last_pw["method_id"] = h(&[0x70; 16]);
    refused(
        "last_password",
        "the only password method cannot be removed",
        last_pw,
        "input_last_method",
    );
    let mut last_rk = c1.input();
    last_rk["current"] = manifest_row(&cur0);
    last_rk["method_id"] = h(&[0x71; 16]);
    refused(
        "last_recovery",
        "the only recovery method cannot be removed",
        last_rk,
        "input_last_method",
    );
    let mut unlisted = c1.input();
    unlisted["current"] = manifest_row(&cur0);
    unlisted["method_id"] = h(&[0x7f; 16]);
    refused(
        "not_listed",
        "the manifest does not list the method",
        unlisted,
        "malformed_entries",
    );
    let mut bad_current = c1.input();
    let mut bad_row = manifest_row(&cur0);
    let mut bad_tag = cur0.tag;
    bad_tag[5] ^= 1;
    bad_row["tag"] = h(&bad_tag);
    bad_current["current"] = bad_row;
    bad_current["method_id"] = h(&[0x72; 16]);
    refused(
        "current_tag",
        "the current manifest row does not verify",
        bad_current,
        "decrypt",
    );
    drop(refused);

    // ---- methods.check_server
    let server = |list: &[(u64, u8, u64)]| -> Value {
        Value::Array(
            list.iter()
                .map(|(ty, id, g)| {
                    json!({
                        "method_type": ty,
                        "method_id": h(&[*id; 16]),
                        "kek_generation": g.to_string(),
                    })
                })
                .collect(),
        )
    };
    let manifest_v = |list: &[Ent]| -> Value {
        json!({ "vk_epoch": "1", "methods": list.iter().map(Ent::json).collect::<Vec<_>>() })
    };
    let three = [pw.clone(), rk.clone(), prf_a.clone()];
    let mut check = |name: &str, title: &str, list: &[Ent], srv: Value, code: Option<&str>| {
        let input = json!({ "manifest": manifest_v(list), "server": srv });
        let id = format!("methods/check_server/{name}");
        cases.push(match code {
            None => valid_case(
                &id,
                title,
                "methods.check_server",
                vec![],
                input,
                json!({ "ok": true }),
            ),
            Some(code) => invalid_case(&id, title, "methods.check_server", vec![], input, code),
        });
    };
    check(
        "agree",
        "the two lists agree",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1), (3, 0x72, 1)]),
        None,
    );
    check(
        "agree_in_another_order",
        "the order of the lists does not matter",
        &three,
        server(&[(3, 0x72, 1), (1, 0x70, 3), (2, 0x71, 1)]),
        None,
    );
    check(
        "unknown_method",
        "the server lists a method the manifest does not",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1), (3, 0x72, 1), (3, 0x7e, 1)]),
        Some("method_list_unknown"),
    );
    check(
        "repeated_id",
        "the server lists one id twice",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1), (3, 0x72, 1), (3, 0x72, 1)]),
        Some("method_list_unknown"),
    );
    check(
        "other_generation",
        "the server shows another generation",
        &three,
        server(&[(1, 0x70, 2), (2, 0x71, 1), (3, 0x72, 1)]),
        Some("method_list_changed"),
    );
    check(
        "other_type",
        "the server shows another type for a listed id",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1), (4, 0x72, 1)]),
        Some("method_list_changed"),
    );
    check(
        "missing_method",
        "the manifest lists a method the server does not",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1)]),
        Some("method_list_missing"),
    );
    check(
        "unknown_before_missing",
        "an unknown method is reported before a missing one",
        &three,
        server(&[(1, 0x70, 3), (2, 0x71, 1), (3, 0x7e, 1)]),
        Some("method_list_unknown"),
    );
    check(
        "changed_before_missing",
        "a changed method is reported before a missing one",
        &three,
        server(&[(1, 0x70, 9)]),
        Some("method_list_changed"),
    );
    check("empty", "two empty lists agree", &[], server(&[]), None);

    // ---- prf.salt_new
    let salt: [u8; 32] = draw("methods/prf_salt/valid/001");
    let mut c = valid_case(
        "methods/prf_salt/valid/001",
        "a PRF salt is one draw of 32 bytes",
        "prf.salt_new",
        vec![],
        json!({}),
        json!({ "salt": h(&salt) }),
    );
    c.rng = vec![hex(&salt)];
    cases.push(c);

    file("methods", "Fase 1 § 4.3 and § 4.6", cases)
}

fn pattern_bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add(u8::try_from(i % 251).unwrap_or(0)))
        .collect()
}
