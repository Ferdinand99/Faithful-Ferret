//! The vector group for changing the list of unlock methods
//! (`methods.json`): adding and removing a method, comparing the server's
//! list with the manifest, and the PRF salt.
//!
//! Spec: Fase 1 § 4.3 and § 4.6. The manifests are written and sealed here
//! with the hand-made CBOR and the item helpers; the request bodies are
//! spelled out as text; the proofs are signed over the TLV written out by
//! hand. The core's `methods` module is not called.
//!
//! A passkey that is added carries its AAGUID in the request body and its
//! name and BE and BS flags in the sealed manifest (keys `n`, `be`, `bs` of
//! its entry, after `c`). The name of a case is given as hex of its UTF-8
//! bytes (`name_utf8`), so that no bidirectional or control character stands
//! in a text file.

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
    /// The stored name, BE and BS of a passkey (`n`, `be`, `bs`).
    named: Option<(String, bool, bool)>,
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
            named: None,
            extra: false,
        }
    }

    fn passkey(id: u8, generation: u64, credential: Vec<u8>) -> Self {
        Ent {
            credential: Some(credential),
            ..Ent::new(3, id, generation)
        }
    }

    /// A passkey with the name as it is stored and its BE and BS flags.
    fn named(mut self, name: &str, be: bool, bs: bool) -> Self {
        self.named = Some((name.to_owned(), be, bs));
        self
    }

    fn cbor(&self) -> Vec<u8> {
        let mut extra: Vec<(&str, Vec<u8>)> = Vec::new();
        if let Some(c) = &self.credential {
            extra.push(("c", cb::bytes(c)));
        }
        if let Some((name, be, bs)) = &self.named {
            extra.push(("n", cb::text(name)));
            extra.push(("be", cb::boolean(*be)));
            extra.push(("bs", cb::boolean(*bs)));
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
    /// The AAGUID of the request body.
    aaguid: [u8; 16],
}

/// The `passkey` object of an add: the AAGUID, the name as the user typed it
/// (as hex of its UTF-8 bytes) and the flags.
fn passkey_json(aaguid: &[u8; 16], name: &str, be: bool, bs: bool) -> Value {
    json!({ "aaguid": h(aaguid), "name_utf8": h(name.as_bytes()), "be": be, "bs": bs })
}

fn add_body(w: &Add<'_>, rev: u64, envelope: &[u8], tag: &[u8; 32]) -> Vec<u8> {
    format!(
        "{{\"method_type\":3,\"method_id\":\"{}\",\"wrap\":\"{}\",\"kek_generation\":{},\"credential_id\":\"{}\",\"prf_salt\":\"{}\",\"aaguid\":\"{}\",\"manifest\":{}}}",
        hex(&[w.id; 16]),
        hex(&w.wrap),
        w.generation,
        hex(w.credential),
        hex(&w.salt),
        hex(&w.aaguid),
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
    let prf_a = Ent::passkey(0x72, 1, cred_a.clone()).named("Work laptop", false, false);
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
        aaguid: arr(0x9d),
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
    input["passkey"] = passkey_json(&wrap_a.aaguid, "Work laptop", false, false);
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
        // Some authenticators report no AAGUID: all zero is accepted.
        aaguid: [0; 16],
    };
    let mut after1 = kept.clone();
    after1.push(Ent::passkey(0x73, 4, cred_b.clone()).named("Phone", true, false));
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
    input1["passkey"] = passkey_json(&wrap_b.aaguid, "Phone", true, false);
    let mut c = valid_case(
        "methods/add/second_passkey_keeps_unknown_keys",
        "a second passkey with an all-zero AAGUID and BE set but BS not; unknown keys of the manifest and its entries are kept",
        "methods.add",
        vec![],
        input1.clone(),
        json!({ "manifest": h(&plain1), "sealed": manifest_row(&next1), "body": h(&body1) }),
    );
    c.rng = vec![hex(&next1.nonce)];
    cases.push(c);

    // The name is stored in NFC and trimmed, and the length is counted after
    // that. Both start from the first manifest.
    let mut stored_case = |slug: &str,
                           title: &str,
                           id: u8,
                           typed: &str,
                           stored: &str,
                           aaguid: [u8; 16],
                           be: bool,
                           bs: bool|
     -> Result<(), Error> {
        let w = Add {
            id,
            generation: 1,
            credential: &pattern_bytes(id, 24),
            salt: arr(0xb3),
            wrap: pattern_bytes(0x5d, 72),
            aaguid,
        };
        let mut list = base.to_vec();
        list.push(Ent::passkey(id, 1, w.credential.to_vec()).named(stored, be, bs));
        let plain = manifest_plain(1, &list, false);
        let next = seal_manifest(&format!("methods/next/{slug}"), &c1, 3, &plain)?;
        let body = add_body(&w, next.rev, &next.envelope, &next.tag);
        let mut input = c1.input();
        input["current"] = manifest_row(&cur0);
        input["wrap"] = wrap_json(w.id, w.generation, w.credential, &w.salt, &w.wrap);
        input["passkey"] = passkey_json(&w.aaguid, typed, be, bs);
        let mut c = valid_case(
            &format!("methods/add/{slug}"),
            title,
            "methods.add",
            vec![],
            input,
            json!({ "manifest": h(&plain), "sealed": manifest_row(&next), "body": h(&body) }),
        );
        c.rng = vec![hex(&next.nonce)];
        cases.push(c);
        Ok(())
    };
    stored_case(
        "name_normalized_and_trimmed",
        "the name is stored in NFC without the white space around it; a synced key with BS set",
        0x74,
        "  Cafe\u{301} \u{1f511}\t",
        "Caf\u{e9} \u{1f511}",
        [
            0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcf, 0xbc, 0x9b, 0x0e, 0x6b, 0x28, 0x3a,
            0xf1, 0x55,
        ],
        true,
        true,
    )?;
    stored_case(
        "name_length_counts_after_nfc",
        "64 letters with a combining accent are 64 characters once in NFC",
        0x75,
        &"e\u{301}".repeat(64),
        &"\u{e9}".repeat(64),
        arr(0x21),
        false,
        false,
    )?;
    stored_case(
        "name_trailing_next_line_trimmed",
        "U+0085 is white space and is trimmed at the end of a name; a zero width non-joiner is kept",
        0x77,
        "Key\u{200c}\u{85}",
        "Key\u{200c}",
        arr(0x23),
        false,
        false,
    )?;
    stored_case(
        "name_joiner_allowed",
        "the zero width joiner of an emoji sequence is allowed in a name",
        0x76,
        "\u{1f468}\u{200d}\u{1f4bb}",
        "\u{1f468}\u{200d}\u{1f4bb}",
        arr(0x22),
        true,
        false,
    )?;

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
    let mut with_name = |slug: &str, title: &str, typed: &str, code: &str| {
        let mut input = input1.clone();
        input["passkey"]["name_utf8"] = h(typed.as_bytes());
        refused(slug, title, input, code);
    };
    with_name(
        "name_empty",
        "a name that is empty",
        "",
        "method_name_empty",
    );
    with_name(
        "name_only_white_space",
        "a name that is only white space",
        " \t\u{a0}\u{3000}",
        "method_name_empty",
    );
    with_name(
        "name_65_characters",
        "a name of 65 characters",
        &"x".repeat(65),
        "method_name_too_long",
    );
    with_name(
        "name_65_characters_after_nfc",
        "65 letters with a combining accent are 65 characters once in NFC",
        &"e\u{301}".repeat(65),
        "method_name_too_long",
    );
    with_name(
        "name_control_character",
        "a name with a line feed",
        "a\nb",
        "method_name_bad_character",
    );
    with_name(
        "name_bidirectional_override",
        "a name with a right-to-left override",
        "a\u{202e}b",
        "method_name_bad_character",
    );
    with_name(
        "name_zero_width_space",
        "a name with a zero width space",
        "a\u{200b}b",
        "method_name_bad_character",
    );
    with_name(
        "name_line_separator",
        "a name with a line separator",
        "a\u{2028}b",
        "method_name_bad_character",
    );
    with_name(
        "name_bad_character_before_length",
        "a bad character is reported before the length",
        &format!("{}\u{202e}", "x".repeat(70)),
        "method_name_bad_character",
    );
    with_name(
        "name_leading_byte_order_mark",
        "a byte order mark is not white space, so it is not trimmed and is refused",
        "\u{feff}Key",
        "method_name_bad_character",
    );
    with_name(
        "name_isolate",
        "a name with a bidirectional isolate",
        "a\u{2066}b",
        "method_name_bad_character",
    );
    with_name(
        "name_next_line",
        "a next-line control inside a name",
        "a\u{85}b",
        "method_name_bad_character",
    );
    let mut bs_only = input1.clone();
    bs_only["passkey"]["be"] = json!(false);
    bs_only["passkey"]["bs"] = json!(true);
    refused(
        "bs_without_be",
        "BS set without BE is not a conformant registration",
        bs_only,
        "invalid_state",
    );
    let mut own = input1.clone();
    own["passkey"]["aaguid"] = json!("dc704a44b994410ca689ed8d71a84ac3");
    refused(
        "ferrets_own_aaguid",
        "Ferret's own AAGUID is refused as an extra guard",
        own,
        "invalid_state",
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

    // The last-method rule counts entries of the type: with a second password
    // (or a second recovery) method listed, one of them can go.
    let mut twice = |name: &str,
                     title: &str,
                     list: Vec<Ent>,
                     gone: u8,
                     rest: Vec<Ent>,
                     rev: u64|
     -> Result<(), Error> {
        let cur = current(name, &list, false, rev)?;
        let plain = manifest_plain(1, &rest, false);
        let next = seal_manifest(&format!("methods/next/{name}"), &c1, rev + 1, &plain)?;
        let mut input = c1.input();
        input["current"] = manifest_row(&cur);
        input["method_id"] = h(&[gone; 16]);
        let mut c = valid_case(
            &format!("methods/remove/{name}"),
            title,
            "methods.remove",
            vec![],
            input,
            json!({
                "manifest": h(&plain),
                "sealed": manifest_row(&next),
                "body": h(&remove_body(gone, next.rev, &next.envelope, &next.tag)),
            }),
        );
        c.rng = vec![hex(&next.nonce)];
        cases.push(c);
        Ok(())
    };
    let pw2 = Ent::new(1, 0x76, 2);
    let rk2 = Ent::new(2, 0x77, 1);
    twice(
        "second_password_listed",
        "a password method can be removed when another one is listed",
        vec![pw.clone(), pw2.clone(), rk.clone()],
        0x70,
        vec![pw2, rk.clone()],
        9,
    )?;
    twice(
        "second_recovery_listed",
        "a recovery method can be removed when another one is listed",
        vec![pw.clone(), rk.clone(), rk2.clone()],
        0x71,
        vec![pw.clone(), rk2],
        11,
    )?;

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
