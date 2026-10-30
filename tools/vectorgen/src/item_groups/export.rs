//! The vector group for the export file (`export.json`): the encrypted
//! `.ferretexport`, opening it, its header, and the plaintext JSON and CSV.
//!
//! As in the other groups, every expected value is made here from the
//! specification (Fase 1 § 6.4 and plan Appendix B) without calling the
//! core's export code: the header and the body are written as CBOR head by
//! head, the TLV bytes by hand, Argon2id, HKDF and the AEAD go to the
//! primitive wrappers (which have their own RFC and Wycheproof vectors),
//! and the plaintext JSON and CSV are rendered by the small writers below.
//!
//! Cases with Argon2id parameters below the floor are `native-only`: only a
//! build with `test-support` accepts them. The cases at the floor (64 MiB)
//! and at the export default (256 MiB) are `slow` and run everywhere. The
//! cases that sabotage the parameters or the layout need no Argon2id run and
//! run everywhere too.

use super::*;
use crate::key_groups::hk;
use ferret_core::KdfParams;
use ferret_core::testing::prim::argon2id_unchecked;
use ferret_core::testing::vector::Tag;

// ---------------------------------------------------------------- items

const CREATED: u64 = 1_700_000_000_000;
const MODIFIED: u64 = 1_700_000_100_000;
const PASSKEY_CREATED: u64 = 1_700_000_050_000;

/// An item written out field by field, from which the CBOR body, the JSON
/// and the CSV row are all made.
#[derive(Clone)]
struct XItem {
    id: [u8; 16],
    ty: &'static str,
    name: String,
    /// `(id, label, kind, value)`.
    fields: Vec<(String, String, String, String)>,
    /// An unknown key (`future`: 7) in the first field.
    field_extra: bool,
    urls: Vec<String>,
    totp: Option<String>,
    passkey: bool,
    notes: Option<String>,
    favorite: bool,
    /// An unknown key at the top of the body: `(key, text)`.
    unknown: Option<(&'static str, String)>,
}

impl XItem {
    fn new(id: u8, ty: &'static str, name: &str) -> Self {
        Self {
            id: [id; 16],
            ty,
            name: name.into(),
            fields: vec![],
            field_extra: false,
            urls: vec![],
            totp: None,
            passkey: false,
            notes: None,
            favorite: false,
            unknown: None,
        }
    }

    fn field(mut self, id: &str, label: &str, kind: &str, value: &str) -> Self {
        self.fields
            .push((id.into(), label.into(), kind.into(), value.into()));
        self
    }

    fn cbor(&self) -> Vec<u8> {
        let fields: Vec<Vec<u8>> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let extra = if self.field_extra && i == 0 {
                    vec![("future", cb::uint(7))]
                } else {
                    vec![]
                };
                field(&f.0, &f.1, &f.2, &f.3, &extra)
            })
            .collect();
        let urls: Vec<Vec<u8>> = self.urls.iter().map(|u| url(u, "host", &[])).collect();
        let mut e: Vec<(&str, Vec<u8>)> = vec![
            ("schema", cb::uint(1)),
            ("type", cb::text(self.ty)),
            ("name", cb::text(&self.name)),
            ("fields", cb::array(&fields)),
            ("urls", cb::array(&urls)),
        ];
        if let Some(uri) = &self.totp {
            e.push(("totp", totp(uri, &[])));
        }
        if self.passkey {
            e.push(("passkey", passkey(true, true, &[])));
        }
        if let Some(n) = &self.notes {
            e.push(("notes", cb::text(n)));
        }
        e.push(("created", cb::uint(CREATED)));
        e.push(("modified", cb::uint(MODIFIED)));
        e.push(("favorite", cb::boolean(self.favorite)));
        if let Some((k, v)) = &self.unknown {
            e.push((k, cb::text(v)));
        }
        cb::map(&e)
    }

    /// The JSON of the body (Fase 1 § 6.4 and the OPS register): compact, the
    /// keys in the order of the CBOR, bytes as lowercase hex.
    fn json(&self, include_passkeys: bool) -> String {
        let mut s = format!(
            "{{\"schema\":1,\"type\":{},\"name\":{},\"fields\":[",
            jstr(self.ty),
            jstr(&self.name)
        );
        let fields: Vec<String> = self
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let extra = if self.field_extra && i == 0 {
                    ",\"future\":7"
                } else {
                    ""
                };
                format!(
                    "{{\"id\":{},\"label\":{},\"kind\":{},\"value\":{}{extra}}}",
                    jstr(&f.0),
                    jstr(&f.1),
                    jstr(&f.2),
                    jstr(&f.3)
                )
            })
            .collect();
        s.push_str(&fields.join(","));
        s.push_str("],\"urls\":[");
        let urls: Vec<String> = self
            .urls
            .iter()
            .map(|u| format!("{{\"url\":{},\"match\":\"host\"}}", jstr(u)))
            .collect();
        s.push_str(&urls.join(","));
        s.push(']');
        if let Some(uri) = &self.totp {
            s.push_str(&format!(",\"totp\":{{\"uri\":{}}}", jstr(uri)));
        }
        if self.passkey {
            s.push_str(&format!(
                ",\"passkey\":{{\"cred_id\":\"{}\",\"rp_id\":\"example.com\",\"user_handle\":\"{}\",\"user_name\":\"alice\"",
                hex_encode(&[0xc1; 32]),
                hex_encode(&[0xd2; 16])
            ));
            if include_passkeys {
                s.push_str(&format!(",\"priv\":\"{}\"", hex_encode(&[0xe3; 138])));
            }
            s.push_str(&format!(",\"sign_count\":0,\"created\":{PASSKEY_CREATED}"));
            if include_passkeys {
                s.push_str(&format!(
                    ",\"prf_seed_uv\":\"{}\",\"prf_seed_nouv\":\"{}\"",
                    hex_encode(&[0xf4; 32]),
                    hex_encode(&[0xf5; 32])
                ));
            }
            s.push('}');
        }
        if let Some(n) = &self.notes {
            s.push_str(&format!(",\"notes\":{}", jstr(n)));
        }
        s.push_str(&format!(
            ",\"created\":{CREATED},\"modified\":{MODIFIED},\"favorite\":{}",
            self.favorite
        ));
        if let Some((k, v)) = &self.unknown {
            s.push_str(&format!(",{}:{}", jstr(k), jstr(v)));
        }
        s.push('}');
        s
    }

    /// The cells of the CSV row, `width` custom fields wide.
    fn csv_cells(&self, width: usize) -> Vec<String> {
        let mut cells = vec![
            hex_encode(&self.id),
            self.ty.to_string(),
            self.name.clone(),
            self.urls.join(" "),
            self.notes.clone().unwrap_or_default(),
            self.totp.clone().unwrap_or_default(),
            self.favorite.to_string(),
            CREATED.to_string(),
            MODIFIED.to_string(),
            if self.passkey {
                "example.com".into()
            } else {
                String::new()
            },
            if self.passkey {
                "alice".into()
            } else {
                String::new()
            },
        ];
        for f in &self.fields {
            cells.extend([f.1.clone(), f.2.clone(), f.3.clone()]);
        }
        while cells.len() < 11 + 3 * width {
            cells.push(String::new());
        }
        cells
    }
}

/// A JSON string with the escapes of RFC 8259 § 7.
fn jstr(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// One CSV cell: `'` in front of a cell that starts like a formula (after any
/// leading spaces), then RFC 4180 quoting.
fn csv_cell(s: &str) -> String {
    let neutral = if s
        .trim_start_matches(' ')
        .starts_with(['=', '+', '-', '@', '\t', '\r'])
    {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if neutral.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", neutral.replace('"', "\"\""))
    } else {
        neutral
    }
}

fn csv(items: &[XItem]) -> String {
    let width = items.iter().map(|i| i.fields.len()).max().unwrap_or(0);
    let mut header: Vec<String> = [
        "id",
        "type",
        "name",
        "url",
        "notes",
        "totp",
        "favorite",
        "created",
        "modified",
        "passkey_rp_id",
        "passkey_user_name",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for n in 1..=width {
        header.extend([
            format!("field_{n}_label"),
            format!("field_{n}_kind"),
            format!("field_{n}_value"),
        ]);
    }
    let mut out = String::new();
    let rows = std::iter::once(header).chain(items.iter().map(|i| i.csv_cells(width)));
    for row in rows {
        let cells: Vec<String> = row.iter().map(|c| csv_cell(c)).collect();
        out.push_str(&cells.join(","));
        out.push_str("\r\n");
    }
    out
}

fn json(items: &[XItem], include_passkeys: bool) -> String {
    let list: Vec<String> = items
        .iter()
        .map(|i| {
            format!(
                "{{\"id\":\"{}\",\"body\":{}}}",
                hex_encode(&i.id),
                i.json(include_passkeys)
            )
        })
        .collect();
    format!("{{\"v\":1,\"items\":[{}]}}", list.join(","))
}

fn items_input(items: &[XItem]) -> Value {
    json!(
        items
            .iter()
            .map(|i| json!({ "id": hex_encode(&i.id), "body": hex_encode(&i.cbor()) }))
            .collect::<Vec<_>>()
    )
}

// ------------------------------------------------------ the file, by hand

const SMALL_A: KdfParams = KdfParams {
    m_kib: 256,
    t: 2,
    p: 2,
};
const SMALL_B: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};
const FLOOR: KdfParams = KdfParams {
    m_kib: 65_536,
    t: 3,
    p: 1,
};
const DEFAULT: KdfParams = KdfParams {
    m_kib: 262_144,
    t: 3,
    p: 1,
};
const CREATED_AT: u64 = 1_761_000_000_000;

#[allow(clippy::too_many_arguments)]
fn header_bytes(
    v: u64,
    suite: u64,
    salt: &[u8],
    m: u64,
    t: u64,
    p: u64,
    created_at: u64,
) -> Vec<u8> {
    cb::map(&[
        ("v", cb::uint(v)),
        ("suite", cb::uint(suite)),
        (
            "kdf",
            cb::map(&[
                ("salt", cb::bytes(salt)),
                ("m", cb::uint(m)),
                ("t", cb::uint(t)),
                ("p", cb::uint(p)),
            ]),
        ),
        ("created_at", cb::uint(created_at)),
    ])
}

fn aad(label_s: &str, header: &[u8]) -> Vec<u8> {
    cat(&[label(label_s), t(0x39, header)])
}

/// An export file made from the specification.
struct Built {
    kdf: KdfParams,
    password: String,
    header: Vec<u8>,
    salt: [u8; 16],
    k_exp: [u8; 32],
    ek: [u8; 32],
    nonce_body: [u8; 24],
    aad_ek: Vec<u8>,
    aad_body: Vec<u8>,
    ek_wrap: Vec<u8>,
    body: Vec<u8>,
    rng: Vec<Vec<u8>>,
}

impl Built {
    fn file(&self) -> Vec<u8> {
        cat(&[self.header.clone(), self.ek_wrap.clone(), self.body.clone()])
    }

    /// The same file with another header in front of the same rest.
    fn with_header(&self, header: &[u8]) -> Vec<u8> {
        cat(&[header.to_vec(), self.ek_wrap.clone(), self.body.clone()])
    }

    /// The same file with another, authentic, body.
    fn with_plain_body(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let body = seal_with(
            ReplayRng::new(vec![self.nonce_body.to_vec()]),
            &self.ek,
            &self.aad_body,
            plain,
        )?;
        Ok(cat(&[self.header.clone(), self.ek_wrap.clone(), body]))
    }
}

/// `plain` is the CBOR of the body. `password_nfkd` is the password as the
/// core normalizes it.
fn build(
    seed: &str,
    password: &str,
    password_nfkd: &[u8],
    kdf: KdfParams,
    created_at: u64,
    plain: &[u8],
) -> Result<Built, Error> {
    let salt: [u8; 16] = draw(&format!("{seed}/salt"));
    let ek: [u8; 32] = draw(&format!("{seed}/ek"));
    let nonce_ek: [u8; 24] = draw(&format!("{seed}/nonce-ek"));
    let nonce_body: [u8; 24] = draw(&format!("{seed}/nonce-body"));
    let header = header_bytes(
        1,
        1,
        &salt,
        u64::from(kdf.m_kib),
        u64::from(kdf.t),
        u64::from(kdf.p),
        created_at,
    );
    let mut stretched = [0u8; 32];
    argon2id_unchecked(password_nfkd, &salt, &[], &[], kdf, &mut stretched)
        .map_err(|e| format!("argon2id failed: {e}"))?;
    let k_exp = hk(
        &label("ferret/v1/export"),
        &stretched,
        b"ferret/v1/export/key",
    )?;
    let aad_ek = aad("ferret/v1/export/ek", &header);
    let aad_body = aad("ferret/v1/export/body", &header);
    let ek_wrap = seal_with(
        ReplayRng::new(vec![nonce_ek.to_vec()]),
        &k_exp,
        &aad_ek,
        &ek,
    )?;
    let body = seal_with(
        ReplayRng::new(vec![nonce_body.to_vec()]),
        &ek,
        &aad_body,
        plain,
    )?;
    Ok(Built {
        kdf,
        password: password.into(),
        header,
        salt,
        k_exp,
        ek,
        nonce_body,
        aad_ek,
        aad_body,
        ek_wrap,
        body,
        rng: vec![
            salt.to_vec(),
            ek.to_vec(),
            nonce_ek.to_vec(),
            nonce_body.to_vec(),
        ],
    })
}

fn body_plain(items: &[XItem]) -> Vec<u8> {
    let list: Vec<Vec<u8>> = items
        .iter()
        .map(|i| cb::map(&[("id", cb::bytes(&i.id)), ("body", i.cbor())]))
        .collect();
    cb::map(&[("v", cb::uint(1)), ("items", cb::array(&list))])
}

fn build_items(
    seed: &str,
    password: &str,
    kdf: KdfParams,
    items: &[XItem],
) -> Result<Built, Error> {
    build(
        seed,
        password,
        password.as_bytes(),
        kdf,
        CREATED_AT,
        &body_plain(items),
    )
}

fn kdf_json(k: KdfParams) -> Value {
    json!({ "m_kib": k.m_kib, "t": k.t, "p": k.p })
}

fn flip(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 0x01;
    out
}

// --------------------------------------------------------------- cases

const NATIVE_REASON: &str =
    "Argon2id parameters below the floor: only a build with test-support accepts them";

fn small_tags() -> (Vec<Tag>, Option<String>) {
    (vec![Tag::NativeOnly], Some(NATIVE_REASON.into()))
}

fn finish(mut c: Case, tags: &(Vec<Tag>, Option<String>)) -> Case {
    c.tags = tags.0.clone();
    c.skip_reason = tags.1.clone();
    c
}

fn encrypt_case(
    name: &str,
    title: &str,
    tags: &(Vec<Tag>, Option<String>),
    b: &Built,
    items: &[XItem],
    intermediate: bool,
) -> Case {
    let mut c = valid_case(
        &format!("export/encrypt/valid/{name}"),
        title,
        "export.encrypt",
        vec![],
        json!({
            "password": b.password,
            "kdf": kdf_json(b.kdf),
            "created_at": CREATED_AT.to_string(),
            "items": items_input(items),
        }),
        json!({ "file": hex_encode(&b.file()) }),
    );
    c.rng = b.rng.iter().map(|d| hex_encode(d)).collect();
    if intermediate {
        c.intermediate = Some(json!({
            "header": hex_encode(&b.header),
            "k_exp": hex_encode(&b.k_exp),
            "aad_ek": hex_encode(&b.aad_ek),
            "aad_body": hex_encode(&b.aad_body),
        }));
    }
    finish(c, tags)
}

fn decrypt_input(password: &str, file: &[u8]) -> Value {
    json!({ "password": password, "file": hex_encode(file) })
}

fn decrypt_case(
    name: &str,
    title: &str,
    tags: &(Vec<Tag>, Option<String>),
    b: &Built,
    items: &[XItem],
) -> Case {
    finish(
        valid_case(
            &format!("export/decrypt/valid/{name}"),
            title,
            "export.decrypt",
            vec![],
            decrypt_input(&b.password, &b.file()),
            json!({
                "created_at": CREATED_AT.to_string(),
                "kdf": kdf_json(b.kdf),
                "items": items_input(items),
            }),
        ),
        tags,
    )
}

fn refused(
    name: &str,
    title: &str,
    tags: &(Vec<Tag>, Option<String>),
    password: &str,
    file: &[u8],
    code: &str,
) -> Case {
    finish(
        invalid_case(
            &format!("export/decrypt/invalid/{name}"),
            title,
            "export.decrypt",
            vec![],
            decrypt_input(password, file),
            code,
        ),
        tags,
    )
}

fn header_case(
    name: &str,
    title: &str,
    file: &[u8],
    built: Option<&Built>,
    code: Option<&str>,
) -> Case {
    let input = json!({ "file": hex_encode(file) });
    match (built, code) {
        (Some(b), None) => valid_case(
            &format!("export/header/valid/{name}"),
            title,
            "export.header",
            vec![],
            input,
            json!({
                "created_at": CREATED_AT.to_string(),
                "kdf": kdf_json(b.kdf),
                "salt": hex_encode(&b.salt),
                "header_len": b.header.len(),
            }),
        ),
        (_, Some(code)) => invalid_case(
            &format!("export/header/invalid/{name}"),
            title,
            "export.header",
            vec![],
            input,
            code,
        ),
        (None, None) => unreachable!("a valid header case needs the built file"),
    }
}

fn plain_case(
    name: &str,
    title: &str,
    op: &str,
    items: &[XItem],
    include: bool,
    text: String,
) -> Case {
    valid_case(
        &format!("export/plain/{name}"),
        title,
        op,
        vec![],
        json!({ "items": items_input(items), "include_passkeys": include }),
        json!({ "text": text }),
    )
}

pub(crate) fn export() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let small = small_tags();
    let slow = (vec![Tag::Slow], None);
    let none = (vec![], None);

    // ---- items
    let mut login = XItem::new(0x11, "login", "Example")
        .field("user", "Username", "text", "alice")
        .field("pass", "Password", "password", "pa,ss\"word");
    login.field_extra = true;
    login.urls = vec!["https://example.com".into(), "https://example.org".into()];
    login.totp = Some("otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP".into());
    login.notes = Some("first line\nsecond line".into());
    login.favorite = true;
    login.unknown = Some(("x_future", "kept as it was".into()));
    let note = XItem::new(0x22, "note", "Æøå note");
    let mut with_passkey = XItem::new(0x33, "login", "Passkey site");
    with_passkey.passkey = true;
    with_passkey.urls = vec!["https://example.com".into()];
    let card = XItem::new(0x44, "card", "Visa").field("n", "Number", "hidden", "4111111111111111");

    let pw_a = "correct horse battery staple";
    let pw_b = "Another passphrase 2026";

    // ---- encrypt and decrypt, valid
    let two = [login.clone(), note.clone()];
    let a = build_items("export/a", pw_a, SMALL_A, &two)?;
    cases.push(encrypt_case(
        "001",
        "two items with unknown fields, small parameters (m 256 KiB, t 2, p 2)",
        &small,
        &a,
        &two,
        true,
    ));
    cases.push(decrypt_case(
        "001",
        "open the file of encrypt/001",
        &small,
        &a,
        &two,
    ));

    let none_items: [XItem; 0] = [];
    let e = build_items("export/empty", pw_b, SMALL_B, &none_items)?;
    cases.push(encrypt_case(
        "002",
        "no items",
        &small,
        &e,
        &none_items,
        true,
    ));
    cases.push(decrypt_case(
        "002",
        "open the file of encrypt/002",
        &small,
        &e,
        &none_items,
    ));

    let three = [with_passkey.clone(), card.clone(), login.clone()];
    let c = build_items("export/c", pw_a, SMALL_B, &three)?;
    cases.push(encrypt_case(
        "003",
        "a passkey item, a card and a login (m 64 KiB, t 1, p 1)",
        &small,
        &c,
        &three,
        true,
    ));
    cases.push(decrypt_case(
        "003",
        "open the file of encrypt/003",
        &small,
        &c,
        &three,
    ));

    // The password "café ..." is given composed (U+00E9); the key uses NFKD.
    let nfc = "caf\u{e9} au lait 2026";
    let nfkd = "cafe\u{301} au lait 2026";
    let n = build(
        "export/nfc",
        nfc,
        nfkd.as_bytes(),
        SMALL_B,
        CREATED_AT,
        &body_plain(std::slice::from_ref(&note)),
    )?;
    cases.push(encrypt_case(
        "004",
        "a password with a composed character is normalized to NFKD",
        &small,
        &n,
        std::slice::from_ref(&note),
        true,
    ));
    // ... and opened with the decomposed spelling.
    let mut decomposed = decrypt_case(
        "004",
        "the same file opened with the decomposed spelling",
        &small,
        &n,
        std::slice::from_ref(&note),
    );
    decomposed.input["password"] = json!(nfkd);
    cases.push(decomposed);

    let f = build_items("export/floor", pw_a, FLOOR, &[login.clone(), note.clone()])?;
    cases.push(encrypt_case(
        "005",
        "profile 1 parameters (64 MiB, t 3, p 1), the lowest an export is written with",
        &slow,
        &f,
        &[login.clone(), note.clone()],
        false,
    ));
    cases.push(decrypt_case(
        "005",
        "open the file of encrypt/005",
        &slow,
        &f,
        &[login.clone(), note.clone()],
    ));

    let d = build_items(
        "export/default",
        pw_b,
        DEFAULT,
        std::slice::from_ref(&with_passkey),
    )?;
    cases.push(encrypt_case(
        "006",
        "the export default (256 MiB, t 3, p 1)",
        &slow,
        &d,
        std::slice::from_ref(&with_passkey),
        false,
    ));
    cases.push(decrypt_case(
        "006",
        "open the file of encrypt/006",
        &slow,
        &d,
        std::slice::from_ref(&with_passkey),
    ));

    // ---- header
    let a_file = a.file();
    cases.push(header_case(
        "001",
        "the header of encrypt/001 ends where ek_wrap begins",
        &a_file,
        Some(&a),
        None,
    ));
    let f_file = f.file();
    cases.push(header_case(
        "002",
        "the header at profile 1",
        &f_file,
        Some(&f),
        None,
    ));
    let mut trailing = a_file.clone();
    trailing.extend_from_slice(&[0xff; 9]);
    cases.push(header_case(
        "003",
        "bytes after the file do not change the header length",
        &trailing,
        Some(&a),
        None,
    ));
    cases.push(header_case(
        "001",
        "an empty file",
        &[],
        None,
        Some("malformed_export_header"),
    ));
    cases.push(header_case(
        "002",
        "not CBOR",
        &[0xff, 0xff, 0xff],
        None,
        Some("malformed_export_header"),
    ));
    let salt = &a.salt;
    let other_header = |v, suite, salt: &[u8], extra: bool| {
        let mut h = header_bytes(v, suite, salt, 256, 2, 2, CREATED_AT);
        if extra {
            // An unknown key: the map head becomes 5 entries.
            h[0] = 0xa5;
            h.extend_from_slice(&cb::text("more"));
            h.extend_from_slice(&cb::null());
        }
        h
    };
    cases.push(header_case(
        "003",
        "an unknown key in the header",
        &a.with_header(&other_header(1, 1, salt, true)),
        None,
        Some("malformed_export_header"),
    ));
    cases.push(header_case(
        "004",
        "a salt of 15 bytes",
        &a.with_header(&other_header(1, 1, &salt[..15], false)),
        None,
        Some("malformed_export_header"),
    ));
    cases.push(header_case(
        "005",
        "version 2",
        &a.with_header(&other_header(2, 1, salt, false)),
        None,
        Some("unsupported"),
    ));
    cases.push(header_case(
        "006",
        "suite 2",
        &a.with_header(&other_header(1, 2, salt, false)),
        None,
        Some("unsupported"),
    ));
    cases.push(header_case(
        "007",
        "version 2 with a memory size that does not fit 32 bits: the version is reported first",
        &a.with_header(&header_bytes(2, 1, salt, 4_294_967_296, 2, 2, CREATED_AT)),
        None,
        Some("unsupported"),
    ));

    // ---- refused: layout, no Argon2id run (run by every binding)
    let ps =
        |m: u64, t_: u64, p: u64| f.with_header(&header_bytes(1, 1, &f.salt, m, t_, p, CREATED_AT));
    for (name, title, m, t_, p) in [
        (
            "001",
            "memory 32 MiB, below the floor",
            32_768u64,
            3u64,
            1u64,
        ),
        ("002", "memory one KiB below the floor", 65_535, 3, 1),
        ("003", "two passes, below the floor", 65_536, 2, 1),
        ("004", "no passes", 65_536, 0, 1),
        ("005", "no lanes", 65_536, 3, 0),
        ("006", "memory one KiB above 512 MiB", 524_289, 3, 1),
        ("007", "memory 1 GiB", 1_048_576, 3, 1),
        ("008", "17 passes, above the ceiling", 65_536, 17, 1),
        ("009", "5 lanes, above the ceiling", 65_536, 3, 5),
        (
            "010",
            "memory 2^32 KiB, which does not fit 32 bits",
            4_294_967_296,
            3,
            1,
        ),
    ] {
        cases.push(refused(
            &format!("kdf-range-{name}"),
            title,
            &none,
            pw_a,
            &ps(m, t_, p),
            "kdf_out_of_range",
        ));
    }
    let h_len = f.header.len();
    let ek_wrap_end = h_len + 72;
    let ff = f_file.clone();
    cases.push(refused(
        "short-001",
        "the header cut in two",
        &none,
        pw_a,
        &ff[..h_len / 2],
        "malformed_export_header",
    ));
    cases.push(refused(
        "short-002",
        "the header and nothing more",
        &none,
        pw_a,
        &ff[..h_len],
        "malformed_export_header",
    ));
    cases.push(refused(
        "short-003",
        "ek_wrap one byte short",
        &none,
        pw_a,
        &ff[..ek_wrap_end - 1],
        "malformed_export_header",
    ));
    cases.push(refused(
        "short-004",
        "no body",
        &none,
        pw_a,
        &ff[..ek_wrap_end],
        "malformed_export_header",
    ));
    cases.push(refused(
        "short-005",
        "a body of 39 bytes, one short of a nonce and a tag",
        &none,
        pw_a,
        &ff[..ek_wrap_end + 39],
        "malformed_export_header",
    ));

    // ---- refused: authentication
    cases.push(refused(
        "password-001",
        "a wrong password at profile 1",
        &slow,
        "correct horse battery stapl3",
        &f_file,
        "decrypt",
    ));
    cases.push(refused(
        "header-001",
        "created_at changed in the header at profile 1",
        &slow,
        pw_a,
        &flip(&f_file, h_len - 1),
        "decrypt",
    ));
    cases.push(refused(
        "password-002",
        "a wrong password",
        &small,
        "correct horse battery stapl3",
        &a_file,
        "decrypt",
    ));
    cases.push(refused(
        "password-003",
        "the right password with a trailing space",
        &small,
        "correct horse battery staple ",
        &a_file,
        "decrypt",
    ));
    let a_salt_at = a
        .header
        .windows(16)
        .position(|w| w == a.salt)
        .ok_or("salt not found in the header")?;
    cases.push(refused(
        "header-002",
        "a byte of the salt changed",
        &small,
        pw_a,
        &flip(&a_file, a_salt_at + 3),
        "decrypt",
    ));
    cases.push(refused(
        "header-003",
        "created_at changed",
        &small,
        pw_a,
        &flip(&a_file, a.header.len() - 1),
        "decrypt",
    ));
    // m 256 -> 257 (head 0x19 0x01 0x00 -> 0x19 0x01 0x01)
    let m_at = a_salt_at + 16;
    let mut m_changed = a_file.clone();
    assert_eq!(&m_changed[m_at..m_at + 5], &[0x61, b'm', 0x19, 0x01, 0x00]);
    m_changed[m_at + 4] = 0x01;
    cases.push(refused(
        "header-004",
        "m changed from 256 to 257 KiB: other Argon2id input and other AAD",
        &small,
        pw_a,
        &m_changed,
        "decrypt",
    ));
    // The same header with the entries in another order.
    let reordered = cb::map(&[
        ("created_at", cb::uint(CREATED_AT)),
        ("v", cb::uint(1)),
        (
            "kdf",
            cb::map(&[
                ("p", cb::uint(2)),
                ("t", cb::uint(2)),
                ("m", cb::uint(256)),
                ("salt", cb::bytes(&a.salt)),
            ]),
        ),
        ("suite", cb::uint(1)),
    ]);
    assert_eq!(reordered.len(), a.header.len());
    cases.push(refused(
        "header-005",
        "the header map in another order: equal meaning, other AAD bytes",
        &small,
        pw_a,
        &a.with_header(&reordered),
        "decrypt",
    ));
    // `v` with a two-byte head: a valid but not shortest encoding.
    let mut long_head = a.header[..3].to_vec();
    long_head.extend_from_slice(&[0x18, 0x01]);
    long_head.extend_from_slice(&a.header[4..]);
    cases.push(refused(
        "header-006",
        "v written as 18 01: equal meaning, other AAD bytes",
        &small,
        pw_a,
        &a.with_header(&long_head),
        "decrypt",
    ));
    cases.push(refused(
        "ek-wrap-001",
        "a byte of the nonce of ek_wrap changed",
        &small,
        pw_a,
        &flip(&a_file, a.header.len()),
        "decrypt",
    ));
    cases.push(refused(
        "ek-wrap-002",
        "the last byte of ek_wrap (its tag) changed",
        &small,
        pw_a,
        &flip(&a_file, a.header.len() + 71),
        "decrypt",
    ));
    cases.push(refused(
        "body-001",
        "the first byte of the body nonce changed",
        &small,
        pw_a,
        &flip(&a_file, a.header.len() + 72),
        "decrypt",
    ));
    cases.push(refused(
        "body-002",
        "a byte in the middle of the body changed",
        &small,
        pw_a,
        &flip(
            &a_file,
            a.header.len() + 72 + (a_file.len() - a.header.len() - 72) / 2,
        ),
        "decrypt",
    ));
    cases.push(refused(
        "body-003",
        "the last byte of the body changed",
        &small,
        pw_a,
        &flip(&a_file, a_file.len() - 1),
        "decrypt",
    ));
    let mut longer = a_file.clone();
    longer.push(0);
    cases.push(refused(
        "body-004",
        "a byte added at the end",
        &small,
        pw_a,
        &longer,
        "decrypt",
    ));
    cases.push(refused(
        "body-005",
        "the last byte removed",
        &small,
        pw_a,
        &a_file[..a_file.len() - 1],
        "decrypt",
    ));
    // ek_wrap of the one file, body of the other (same password).
    let b2 = build_items("export/a2", pw_a, SMALL_A, &two)?;
    cases.push(refused(
        "swap-001",
        "ek_wrap and body of another file under this header",
        &small,
        pw_a,
        &cat(&[a.header.clone(), b2.ek_wrap.clone(), b2.body.clone()]),
        "decrypt",
    ));

    // ---- authentic, wrong shape
    let id1 = [0x77u8; 16];
    let some = XItem::new(0x77, "note", "ok");
    let wrap = |entries: &[(&str, Vec<u8>)]| cb::map(entries);
    let list1 = cb::array(&[cb::map(&[("id", cb::bytes(&id1)), ("body", some.cbor())])]);
    let list_dup = cb::array(&[
        cb::map(&[("id", cb::bytes(&id1)), ("body", some.cbor())]),
        cb::map(&[("id", cb::bytes(&id1)), ("body", some.cbor())]),
    ]);
    for (name, title, plain, code) in [
        (
            "body-shape-001",
            "an authentic body with v 2",
            wrap(&[("v", cb::uint(2)), ("items", cb::array(&[]))]),
            "unsupported",
        ),
        (
            "body-shape-002",
            "an authentic body with an unknown key at the top",
            wrap(&[
                ("v", cb::uint(1)),
                ("items", list1.clone()),
                ("more", cb::null()),
            ]),
            "malformed_item_body",
        ),
        (
            "body-shape-003",
            "an authentic body with the same id twice",
            wrap(&[("v", cb::uint(1)), ("items", list_dup)]),
            "malformed_item_body",
        ),
        (
            "body-shape-004",
            "an authentic body with the reserved manifest id",
            wrap(&[
                ("v", cb::uint(1)),
                (
                    "items",
                    cb::array(&[cb::map(&[
                        ("id", cb::bytes(&[0; 16])),
                        ("body", some.cbor()),
                    ])]),
                ),
            ]),
            "malformed_item_body",
        ),
        (
            "body-shape-005",
            "an authentic body that is not CBOR",
            vec![0xff],
            "malformed_cbor",
        ),
    ] {
        cases.push(refused(
            name,
            title,
            &small,
            pw_a,
            &a.with_plain_body(&plain)?,
            code,
        ));
    }
    // ... and the good one among them, to show the sabotage is the shape.
    cases.push(finish(
        valid_case(
            "export/decrypt/valid/007",
            "an authentic body with one item, resealed under the header of encrypt/001",
            "export.decrypt",
            vec![],
            decrypt_input(
                pw_a,
                &a.with_plain_body(&wrap(&[("v", cb::uint(1)), ("items", list1.clone())]))?,
            ),
            json!({
                "created_at": CREATED_AT.to_string(),
                "kdf": kdf_json(SMALL_A),
                "items": items_input(std::slice::from_ref(&some)),
            }),
        ),
        &small,
    ));

    // ---- plain exports
    let formulas: Vec<XItem> = [
        "=1+1", "+x", "-x", "@x", "\tx", "\rx", "plain", "a=b", "'x", "",
        // after leading spaces
        " =x", "   +x", " -x", "  @x", " \tx", " \rx", "\t =x",
        // spaces before something else: unchanged
        " x", "  1+1", " 'x",
    ]
    .iter()
    .enumerate()
    .map(|(i, name)| XItem::new(0x50 + i as u8, "note", name))
    .collect();
    cases.push(plain_case(
        "csv-001",
        "names that start like a formula, also after spaces, get a leading apostrophe; others do not",
        "export.plain.csv",
        &formulas,
        false,
        csv(&formulas),
    ));
    let mut tricky = XItem::new(0x61, "login", "A, \"B\"")
        .field("a", "=label", "text", "plus, comma")
        .field("b", "Line", "hidden", "one\r\ntwo")
        .field("c", "Quote", "password", "say \"hi\"");
    tricky.urls = vec!["https://a.example".into(), "https://b.example".into()];
    tricky.notes = Some("-3 degrees\nnext line".into());
    tricky.totp = Some("@totp".into());
    let simple = XItem::new(0x62, "note", "Short").field("a", "Only", "text", "one");
    let rows = vec![tricky.clone(), simple.clone()];
    cases.push(plain_case(
        "csv-002",
        "quoting of commas, quotes and line breaks; rows padded to the widest item",
        "export.plain.csv",
        &rows,
        false,
        csv(&rows),
    ));
    let pk_rows = vec![with_passkey.clone(), login.clone()];
    cases.push(plain_case(
        "csv-003",
        "a passkey item: only rp_id and user name, never the key or the seeds",
        "export.plain.csv",
        &pk_rows,
        true,
        csv(&pk_rows),
    ));
    cases.push(plain_case(
        "csv-004",
        "no items: only the header row",
        "export.plain.csv",
        &[],
        false,
        csv(&[]),
    ));
    cases.push(plain_case(
        "json-001",
        "JSON without the passkey secrets (the default)",
        "export.plain.json",
        &pk_rows,
        false,
        json(&pk_rows, false),
    ));
    cases.push(plain_case(
        "json-002",
        "JSON with the passkey secrets (asked for)",
        "export.plain.json",
        &pk_rows,
        true,
        json(&pk_rows, true),
    ));
    let esc = XItem::new(0x71, "note", "q\"\\\u{1}\u{1f}\t\n\u{e5}\u{2028}");
    cases.push(plain_case(
        "json-003",
        "JSON string escapes",
        "export.plain.json",
        std::slice::from_ref(&esc),
        false,
        json(std::slice::from_ref(&esc), false),
    ));
    cases.push(plain_case(
        "json-004",
        "no items",
        "export.plain.json",
        &[],
        false,
        json(&[], false),
    ));
    cases.push(plain_case(
        "json-005",
        "unknown fields come out after the known ones",
        "export.plain.json",
        &two,
        false,
        json(&two, false),
    ));

    // A body of a newer schema is written as it was read, never rebuilt: the
    // mistyped known keys (`name`, `fields`) stay where they were, once. A
    // `passkey` that is not a map has no secret keys to remove, so without
    // the option the whole key is left out.
    let newer = |with_passkey: bool| {
        let mut e: Vec<(&str, Vec<u8>)> = vec![
            ("zzz-first", cb::uint(7)),
            ("schema", cb::uint(2)),
            ("type", cb::text("login")),
            ("name", cb::uint(5)),
            ("fields", cb::text("not a list")),
            ("urls", cb::array(&[])),
        ];
        if with_passkey {
            e.push((
                "passkey",
                cb::array(&[cb::map(&[("priv", cb::bytes(&[0xe3, 0xe3]))])]),
            ));
        }
        e.extend([
            ("created", cb::uint(1)),
            ("modified", cb::uint(2)),
            ("favorite", cb::boolean(false)),
        ]);
        cb::map(&e)
    };
    let newer_id = [0x72u8; 16];
    let newer_case = |name: &str, title: &str, with_passkey: bool, include: bool, body: &str| {
        valid_case(
            &format!("export/plain/{name}"),
            title,
            "export.plain.json",
            vec![],
            json!({
                "items": [ { "id": hex_encode(&newer_id), "body": hex_encode(&newer(with_passkey)) } ],
                "include_passkeys": include,
            }),
            json!({ "text": format!("{{\"v\":1,\"items\":[{{\"id\":\"{}\",\"body\":{body}}}]}}", hex_encode(&newer_id)) }),
        )
    };
    cases.push(newer_case(
        "json-006",
        "a body of schema 2 with mistyped known keys is written as it was read",
        false,
        false,
        r#"{"zzz-first":7,"schema":2,"type":"login","name":5,"fields":"not a list","urls":[],"created":1,"modified":2,"favorite":false}"#,
    ));
    cases.push(newer_case(
        "json-007",
        "a passkey of a newer schema that is not a map is left out by default",
        true,
        false,
        r#"{"zzz-first":7,"schema":2,"type":"login","name":5,"fields":"not a list","urls":[],"created":1,"modified":2,"favorite":false}"#,
    ));
    cases.push(newer_case(
        "json-008",
        "and kept when the passkey secrets are asked for",
        true,
        true,
        r#"{"zzz-first":7,"schema":2,"type":"login","name":5,"fields":"not a list","urls":[],"passkey":[{"priv":"e3e3"}],"created":1,"modified":2,"favorite":false}"#,
    ));

    file("export", "Fase 1 § 6.4 (F-27) and plan U15, U18", cases)
}
