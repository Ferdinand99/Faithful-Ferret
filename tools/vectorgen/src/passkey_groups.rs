//! The vector group for the passkey authenticator (`passkey.json`).
//!
//! Expected values are built here from the specifications, not by calling the
//! core: `authenticatorData` and the COSE key are written byte by byte
//! (WebAuthn L3 § 6.1, RFC 9052), `clientDataJSON` as a format string (the
//! challenge and origin used here need no escaping; the escaping is tested
//! separately), the PKCS#8 and SPKI wrappers as fixed DER prefixes, and the
//! PRF outputs with the HMAC wrapper from the primitive tests. The public key
//! comes from `p256` and the ES256 signature from `p256` with the
//! deterministic nonce of RFC 6979, so the file does not depend on a random
//! draw; the signature is verified in the tests by `p256`'s verifier, which
//! also passes the Wycheproof file.
//!
//! Ops (see `vectors/OPS.md`): `passkey.create`, `passkey.get`, `passkey.prf`.

use crate::groups::{generator, invalid_case, valid_case};
use crate::{Error, render};
use ferret_core::testing::hex_encode;
use ferret_core::testing::prim::hmac_sha256;
use ferret_core::testing::vector::{Case, VectorFile};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The AAGUID of Ferret, `dc704a44-b994-410c-a689-ed8d71a84ac3`.
const AAGUID: &str = "dc704a44b994410ca689ed8d71a84ac3";

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

fn pat(start: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| start.wrapping_add(u8::try_from(i % 251).unwrap_or(0)))
        .collect()
}

fn hex(b: &[u8]) -> String {
    hex_encode(b)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A key pair from a scalar: `(d, x, y)`.
struct Pair {
    d: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

fn pair(d: Vec<u8>) -> Result<Pair, Error> {
    let key = SigningKey::from_slice(&d).map_err(|e| format!("scalar: {e}"))?;
    let point = key.verifying_key().to_sec1_point(false);
    let x = point.x().ok_or("no x")?.to_vec();
    let y = point.y().ok_or("no y")?.to_vec();
    Ok(Pair { d, x, y })
}

/// PKCS#8 `PrivateKeyInfo` of a P-256 key with the public key included
/// (RFC 5958, RFC 5915): 138 bytes.
fn pkcs8(p: &Pair) -> Vec<u8> {
    let mut out =
        hex_to_bytes("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420");
    out.extend_from_slice(&p.d);
    out.extend_from_slice(&hex_to_bytes("a14403420004"));
    out.extend_from_slice(&p.x);
    out.extend_from_slice(&p.y);
    out
}

/// SubjectPublicKeyInfo of an uncompressed P-256 point: 91 bytes.
fn spki(p: &Pair) -> Vec<u8> {
    let mut out = hex_to_bytes("3059301306072a8648ce3d020106082a8648ce3d03010703420004");
    out.extend_from_slice(&p.x);
    out.extend_from_slice(&p.y);
    out
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    ferret_core::testing::hex_decode(s).unwrap_or_default()
}

/// `a5 01 02 03 26 20 01 21 5820 x 22 5820 y`.
fn cose_key(p: &Pair) -> Vec<u8> {
    let mut out = hex_to_bytes("a5010203262001215820");
    out.extend_from_slice(&p.x);
    out.extend_from_slice(&hex_to_bytes("225820"));
    out.extend_from_slice(&p.y);
    out
}

fn bstr_head(len: usize) -> Vec<u8> {
    if len < 24 {
        vec![0x40 | u8::try_from(len).unwrap_or(0)]
    } else if len < 256 {
        vec![0x58, u8::try_from(len).unwrap_or(0)]
    } else {
        let mut v = vec![0x59];
        v.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_be_bytes());
        v
    }
}

fn attestation_object(auth: &[u8]) -> Vec<u8> {
    // {"fmt": "none", "attStmt": {}, "authData": h'..'}
    let mut out = hex_to_bytes("a363666d74646e6f6e656761747453746d74a0686175746844617461");
    out.extend_from_slice(&bstr_head(auth.len()));
    out.extend_from_slice(auth);
    out
}

fn client_data(kind: &str, challenge: &[u8], origin: &str) -> String {
    let b64 = base64url(challenge);
    format!(
        "{{\"type\":\"webauthn.{kind}\",\"challenge\":\"{b64}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}"
    )
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for byte in b {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(char::from(A[((acc >> bits) & 63) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(A[((acc << (6 - bits)) & 63) as usize]));
    }
    out
}

fn prf_out(seed: &[u8], input: &[u8]) -> Result<Vec<u8>, Error> {
    let salt = sha256(&[b"WebAuthn PRF", &[0u8], input]);
    Ok(hmac_sha256(seed, &salt)
        .map_err(|e| format!("hmac: {e}"))?
        .to_vec())
}

fn sign(p: &Pair, auth: &[u8], client_data_json: &str) -> Result<Vec<u8>, Error> {
    let key = SigningKey::from_slice(&p.d).map_err(|e| format!("scalar: {e}"))?;
    let mut msg = auth.to_vec();
    msg.extend_from_slice(&sha256(&[client_data_json.as_bytes()]));
    let sig: p256::ecdsa::Signature = key.try_sign(&msg).map_err(|e| format!("sign: {e}"))?;
    Ok(sig.to_der().as_bytes().to_vec())
}

// ------------------------------------------------------------- requests

#[derive(Clone)]
struct Uv {
    present: bool,
    verified: bool,
}

const UV_YES: Uv = Uv {
    present: true,
    verified: true,
};
const UV_NO: Uv = Uv {
    present: true,
    verified: false,
};

fn uv_json(u: &Uv) -> Value {
    json!({ "user_present": u.present, "user_verified": u.verified })
}

#[derive(Clone)]
struct Eval {
    first: Vec<u8>,
    second: Option<Vec<u8>>,
}

fn eval_json(e: &Eval) -> Value {
    json!({ "first": hex(&e.first), "second": e.second.as_ref().map(|s| hex(s)) })
}

#[derive(Clone)]
struct Create {
    origin: &'static str,
    same_top: bool,
    challenge: Vec<u8>,
    rp_id: Option<&'static str>,
    user_id: Vec<u8>,
    algorithms: Vec<i64>,
    exclude: Vec<Vec<u8>>,
    /// `(rp_id, credential id)` of the passkeys already stored.
    existing: Vec<(&'static str, Vec<u8>)>,
    uv_req: &'static str,
    prf: Option<Option<Eval>>,
    uv: Uv,
}

impl Create {
    fn new(origin: &'static str) -> Self {
        Self {
            origin,
            same_top: true,
            challenge: pat(0x40, 32),
            rp_id: None,
            user_id: pat(0x70, 16),
            algorithms: vec![-7, -257],
            exclude: vec![],
            existing: vec![],
            uv_req: "preferred",
            prf: None,
            uv: UV_YES,
        }
    }

    fn input(&self) -> Value {
        json!({
            "origin": self.origin,
            "top_origin_is_same": self.same_top,
            "request": {
                "challenge": hex(&self.challenge),
                "rp_id": self.rp_id,
                "rp_name": "Example",
                "user_id": hex(&self.user_id),
                "user_name": "alice@example.com",
                "user_display_name": "Alice",
                "algorithms": self.algorithms,
                "exclude": self.exclude.iter().map(|e| hex(e)).collect::<Vec<_>>(),
                "user_verification": self.uv_req,
                "prf": self.prf.as_ref().map(|p| json!({ "eval": p.as_ref().map(eval_json) })),
            },
            "uv": uv_json(&self.uv),
            "existing_credentials": self.existing.iter().map(|(rp, id)| json!({ "rp_id": rp, "id": hex(id) })).collect::<Vec<_>>(),
            "created_ms": "1700000000000",
        })
    }
}

const CRED_ID_START: u8 = 0xa0;
const SCALAR_START: u8 = 0x11;
const SEED_UV_START: u8 = 0x31;
const SEED_NOUV_START: u8 = 0x51;
const CREATED: &str = "1700000000000";

fn create_rng(with_prf: bool) -> Vec<String> {
    let mut v = vec![hex(&pat(CRED_ID_START, 32)), hex(&pat(SCALAR_START, 32))];
    if with_prf {
        v.push(hex(&pat(SEED_UV_START, 32)));
        v.push(hex(&pat(SEED_NOUV_START, 32)));
    }
    v
}

fn valid_create(id: &str, title: &str, c: &Create, rp_id: &str) -> Result<Case, Error> {
    let with_prf = c.prf.is_some();
    let p = pair(pat(SCALAR_START, 32))?;
    let cred_id = pat(CRED_ID_START, 32);
    let mut flags = UP | BE | BS | AT;
    if c.uv.verified {
        flags |= UV;
    }
    if with_prf {
        flags |= ED;
    }
    let cose = cose_key(&p);
    let mut auth = sha256(&[rp_id.as_bytes()]).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&[0, 0, 0, 0]);
    auth.extend_from_slice(&hex_to_bytes(AAGUID));
    auth.extend_from_slice(&[0, 32]);
    auth.extend_from_slice(&cred_id);
    auth.extend_from_slice(&cose);
    if with_prf {
        // {"hmac-secret": true}
        auth.extend_from_slice(&hex_to_bytes("a16b686d61632d736563726574f5"));
    }
    let cdj = client_data("create", &c.challenge, c.origin);
    let seed_uv = pat(SEED_UV_START, 32);
    let seed_nouv = pat(SEED_NOUV_START, 32);
    let prf = match &c.prf {
        None => Value::Null,
        Some(eval) => {
            let seed = if c.uv.verified { &seed_uv } else { &seed_nouv };
            match eval {
                None => json!({ "enabled": true, "first": null, "second": null }),
                Some(e) => json!({
                    "enabled": true,
                    "first": hex(&prf_out(seed, &e.first)?),
                    "second": match &e.second { Some(s) => Value::from(hex(&prf_out(seed, s)?)), None => Value::Null },
                }),
            }
        }
    };
    let expect = json!({
        "record": {
            "cred_id": hex(&cred_id),
            "rp_id": rp_id,
            "user_handle": hex(&c.user_id),
            "user_name": "alice@example.com",
            "created": CREATED,
            "private_scalar": hex(&p.d),
            "priv_pkcs8": hex(&pkcs8(&p)),
            "prf_seed_uv": if with_prf { Value::from(hex(&seed_uv)) } else { Value::Null },
            "prf_seed_nouv": if with_prf { Value::from(hex(&seed_nouv)) } else { Value::Null },
        },
        "response": {
            "id": hex(&cred_id),
            "attestation_object": hex(&attestation_object(&auth)),
            "client_data_json": cdj,
            "authenticator_data": hex(&auth),
            "public_key_spki": hex(&spki(&p)),
            "alg": -7,
            "prf": prf,
        },
    });
    let mut case = valid_case(id, title, "passkey.create", vec![], c.input(), expect);
    case.rng = create_rng(with_prf);
    case.intermediate = Some(json!({ "flags": flags, "cose_key": hex(&cose) }));
    Ok(case)
}

/// A request that is refused before anything is drawn, so `rng` is empty.
fn invalid_create(id: &str, title: &str, c: &Create, code: &str) -> Case {
    invalid_case(id, title, "passkey.create", vec![], c.input(), code)
}

// ------------------------------------------------------------------ get

#[derive(Clone)]
struct StoredRecord {
    rp_id: &'static str,
    cred_id: Vec<u8>,
    scalar: Vec<u8>,
    seeds: bool,
}

impl StoredRecord {
    fn standard(rp_id: &'static str) -> Self {
        Self {
            rp_id,
            cred_id: pat(CRED_ID_START, 32),
            scalar: pat(SCALAR_START, 32),
            seeds: true,
        }
    }

    fn pair(&self) -> Result<Pair, Error> {
        pair(self.scalar.clone())
    }

    fn json(&self) -> Result<Value, Error> {
        let p = self.pair()?;
        Ok(json!({
            "cred_id": hex(&self.cred_id),
            "rp_id": self.rp_id,
            "user_handle": hex(&pat(0x70, 16)),
            "user_name": "alice@example.com",
            "created": CREATED,
            "priv_pkcs8": hex(&pkcs8(&p)),
            "prf_seed_uv": if self.seeds { Value::from(hex(&pat(SEED_UV_START, 32))) } else { Value::Null },
            "prf_seed_nouv": if self.seeds { Value::from(hex(&pat(SEED_NOUV_START, 32))) } else { Value::Null },
        }))
    }
}

/// `(eval, evalByCredential)`.
type GetPrf = (Option<Eval>, Vec<(Vec<u8>, Eval)>);

#[derive(Clone)]
struct Get {
    origin: &'static str,
    same_top: bool,
    challenge: Vec<u8>,
    rp_id: Option<&'static str>,
    allow: Vec<Vec<u8>>,
    uv_req: &'static str,
    /// `(eval, evalByCredential)`.
    prf: Option<GetPrf>,
    uv: Uv,
}

impl Get {
    fn new(origin: &'static str) -> Self {
        Self {
            origin,
            same_top: true,
            challenge: pat(0x90, 32),
            rp_id: None,
            allow: vec![],
            uv_req: "preferred",
            prf: None,
            uv: UV_YES,
        }
    }

    fn input(&self, rec: &StoredRecord) -> Result<Value, Error> {
        Ok(json!({
            "origin": self.origin,
            "top_origin_is_same": self.same_top,
            "record": rec.json()?,
            "request": {
                "challenge": hex(&self.challenge),
                "rp_id": self.rp_id,
                "allow": self.allow.iter().map(|a| hex(a)).collect::<Vec<_>>(),
                "user_verification": self.uv_req,
                "prf": self.prf.as_ref().map(|(eval, by_cred)| json!({
                    "eval": eval.as_ref().map(eval_json),
                    "eval_by_credential": by_cred.iter().map(|(id, e)| {
                        let mut v = eval_json(e);
                        v["id"] = Value::from(hex(id));
                        v
                    }).collect::<Vec<_>>(),
                })),
            },
            "uv": uv_json(&self.uv),
        }))
    }
}

fn valid_get(id: &str, title: &str, g: &Get, rec: &StoredRecord) -> Result<Case, Error> {
    let p = rec.pair()?;
    let mut flags = UP | BE | BS;
    if g.uv.verified {
        flags |= UV;
    }
    let mut auth = sha256(&[rec.rp_id.as_bytes()]).to_vec();
    auth.push(flags);
    auth.extend_from_slice(&[0, 0, 0, 0]);
    let cdj = client_data("get", &g.challenge, g.origin);
    let signature = sign(&p, &auth, &cdj)?;
    let seed_uv = pat(SEED_UV_START, 32);
    let seed_nouv = pat(SEED_NOUV_START, 32);
    let seed = if g.uv.verified { seed_uv } else { seed_nouv };
    let chosen = g.prf.as_ref().and_then(|(eval, by_cred)| {
        by_cred
            .iter()
            .find(|(i, _)| *i == rec.cred_id)
            .map(|(_, e)| e)
            .or(eval.as_ref())
    });
    let prf = match (chosen, rec.seeds) {
        (Some(e), true) => json!({
            "first": hex(&prf_out(&seed, &e.first)?),
            "second": match &e.second { Some(s) => Value::from(hex(&prf_out(&seed, s)?)), None => Value::Null },
        }),
        _ => Value::Null,
    };
    let expect = json!({
        "id": hex(&rec.cred_id),
        "authenticator_data": hex(&auth),
        "client_data_json": cdj,
        "signature": hex(&signature),
        "user_handle": hex(&pat(0x70, 16)),
        "prf": prf,
    });
    let mut case = valid_case(id, title, "passkey.get", vec![], g.input(rec)?, expect);
    case.intermediate = Some(json!({ "flags": flags }));
    Ok(case)
}

fn invalid_get(
    id: &str,
    title: &str,
    g: &Get,
    rec: &StoredRecord,
    code: &str,
) -> Result<Case, Error> {
    Ok(invalid_case(
        id,
        title,
        "passkey.get",
        vec![],
        g.input(rec)?,
        code,
    ))
}

// ------------------------------------------------------------------ prf

fn prf_case(
    id: &str,
    title: &str,
    seed: Vec<u8>,
    input: Value,
    bytes: &[u8],
) -> Result<Case, Error> {
    Ok(valid_case(
        id,
        title,
        "passkey.prf",
        vec![],
        json!({ "seed": hex(&seed), "input": input }),
        json!({
            "salt": hex(&sha256(&[b"WebAuthn PRF", &[0u8], bytes])),
            "output": hex(&prf_out(&seed, bytes)?),
        }),
    ))
}

pub(crate) fn passkey() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let base = "https://example.com";

    // ---- create, valid
    let c = Create::new(base);
    cases.push(valid_create(
        "passkey/create/valid/001",
        "create with UV, no prf",
        &c,
        "example.com",
    )?);
    let mut c = Create::new(base);
    c.uv = UV_NO;
    cases.push(valid_create(
        "passkey/create/valid/002",
        "create without UV when UV is only preferred: the UV flag is clear",
        &c,
        "example.com",
    )?);
    let mut c = Create::new(base);
    c.prf = Some(None);
    cases.push(valid_create(
        "passkey/create/valid/003",
        "create with prf and no eval: ED and hmac-secret, two seeds, enabled",
        &c,
        "example.com",
    )?);
    let mut c = Create::new(base);
    c.prf = Some(Some(Eval {
        first: pat(0xc0, 8),
        second: None,
    }));
    cases.push(valid_create(
        "passkey/create/valid/004",
        "create with prf eval.first and UV: output from the UV seed",
        &c,
        "example.com",
    )?);
    let mut c = Create::new(base);
    c.uv = UV_NO;
    c.prf = Some(Some(Eval {
        first: pat(0xc0, 8),
        second: Some(vec![]),
    }));
    cases.push(valid_create(
        "passkey/create/valid/005",
        "create with prf eval first and second (empty) without UV: output from the no-UV seed",
        &c,
        "example.com",
    )?);
    let mut c = Create::new("https://login.example.com");
    c.rp_id = Some("example.com");
    c.uv_req = "required";
    cases.push(valid_create(
        "passkey/create/valid/006",
        "create for a parent domain of the origin, UV required and done",
        &c,
        "example.com",
    )?);
    let mut c = Create::new("https://xn--bcher-kva.example:8443");
    c.challenge = pat(0, 48);
    cases.push(valid_create(
        "passkey/create/valid/007",
        "create from an IDN origin with a port (the origin keeps the port, the RP ID has none)",
        &c,
        "xn--bcher-kva.example",
    )?);

    let mut c = Create::new(base);
    c.exclude = vec![pat(1, 32), pat(2, 32)];
    c.existing = vec![("other.example", pat(2, 32))];
    cases.push(valid_create(
        "passkey/create/valid/008",
        "an excluded id stored for another RP ID does not count",
        &c,
        "example.com",
    )?);

    // ---- create, invalid
    let mut c = Create::new(base);
    c.uv = UV_NO;
    c.uv_req = "required";
    cases.push(invalid_create(
        "passkey/create/invalid/001",
        "UV required but not done: NotAllowed",
        &c,
        "not_allowed",
    ));
    let mut c = Create::new(base);
    c.same_top = false;
    cases.push(invalid_create(
        "passkey/create/invalid/002",
        "cross-origin frame: NotAllowed",
        &c,
        "not_allowed",
    ));
    let mut c = Create::new(base);
    c.exclude = vec![pat(1, 32), pat(2, 32)];
    c.existing = vec![("example.com", pat(9, 32)), ("example.com", pat(2, 32))];
    cases.push(invalid_create(
        "passkey/create/invalid/003",
        "a credential in excludeCredentials is stored for this RP ID: InvalidStateError",
        &c,
        "invalid_state",
    ));
    let mut c = Create::new("https://a.github.io");
    c.rp_id = Some("github.io");
    cases.push(invalid_create(
        "passkey/create/invalid/004",
        "RP ID is a public suffix (private domain)",
        &c,
        "malformed_rp_id",
    ));
    let mut c = Create::new(base);
    c.challenge = vec![0x55; 1025];
    cases.push(invalid_create(
        "passkey/create/invalid/005",
        "challenge of 1 025 bytes",
        &c,
        "too_large",
    ));
    let mut c = Create::new(base);
    c.user_id = vec![];
    cases.push(invalid_create(
        "passkey/create/invalid/006",
        "user handle of 0 bytes",
        &c,
        "malformed_webauthn_options",
    ));
    let mut c = Create::new(base);
    c.uv = Uv {
        present: false,
        verified: false,
    };
    cases.push(invalid_create(
        "passkey/create/invalid/007",
        "no user presence: NotAllowed",
        &c,
        "not_allowed",
    ));
    let mut c = Create::new(base);
    c.algorithms = vec![-257];
    cases.push(invalid_create(
        "passkey/create/invalid/008",
        "no ES256 among the algorithms",
        &c,
        "unsupported",
    ));
    let mut c = Create::new(base);
    c.exclude = vec![pat(1, 32); 201];
    cases.push(invalid_create(
        "passkey/create/invalid/009",
        "201 excludeCredentials",
        &c,
        "too_large",
    ));

    // ---- get, valid
    let rec = StoredRecord::standard("example.com");
    let g = Get::new(base);
    cases.push(valid_get(
        "passkey/get/valid/001",
        "get with UV, no prf",
        &g,
        &rec,
    )?);
    let mut g = Get::new(base);
    g.uv = UV_NO;
    g.uv_req = "discouraged";
    cases.push(valid_get(
        "passkey/get/valid/002",
        "get without UV when UV is discouraged: the UV flag is clear",
        &g,
        &rec,
    )?);
    let mut g = Get::new(base);
    g.prf = Some((
        Some(Eval {
            first: pat(0xc0, 8),
            second: Some(pat(0xd0, 40)),
        }),
        vec![],
    ));
    cases.push(valid_get(
        "passkey/get/valid/003",
        "get with prf eval first and second and UV",
        &g,
        &rec,
    )?);
    g.uv = UV_NO;
    cases.push(valid_get(
        "passkey/get/valid/004",
        "the same prf input without UV gives different outputs (other seed)",
        &g,
        &rec,
    )?);
    let mut g = Get::new(base);
    g.allow = vec![pat(7, 32), rec.cred_id.clone()];
    g.prf = Some((
        Some(Eval {
            first: pat(0xc0, 8),
            second: None,
        }),
        vec![(
            rec.cred_id.clone(),
            Eval {
                first: pat(0xe0, 8),
                second: None,
            },
        )],
    ));
    cases.push(valid_get(
        "passkey/get/valid/005",
        "evalByCredential wins over eval for the credential in use",
        &g,
        &rec,
    )?);
    let mut rec_no_prf = rec.clone();
    rec_no_prf.seeds = false;
    let mut g = Get::new(base);
    g.prf = Some((
        Some(Eval {
            first: pat(0xc0, 8),
            second: None,
        }),
        vec![],
    ));
    cases.push(valid_get(
        "passkey/get/valid/006",
        "prf asked for but the passkey was made without prf: no results",
        &g,
        &rec_no_prf,
    )?);
    let mut g = Get::new("https://login.example.com");
    g.rp_id = Some("example.com");
    g.uv_req = "required";
    cases.push(valid_get(
        "passkey/get/valid/007",
        "get from a subdomain with the exact stored RP ID, UV required and done",
        &g,
        &rec,
    )?);

    // ---- get, invalid
    let g = Get::new("https://sub.example.com");
    cases.push(invalid_get(
        "passkey/get/invalid/001",
        "stored example.com, requested sub.example.com: NotAllowed",
        &g,
        &rec,
        "not_allowed",
    )?);
    let mut g = Get::new(base);
    g.uv = UV_NO;
    g.uv_req = "required";
    cases.push(invalid_get(
        "passkey/get/invalid/002",
        "UV required but not done: NotAllowed",
        &g,
        &rec,
        "not_allowed",
    )?);
    let mut g = Get::new(base);
    g.allow = vec![pat(7, 32)];
    cases.push(invalid_get(
        "passkey/get/invalid/003",
        "the credential is not in allowCredentials: NotAllowed",
        &g,
        &rec,
        "not_allowed",
    )?);
    let mut g = Get::new(base);
    g.prf = Some((
        None,
        vec![(
            rec.cred_id.clone(),
            Eval {
                first: pat(1, 4),
                second: None,
            },
        )],
    ));
    cases.push(invalid_get(
        "passkey/get/invalid/004",
        "evalByCredential without allowCredentials: NotSupported",
        &g,
        &rec,
        "unsupported",
    )?);
    let mut g = Get::new(base);
    g.allow = vec![rec.cred_id.clone()];
    g.prf = Some((
        None,
        vec![(
            pat(7, 32),
            Eval {
                first: pat(1, 4),
                second: None,
            },
        )],
    ));
    cases.push(invalid_get(
        "passkey/get/invalid/005",
        "evalByCredential names a credential that is not allowed: SyntaxError",
        &g,
        &rec,
        "malformed_webauthn_options",
    )?);
    let mut g = Get::new(base);
    g.same_top = false;
    cases.push(invalid_get(
        "passkey/get/invalid/006",
        "cross-origin frame: NotAllowed",
        &g,
        &rec,
        "not_allowed",
    )?);
    let mut g = Get::new(base);
    g.rp_id = Some("com");
    cases.push(invalid_get(
        "passkey/get/invalid/007",
        "RP ID is a public suffix",
        &g,
        &rec,
        "malformed_rp_id",
    )?);

    // ---- prf
    let seed = pat(SEED_UV_START, 32);
    cases.push(prf_case(
        "passkey/prf/valid/001",
        "prf output for an empty input",
        seed.clone(),
        json!({ "segments": [] }),
        &[],
    )?);
    cases.push(prf_case(
        "passkey/prf/valid/002",
        "prf output for a 32-byte input",
        seed.clone(),
        json!({ "segments": [ { "hex": hex(&pat(0, 32)), "repeat": 1 } ] }),
        &pat(0, 32),
    )?);
    cases.push(prf_case(
        "passkey/prf/valid/003",
        "prf output for a 1 024-byte input",
        pat(SEED_NOUV_START, 32),
        json!({ "segments": [ { "hex": "ab", "repeat": 1024 } ] }),
        &[0xab; 1024],
    )?);

    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "passkey".into(),
        suite: 1,
        spec: "Fase 1 § 9".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}
