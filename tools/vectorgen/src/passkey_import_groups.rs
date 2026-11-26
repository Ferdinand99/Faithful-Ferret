//! The vector group for the import of a passkey (`passkey_import.json`).
//!
//! Op (see `vectors/OPS.md`): `passkey.import`. The expected values are built
//! here from the formats and not by calling the core: the stored PKCS#8 is the
//! fixed DER prefix of RFC 5958 and RFC 5915 with the scalar and the public
//! point (the scalar is known to the generator, which makes the keys from a
//! pattern or takes it from the exported test files), the SubjectPublicKeyInfo
//! is a fixed prefix and the point, and the texts are cleaned by the list of
//! code points written out in `passkey_groups`.
//!
//! The first cases use keys and values taken from exports of throwaway test
//! keys in the formats of Bitwarden (PKCS#8, GUID and `b64.` credential ids)
//! and AliasVault (JWK, PRF key); the others are made from patterns.

use crate::groups::{generator, invalid_case, valid_case};
use crate::passkey_groups::{
    Pair, base64url, hex, hex_to_bytes, pair, pat, pkcs8, spki, stored_text, without_controls,
};
use crate::{Error, render};
use ferret_core::testing::vector::{Case, VectorFile};
use serde_json::{Value, json};

/// How the key is given.
#[derive(Clone)]
enum Key {
    Pkcs8(Vec<u8>),
    Jwk(String),
}

#[derive(Clone)]
struct Seeds {
    uv: Vec<u8>,
    nouv: Vec<u8>,
}

/// One import: the input and, for a valid case, the key it should become.
#[derive(Clone)]
struct Import {
    cred_id: Vec<u8>,
    rp_id: String,
    user_handle: Vec<u8>,
    user_name: String,
    rp_name: Option<String>,
    display_name: Option<String>,
    created: String,
    key: Key,
    prf: Option<Seeds>,
    counter: u32,
}

impl Import {
    fn new(key: Key) -> Self {
        Self {
            cred_id: pat(0xa0, 32),
            rp_id: "example.com".into(),
            user_handle: pat(0x70, 16),
            user_name: "alice@example.com".into(),
            rp_name: Some("Example".into()),
            display_name: Some("Alice".into()),
            created: "1700000000000".into(),
            key,
            prf: None,
            counter: 0,
        }
    }

    fn input(&self) -> Value {
        let key = match &self.key {
            Key::Pkcs8(der) => json!({ "format": "pkcs8", "hex": hex(der) }),
            Key::Jwk(text) => json!({ "format": "jwk", "text": text }),
        };
        json!({
            "cred_id": hex(&self.cred_id),
            "rp_id": self.rp_id,
            "user_handle": hex(&self.user_handle),
            "user_name": self.user_name,
            "rp_name": self.rp_name,
            "user_display_name": self.display_name,
            "created": self.created,
            "key": key,
            "prf": self.prf.as_ref().map(|s| json!({ "uv": hex(&s.uv), "nouv": hex(&s.nouv) })),
            "counter": self.counter,
        })
    }
}

/// The scalar of a key.
fn d_of(hex_text: &str) -> Vec<u8> {
    hex_to_bytes(hex_text)
}

/// The PKCS#8 of a pair with the public key left out (RFC 5915 makes it
/// optional): 67 bytes.
fn pkcs8_short(p: &Pair) -> Vec<u8> {
    let mut out =
        hex_to_bytes("3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420");
    out.extend_from_slice(&p.d);
    out
}

/// The PKCS#8 of a pair with the curve repeated in the `ECPrivateKey`
/// (`parameters [0]`, as OpenSSL writes it): 138 + 12 bytes.
fn pkcs8_with_params(p: &Pair) -> Vec<u8> {
    let mut out =
        hex_to_bytes("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420");
    out.extend_from_slice(&p.d);
    out.extend_from_slice(&hex_to_bytes("a00a06082a8648ce3d030107a14403420004"));
    out.extend_from_slice(&p.x);
    out.extend_from_slice(&p.y);
    out
}

/// A JWK as AliasVault writes it, or without the public part.
fn jwk(p: &Pair, with_public: bool) -> String {
    if with_public {
        format!(
            "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\",\"d\":\"{}\"}}",
            base64url(&p.x),
            base64url(&p.y),
            base64url(&p.d)
        )
    } else {
        format!(
            "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"d\":\"{}\"}}",
            base64url(&p.d)
        )
    }
}

fn opt_text(v: &Option<String>) -> Value {
    v.as_deref().map_or(Value::Null, stored_text)
}

/// A valid import: the expected record is built from `d` (the scalar the key
/// has, however it is written in `key`).
fn valid(id: &str, title: &str, i: &Import, d: &[u8]) -> Result<Case, Error> {
    let p = pair(d.to_vec())?;
    let seed = |s: &Option<Seeds>, uv: bool| {
        s.as_ref().map_or(Value::Null, |s| {
            Value::from(hex(if uv { &s.uv } else { &s.nouv }))
        })
    };
    let expect = json!({
        "record": {
            "cred_id": hex(&i.cred_id),
            "rp_id": i.expected_rp(),
            "user_handle": hex(&i.user_handle),
            "user_name": without_controls(&i.user_name),
            "rp_name": opt_text(&i.rp_name),
            "user_display_name": opt_text(&i.display_name),
            "created": i.created,
            "priv_pkcs8": hex(&pkcs8(&p)),
            "public_key_spki": hex(&spki(&p)),
            "prf_seed_uv": seed(&i.prf, true),
            "prf_seed_nouv": seed(&i.prf, false),
        },
        "notes": {
            "register_again": i.counter > 0,
            "counter": i.counter,
            "prf": i.prf.is_some(),
        },
    });
    Ok(valid_case(
        &format!("passkey_import/valid/{id}"),
        title,
        "passkey.import",
        vec![],
        i.input(),
        expect,
    ))
}

fn invalid(id: &str, title: &str, i: &Import, code: &str) -> Case {
    invalid_case(
        &format!("passkey_import/invalid/{id}"),
        title,
        "passkey.import",
        vec![],
        i.input(),
        code,
    )
}

impl Import {
    /// The RP ID as the expected record has it: the one written in the case
    /// is already canonical unless the case says what it should become.
    fn expected_rp(&self) -> String {
        match self.rp_id.as_str() {
            "Example.COM." => "example.com".into(),
            "B\u{dc}CHER.Example" => "xn--bcher-kva.example".into(),
            "b\u{fc}cher.example" => "xn--bcher-kva.example".into(),
            "Login.Example.CO.UK" => "login.example.co.uk".into(),
            other => other.into(),
        }
    }
}

const BAD_KEY: &str = "malformed_item_body";

pub(crate) fn passkey_import() -> Result<Vec<u8>, Error> {
    let mut cases: Vec<Case> = Vec::new();
    let site = "rp-a.test";

    // ---- real exports: Bitwarden (PKCS#8), Firefox WebCrypto, AliasVault (JWK)
    let bw1 = hex_to_bytes(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420bc29e38fef80dd5b5b456eeef7f8e3916770550baeece1c45d7f920888db5003a14403420004274008d95e7f240cd256798768569d136b3a75f9ed9dc0222386eb1336fcb223400ae22f7539b40e3ef8935413a5511533059bbc92081541f2191e616e68ee6f",
    );
    let mut i = Import::new(Key::Pkcs8(bw1));
    i.rp_id = site.into();
    i.cred_id = hex_to_bytes("a1bc3321a9e5434a8c236600066cc911");
    i.user_handle = hex_to_bytes("ecb8a0cce4034a4393ff2afeddedcdf7");
    i.user_name = "import-test-1@rp-a.test".into();
    i.rp_name = Some("RP A (test)".into());
    i.display_name = Some("Import Test 1".into());
    cases.push(valid(
        "001",
        "Bitwarden PKCS#8, credential id from a GUID",
        &i,
        &d_of("bc29e38fef80dd5b5b456eeef7f8e3916770550baeece1c45d7f920888db5003"),
    )?);

    let bw2 = hex_to_bytes(
        "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420845df421ca594810931a270ae86aad3973c3679396be4d6cab25412233e67257a14403420004b126ca40d3992ad4250df0111dc5617938ccabbe36782af04ec2e5e2e6439378434cb0fa6882a9bad683c189d5a44f8b5bc1f7b7e0d465eee858e979428768a0",
    );
    let mut i = Import::new(Key::Pkcs8(bw2));
    i.rp_id = site.into();
    i.cred_id = hex_to_bytes("ac6efea58e8231ad22372c60740f62c4057ed7b87ec679cfb1253c25c83a3c4b");
    i.user_handle = hex_to_bytes("ec5a74b003819f004b636b562b7b6321");
    i.counter = 7;
    cases.push(valid(
        "002",
        "Bitwarden PKCS#8, credential id of another length (b64.), counter 7: register again",
        &i,
        &d_of("845df421ca594810931a270ae86aad3973c3679396be4d6cab25412233e67257"),
    )?);

    for (n, der, d) in [
        (
            "003",
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042090f17f913e911470d7dc4219a12191fc3864cfffce9aa06d756ebb8df465ef4ea14403420004b501ea53ec438e49d1c732b8ab4262d4337beba8814aeb83132006bbe434d3624e708c3bc791026917aebf37d844c055e0182eda58e026b9b846c90c00744882",
            "90f17f913e911470d7dc4219a12191fc3864cfffce9aa06d756ebb8df465ef4e",
        ),
        (
            "004",
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420ae2bbff0d26f967877004e7b3036e598e43863ee26c08101faf633d07a21386ba1440342000485ec23f41abf2e0ea079252ed3ec999ba879fce9868d510431fd2ce39fd80c71f158b6c471f7bb67a421a11652fea3aa8621c5dc98013a20da5a224a0c8ec081",
            "ae2bbff0d26f967877004e7b3036e598e43863ee26c08101faf633d07a21386b",
        ),
    ] {
        let mut i = Import::new(Key::Pkcs8(hex_to_bytes(der)));
        i.rp_id = site.into();
        cases.push(valid(
            n,
            "PKCS#8 that a browser's WebCrypto exported (the Bitwarden browser path)",
            &i,
            &d_of(d),
        )?);
    }

    let av1 = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"o1ZO_uWIYpHOZUTIGGmUxaBuGinN03mhCfTYFevyJAM\",\"y\":\"7-O7yU26PtMbZKpR9em2_iBxVi9uig8BFuUmCsVTKW4\",\"d\":\"_TJYBPqMLIHOm_jND70ADCzB6ud_HXAB-bz53gOnVOo\"}";
    let mut i = Import::new(Key::Jwk(av1.into()));
    i.rp_id = site.into();
    i.cred_id = hex_to_bytes("4191c49b05d44b2c9bd94fecaf23c834");
    i.user_handle = hex_to_bytes("01acb91b719b58f9c0b508d15418c723");
    cases.push(valid(
        "005",
        "AliasVault JWK, no PRF, credential id from the GUID",
        &i,
        &base64url_decode("_TJYBPqMLIHOm_jND70ADCzB6ud_HXAB-bz53gOnVOo"),
    )?);

    let av2 = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"vKxOHg_kENeuW_l-KEv42CLA7_2Nz6JOV6DE059z17Q\",\"y\":\"4dXAjWMD40RxZzDB9aJfAZRNbACZluKuD-GHMqLxoYM\",\"d\":\"zjML5vP4_TAnqlLVL0MfFgPEVRiWUhkQJ5InIyfxljI\"}";
    let prf_key = hex_to_bytes("3ba4d0b8cece6535eb22d2446f157846ef78b02e8e4621fdda006d3833a8bac7");
    let mut i = Import::new(Key::Jwk(av2.into()));
    i.rp_id = site.into();
    i.cred_id = hex_to_bytes("e10b19bb95a252ee6204cd13f747cded7c98f1269ce9006f004e6256bcbebd11");
    i.user_handle = hex_to_bytes("f94cb6c7ba1148dacb4aadca13e6b279");
    i.prf = Some(Seeds {
        uv: prf_key.clone(),
        nouv: prf_key,
    });
    cases.push(valid(
        "006",
        "AliasVault JWK with a PRF key: both seeds are the key (the same formula)",
        &i,
        &base64url_decode("zjML5vP4_TAnqlLVL0MfFgPEVRiWUhkQJ5InIyfxljI"),
    )?);

    // ---- key forms
    let d = pat(0x11, 32);
    let p = pair(d.clone())?;
    cases.push(valid(
        "007",
        "PKCS#8 without the public key is written with it",
        &Import::new(Key::Pkcs8(pkcs8_short(&p))),
        &d,
    )?);
    cases.push(valid(
        "008",
        "PKCS#8 with the curve repeated inside the key is written in the one form",
        &Import::new(Key::Pkcs8(pkcs8_with_params(&p))),
        &d,
    )?);
    cases.push(valid(
        "009",
        "JWK without the public coordinates",
        &Import::new(Key::Jwk(jwk(&p, false))),
        &d,
    )?);
    cases.push(valid(
        "010",
        "JWK with the public coordinates",
        &Import::new(Key::Jwk(jwk(&p, true))),
        &d,
    )?);
    cases.push(valid(
        "011",
        "JWK without kty (read as EC)",
        &Import::new(Key::Jwk(format!(
            "{{\"crv\":\"P-256\",\"d\":\"{}\"}}",
            base64url(&p.d)
        ))),
        &d,
    )?);
    cases.push(valid(
        "012",
        "JWK with other members of every kind, whitespace and an escape in a value that is skipped",
        &Import::new(Key::Jwk(format!(
            "{{\n  \"kid\": \"a\\\"b\\u00e5\", \"ext\": true, \"key_ops\": [\"sign\", {{\"n\": [1, -2.5e3, null, false]}}],\n  \"alg\": \"ES256\", \"use\": \"sig\",\n  \"crv\": \"P-256\", \"kty\": \"EC\", \"d\": \"{}\"\n}}\n",
            base64url(&p.d)
        ))),
        &d,
    )?);
    cases.push(valid(
        "013",
        "JWK whose d has padding",
        &Import::new(Key::Jwk(format!(
            "{{\"crv\":\"P-256\",\"d\":\"{}=\"}}",
            base64url(&p.d)
        ))),
        &d,
    )?);
    // A scalar with a leading zero byte and one that is the order minus one.
    let mut lead = pat(0x21, 32);
    lead[0] = 0;
    let lead_pair = pair(lead.clone())?;
    cases.push(valid(
        "014",
        "a scalar with a leading zero byte",
        &Import::new(Key::Jwk(jwk(&lead_pair, true))),
        &lead,
    )?);
    let max = hex_to_bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
    let max_pair = pair(max.clone())?;
    cases.push(valid(
        "015",
        "the largest valid scalar (n - 1)",
        &Import::new(Key::Pkcs8(pkcs8(&max_pair))),
        &max,
    )?);

    // ---- PRF
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.prf = Some(Seeds {
        uv: pat(0x31, 32),
        nouv: pat(0x51, 32),
    });
    cases.push(valid(
        "016",
        "two seeds of Ferret's formula are kept as they are",
        &i,
        &d,
    )?);

    // ---- RP ID
    for (n, title, written) in [
        (
            "017",
            "RP ID with upper case and a trailing dot",
            "Example.COM.",
        ),
        (
            "018",
            "RP ID as Unicode becomes A-labels",
            "b\u{fc}cher.example",
        ),
        (
            "019",
            "RP ID as upper-case Unicode becomes A-labels",
            "B\u{dc}CHER.Example",
        ),
        (
            "020",
            "RP ID that is a host of a private suffix, not the suffix",
            "a.github.io",
        ),
        (
            "021",
            "RP ID below a registry suffix",
            "Login.Example.CO.UK",
        ),
        (
            "022",
            "RP ID that is a registrable domain of an unknown suffix",
            "rp-a.test",
        ),
    ] {
        let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
        i.rp_id = written.into();
        cases.push(valid(n, title, &i, &d)?);
    }

    // ---- texts
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.user_name = "al\u{202e}ice\u{0}@example.com\u{200b}\n".into();
    i.rp_name = Some("Exam\u{2066}ple\t".into());
    i.display_name = Some("\u{c5}se\u{feff}".into());
    cases.push(valid(
        "023",
        "the texts of the site lose the control and bidirectional characters",
        &i,
        &d,
    )?);
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.rp_name = None;
    i.display_name = Some("\u{0}\u{7f}\u{200e}".into());
    cases.push(valid(
        "024",
        "no site name, and a display name that is nothing but control characters",
        &i,
        &d,
    )?);
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.user_name = String::new();
    cases.push(valid("025", "an empty user name", &i, &d)?);

    // ---- sizes
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.cred_id = vec![0x5a];
    i.user_handle = vec![0x01];
    cases.push(valid(
        "026",
        "credential id of 1 byte and user handle of 1 byte",
        &i,
        &d,
    )?);
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.cred_id = pat(0, 1023);
    i.user_handle = pat(0x80, 64);
    cases.push(valid(
        "027",
        "credential id of 1 023 bytes and user handle of 64 bytes",
        &i,
        &d,
    )?);
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.counter = u32::MAX;
    i.created = "9007199254740991".into();
    cases.push(valid(
        "028",
        "the largest counter and creation time",
        &i,
        &d,
    )?);
    let mut i = Import::new(Key::Pkcs8(pkcs8(&p)));
    i.user_name = "u".repeat(1024);
    i.rp_name = Some("r".repeat(1024));
    i.display_name = Some("n".repeat(1024));
    cases.push(valid("029", "names of exactly 1 KiB", &i, &d)?);

    // ---- invalid: the key
    let base = Import::new(Key::Pkcs8(pkcs8(&p)));
    let with_key = |key: Key| {
        let mut i = base.clone();
        i.key = key;
        i
    };
    let ed25519 = {
        let mut v = hex_to_bytes("302e020100300506032b657004220420");
        v.extend_from_slice(&d);
        v
    };
    let rsa = hex_to_bytes("3016020100300d06092a864886f70d010101050004023030");
    let p384 = {
        let mut v =
            hex_to_bytes("303e020100301006072a8648ce3d020106052b81040022042730250201010420");
        v.extend_from_slice(&d);
        v
    };
    for (n, title, key) in [
        ("001", "PKCS#8 of an Ed25519 key", Key::Pkcs8(ed25519)),
        ("002", "PKCS#8 of an RSA key", Key::Pkcs8(rsa)),
        ("003", "PKCS#8 of a P-384 key", Key::Pkcs8(p384)),
        (
            "004",
            "JWK of an RSA key",
            Key::Jwk("{\"kty\":\"RSA\",\"n\":\"AQAB\",\"e\":\"AQAB\",\"d\":\"AQAB\"}".into()),
        ),
        (
            "005",
            "JWK of an Ed25519 key",
            Key::Jwk(format!(
                "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"d\":\"{}\"}}",
                base64url(&d)
            )),
        ),
        (
            "006",
            "JWK of a P-384 key",
            Key::Jwk(format!(
                "{{\"kty\":\"EC\",\"crv\":\"P-384\",\"d\":\"{}\"}}",
                base64url(&d)
            )),
        ),
        (
            "007",
            "JWK that names another algorithm",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"alg\":\"ES384\",\"d\":\"{}\"}}",
                base64url(&d)
            )),
        ),
    ] {
        cases.push(invalid(n, title, &with_key(key), "unsupported"));
    }
    let mut zero_der = pkcs8(&p);
    zero_der[36..68].fill(0);
    let dj = base64url(&d);
    for (n, title, key) in [
        (
            "008",
            "PKCS#8 of a P-256 key whose scalar is 0",
            Key::Pkcs8(zero_der),
        ),
        ("009", "PKCS#8 that is not PKCS#8", Key::Pkcs8(pat(0, 138))),
        ("010", "PKCS#8 of no bytes", Key::Pkcs8(vec![])),
        (
            "011",
            "JWK whose d is 0",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"d\":\"{}\"}}",
                base64url(&[0u8; 32])
            )),
        ),
        (
            "012",
            "JWK whose d is the order of the curve",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"d\":\"{}\"}}",
                base64url(&hex_to_bytes(
                    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
                ))
            )),
        ),
        (
            "013",
            "JWK with x and y of another key",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\",\"d\":\"{dj}\"}}",
                base64url(&pair(pat(0x66, 32))?.x),
                base64url(&pair(pat(0x66, 32))?.y)
            )),
        ),
        (
            "014",
            "JWK with x and no y",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"x\":\"{}\",\"d\":\"{dj}\"}}",
                base64url(&p.x)
            )),
        ),
        (
            "015",
            "JWK without a curve",
            Key::Jwk(format!("{{\"kty\":\"EC\",\"d\":\"{dj}\"}}")),
        ),
        (
            "016",
            "JWK without d",
            Key::Jwk("{\"kty\":\"EC\",\"crv\":\"P-256\"}".into()),
        ),
        (
            "017",
            "JWK with d twice",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"d\":\"{dj}\",\"d\":\"{dj}\"}}"
            )),
        ),
        (
            "018",
            "JWK whose d is one symbol short",
            Key::Jwk(format!("{{\"crv\":\"P-256\",\"d\":\"{}\"}}", &dj[1..])),
        ),
        (
            "019",
            "JWK whose d has a symbol that is not base64url",
            Key::Jwk(format!("{{\"crv\":\"P-256\",\"d\":\"{}+\"}}", &dj[..42])),
        ),
        (
            "020",
            "JWK whose d has an escape",
            Key::Jwk(format!(
                "{{\"crv\":\"P-256\",\"d\":\"{}\\u0041\"}}",
                &dj[..42]
            )),
        ),
        (
            "021",
            "JWK whose d is not text",
            Key::Jwk("{\"crv\":\"P-256\",\"d\":7}".into()),
        ),
        (
            "022",
            "a JWK that is an array",
            Key::Jwk(format!("[\"{dj}\"]")),
        ),
        (
            "023",
            "a JWK with text after the object",
            Key::Jwk(format!("{{\"crv\":\"P-256\",\"d\":\"{dj}\"}} x")),
        ),
        (
            "024",
            "a JWK that is not finished",
            Key::Jwk(format!("{{\"crv\":\"P-256\",\"d\":\"{dj}\"")),
        ),
        ("025", "a JWK of no text", Key::Jwk(String::new())),
    ] {
        cases.push(invalid(n, title, &with_key(key), BAD_KEY));
    }
    cases.push(invalid(
        "026",
        "a JWK of more than 4 KiB",
        &with_key(Key::Jwk(format!(
            "{{\"crv\":\"P-256\",\"d\":\"{dj}\",\"n\":\"{}\"}}",
            "a".repeat(5000)
        ))),
        "too_large",
    ));
    cases.push(invalid(
        "027",
        "a PKCS#8 document of more than 1 KiB",
        &with_key(Key::Pkcs8(vec![0x30; 2000])),
        "too_large",
    ));

    // ---- invalid: RP ID
    for (n, title, rp) in [
        ("028", "RP ID that is a registry suffix", "co.uk"),
        ("029", "RP ID that is a private suffix", "github.io"),
        ("030", "RP ID that is a top-level domain", "com"),
        ("031", "RP ID that is an IPv4 address", "10.0.0.1"),
        ("032", "RP ID with a port", "example.com:8443"),
        ("033", "RP ID that is an address", "https://example.com"),
        ("034", "RP ID with a path", "example.com/login"),
        ("035", "RP ID that is empty", ""),
        (
            "036",
            "RP ID with a label that starts with a hyphen",
            "-a.example.com",
        ),
        ("037", "RP ID with an empty label", "a..example.com"),
        ("038", "RP ID that is localhost", "localhost"),
    ] {
        let mut i = base.clone();
        i.rp_id = rp.into();
        cases.push(invalid(n, title, &i, "malformed_rp_id"));
    }

    // ---- invalid: ids, handles, PRF, texts
    let mut i = base.clone();
    i.cred_id = vec![];
    cases.push(invalid(
        "039",
        "credential id of no bytes",
        &i,
        "malformed_webauthn_options",
    ));
    let mut i = base.clone();
    i.cred_id = pat(0, 1024);
    cases.push(invalid(
        "040",
        "credential id of 1 024 bytes",
        &i,
        "too_large",
    ));
    let mut i = base.clone();
    i.user_handle = vec![];
    cases.push(invalid(
        "041",
        "user handle of no bytes",
        &i,
        "malformed_webauthn_options",
    ));
    let mut i = base.clone();
    i.user_handle = pat(0, 65);
    cases.push(invalid(
        "042",
        "user handle of 65 bytes",
        &i,
        "malformed_webauthn_options",
    ));
    let mut i = base.clone();
    i.prf = Some(Seeds {
        uv: pat(0x31, 31),
        nouv: pat(0x51, 32),
    });
    cases.push(invalid("043", "a PRF seed of 31 bytes", &i, BAD_KEY));
    let mut i = base.clone();
    i.prf = Some(Seeds {
        uv: pat(0x31, 32),
        nouv: pat(0x51, 64),
    });
    cases.push(invalid("044", "a PRF seed of 64 bytes", &i, BAD_KEY));
    let mut i = base.clone();
    i.user_name = "u".repeat(1025);
    cases.push(invalid(
        "045",
        "a user name of more than 1 KiB",
        &i,
        "too_large",
    ));
    let mut i = base.clone();
    i.rp_name = Some("r".repeat(1025));
    cases.push(invalid(
        "046",
        "a site name of more than 1 KiB",
        &i,
        "too_large",
    ));
    let mut i = base.clone();
    i.display_name = Some("n".repeat(1025));
    cases.push(invalid(
        "047",
        "a display name of more than 1 KiB",
        &i,
        "too_large",
    ));
    let mut i = base.clone();
    i.created = "9007199254740992".into();
    cases.push(invalid(
        "048",
        "a creation time above 2^53 - 1",
        &i,
        "too_large",
    ));

    for (n, title, text) in [
        (
            "049",
            "JWK with a member name that has an escape (a second d)",
            format!("{{\"crv\":\"P-256\",\"d\":\"{dj}\",\"\\u0064\":\"{dj}\"}}"),
        ),
        (
            "050",
            "JWK with a second token after a skipped value that hides a member",
            format!("{{\"crv\":\"P-256\",\"d\":\"{dj}\",\"n\":0 \"d\":\"{dj}\"}}"),
        ),
    ] {
        cases.push(invalid(n, title, &with_key(Key::Jwk(text)), BAD_KEY));
    }

    let file = VectorFile {
        format: ferret_core::testing::vector::FORMAT.into(),
        group: "passkey_import".into(),
        suite: 1,
        spec: "Fase 1 § 9.1, § 9.6".into(),
        generator: generator(),
        cases,
    };
    render(&file)
}

/// Base64url text to bytes (no padding), for the scalars of the exported keys.
fn base64url_decode(text: &str) -> Vec<u8> {
    const A: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = vec![];
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.chars() {
        let v = u32::try_from(A.find(c).unwrap_or(0)).unwrap_or(0);
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            acc &= (1 << bits) - 1;
        }
    }
    out
}
