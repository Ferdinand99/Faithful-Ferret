//! The emergency sheet content and the setup QR payload (Fase 1 § 6.1): `vectors/internal/sheet.json` and properties.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::*;
use ferret_core::testing::vector::Outcome;
use ferret_core::{
    AccountId, Error, KsfProfile, MalformedKind, RecoveryKey, SecretKey, SetupQr, emergency_sheet,
    encode_recovery_key, encode_secret_key, parse_server_address, parse_setup_qr, setup_qr_payload,
};
use proptest::prelude::*;

const KEY: [u8; 32] = [0xa5; 32];

fn id() -> AccountId {
    AccountId::from_bytes([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc,
        0xfe,
    ])
}

fn build(url: &str, sk: bool) -> Result<String, Error> {
    setup_qr_payload(url, &id(), KsfProfile::P1, sk, &KEY)
}

#[test]
fn qr_payload_roundtrip_and_rejects_garbage() {
    let url = "https://vault.example.com:8443/ferret";
    let payload = build(url, true).unwrap();
    assert_eq!(
        payload,
        "ferret-setup:v1?u=https%3A%2F%2Fvault.example.com%3A8443%2Fferret\
         &a=0123456789abcdef1032547698badcfe&k=1&s=1&o=\
         a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"
    );
    let qr = parse_setup_qr(&payload).unwrap();
    assert_eq!(
        qr,
        SetupQr {
            server_url: url.into(),
            account_id: id(),
            ksf_profile: KsfProfile::P1,
            sk_bit: true,
            server_public_key: KEY,
        }
    );
    // The reader and the writer agree on one spelling.
    assert_eq!(
        setup_qr_payload(
            &qr.server_url,
            &qr.account_id,
            qr.ksf_profile,
            qr.sk_bit,
            &qr.server_public_key
        )
        .unwrap(),
        payload
    );
    assert!(!parse_setup_qr(&build(url, false).unwrap()).unwrap().sk_bit);

    for garbage in [
        "",
        "ferret-setup:",
        "ferret-setup:v1",
        "ferret-setup:v1?",
        "FERRET-SETUP:v1?u=x",
        "https://vault.example.com",
        "ferret-setup:v1?u=&a=&k=&s=&o=",
        "\0",
        "ferret-setup:v1?u=https%3A%2F%2Fa&a=00&k=1&s=1&o=00",
    ] {
        assert!(parse_setup_qr(garbage).is_err(), "{garbage:?}");
    }
    // Truncations of a good payload never read.
    for n in 0..payload.len() - 1 {
        assert!(
            parse_setup_qr(&payload[..n]).is_err(),
            "prefix of {n} bytes"
        );
    }
    // Another version.
    assert_eq!(
        parse_setup_qr(&payload.replacen("v1?", "v2?", 1)).err(),
        Some(Error::Unsupported)
    );
}

#[test]
fn qr_payload_limits() {
    // 512 bytes are accepted, 513 are not (on both sides).
    let ok = format!("https://{}", "a".repeat(504));
    assert_eq!(ok.len(), 512);
    let payload = build(&ok, true).unwrap();
    assert_eq!(parse_setup_qr(&payload).unwrap().server_url, ok);
    let long = format!("https://{}", "a".repeat(505));
    assert_eq!(build(&long, true).err(), Some(Error::TooLarge));
    let doctored = payload.replacen(&"a".repeat(504), &"a".repeat(505), 1);
    assert_eq!(parse_setup_qr(&doctored).err(), Some(Error::TooLarge));
    // A payload longer than any valid one is refused before it is read.
    assert_eq!(
        parse_setup_qr(&format!("{payload}{}", "0".repeat(1_700))).err(),
        Some(Error::TooLarge)
    );
    // Addresses the writer refuses.
    for bad in [
        "",
        "https://",
        "http://",
        "ftp://vault.example",
        "vault.example",
        "https://vault example",
        "https://vault.example/\n",
        "https://v\u{e6}ult.example",
        "HTTPS://vault.example",
    ] {
        assert_eq!(
            build(bad, true).err(),
            Some(Error::Malformed(MalformedKind::SetupQr)),
            "{bad:?}"
        );
    }
    // A worst case address, every byte a `%XX`, still fits the reader.
    let wild = format!("https://{}", "~#".repeat(252));
    let payload = build(&wild, true).unwrap();
    assert!(payload.len() <= 1_700, "{}", payload.len());
    assert_eq!(parse_setup_qr(&payload).unwrap().server_url, wild);
    // Other versions and unknown profiles.
    let good = build("https://a.example", true).unwrap();
    assert_eq!(
        parse_setup_qr(&good.replacen("&k=1", "&k=2", 1)).err(),
        Some(Error::KdfProfileUnknown)
    );
    for bad_k in ["&k=0", "&k=01", "&k=+1", "&k=1x", "&k=", "&k=1000"] {
        assert!(
            parse_setup_qr(&good.replacen("&k=1", bad_k, 1)).is_err(),
            "{bad_k}"
        );
    }
}

fn config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// What the writer makes, the reader reads back, and writing that gives
    /// the same text.
    #[test]
    fn qr_payload_roundtrip(
        host in "[a-z0-9.\\-]{1,40}",
        path in "[ -~]{0,100}",
        https in any::<bool>(),
        account in any::<[u8; 16]>(),
        sk in any::<bool>(),
        key in any::<[u8; 32]>(),
    ) {
        // A space is not allowed in an address, a backslash is not either.
        let path = path.replace([' ', '\\'], "_");
        // http is for a LAN or local server only.
        let url = if https {
            // A last label of digits or `0x...` is read as an IPv4 address.
            format!("https://{host}.example/{path}")
        } else {
            format!("http://localhost/{path}")
        };
        let payload = setup_qr_payload(&url, &AccountId::from_bytes(account), KsfProfile::P1, sk, &key).unwrap();
        let qr = parse_setup_qr(&payload).unwrap();
        prop_assert_eq!(&qr.server_url, &url);
        prop_assert_eq!(qr.account_id, AccountId::from_bytes(account));
        prop_assert_eq!(qr.sk_bit, sk);
        prop_assert_eq!(qr.server_public_key, key);
        let again = setup_qr_payload(&qr.server_url, &qr.account_id, qr.ksf_profile, qr.sk_bit, &qr.server_public_key).unwrap();
        prop_assert_eq!(again, payload);
    }

    /// Anything the reader accepts is the canonical spelling of what it read,
    /// and nothing makes it panic.
    #[test]
    fn qr_reader_accepts_only_canonical_text(s in "\\PC{0,300}") {
        if let Ok(qr) = parse_setup_qr(&s) {
            let again = setup_qr_payload(&qr.server_url, &qr.account_id, qr.ksf_profile, qr.sk_bit, &qr.server_public_key).unwrap();
            prop_assert_eq!(again, s);
        }
    }

    /// A single changed byte of a good payload either fails or reads as a
    /// different value that writes back to the changed text.
    #[test]
    fn a_changed_payload_never_reads_as_the_old_one(pos in 0usize..200, byte in 0x20u8..0x7f) {
        let good = build("https://vault.example.com:8443/ferret", true).unwrap();
        let mut bytes = good.clone().into_bytes();
        let pos = pos % bytes.len();
        if bytes[pos] == byte { return Ok(()); }
        bytes[pos] = byte;
        let changed = String::from_utf8(bytes).unwrap();
        if let Ok(qr) = parse_setup_qr(&changed) {
            prop_assert_ne!(qr, parse_setup_qr(&good).unwrap());
        }
    }
}

#[test]
fn the_sheet_has_separate_pages() {
    let sk = SecretKey::from_test_bytes([0x5a; 16]);
    let rk = RecoveryKey::from_test_bytes([0x66; 32]);
    let sheet = emergency_sheet(
        "https://ferret.example",
        "me@example.com",
        &id(),
        KsfProfile::P1,
        &KEY,
        Some(&sk),
        &rk,
    )
    .unwrap();
    let rk_code = encode_recovery_key(&rk);
    let sk_code = encode_secret_key(&sk);
    assert_eq!(sheet.access.server_url, "https://ferret.example");
    assert_eq!(sheet.access.email, "me@example.com");
    assert_eq!(
        sheet.access.account_id,
        "01234567-89ab-cdef-1032-547698badcfe"
    );
    assert_eq!(sheet.access.ksf_profile, 1);
    assert_eq!(
        &**sheet.access.secret_key_code.as_ref().unwrap(),
        &**sk_code
    );
    assert_eq!(&*sheet.recovery.recovery_key_code, &*rk_code);
    // The recovery key is not on page 1, the secret key not on page 2.
    let page1 = format!(
        "{} {} {} {}",
        sheet.access.server_url,
        sheet.access.email,
        sheet.access.account_id,
        sheet.access.qr_payload
    );
    assert!(!page1.contains(&**rk_code));
    assert!(!page1.contains(&**sk_code));
    assert!(!sheet.recovery.recovery_key_code.contains(&**sk_code));
    let qr = parse_setup_qr(&sheet.access.qr_payload).unwrap();
    assert!(qr.sk_bit);
    // No secret key: no code on the page and the bit is off.
    let sheet = emergency_sheet(
        "https://ferret.example",
        "me@example.com",
        &id(),
        KsfProfile::P1,
        &KEY,
        None,
        &rk,
    )
    .unwrap();
    assert!(sheet.access.secret_key_code.is_none());
    assert!(!parse_setup_qr(&sheet.access.qr_payload).unwrap().sk_bit);
    // E-mail rules.
    for bad in ["", "a\nb@example.com", &"a".repeat(321)] {
        assert!(
            emergency_sheet(
                "https://ferret.example",
                bad,
                &id(),
                KsfProfile::P1,
                &KEY,
                None,
                &rk
            )
            .is_err()
        );
    }
}

/// Every case of `vectors/internal/sheet.json`.
#[test]
fn sheet_vectors_from_file() {
    let path = vectors_dir().join("internal/sheet.json");
    let file = ferret_core::testing::vector::load(&path).unwrap();
    let report = ferret_core::testing::vector::run_all(&file, |case, rng| {
        ferret_core::testing::account::run_case(&case.op, &case.input, rng).map(|output| Outcome {
            output,
            intermediate: None,
        })
    });
    assert!(report.failures.is_empty(), "{:#?}", report.failures);
    assert!(report.passed >= 10, "{} cases", report.passed);
}

#[test]
fn the_host_is_what_a_browser_connects_to() {
    let bad_form = Error::Malformed(MalformedKind::SetupQr);
    // The host a user is asked to confirm must be the host a browser reaches.
    // A backslash would be read as a slash and move the host; `user@` hides
    // it; a `%` escape is decoded in a host.
    for bad in [
        "https://evil.example~BS~@good.example/",
        "https://good.example@evil.example/",
        "https://user:pw@evil.example/",
        "https://a.example%2F@b.example",
        "https://a.example%2eevil",
        "https://a.example/path~BS~x",
        "https://a.example?x=~BS~y",
        "http://vault.example",
        "http://vault.example:3001",
        "http://localhost.evil.example",
        "https://a.example:99999",
        "https://a.example:65536",
        "https://a.example:",
        "https://a.example:80x",
        "https://a.example:80:80",
        "https://a.example:0",
        "https://a.example:00000",
        "http://010.0.0.1",
        "http://192.168.1.010",
        "https://0x7f.0.0.1",
        "https://0X7F.0.0.1",
        "https://127.1",
        "https://2130706433",
        "https://1.2.3.4.5",
        "http://127.0.0.1.",
        "https://a.example.1",
        "HTTPS://vault.example",
        "https://:8443",
        "https://[::1",
        "https://[]",
        "https://[zz::1]",
        "https://[::1]x",
        "https://a.example ",
        "https://a!b.example",
        "https://a,b.example",
    ] {
        let bad = bad.replace("~BS~", BS);
        assert_eq!(parse_server_address(&bad).err(), Some(bad_form), "{bad:?}");
        assert_eq!(build(&bad, true).err(), Some(bad_form), "{bad:?}");
    }
    // What is fine: the host is lower-cased, the port is read, a LAN server
    // may be reached over http, an IPv6 literal keeps its brackets.
    let a = parse_server_address("https://Vault.EXAMPLE:8443/Path?Q=1#F").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (true, "vault.example", Some(8443))
    );
    let a = parse_server_address("https://vault.example").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (true, "vault.example", None)
    );
    let a = parse_server_address("http://LocalHost:3001").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (false, "localhost", Some(3001))
    );
    let a = parse_server_address("http://10.0.3.26:3001").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (false, "10.0.3.26", Some(3001))
    );
    let a = parse_server_address("http://[::1]:8080/x").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (false, "[::1]", Some(8080))
    );
    let a = parse_server_address("https://[2001:DB8::1]/").unwrap();
    assert_eq!(
        (a.https, a.host.as_str(), a.port),
        (true, "[2001:db8::1]", None)
    );
    // Canonical dotted decimal is an IPv4 address; a name with a trailing dot
    // is kept as written.
    for ok in [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://0.0.0.0:1",
        "http://192.168.1.10",
    ] {
        assert!(parse_server_address(ok).is_ok(), "{ok}");
    }
    assert_eq!(
        parse_server_address("https://vault.example.").unwrap().host,
        "vault.example."
    );
    // A user@ after the path is part of the path, not of the authority.
    let a = parse_server_address("https://vault.example/a@b").unwrap();
    assert_eq!(a.host, "vault.example");
    // The reader applies the same rules to a payload.
    let payload = build("https://vault.example", true).unwrap();
    let doctored = payload.replacen("vault.example", "good.example%40evil.example", 1);
    assert_eq!(parse_setup_qr(&doctored).err(), Some(bad_form));
}

const BS: &str = "\\";
