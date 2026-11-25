//! Property tests for the passkey authenticator and origin rules.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::passkey::{FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV};
use ferret_core::testing::TestRng;
use ferret_core::testing::passkey::is_public_suffix;
use ferret_core::{
    CallerContext, CreateRequest, GetRequest, ImportKey, ImportPrf, ImportedPasskeyInput,
    StoredPasskeyRef, UserVerification, UvOutcome, canonical_origin, passkey_candidates,
    passkey_create, passkey_get, passkey_import, passkey_site, validate_rp_id,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use proptest::prelude::*;
use sha2::{Digest, Sha256};

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

fn uv_kind() -> impl Strategy<Value = UserVerification> {
    prop_oneof![
        Just(UserVerification::Required),
        Just(UserVerification::Preferred),
        Just(UserVerification::Discouraged),
    ]
}

fn ctx() -> CallerContext {
    CallerContext {
        origin: canonical_origin("https://login.example.com").unwrap(),
        top_origin_is_same: true,
    }
}

proptest! {
    #![proptest_config(config())]

    /// A signature from `create`/`get` verifies with p256's verifier over
    /// `authData ‖ SHA-256(clientDataJSON)` for the key that `create` showed.
    #[test]
    fn passkey_sign_verifies(
        seed in proptest::collection::vec(any::<u8>(), 1..16),
        create_challenge in proptest::collection::vec(any::<u8>(), 0..=1024),
        get_challenge in proptest::collection::vec(any::<u8>(), 0..=1024),
        verified in any::<bool>(),
    ) {
        let uv = UvOutcome { user_present: true, user_verified: verified };
        let req = CreateRequest {
            challenge: create_challenge,
            rp_id: Some("example.com".into()),
            rp_name: "Example".into(),
            user_id: vec![1; 8],
            user_name: "u".into(),
            user_display_name: "U".into(),
            algorithms: vec![-7],
            exclude: vec![],
            user_verification: UserVerification::Preferred,
            prf: None,
            cred_props: false,
        };
        let mut rng = TestRng::new(&seed);
        let created = passkey_create(&mut rng, &req, &ctx(), uv, &[], 0).unwrap();
        let vk = VerifyingKey::from_public_key_der(&created.response.public_key_spki).unwrap();
        let get = GetRequest {
            challenge: get_challenge,
            rp_id: Some("example.com".into()),
            allow: vec![],
            user_verification: UserVerification::Preferred,
            prf: None,
        };
        let g = passkey_get(&created.record, &get, &ctx(), uv).unwrap();
        let mut msg = g.authenticator_data.clone();
        msg.extend_from_slice(&Sha256::digest(&g.client_data_json));
        let sig = Signature::from_der(&g.signature).unwrap();
        prop_assert!(vk.verify(&msg, &sig).is_ok());
    }

    /// BE = BS = 1, signCount = 0, UP set, UV only when performed, AT only
    /// for create.
    #[test]
    fn passkey_flags_invariants(
        seed in proptest::collection::vec(any::<u8>(), 1..16),
        create_uv in any::<bool>(),
        get_uv in any::<bool>(),
        wanted_create in uv_kind(),
        wanted_get in uv_kind(),
        with_prf in any::<bool>(),
    ) {
        let create_outcome = UvOutcome { user_present: true, user_verified: create_uv };
        let get_outcome = UvOutcome { user_present: true, user_verified: get_uv };
        let req = CreateRequest {
            challenge: vec![1; 16],
            rp_id: None,
            rp_name: "Example".into(),
            user_id: vec![1; 8],
            user_name: "u".into(),
            user_display_name: "U".into(),
            algorithms: vec![],
            exclude: vec![],
            user_verification: wanted_create,
            prf: with_prf.then(Default::default),
            cred_props: false,
        };
        let mut rng = TestRng::new(&seed);
        let created = passkey_create(&mut rng, &req, &ctx(), create_outcome, &[], 0);
        if wanted_create == UserVerification::Required && !create_uv {
            prop_assert!(created.is_err());
            return Ok(());
        }
        let created = created.unwrap();
        let f = created.response.authenticator_data[32];
        prop_assert_eq!(f & (FLAG_BE | FLAG_BS | FLAG_UP | FLAG_AT), FLAG_BE | FLAG_BS | FLAG_UP | FLAG_AT);
        prop_assert_eq!(f & FLAG_UV != 0, create_uv);
        prop_assert_eq!(&created.response.authenticator_data[33..37], &[0u8; 4][..]);

        let get = GetRequest {
            challenge: vec![2; 16],
            rp_id: None,
            allow: vec![],
            user_verification: wanted_get,
            prf: None,
        };
        let g = passkey_get(&created.record, &get, &ctx(), get_outcome);
        if wanted_get == UserVerification::Required && !get_uv {
            prop_assert!(g.is_err());
            return Ok(());
        }
        let g = g.unwrap();
        let f = g.authenticator_data[32];
        prop_assert_eq!(f & (FLAG_BE | FLAG_BS | FLAG_UP), FLAG_BE | FLAG_BS | FLAG_UP);
        prop_assert_eq!(f & FLAG_AT, 0);
        prop_assert_eq!(f & FLAG_UV != 0, get_uv);
        prop_assert_eq!(g.authenticator_data.len(), 37);
        prop_assert_eq!(&g.authenticator_data[33..37], &[0u8; 4][..]);
    }

    /// The candidates of a get are exactly the stored passkeys whose RP ID
    /// is the one the request resolves to (no suffix, no case folding) and
    /// whose id is in a non-empty `allow` list: in the order of `stored`,
    /// whatever else is stored. `passkey_site` refuses the same requests.
    #[test]
    fn candidates_are_exactly_the_exact_rp_matches(
        stored in prop::collection::vec(
            (
                prop_oneof![
                    Just("login.example.com"), Just("example.com"), Just("com"),
                    Just("sub.login.example.com"), Just("LOGIN.EXAMPLE.COM"),
                    Just("login.example.com."), Just("example.org"),
                    Just("xn--bcher-kva.example"), Just("b\u{fc}cher.example"),
                ],
                0u8..4,
            ),
            0..12,
        ),
        allow in prop::collection::vec(0u8..4, 0..4),
        request_rp in prop_oneof![
            Just(None), Just(Some("login.example.com")), Just(Some("example.com")),
            Just(Some("com")), Just(Some("example.org")), Just(Some("LOGIN.example.com")),
        ],
    ) {
        let ids: Vec<[u8; 32]> = stored.iter().map(|(_, i)| [*i; 32]).collect();
        let refs: Vec<StoredPasskeyRef<'_>> = stored
            .iter()
            .zip(&ids)
            .map(|((rp, _), id)| StoredPasskeyRef { rp_id: rp, cred_id: id })
            .collect();
        let allow: Vec<Vec<u8>> = allow.iter().map(|i| vec![*i; 32]).collect();
        let got = passkey_candidates(&ctx(), request_rp, &allow, &refs);
        let site = passkey_site(&ctx(), request_rp);
        match (&got, &site) {
            (Err(a), Err(b)) => prop_assert_eq!(a, b),
            (Ok(_), Ok(_)) => {}
            _ => prop_assert!(false, "candidates and site disagree"),
        }
        if let (Ok(got), Ok(site)) = (got, site) {
            let want: Vec<usize> = refs
                .iter()
                .enumerate()
                .filter(|(_, s)| {
                    s.rp_id == site.rp_id
                        && (allow.is_empty() || allow.iter().any(|a| a.as_slice() == s.cred_id))
                })
                .map(|(i, _)| i)
                .collect();
            prop_assert_eq!(&got, &want);
            prop_assert!(got.windows(2).all(|w| w[0] < w[1]));
            for i in got {
                prop_assert_eq!(refs[i].rp_id, site.rp_id.as_str());
            }
        }
    }

    /// Reading a canonical origin again gives itself, and the result is
    /// never `null`, an IP host or opaque.
    #[test]
    fn origin_canonicalization_idempotent(
        scheme in prop_oneof![Just("https"), Just("HTTPS"), Just("http"), Just("ftp")],
        host in "[A-Za-z0-9.\u{e4}\u{e9}\u{3b1}\u{65e5}\u{ff21}-]{0,40}",
        port in prop_oneof![Just(String::new()), (0u32..70000).prop_map(|p| format!(":{p}"))],
    ) {
        let raw = format!("{scheme}://{host}{port}");
        if let Ok(o) = canonical_origin(&raw) {
            let again = canonical_origin(o.as_str()).unwrap();
            prop_assert_eq!(&o, &again);
            prop_assert!(o.as_str() != "null");
            prop_assert!(o.is_https() || o.host() == "localhost");
            prop_assert!(o.host().is_ascii());
            prop_assert!(o.host().to_ascii_lowercase() == o.host());
            prop_assert!(!o.host().ends_with('.'));
            let last = o.host().rsplit('.').next().unwrap();
            prop_assert!(!last.bytes().all(|b| b.is_ascii_digit()));
        }
    }

    /// Any text: reading it either fails or is idempotent.
    #[test]
    fn origin_canonicalization_total(raw in ".{0,80}") {
        if let Ok(o) = canonical_origin(&raw) {
            prop_assert_eq!(canonical_origin(o.as_str()).unwrap(), o);
        }
    }

    /// An RP ID that is a public suffix is always refused; one that is
    /// accepted is a suffix of the host and not a public suffix.
    #[test]
    fn rp_id_never_public_suffix(
        prefix in "[a-z0-9]{1,8}(\\.[a-z0-9]{1,8}){0,2}",
        suffix in prop_oneof![
            Just("com"), Just("co.uk"), Just("github.io"), Just("vercel.app"),
            Just("blogspot.com"), Just("uk"), Just("xn--55qx5d.cn"), Just("foo.ck"),
            Just("example.com"), Just("sub.example.org"), Just("zzzunknown"),
        ],
        cut in 0usize..4,
    ) {
        let host = format!("{prefix}.{suffix}");
        let Ok(origin) = canonical_origin(&format!("https://{host}")) else { return Ok(()); };
        // Every dot-delimited suffix of the host.
        let labels: Vec<&str> = origin.host().split('.').collect();
        for i in 0..labels.len() {
            let candidate = labels[i..].join(".");
            match validate_rp_id(&origin, &candidate) {
                Ok(rp) => {
                    prop_assert!(!is_public_suffix(rp.as_str()), "{} accepted", rp.as_str());
                    let dotted = format!(".{}", rp.as_str());
                    let related = origin.host() == rp.as_str() || origin.host().ends_with(&dotted);
                    prop_assert!(related);
                }
                Err(_) => {
                    // Refused: it must be a public suffix, since it is a
                    // suffix of the host.
                    prop_assert!(is_public_suffix(&candidate), "{candidate} refused");
                }
            }
        }
        // The suffix chosen from the list is refused as an RP ID.
        if cut == 0 {
            prop_assert_eq!(
                validate_rp_id(&origin, suffix).is_err(),
                is_public_suffix(suffix)
            );
        }
    }
}

// ------------------------------------------------------------ import

/// The base64url text of `bytes`, no padding.
fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            out.push(A[((acc >> bits) & 63) as usize] as char);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(A[((acc << (6 - bits)) & 63) as usize] as char);
    }
    out
}

proptest! {
    #![proptest_config(config())]

    /// A key given as PKCS#8 (with or without the public key) or as a JWK (with
    /// or without `x` and `y`) is stored as the same scalar in the same
    /// PKCS#8, and the passkey signs for the public key of that scalar.
    #[test]
    fn imported_key_round_trips(
        scalar in proptest::array::uniform32(any::<u8>()),
        cred_id in proptest::collection::vec(any::<u8>(), 1..=1023),
        user_handle in proptest::collection::vec(any::<u8>(), 1..=64),
        counter in any::<u32>(),
        challenge in proptest::collection::vec(any::<u8>(), 0..=64),
        verified in any::<bool>(),
    ) {
        let Ok(key) = SigningKey::from_slice(&scalar) else { return Ok(()); };
        let point = key.verifying_key().to_sec1_point(false);
        let mut full = vec![];
        full.extend_from_slice(&hex_to_vec(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420",
        ));
        full.extend_from_slice(&scalar);
        full.extend_from_slice(&hex_to_vec("a14403420004"));
        full.extend_from_slice(point.x().unwrap());
        full.extend_from_slice(point.y().unwrap());
        let mut short = hex_to_vec(
            "3041020100301306072a8648ce3d020106082a8648ce3d030107042730250201010420",
        );
        short.extend_from_slice(&scalar);
        let jwk_with = format!(
            "{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{}\",\"y\":\"{}\",\"d\":\"{}\"}}",
            b64url(point.x().unwrap()),
            b64url(point.y().unwrap()),
            b64url(&scalar)
        );
        let jwk_without = format!("{{\"crv\":\"P-256\",\"d\":\"{}\"}}", b64url(&scalar));

        let mut stored: Vec<Vec<u8>> = vec![];
        for key_input in [
            ImportKey::Pkcs8Der(&full),
            ImportKey::Pkcs8Der(&short),
            ImportKey::JwkJson(&jwk_with),
            ImportKey::JwkJson(&jwk_without),
        ] {
            let input = ImportedPasskeyInput {
                cred_id: &cred_id,
                rp_id: "Example.com",
                user_handle: &user_handle,
                user_name: "u",
                rp_name: None,
                user_display_name: None,
                created: 1,
                key: key_input,
                prf: ImportPrf::None,
                counter,
            };
            let (record, notes) = passkey_import(&input).unwrap();
            prop_assert_eq!(notes.register_again, counter > 0);
            prop_assert_eq!(&record.rp_id, "example.com");
            prop_assert_eq!(&record.cred_id, &cred_id);
            stored.push(ferret_core::testing::passkey::item_of(&record).private_key.clone());

            let req = GetRequest {
                challenge: challenge.clone(),
                rp_id: Some("example.com".into()),
                allow: vec![cred_id.clone()],
                user_verification: UserVerification::Preferred,
                prf: None,
            };
            let uv = UvOutcome { user_present: true, user_verified: verified };
            let g = passkey_get(&record, &req, &ctx(), uv).unwrap();
            let mut msg = g.authenticator_data.clone();
            msg.extend_from_slice(&Sha256::digest(&g.client_data_json));
            let sig = Signature::from_der(&g.signature).unwrap();
            prop_assert!(key.verifying_key().verify(&msg, &sig).is_ok());
        }
        // One stored form, and it is the PKCS#8 with the public key.
        prop_assert!(stored.iter().all(|s| *s == full));
    }
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    ferret_core::testing::hex_decode(s).unwrap()
}
