//! Property tests for the passkey authenticator and origin rules (plan
//! section 9.1).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::passkey::{FLAG_AT, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV};
use ferret_core::testing::TestRng;
use ferret_core::testing::passkey::is_public_suffix;
use ferret_core::{
    CallerContext, CreateRequest, GetRequest, UserVerification, UvOutcome, canonical_origin,
    passkey_create, passkey_get, validate_rp_id,
};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
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
