//! `passkey_import` on arbitrary key text and bytes: never a panic, and an
//! import that is accepted is a well-formed passkey (a canonical RP ID, a
//! stored P-256 key in the one PKCS#8 form, ids and handles inside their
//! limits, cleaned texts) that signs.
//!
//! Layout of the input: one byte of flags (bit 0: the key is a JWK, else
//! PKCS#8; bit 1: PRF seeds are given; bit 2: the site name is given; bit 3: the
//! display name is given), one byte for the length of the credential id (times
//! 5), one byte for the length of the user handle, then three parts that end at
//! a zero byte: the RP ID, the user name and the key (the rest).
#![no_main]

use ferret_core::testing::passkey::item_of;
use ferret_core::{
    CallerContext, GetRequest, ImportKey, ImportPrf, ImportedPasskeyInput, PasskeyRecord,
    UserVerification, UvOutcome, canonical_origin, canonical_rp_id, passkey_get, passkey_import,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((head, rest)) = data.split_at_checked(3) else {
        return;
    };
    let (flags, cred_len, handle_len) = (head[0], usize::from(head[1]) * 5, usize::from(head[2]));
    let mut parts = rest.splitn(3, |b| *b == 0);
    let (rp, name, key) = (
        parts.next().unwrap_or(&[]),
        parts.next().unwrap_or(&[]),
        parts.next().unwrap_or(&[]),
    );
    let (Ok(rp_id), Ok(user_name)) = (std::str::from_utf8(rp), std::str::from_utf8(name)) else {
        return;
    };
    let key_text;
    let key_input = if flags & 1 == 1 {
        let Ok(text) = std::str::from_utf8(key) else {
            return;
        };
        key_text = text;
        ImportKey::JwkJson(key_text)
    } else {
        ImportKey::Pkcs8Der(key)
    };
    let cred_id = vec![0x5a; cred_len];
    let user_handle = vec![0x3c; handle_len];
    let seed_uv = vec![0x31; if flags & 0x10 != 0 { 31 } else { 32 }];
    let seed_nouv = vec![0x51; 32];
    let input = ImportedPasskeyInput {
        cred_id: &cred_id,
        rp_id,
        user_handle: &user_handle,
        user_name,
        rp_name: (flags & 4 != 0).then_some(user_name),
        user_display_name: (flags & 8 != 0).then_some(rp_id),
        created: 1,
        key: key_input,
        prf: if flags & 2 != 0 {
            ImportPrf::Seeds {
                uv: &seed_uv,
                nouv: &seed_nouv,
            }
        } else {
            ImportPrf::None
        },
        counter: u32::from(head[2]) * u32::from(flags >> 5),
    };
    let Ok((record, notes)) = passkey_import(&input) else {
        return;
    };
    assert!((1..=1023).contains(&cred_len) && (1..=64).contains(&handle_len));
    assert_eq!(notes.register_again, input.counter > 0);
    assert_eq!(notes.prf, flags & 2 != 0 && flags & 0x10 == 0);
    assert_eq!(
        canonical_rp_id(rp_id)
            .expect("the RP ID was accepted")
            .as_str(),
        record.rp_id
    );
    let item = item_of(&record);
    assert_eq!(item.private_key.len(), 138);
    assert_eq!(item.sign_count, 0);
    assert!(item.user_name.chars().all(|c| !c.is_control()));
    // The stored form reads back as a record and signs for the RP.
    let again = PasskeyRecord::from_item(&item).expect("the stored passkey reads back");
    let ctx = CallerContext {
        origin: canonical_origin(&format!("https://{}", record.rp_id)).expect("an origin"),
        top_origin_is_same: true,
    };
    let get = GetRequest {
        challenge: vec![1; 32],
        rp_id: None,
        allow: vec![],
        user_verification: UserVerification::Preferred,
        prf: None,
    };
    let uv = UvOutcome {
        user_present: true,
        user_verified: false,
    };
    passkey_get(&again, &get, &ctx, uv).expect("an imported passkey signs");
});
