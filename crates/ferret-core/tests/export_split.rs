//! The export cut in two halves, so that the slow Argon2id step can run in a
//! short-lived worker: `export_begin`, `export_wrap_key`,
//! `ExportDraft::finish` and `import_prepare`, `import_decrypt_with_key`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use ferret_core::testing::TestRng;
use ferret_core::{
    Error, ExportItem, ExportPassword, ExportWrapKey, ItemBody, ItemId, ItemType, KDF_FLOOR,
    MalformedKind, export_begin, export_encrypt, export_wrap_key, import_decrypt,
    import_decrypt_with_key, import_prepare,
};

const PASSWORD: &str = "export password for the split";

fn items() -> Vec<ExportItem> {
    let mut login = ItemBody::new(ItemType::Login, "Example", 1_700_000_000_000);
    login.notes = Some("note".into());
    vec![
        ExportItem {
            item_id: ItemId::from_bytes([0x41; 16]),
            body: login,
        },
        ExportItem {
            item_id: ItemId::from_bytes([0x42; 16]),
            body: ItemBody::new(ItemType::Note, "Second", 1_700_000_000_001),
        },
    ]
}

fn password(text: &str) -> ExportPassword {
    ExportPassword::new(text.as_bytes(), None).unwrap()
}

#[test]
fn the_two_halves_make_the_file_of_the_whole() {
    let pw = password(PASSWORD);
    let whole = export_encrypt(
        &mut TestRng::new(b"split"),
        &pw,
        KDF_FLOOR,
        1_700_000_000_000,
        &items(),
    )
    .unwrap();

    let mut rng = TestRng::new(b"split");
    let draft = export_begin(&mut rng, KDF_FLOOR, 1_700_000_000_000, &items()).unwrap();
    assert_eq!(draft.kdf(), KDF_FLOOR);
    let key = export_wrap_key(&pw, draft.salt(), draft.kdf()).unwrap();
    let salt = *draft.salt();
    let file = draft.finish(&mut rng, &key).unwrap();
    // The same draws in the same order give the same bytes.
    assert_eq!(file, whole);

    // The header read before the password says what the first half made.
    let header = import_prepare(&file).unwrap();
    assert_eq!(header.salt, salt);
    assert_eq!(header.kdf, KDF_FLOOR);
    assert_eq!(header.created_at, 1_700_000_000_000);

    // And the second half opens it, as the whole does.
    let key = export_wrap_key(&password(PASSWORD), &header.salt, header.kdf).unwrap();
    let split = import_decrypt_with_key(&key, &file).unwrap();
    let whole = import_decrypt(&password(PASSWORD), &file).unwrap();
    assert_eq!(split, whole);
    assert_eq!(split.len(), 2);
}

#[test]
fn a_wrong_key_or_a_changed_byte_is_decrypt() {
    let pw = password(PASSWORD);
    let mut rng = TestRng::new(b"split-2");
    let draft = export_begin(&mut rng, KDF_FLOOR, 5, &items()).unwrap();
    let key = export_wrap_key(&pw, draft.salt(), draft.kdf()).unwrap();
    let file = draft.finish(&mut rng, &key).unwrap();

    let header = import_prepare(&file).unwrap();
    let wrong = export_wrap_key(
        &password("another export password"),
        &header.salt,
        header.kdf,
    )
    .unwrap();
    assert_eq!(
        import_decrypt_with_key(&wrong, &file).err(),
        Some(Error::Decrypt)
    );

    let mut bad = file.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        import_decrypt_with_key(&key, &bad).err(),
        Some(Error::Decrypt)
    );
    // The header is part of both AADs.
    let mut bad = file;
    bad[30] ^= 1;
    assert!(import_decrypt_with_key(&key, &bad).is_err());
}

#[test]
fn the_checks_that_need_no_password_come_first() {
    assert_eq!(
        import_prepare(b"not an export").err(),
        Some(Error::Malformed(MalformedKind::ExportHeader))
    );
    // Parameters under the floor or over the ceiling are refused before
    // anything is drawn or computed.
    let low = ferret_core::KdfParams {
        m_kib: 1024,
        t: 1,
        p: 1,
    };
    let mut rng = TestRng::new(b"split-3");
    assert_eq!(
        export_begin(&mut rng, low, 1, &items()).err(),
        Some(Error::KdfOutOfRange)
    );
    let salt = [3u8; 16];
    assert_eq!(
        export_wrap_key(&password(PASSWORD), &salt, low).err(),
        Some(Error::KdfOutOfRange)
    );
    let high = ferret_core::KdfParams {
        m_kib: 600 * 1024,
        t: 3,
        p: 1,
    };
    assert_eq!(
        export_wrap_key(&password(PASSWORD), &salt, high).err(),
        Some(Error::KdfOutOfRange)
    );
    // The same items twice, or a read-only one, are refused at the start.
    let mut twice = items();
    twice.push(twice[0].clone());
    assert!(export_begin(&mut rng, KDF_FLOOR, 1, &twice).is_err());
}

#[test]
fn the_wrap_key_has_a_release_constructor_for_the_hand_over() {
    let key = ExportWrapKey::from_slice(&[7u8; 32]).unwrap();
    assert_eq!(*key.to_bytes(), [7u8; 32]);
    assert_eq!(
        ExportWrapKey::from_slice(&[0u8; 31]).err(),
        Some(Error::InvalidInput(ferret_core::InputError::TooShort))
    );
    assert_eq!(
        ExportWrapKey::from_slice(&[0u8; 33]).err(),
        Some(Error::InvalidInput(ferret_core::InputError::TooLong))
    );
    assert!(ferret_core::PrfOutput::from_slice(&[1u8; 32]).is_ok());
    assert!(ferret_core::PrfOutput::from_slice(&[1u8; 16]).is_err());
    assert!(ferret_core::KekDevPin::from_slice(&[1u8; 32]).is_ok());
    assert!(ferret_core::KekDevPin::from_slice(&[]).is_err());
}
