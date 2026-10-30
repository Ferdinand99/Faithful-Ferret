//! The export file reader on arbitrary bytes, in two ways: the bytes as a
//! whole file (the header parser and the checks before Argon2id), and the
//! bytes sealed as an authentic body under a known key, so that the reader of
//! the body gets past the AEAD.
//!
//! Argon2id runs only with tiny parameters: a header with parameters inside
//! the real floor and ceiling would cost 64 MiB or more per input, so such a
//! file is only checked up to the point where the production reader would
//! start Argon2id.
#![no_main]

use ferret_core::testing::TestRng;
use ferret_core::testing::export::{
    export_encrypt_raw_unchecked, export_encrypt_unchecked, import_decrypt_unchecked,
};
use ferret_core::{
    Error, ExportPassword, KdfParams, check_kdf_params, import_decrypt, parse_export_header,
};
use libfuzzer_sys::fuzz_target;

const TINY: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fuzz_target!(|data: &[u8]| {
    let pw = ExportPassword::for_open(b"a fuzzing password").expect("a valid password");

    // 1. The bytes as a file.
    match parse_export_header(data) {
        Ok((header, used)) => {
            assert!(used <= data.len());
            if check_kdf_params(header.kdf).is_err() {
                // The production reader refuses before it computes anything.
                assert_eq!(import_decrypt(&pw, data).err(), Some(Error::KdfOutOfRange));
            }
            if header.kdf.m_kib <= 256 && header.kdf.t <= 2 && header.kdf.p <= 2 {
                // Never opens (no one can forge the tags), but must not panic.
                assert!(import_decrypt_unchecked(&pw, data).is_err());
            }
        }
        Err(_) => assert!(import_decrypt(&pw, data).is_err()),
    }

    // 2. The bytes as an authentic body.
    let mut rng = TestRng::new(b"fuzz export");
    let file = export_encrypt_raw_unchecked(&mut rng, &pw, TINY, 0, data)
        .expect("a body within the limit is sealed");
    if let Ok(items) = import_decrypt_unchecked(&pw, &file) {
        // What reads writes again and reads back the same, unless it is
        // read-only (a newer schema), which cannot be written.
        match export_encrypt_unchecked(&mut rng, &pw, TINY, 0, &items) {
            Ok(again) => {
                let back = import_decrypt_unchecked(&pw, &again).expect("what was written reads");
                assert_eq!(back, items);
            }
            Err(e) => assert_eq!(e, Error::ReadOnlySchema),
        }
    }
});
