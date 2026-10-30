//! The decoder of the two secret files of the server (`opaque_setup`, 128 byte
//! payload, and `prelogin_secret`, 32 byte payload) on arbitrary bytes, and
//! the readers of their payloads.
//!
//! * No input panics.
//! * A file is only accepted at its exact length, and what is accepted is
//!   canonical: encoding the payload again gives exactly the input.
//! * A file of one kind is never accepted as the other.
//! * The payload readers take the exact payload length only; a payload that
//!   they accept gives the same bytes back.
//! * A file made from the input as a payload is accepted, and one flipped
//!   bit, one byte more or one byte less is refused (the checksum covers the
//!   whole file).
#![no_main]

use ferret_server_auth::{
    FileKind, PreloginSecret, SecretFileError, ServerKeys, decode_secret_file, encode_secret_file,
};
use libfuzzer_sys::fuzz_target;

const KINDS: [(FileKind, usize); 2] =
    [(FileKind::OpaqueSetup, 128), (FileKind::PreloginSecret, 32)];

/// The first `n` bytes of `data`, padded with zeros.
fn fit(data: &[u8], n: usize) -> Vec<u8> {
    let mut out = data.get(..n).unwrap_or(data).to_vec();
    out.resize(n, 0);
    out
}

fn payload_readers(kind: FileKind, payload: &[u8]) {
    match kind {
        FileKind::OpaqueSetup => match ServerKeys::from_payload(payload) {
            Ok(keys) => {
                assert_eq!(payload.len(), 128);
                assert_eq!(
                    keys.payload().as_slice(),
                    payload,
                    "the set-up is canonical"
                );
            }
            Err(error) => assert_eq!(error, SecretFileError::PayloadInvalid),
        },
        FileKind::PreloginSecret => match PreloginSecret::from_payload(payload) {
            Ok(secret) => {
                assert_eq!(payload.len(), 32);
                assert_eq!(secret.payload().as_slice(), payload);
            }
            Err(error) => assert_eq!(error, SecretFileError::PayloadInvalid),
        },
    }
}

fuzz_target!(|data: &[u8]| {
    for (kind, payload_len) in KINDS {
        // 1. The bytes as a file.
        let other = if kind == FileKind::OpaqueSetup {
            FileKind::PreloginSecret
        } else {
            FileKind::OpaqueSetup
        };
        match decode_secret_file(kind, data) {
            Ok(payload) => {
                assert_eq!(data.len(), kind.file_len());
                assert_eq!(payload.len(), payload_len);
                let again = encode_secret_file(kind, &payload).expect("a payload of the kind");
                assert_eq!(again.as_slice(), data, "an accepted file is canonical");
                assert!(decode_secret_file(other, data).is_err());
                payload_readers(kind, &payload);
            }
            Err(_) => {}
        }
        if data.len() != kind.file_len() {
            assert!(
                decode_secret_file(kind, data).is_err(),
                "only the exact length"
            );
        }

        // 2. The bytes as a payload, of any length.
        payload_readers(kind, data);

        // 3. A file made around the input, and its damaged copies.
        let payload = fit(data, payload_len);
        let file = encode_secret_file(kind, &payload).expect("a payload of the kind");
        assert_eq!(file.len(), kind.file_len());
        let decoded = decode_secret_file(kind, &file).expect("a file we made");
        assert_eq!(decoded.as_slice(), payload.as_slice());
        payload_readers(kind, &decoded);

        let bit = data.last_chunk::<2>().map_or(0, |b| {
            usize::from(u16::from_be_bytes(*b)) % (file.len() * 8)
        });
        let mut flipped = file.to_vec();
        flipped[bit / 8] ^= 1 << (bit % 8);
        assert!(
            decode_secret_file(kind, &flipped).is_err(),
            "bit {bit} was not noticed"
        );

        let mut longer = file.to_vec();
        longer.push(data.first().copied().unwrap_or(0));
        assert_eq!(
            decode_secret_file(kind, &longer).err(),
            Some(SecretFileError::TrailingBytes)
        );
        assert_eq!(
            decode_secret_file(kind, &file[..file.len() - 1]).err(),
            Some(SecretFileError::BadLength)
        );
        // A payload of the wrong length is not made into a file.
        assert_eq!(
            encode_secret_file(kind, &payload[..payload_len - 1]).err(),
            Some(SecretFileError::BadLength)
        );
    }
});
