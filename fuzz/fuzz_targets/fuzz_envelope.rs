//! The envelope parser and the opening functions (plan section 9.2), in two
//! ways.
//!
//! 1. Unkeyed: the bytes as an envelope, and as an envelope plus its tag.
//!    `parse_envelope` is total and keeps the length rules, and no arbitrary
//!    input opens (it has no valid tag).
//! 2. Keyed: a mutated input never gets past the tag and the AEAD by itself,
//!    so the input is sealed under a fixed test vault key and then opened.
//!    That puts the mutated bytes behind the authentication, where the
//!    padding removal and the CBOR readers of the item body and the manifest
//!    run. The first byte chooses what is sealed: an item or the manifest,
//!    and the rest as plaintext (padded by the core) or as an already padded
//!    body (so that a bad padding is authentic too). Its upper six bits pick
//!    the byte that is flipped in the tamper check.
//!
//! The oracle of the keyed part is differential: opening the sealed input
//! gives exactly what reading the same bytes directly gives. A flipped bit
//! anywhere in the sealed envelope or its tag never opens.
#![no_main]

use ferret_core::item::pad;
use ferret_core::testing::TestRng;
use ferret_core::testing::item::{
    seal_manifest_padded_body, seal_manifest_plaintext, seal_padded, seal_plaintext,
};
use ferret_core::{
    AccountId, DecodedItem, Error, ItemBody, ItemId, Manifest, SealedItem, UnlockedVault,
    VaultContext, VaultId, VaultKey, decrypt_item, decrypt_manifest, parse_envelope,
};
use libfuzzer_sys::fuzz_target;

const EPOCH: u64 = 1;
const REV: u64 = 7;

fn vault() -> UnlockedVault {
    UnlockedVault::from_vault_key(
        VaultContext {
            account_id: AccountId::from_bytes([1; 16]),
            vault_id: VaultId::from_bytes([2; 16]),
            vk_epoch: EPOCH,
        },
        VaultKey::from_test_bytes([3; 32]),
    )
    .expect("the keys derive")
}

fn item_id() -> ItemId {
    ItemId::from_bytes([4; 16])
}

/// The error codes the readers of a body or a manifest give for authentic
/// bytes: a bad padding is `decrypt`, bad CBOR is `malformed_cbor*`, a body
/// of the wrong shape is `malformed_item_body`, a manifest of a future
/// version is `unsupported`.
fn is_reader_error(e: &Error) -> bool {
    let code = e.code();
    code.starts_with("malformed_cbor")
        || code == "malformed_item_body"
        || code == "unsupported"
        || code == "decrypt"
}

fn unkeyed(vault: &UnlockedVault, data: &[u8]) {
    match parse_envelope(data) {
        Ok(view) => {
            assert!(data.len() <= 65_536);
            assert!(view.body.len() >= 24 + 256 + 16);
            assert!(view.ik_wrap.is_none_or(|w| w.len() == 72));
        }
        Err(e) => assert!(matches!(
            e.code(),
            "malformed_envelope" | "decrypt" | "too_large"
        )),
    }
    // The first 32 bytes double as the tag, the rest is the envelope.
    let (tag, envelope) = data.split_at(data.len().min(32));
    let mut tag32 = [0u8; 32];
    tag32[..tag.len()].copy_from_slice(tag);
    assert!(decrypt_item(vault, item_id(), REV, envelope, &tag32).is_err());
    assert!(decrypt_manifest(vault, REV, envelope, &tag32).is_err());
}

/// What reading an item body directly gives, after the padding is removed.
fn direct_item(plain_len: Result<usize, Error>, padded: &[u8]) -> Result<DecodedItem, Error> {
    match plain_len {
        Ok(len) => ItemBody::from_cbor(&padded[..len]),
        Err(e) => Err(e),
    }
}

/// What reading the manifest directly gives, with the epoch check of
/// `decrypt_manifest`.
fn direct_manifest(plain_len: Result<usize, Error>, padded: &[u8]) -> Result<Manifest, Error> {
    let len = plain_len?;
    let manifest = Manifest::from_cbor(&padded[..len])?;
    if manifest.vk_epoch == EPOCH {
        Ok(manifest)
    } else {
        Err(Error::Decrypt)
    }
}

/// Flips one bit of the envelope or the tag.
fn flip(sealed: &SealedItem, at: usize) -> (Vec<u8>, [u8; 32]) {
    let mut envelope = sealed.envelope.clone();
    let mut tag = sealed.tag;
    let at = at % (envelope.len() + tag.len());
    if at < envelope.len() {
        envelope[at] ^= 1 << (at % 8);
    } else {
        tag[at - envelope.len()] ^= 1 << (at % 8);
    }
    (envelope, tag)
}

fn keyed(vault: &UnlockedVault, data: &[u8]) {
    let Some((&mode, payload)) = data.split_first() else {
        return;
    };
    let manifest = mode & 1 == 1;
    let already_padded = mode & 2 == 2;
    let at = usize::from(mode >> 2)
        .wrapping_mul(997)
        .wrapping_add(payload.len());
    let mut rng = TestRng::new(b"fuzz envelope keyed");

    // The buffer the core seals, and what the padding removal makes of it.
    let padded: Vec<u8> = if already_padded {
        // The payload as it is, with zeros up to the next padding class.
        let Ok(class) = pad::padded_len(payload.len().saturating_sub(1)) else {
            return;
        };
        let mut padded = payload.to_vec();
        padded.resize(class, 0);
        padded
    } else {
        match pad::pad(payload) {
            Ok(padded) => padded.to_vec(),
            Err(_) => return,
        }
    };
    let unpadded = pad::unpad(&padded);

    if manifest {
        let sealed = if already_padded {
            seal_manifest_padded_body(&mut rng, vault, REV, &padded)
        } else {
            seal_manifest_plaintext(&mut rng, vault, REV, payload)
        }
        .expect("a padded body is sealed");
        assert!(parse_envelope(&sealed.envelope).is_ok());
        let opened = decrypt_manifest(vault, REV, &sealed.envelope, &sealed.tag);
        assert_eq!(opened, direct_manifest(unpadded, &padded));
        if let Err(e) = &opened {
            assert!(is_reader_error(e), "{}", e.code());
        }
        let (envelope, tag) = flip(&sealed, at);
        let e = decrypt_manifest(vault, REV, &envelope, &tag).expect_err("a flipped bit opened");
        assert!(matches!(e.code(), "decrypt" | "malformed_envelope"));
    } else {
        let sealed = if already_padded {
            seal_padded(&mut rng, vault, item_id(), REV, &padded)
        } else {
            seal_plaintext(&mut rng, vault, item_id(), REV, payload, None)
        }
        .expect("a padded body is sealed");
        assert!(parse_envelope(&sealed.envelope).is_ok());
        let opened = decrypt_item(vault, item_id(), REV, &sealed.envelope, &sealed.tag);
        assert_eq!(opened, direct_item(unpadded, &padded));
        match &opened {
            // What opens and can be written writes again and opens to the
            // same body, unknown fields included.
            Ok(item) if !item.read_only => {
                let cbor = item.body.to_cbor().expect("an opened body can be written");
                let again = ItemBody::from_cbor(&cbor).expect("and read again");
                assert_eq!(again.body, item.body);
            }
            Ok(_) => {}
            Err(e) => assert!(is_reader_error(e), "{}", e.code()),
        }
        let (envelope, tag) = flip(&sealed, at);
        let e =
            decrypt_item(vault, item_id(), REV, &envelope, &tag).expect_err("a flipped bit opened");
        assert!(matches!(e.code(), "decrypt" | "malformed_envelope"));
    }
}

fuzz_target!(|data: &[u8]| {
    let vault = vault();
    unkeyed(&vault, data);
    keyed(&vault, data);
});
