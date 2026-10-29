//! The passkey key pair (ECDSA P-256, ES256), its COSE and SPKI encodings,
//! the attestation object and the assertion signature.
//!
//! Spec: Fase 1 § 9.1 and § 9.3. The private key is PKCS#8 DER inside the
//! item body and is used only in the core. It has no `Debug`, `Clone` or
//! `PartialEq`, and the DER is wiped on drop.
//!
//! * COSE_Key (RFC 9053 § 2.1, RFC 9052): `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`
//!   (kty EC2, alg ES256, crv P-256), in CTAP2 canonical order.
//! * Attestation object: `{"fmt": "none", "attStmt": {}, "authData": …}`.
//! * Signature: ES256, ASN.1 DER, over `authData ‖ SHA-256(clientDataJSON)`.
//!   The ECDSA nonce is the deterministic one of RFC 6979 (what the `ecdsa`
//!   crate does), so no randomness is drawn when signing.

use crate::error::{Error, MalformedKind};
use crate::rng::SecureRng;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// COSE algorithm identifier of ES256.
pub const COSE_ALG_ES256: i64 = -7;

/// How many times a draw is repeated when it is not a valid scalar. A draw is
/// outside the range with probability about 2^-32.
const MAX_KEY_DRAWS: usize = 16;

/// The private key of a passkey: P-256, PKCS#8 DER.
pub struct PasskeyPrivateKey {
    der: Zeroizing<Vec<u8>>,
}

fn bad_key() -> Error {
    Error::Malformed(MalformedKind::ItemBody)
}

impl PasskeyPrivateKey {
    /// A fresh key. Draws 32 bytes from `rng` for the scalar (and draws again
    /// in the negligible case that they are not a valid one).
    pub(crate) fn generate<R: SecureRng>(rng: &mut R) -> Result<Self, Error> {
        for _ in 0..MAX_KEY_DRAWS {
            let mut scalar = Zeroizing::new([0u8; 32]);
            rng.fill(scalar.as_mut_slice());
            if let Ok(key) = SigningKey::from_slice(scalar.as_slice()) {
                return Self::from_signing_key(&key);
            }
        }
        // 16 invalid draws in a row cannot happen with a working source.
        Err(Error::Unsupported)
    }

    fn from_signing_key(key: &SigningKey) -> Result<Self, Error> {
        let doc = key.to_pkcs8_der().map_err(|_| bad_key())?;
        Ok(Self {
            der: Zeroizing::new(doc.as_bytes().to_vec()),
        })
    }

    /// Reads a key from PKCS#8 DER (as stored in the item body). Rejects
    /// anything that is not a P-256 private key.
    pub(crate) fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_der(der).map_err(|_| bad_key())?;
        drop(key);
        Ok(Self {
            der: Zeroizing::new(der.to_vec()),
        })
    }

    /// The PKCS#8 DER, for sealing into the item body.
    pub(crate) fn der(&self) -> &[u8] {
        &self.der
    }

    fn signing_key(&self) -> Result<SigningKey, Error> {
        SigningKey::from_pkcs8_der(&self.der).map_err(|_| bad_key())
    }

    /// The public key as `(x, y)`, 32 bytes each.
    pub(crate) fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), Error> {
        let key = self.signing_key()?;
        let point = key.verifying_key().to_sec1_point(false);
        let x = point.x().ok_or_else(bad_key)?;
        let y = point.y().ok_or_else(bad_key)?;
        let x: [u8; 32] = x.as_slice().try_into().map_err(|_| bad_key())?;
        let y: [u8; 32] = y.as_slice().try_into().map_err(|_| bad_key())?;
        Ok((x, y))
    }

    /// The public key as SubjectPublicKeyInfo DER (`getPublicKey()`).
    pub(crate) fn public_spki(&self) -> Result<Vec<u8>, Error> {
        let key = self.signing_key()?;
        let doc = key
            .verifying_key()
            .to_public_key_der()
            .map_err(|_| bad_key())?;
        Ok(doc.as_bytes().to_vec())
    }

    /// ES256 over `auth_data ‖ SHA-256(client_data_json)`, DER encoded.
    pub(crate) fn sign_assertion(
        &self,
        auth_data: &[u8],
        client_data_json: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let key = self.signing_key()?;
        let mut msg = Vec::with_capacity(auth_data.len().saturating_add(32));
        msg.extend_from_slice(auth_data);
        msg.extend_from_slice(&Sha256::digest(client_data_json));
        let sig: Signature = key.try_sign(&msg).map_err(|_| Error::Unsupported)?;
        msg.zeroize();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// The COSE_Key of an ES256 public key: 77 bytes.
///
/// ```text
/// a5 01 02 03 26 20 01 21 58 20 <x:32> 22 58 20 <y:32>
/// ```
pub(crate) fn cose_key_es256(x: &[u8; 32], y: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(77);
    out.extend_from_slice(&[
        0xa5, // map(5)
        0x01, 0x02, // 1: 2        kty: EC2
        0x03, 0x26, // 3: -7       alg: ES256
        0x20, 0x01, // -1: 1       crv: P-256
        0x21, 0x58, 0x20, // -2: bstr(32)  x
    ]);
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]); // -3: bstr(32)  y
    out.extend_from_slice(y);
    out
}

/// The attestation object with format `none`:
/// `{"fmt": "none", "attStmt": {}, "authData": auth_data}`.
pub(crate) fn attestation_object_none(auth_data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(auth_data.len().saturating_add(40));
    out.push(0xa3); // map(3)
    out.extend_from_slice(&[0x63, b'f', b'm', b't']); // "fmt"
    out.extend_from_slice(&[0x64, b'n', b'o', b'n', b'e']); // "none"
    out.extend_from_slice(&[0x67, b'a', b't', b't', b'S', b't', b'm', b't']); // "attStmt"
    out.push(0xa0); // {}
    out.extend_from_slice(&[0x68, b'a', b'u', b't', b'h', b'D', b'a', b't', b'a']); // "authData"
    let len = auth_data.len();
    if len < 24 {
        out.push(0x40 | u8::try_from(len).map_err(|_| Error::TooLarge)?);
    } else if len < 256 {
        out.extend_from_slice(&[0x58, u8::try_from(len).map_err(|_| Error::TooLarge)?]);
    } else {
        out.push(0x59);
        out.extend_from_slice(
            &u16::try_from(len)
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
    }
    out.extend_from_slice(auth_data);
    Ok(out)
}
