//! `authenticatorData` (WebAuthn L3 § 6.1).
//!
//! Spec: Fase 1 § 9.3 (F-29) and plan U13.
//!
//! ```text
//! rpIdHash(32) ‖ flags(1) ‖ signCount(4) ‖ [ aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE_Key ] ‖ [ extensions ]
//! ```
//!
//! * Flags: `UP` 0x01, `UV` 0x04, `BE` 0x08, `BS` 0x10, `AT` 0x40, `ED` 0x80.
//!   `BE` and `BS` are always set: every Ferret passkey is a synchronized,
//!   backed-up credential, and `BE` does not change during its life.
//! * `signCount` is always 0, as for other synchronized passkeys.
//! * `AT` and the attested credential data are only in the answer to
//!   `create`. `ED` and `{"hmac-secret": true}` only when `create` asked for
//!   `prf`; nothing for `get`.
//! * `UV` is set only when the user verified in this request.

use crate::error::Error;

/// Bit 0: user present.
pub const FLAG_UP: u8 = 0x01;
/// Bit 2: user verified.
pub const FLAG_UV: u8 = 0x04;
/// Bit 3: backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Bit 4: backup state.
pub const FLAG_BS: u8 = 0x10;
/// Bit 6: attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Bit 7: extension data included.
pub const FLAG_ED: u8 = 0x80;

/// The AAGUID of Ferret: one UUIDv4 for every installation, chosen once for
/// this project, `dc704a44-b994-410c-a689-ed8d71a84ac3`.
///
/// It is not per instance and not per user (an AAGUID per instance would
/// identify self-hosters). It is exposed in every `create` response and
/// documented, so that sites can put Ferret on an allow-list. Attestation is
/// `none`, so the value is not signed by anything.
pub const AAGUID: [u8; 16] = [
    0xdc, 0x70, 0x4a, 0x44, 0xb9, 0x94, 0x41, 0x0c, 0xa6, 0x89, 0xed, 0x8d, 0x71, 0xa8, 0x4a, 0xc3,
];

/// The extension data of `create` with `prf`: the CBOR map
/// `{"hmac-secret": true}`.
const EXT_HMAC_SECRET: [u8; 14] = [
    0xa1, // map(1)
    0x6b, // text(11)
    b'h', b'm', b'a', b'c', b'-', b's', b'e', b'c', b'r', b'e', b't', //
    0xf5, // true
];

/// What `create` adds to the authenticator data.
pub(crate) struct Attested<'a> {
    /// The credential id.
    pub credential_id: &'a [u8],
    /// The COSE_Key of the public key.
    pub cose_key: &'a [u8],
    /// Whether to write the `hmac-secret` extension (`create` with `prf`).
    pub hmac_secret: bool,
}

/// Builds the authenticator data.
pub(crate) fn authenticator_data(
    rp_id_hash: &[u8; 32],
    user_verified: bool,
    attested: Option<&Attested<'_>>,
) -> Result<Vec<u8>, Error> {
    // UP is always set: a response without a user click is never made.
    let mut flags = FLAG_UP | FLAG_BE | FLAG_BS;
    if user_verified {
        flags |= FLAG_UV;
    }
    if let Some(a) = attested {
        flags |= FLAG_AT;
        if a.hmac_secret {
            flags |= FLAG_ED;
        }
    }
    let mut out = Vec::with_capacity(160);
    out.extend_from_slice(rp_id_hash);
    out.push(flags);
    out.extend_from_slice(&0u32.to_be_bytes());
    if let Some(a) = attested {
        let len = u16::try_from(a.credential_id.len()).map_err(|_| Error::TooLarge)?;
        out.extend_from_slice(&AAGUID);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(a.credential_id);
        out.extend_from_slice(a.cose_key);
        if a.hmac_secret {
            out.extend_from_slice(&EXT_HMAC_SECRET);
        }
    }
    Ok(out)
}
