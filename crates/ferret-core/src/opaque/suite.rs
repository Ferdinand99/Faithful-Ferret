//! The OPAQUE cipher suite of Ferret suite 1.
//!
//! Spec: Fase 1 § 4.2 ("Konfigurasjon"):
//!
//! | Part | Choice |
//! |---|---|
//! | Group and OPRF | ristretto255 with SHA-512 (`ristretto255-SHA512`) |
//! | Key exchange | 3DH over ristretto255 |
//! | Hash, MAC, KDF | SHA-512, HMAC-SHA-512, HKDF-SHA-512 |
//! | KSF | Argon2id v1.3, salt 16 zero bytes, output 64 bytes |
//! | Envelope | internal mode |
//! | Context | ASCII `ferret/v1/opaque` |
//! | Identities | none: the public keys stand in |

use super::ksf::FerretKsf;
use opaque_ke::{CipherSuite, Ristretto255, TripleDh};

/// The OPAQUE context: `ferret/v1/opaque` in ASCII. Both sides put it in the
/// 3DH transcript, so a server that uses another context cannot
/// authenticate.
///
/// Spec: Fase 1 § 4.2 (table, row "Kontekst").
pub const OPAQUE_CONTEXT: &[u8] = b"ferret/v1/opaque";

/// Ferret suite 1: the configuration of the table in the module docs.
///
/// The type is reachable from outside the crate only through
/// `opaque::server_suite`, behind the feature `server-suite`. Without it,
/// nothing outside the crate gets to build a protocol state of this
/// configuration, and no other configuration exists.
pub struct FerretSuite;

impl CipherSuite for FerretSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_010::Sha512>;
    type Ksf = FerretKsf;
}

/// The suite of the RFC 9807 test vectors (Appendix C.1.1 and C.1.2): the
/// same as [`FerretSuite`] in every part except the KSF, which is the
/// identity function there. Only for `test-support`: it is how the
/// implementation is shown to follow the RFC byte for byte, with the same
/// protocol code that runs in production.
#[cfg(feature = "test-support")]
pub(crate) struct RfcSuite;

#[cfg(feature = "test-support")]
impl CipherSuite for RfcSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_010::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}
