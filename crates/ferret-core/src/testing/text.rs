//! Access to the bytes inside the text and code types, for tests and vector
//! runners. Behind `test-support`; never part of a release.

use crate::secret::{RecoveryKey, SecretKey};
use crate::text::{ExportPassword, MasterPassword, OpaqueInput};

/// The NFKD bytes of a master password.
pub fn master_password_bytes(mp: &MasterPassword) -> Vec<u8> {
    mp.as_bytes().to_vec()
}

/// The bytes of an OPAQUE input.
pub fn opaque_input_bytes(input: &OpaqueInput) -> Vec<u8> {
    input.as_bytes().to_vec()
}

/// The NFKD bytes of an export password.
pub fn export_password_bytes(pw: &ExportPassword) -> Vec<u8> {
    pw.as_bytes().to_vec()
}

/// The 32 bytes of a recovery key.
pub fn recovery_key_bytes(rk: &RecoveryKey) -> [u8; 32] {
    *rk.expose()
}

/// The 16 bytes of a secret key.
pub fn secret_key_bytes(sk: &SecretKey) -> [u8; 16] {
    *sk.expose()
}
