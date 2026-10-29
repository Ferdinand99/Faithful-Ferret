//! The server's OPAQUE messages on arbitrary bytes (plan section 9.2): the
//! bytes as `KE2` of a login, and as the `registration_response` of a
//! registration, each with a client in a fixed state.
//!
//! The key stretching function runs with tiny parameters (through
//! `testing::opaque`): a real profile would cost 64 MiB for every input that
//! parses. Both messages must be refused with the structure error or the
//! authentication error, or (for a registration response, which has nothing
//! to verify) produce a record of the right length; nothing may panic.
#![no_main]

use ferret_core::testing::TestRng;
use ferret_core::testing::opaque::{TestKsf, login_finish_with, register_finish_with};
use ferret_core::{
    Error, KdfParams, MalformedKind, MasterPassword, OPAQUE_CONTEXT, PinState, opaque_login_start,
    opaque_register_start,
};
use libfuzzer_sys::fuzz_target;

const TINY: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fuzz_target!(|data: &[u8]| {
    let ksf = TestKsf::new(TINY);
    let pw = MasterPassword::for_unlock(b"a fuzzing password")
        .expect("a valid password")
        .opaque_input(None);
    let mut rng = TestRng::new(b"fuzz opaque");

    // 1. The bytes as KE2.
    let (_ke1, state) = opaque_login_start(&mut rng, &pw).expect("login start");
    match login_finish_with(&mut rng, state, &pw, data, &ksf, Some(OPAQUE_CONTEXT), PinState::FirstUse) {
        Ok(_) => panic!("random bytes were accepted as a KE2"),
        Err(Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)) => {}
        Err(other) => panic!("unexpected error {other:?}"),
    }

    // 2. The bytes as a registration response.
    let (_request, state) = opaque_register_start(&mut rng, &pw).expect("register start");
    match register_finish_with(&mut rng, state, &pw, data, &ksf) {
        Ok(done) => assert_eq!(done.record.len(), 192),
        Err(Error::Decrypt | Error::Malformed(MalformedKind::OpaqueMessage)) => {}
        Err(other) => panic!("unexpected error {other:?}"),
    }
});
