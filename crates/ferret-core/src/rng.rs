//! Randomness. All code that needs random bytes takes `&mut impl SecureRng`;
//! production code uses [`OsRng`] only.

/// A source of cryptographically secure random bytes.
pub trait SecureRng {
    /// Fills `dest` completely with random bytes.
    ///
    /// There is no error path: a source that cannot deliver randomness must
    /// not let the caller continue with weak or partial output.
    fn fill(&mut self, dest: &mut [u8]);
}

/// The operating system's random number generator (`getrandom` 0.4).
///
/// On `wasm32-unknown-unknown` this uses the `wasm_js` backend (Web Crypto),
/// selected through `--cfg getrandom_backend="wasm_js"` in `.cargo/config.toml`.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl SecureRng for OsRng {
    fn fill(&mut self, dest: &mut [u8]) {
        if getrandom::fill(dest).is_err() {
            os_rng_unavailable();
        }
    }
}

/// Aborts the operation when the operating system cannot supply randomness.
/// Continuing would mean generating keys or nonces from weak input. The
/// release profile uses `panic = "abort"`.
#[cold]
#[inline(never)]
#[allow(clippy::panic)]
fn os_rng_unavailable() -> ! {
    panic!("operating system randomness unavailable")
}
