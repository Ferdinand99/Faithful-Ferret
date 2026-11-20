//! The response headers of the web vault's origin.
//!
//! Spec: Fase 1 § 12. The values below are the section's list, word for word;
//! `tests/fixtures/wire/headers.json` has the same list, which the tests
//! compare with the specification and with these constants, and which the web
//! vault's test server sends. No third-party script, no inline script or
//! style, and Trusted Types for every script sink.

/// `Content-Security-Policy` of every response of the vault listener.
pub const VAULT_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types ferret";

/// The headers every response of the vault listener carries, as `(name,
/// value)`.
pub const VAULT_HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", VAULT_CSP),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
    ),
];

/// The two files of the import worker: the entry that the page starts and the module that it
/// loads. The worker reads the file a user imports and passes what it makes to the vault worker
/// over a port, so it needs no connection and gets a stricter policy than the rest of the vault.
pub const IMPORT_WORKER_PATHS: [&str; 2] =
    ["/js/import.worker.mjs", "/app/workers/import.worker.mjs"];

/// `Content-Security-Policy` of the import worker's files: [`VAULT_CSP`] with `connect-src 'none'`,
/// so the worker cannot send, fetch or open anything over the network (a worker keeps the policy
/// of its own script, not that of the page). Everything else is the same.
pub const IMPORT_WORKER_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'none'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'; trusted-types ferret";
