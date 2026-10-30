//! The small fields a client or a session store hands to the server as bytes:
//! the login id, the stored session scope, and the nonce and proof of a signed
//! request. The first byte picks one.
//!
//! * `LoginId::parse` takes exactly 32 lower-case hexadecimal characters, and
//!   what it accepts writes back as the same bytes.
//! * `SessionScope::parse_stored` gives a scope other than `Unverified` only
//!   for the exact name of that scope; everything else, a missing value and
//!   text with other case or white space included, is `Unverified`, and the
//!   names round-trip.
//! * `authorize_replacement` and `authorize_signed` never accept bytes as a
//!   nonce and a proof: a nonce of the wrong length is `Malformed(Nonce)`, a
//!   proof of the wrong length `Malformed(Proof)` (and neither burns the
//!   nonce), a nonce that was not issued to the session is `NonceUnknown`, and
//!   a proof that was not made by the account is `ProofInvalid` and burns the
//!   nonce. The parser of the endpoint (here a sink) is called only after a
//!   valid proof, so never.
#![no_main]

#[path = "../common/server.rs"]
mod server;

use std::cell::Cell;

use ferret_core::MutationOp;
use ferret_server_auth::testing::{LoginFixture, put_nonce};
use ferret_server_auth::{
    AccountAuthState, AuthError, Capability, DenyReason, InMemoryChallengeStore, InternalKind,
    LoginId, Malformed, ReplaceFields, ReplaceKind, ReplaceRequest, SessionBinding, SessionScope,
    SignedRequest, authorize, authorize_replacement, authorize_signed,
};
use libfuzzer_sys::fuzz_target;
use server::{Signer, World, fit};

struct Fixed {
    world: World,
    signer: Signer,
}

thread_local! {
    static FIXED: Fixed = Fixed { world: World::new(), signer: Signer::new() };
}

const SESSION: SessionBinding = SessionBinding([0xA1; 32]);

fuzz_target!(|data: &[u8]| {
    let Some((&select, body)) = data.split_first() else {
        return;
    };
    match select % 3 {
        0 => login_id(body),
        1 => scope(body),
        _ => FIXED.with(|fixed| nonce_and_proof(fixed, select / 3, body)),
    }
});

// ------------------------------------------------------------ login id

fn login_id(body: &[u8]) {
    let malformed = AuthError::Malformed(Malformed::LoginId);
    match LoginId::parse(body) {
        Ok(id) => {
            assert_eq!(body.len(), LoginId::HEX_LEN);
            assert!(body.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
            assert_eq!(id.to_hex().as_bytes(), body, "a login id is canonical");
            // Upper case is not the wire form.
            if body.iter().any(u8::is_ascii_lowercase) {
                assert_eq!(
                    LoginId::parse(&body.to_ascii_uppercase()).err(),
                    Some(malformed)
                );
            }
        }
        Err(error) => assert_eq!(error, malformed),
    }
    if body.len() != LoginId::HEX_LEN {
        assert_eq!(LoginId::parse(body).err(), Some(malformed));
    }
    let exact = fit(body, LoginId::HEX_LEN);
    match LoginId::parse(&exact) {
        Ok(id) => assert_eq!(id.to_hex().as_bytes(), exact.as_slice()),
        Err(error) => assert_eq!(error, malformed),
    }
    let mut longer = exact.clone();
    longer.push(b'0');
    assert_eq!(LoginId::parse(&longer).err(), Some(malformed));
    assert_eq!(
        LoginId::parse(&exact[..exact.len() - 1]).err(),
        Some(malformed)
    );
}

// ----------------------------------------------------- the stored scope

const SCOPES: [SessionScope; 4] = [
    SessionScope::Full,
    SessionScope::Pending2fa,
    SessionScope::AccountReset,
    SessionScope::Unverified,
];

fn scope(body: &[u8]) {
    assert_eq!(SessionScope::parse_stored(None), SessionScope::Unverified);
    for scope in SCOPES {
        assert_eq!(SessionScope::parse_stored(Some(scope.as_str())), scope);
    }
    let lossy = String::from_utf8_lossy(body);
    let texts = [std::str::from_utf8(body).ok(), Some(lossy.as_ref())];
    for text in texts.into_iter().flatten() {
        let parsed = SessionScope::parse_stored(Some(text));
        match SCOPES.iter().find(|s| s.as_str() == text) {
            Some(named) => assert_eq!(parsed, *named),
            None => assert_eq!(parsed, SessionScope::Unverified, "{text:?} is not a scope"),
        }
        // What a text can never do is give a scope more than the exact name.
        for cap in Capability::ALL {
            assert_eq!(authorize(parsed, *cap).is_ok(), parsed.allows(*cap));
            if let Err(error) = authorize(parsed, *cap) {
                assert_eq!(error, AuthError::Denied(DenyReason::ScopeForbids));
            }
        }
    }
}

// -------------------------------------------------- nonce and proof

/// The answer to a request that carries `nonce` and `proof` that nobody
/// signed. Every route is tried with a fresh store.
fn nonce_and_proof(fixed: &Fixed, which: u8, body: &[u8]) {
    let Some((&cut, rest)) = body.split_first() else {
        return;
    };
    let cut = usize::from(cut) % (rest.len() + 1);
    let (nonce, proof) = rest.split_at(cut);
    let nonce32 = fit(nonce, 32);
    let proof64 = fit(proof, 64);
    let issued: [u8; 32] = nonce32.as_slice().try_into().expect("32 bytes");

    // Which route: the two record replacements, then the other signed
    // operations.
    let ops = MutationOp::ALL;
    let op = ops[usize::from(which) % ops.len()];
    let sink_called = Cell::new(false);
    let run = |store: &InMemoryChallengeStore,
               scope: SessionScope,
               session: SessionBinding,
               nonce: &[u8],
               proof: &[u8]| {
        let cx = fixed.world.cx();
        match op {
            MutationOp::UnlockMethodPasswordPut | MutationOp::Recover => {
                let kind = if op == MutationOp::Recover {
                    ReplaceKind::Recover
                } else {
                    ReplaceKind::PasswordPut
                };
                authorize_replacement(
                    &cx,
                    store,
                    &AccountAuthState {
                        account: fixed.signer.account,
                        current: &fixed.world.f.record,
                    },
                    &ReplaceRequest {
                        caller: World::caller(),
                        kind,
                        scope,
                        session,
                        nonce,
                        proof,
                        body: b"{}",
                    },
                    |_| {
                        sink_called.set(true);
                        Err::<ReplaceFields, _>(AuthError::Malformed(Malformed::RegistrationRecord))
                    },
                )
                .map(|_| ())
            }
            _ => authorize_signed(
                &cx,
                store,
                &fixed.signer.account,
                &SignedRequest {
                    caller: World::caller(),
                    op,
                    scope,
                    session,
                    nonce,
                    proof,
                    body: b"{}",
                },
            )
            .map(|_| ()),
        }
    };
    let store_with_nonce = || {
        let store = InMemoryChallengeStore::new();
        put_nonce(&store, &SESSION, &issued, LoginFixture::START);
        store
    };

    // 1. The bytes as they are, with the nonce issued (if it has the length).
    let store = store_with_nonce();
    let raw = run(&store, SessionScope::Full, SESSION, nonce, proof);
    let expected = if nonce.len() != 32 {
        AuthError::Malformed(Malformed::Nonce)
    } else if proof.len() != 64 {
        AuthError::Malformed(Malformed::Proof)
    } else {
        AuthError::Denied(DenyReason::ProofInvalid)
    };
    assert_eq!(
        raw,
        Err(expected),
        "{op:?}: unsigned bytes must not be accepted"
    );
    // A length error burns nothing; a wrong proof burns the nonce.
    let again = run(&store, SessionScope::Full, SESSION, &nonce32, &proof64);
    if expected == AuthError::Denied(DenyReason::ProofInvalid) && nonce == nonce32 {
        assert_eq!(again, Err(AuthError::Denied(DenyReason::NonceUnknown)));
    } else if nonce == nonce32 {
        assert_eq!(again, Err(AuthError::Denied(DenyReason::ProofInvalid)));
    }

    // 2. A nonce that was issued: a proof that is not the account's.
    let store = store_with_nonce();
    assert_eq!(
        run(&store, SessionScope::Full, SESSION, &nonce32, &proof64),
        Err(AuthError::Denied(DenyReason::ProofInvalid))
    );
    assert_eq!(
        run(&store, SessionScope::Full, SESSION, &nonce32, &proof64),
        Err(AuthError::Denied(DenyReason::NonceUnknown)),
        "a nonce is used once"
    );

    // 3. A nonce issued to another session finds nothing.
    let store = store_with_nonce();
    assert_eq!(
        run(
            &store,
            SessionScope::Full,
            SessionBinding([0xB2; 32]),
            &nonce32,
            &proof64
        ),
        Err(AuthError::Denied(DenyReason::NonceUnknown))
    );

    // 4. A session that may not do this is refused before the bytes are read,
    // and its nonce is not used.
    let store = store_with_nonce();
    for scope in [SessionScope::Unverified, SessionScope::Pending2fa] {
        assert_eq!(
            run(&store, scope, SESSION, nonce, proof),
            Err(AuthError::Denied(DenyReason::ScopeForbids))
        );
    }
    assert_eq!(
        run(&store, SessionScope::Full, SESSION, &nonce32, &proof64),
        Err(AuthError::Denied(DenyReason::ProofInvalid)),
        "the nonce was still there"
    );

    assert!(
        !sink_called.get(),
        "the body was read before a proof was seen"
    );

    // The two operations that replace the record are not signed requests
    // of the other kind: the library refuses to skip the checks of the record.
    for op in [MutationOp::UnlockMethodPasswordPut, MutationOp::Recover] {
        assert_eq!(
            authorize_signed(
                &fixed.world.cx(),
                &store_with_nonce(),
                &fixed.signer.account,
                &SignedRequest {
                    caller: World::caller(),
                    op,
                    scope: SessionScope::Full,
                    session: SESSION,
                    nonce: &nonce32,
                    proof: &proof64,
                    body: b"{}",
                },
            )
            .err(),
            Some(AuthError::Internal(InternalKind::Policy))
        );
    }
}
