//! The four messages a client sends to the OPAQUE server, as arbitrary bytes:
//! the registration request (32 bytes), the uploaded record (192), KE1 (96)
//! and KE3 (64). The first byte picks the message; the rest is the message,
//! tried as it is and also cut or padded to its exact length (so that a
//! mutated input gets past the length check and reaches the point decoding).
//!
//! The server is a fixed one (see `common/server.rs`) with a throttle that
//! admits everything. For every message:
//!
//! * nothing panics, and the answer is `Ok` or exactly the error that the
//!   bytes alone decide (`Malformed`, or for a KE3 that does not verify
//!   `Denied`);
//! * a message of the wrong length is refused with the same error whatever
//!   it holds, and a refusal by structure leaves the login state in the
//!   store;
//! * `login_finish` is never `Ok` for a KE3 that is not the one of the login;
//!   one flipped bit of the right KE3 is refused; and a known and an unknown
//!   name (or a disabled account) are answered alike for every KE1.
#![no_main]

#[path = "../common/server.rs"]
mod server;

use ferret_server_auth::{
    AccountLookup, AuthError, CredentialId, DenyReason, InMemoryLoginStateStore, LoginId,
    LoginPurpose, Malformed, NoThrottle, ProfileRules, RegisterStartRequest, RegistrationAuthority,
    RegistrationKind, SessionBinding, SessionScope, ValidatedRecord, register_finish,
    register_start,
};
use libfuzzer_sys::fuzz_target;
use server::{World, fit};

const REQUEST_LEN: usize = 32;
const RESPONSE_LEN: usize = 64;
const RECORD_LEN: usize = 192;
const KE1_LEN: usize = 96;
const KE2_LEN: usize = 320;
const KE3_LEN: usize = 64;

thread_local! {
    static WORLD: World = World::new();
}

fuzz_target!(|data: &[u8]| {
    let Some((&select, body)) = data.split_first() else {
        return;
    };
    WORLD.with(|world| match select % 4 {
        0 => registration_request(world, body),
        1 => record(body),
        2 => ke1(world, body),
        _ => ke3(world, body),
    });
});

// ------------------------------------------------- registration request

fn register(
    world: &World,
    authority: RegistrationAuthority,
    request: &[u8],
) -> Result<Vec<u8>, AuthError> {
    register_start(
        &world.f.keys,
        &NoThrottle,
        0,
        &RegisterStartRequest {
            caller: World::caller(),
            authority,
            credential: world.f.credential,
            request,
        },
    )
}

fn registration_request(world: &World, body: &[u8]) {
    let malformed = AuthError::Malformed(Malformed::RegistrationRequest);
    let new_account = RegistrationAuthority::NewAccount;

    // The bytes as they are: right length and a valid element, or the one
    // error of the structure.
    let raw = register(world, new_account, body);
    match &raw {
        Ok(response) => {
            assert_eq!(body.len(), REQUEST_LEN);
            assert_eq!(response.len(), RESPONSE_LEN);
        }
        Err(error) => assert_eq!(*error, malformed),
    }
    if body.len() != REQUEST_LEN {
        assert_eq!(raw, Err(malformed), "a wrong length is refused");
    }

    // The exact length: the same two answers, and the same one every time.
    let exact = fit(body, REQUEST_LEN);
    let first = register(world, new_account, &exact);
    match &first {
        Ok(response) => assert_eq!(response.len(), RESPONSE_LEN),
        Err(error) => assert_eq!(*error, malformed),
    }
    assert_eq!(first, register(world, new_account, &exact));

    // One byte more or less is refused, whatever the bytes are.
    let mut longer = exact.clone();
    longer.push(body.first().copied().unwrap_or(0));
    assert_eq!(register(world, new_account, &longer), Err(malformed));
    assert_eq!(
        register(world, new_account, &exact[..REQUEST_LEN - 1]),
        Err(malformed)
    );

    // A session of the account answers as a new account does; a session that
    // may not register, or that is for another account, is refused before the
    // bytes are read.
    let own = RegistrationAuthority::Session {
        scope: SessionScope::Full,
        account: world.f.credential,
    };
    assert_eq!(register(world, own, &exact), first);
    let unverified = RegistrationAuthority::Session {
        scope: SessionScope::Unverified,
        account: world.f.credential,
    };
    let foreign = RegistrationAuthority::Session {
        scope: SessionScope::Full,
        account: CredentialId::from_bytes([0x99; 16]),
    };
    for refused in [unverified, foreign] {
        assert_eq!(
            register(world, refused, body),
            Err(AuthError::Denied(DenyReason::ScopeForbids))
        );
    }
}

// ---------------------------------------------------------- the record

fn record(body: &[u8]) {
    let malformed = AuthError::Malformed(Malformed::RegistrationRecord);

    let parsed = ValidatedRecord::parse(body);
    match &parsed {
        Ok(record) => {
            assert_eq!(body.len(), RECORD_LEN);
            assert_eq!(record.as_bytes(), body, "the record is stored as it came");
        }
        Err(error) => assert_eq!(*error, malformed),
    }
    if body.len() != RECORD_LEN {
        assert!(parsed.is_err(), "a wrong length is refused");
    }

    let exact = fit(body, RECORD_LEN);
    match ValidatedRecord::parse(&exact) {
        Ok(record) => assert_eq!(record.as_bytes(), exact.as_slice()),
        Err(error) => assert_eq!(error, malformed),
    }
    let mut longer = exact.clone();
    longer.push(0);
    assert!(ValidatedRecord::parse(&longer).is_err());
    assert!(ValidatedRecord::parse(&exact[..RECORD_LEN - 1]).is_err());

    // The profile is claimed in the first four bytes of the body, so a
    // mutation of the first bytes moves it together with the record.
    let claimed = body
        .get(..4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or(1, u32::from_be_bytes);
    let rules = ProfileRules::ferret_v1();
    for upload in [body, exact.as_slice()] {
        let shape = ValidatedRecord::parse(upload);
        match register_finish(upload, claimed, &rules, RegistrationKind::NewAccount) {
            Ok(stored) => {
                assert!(shape.is_ok());
                assert_eq!(stored.record.as_bytes(), upload);
                assert_eq!(
                    rules.accept(claimed, RegistrationKind::NewAccount),
                    Ok(stored.ksf_profile)
                );
            }
            // The shape is checked first, so a bad record never depends on
            // the profile.
            Err(error) if shape.is_err() => assert_eq!(error, malformed),
            Err(error) => assert_eq!(error, AuthError::ProfileRejected),
        }
        // A password change never lowers the stored profile.
        let lowered = register_finish(upload, claimed, &rules, RegistrationKind::Existing(255));
        assert!(
            lowered.is_err() || claimed == 255,
            "a profile below the stored one was accepted"
        );
    }
}

// --------------------------------------------------------------- KE1

fn ke1(world: &World, body: &[u8]) {
    let malformed = AuthError::Malformed(Malformed::Ke1);
    let exact = fit(body, KE1_LEN);
    for ke1 in [body, exact.as_slice()] {
        let mut shapes = Vec::new();
        for lookup in [
            world.f.active(),
            AccountLookup::Unknown,
            AccountLookup::Disabled,
        ] {
            let store = InMemoryLoginStateStore::new();
            let answer = world.start(&store, lookup, ke1, LoginPurpose::Login, None);
            match &answer {
                Ok(started) => {
                    assert_eq!(ke1.len(), KE1_LEN);
                    assert_eq!(started.ke2.len(), KE2_LEN);
                    assert_eq!(store.len(), 1, "one state per login");
                }
                Err(error) => {
                    assert_eq!(*error, malformed);
                    assert!(store.is_empty(), "a refused KE1 leaves no state");
                }
            }
            if ke1.len() != KE1_LEN {
                assert_eq!(answer.as_ref().err(), Some(&malformed));
            }
            // What a client can see: whether it worked, the size and the
            // profile. Not which of the three it was.
            shapes.push(answer.map(|a| (a.ke2.len(), a.ksf_profile)));
        }
        assert!(
            shapes.windows(2).all(|pair| pair[0] == pair[1]),
            "known, unknown and disabled are answered alike"
        );
    }

    // A re-authentication needs a scope that allows it, whatever the KE1.
    let reauth = LoginPurpose::Reauth {
        session: SessionBinding([7; 32]),
        account: world.f.credential,
    };
    for scope in [
        None,
        Some(SessionScope::Pending2fa),
        Some(SessionScope::Unverified),
    ] {
        let store = InMemoryLoginStateStore::new();
        assert_eq!(
            world
                .start(&store, world.f.active(), body, reauth, scope)
                .err(),
            Some(AuthError::Denied(DenyReason::ScopeForbids))
        );
        assert!(store.is_empty());
    }
    let store = InMemoryLoginStateStore::new();
    let allowed = world.start(
        &store,
        world.f.active(),
        &exact,
        reauth,
        Some(SessionScope::Full),
    );
    assert!(allowed.is_ok() || allowed.err() == Some(malformed));
}

// --------------------------------------------------------------- KE3

fn ke3(world: &World, body: &[u8]) {
    let malformed = AuthError::Malformed(Malformed::Ke3);
    let id = world.login_id.as_slice();

    // A KE3 of the wrong length is refused by structure and leaves the state
    // in the store, so the right KE3 still finishes the login afterwards.
    if body.len() != KE3_LEN {
        let store = world.store_with_login();
        assert_eq!(world.finish(&store, id, body, None).err(), Some(malformed));
        assert_eq!(
            store.len(),
            1,
            "a structure error does not use the state up"
        );
        let done = world
            .finish(&store, id, &world.ke3, None)
            .expect("the right KE3 finishes the login");
        assert!(done.credential == world.f.credential);
    }

    // The bytes at the exact length: only the real KE3 finishes the login,
    // and the state is used up by every KE3 that was checked.
    let exact = fit(body, KE3_LEN);
    let store = world.store_with_login();
    match world.finish(&store, id, &exact, None) {
        Ok(done) => {
            assert_eq!(exact, world.ke3, "random bytes were accepted as a KE3");
            assert!(done.credential == world.f.credential);
            assert!(store.is_empty());
        }
        Err(AuthError::Denied(DenyReason::Ke3)) => assert!(store.is_empty()),
        Err(error) => panic!("unexpected error {error:?}"),
    }

    // One flipped bit of the right KE3 is refused, and the state is gone.
    let bit = body
        .get(..2)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, |b| usize::from(u16::from_be_bytes(b)) % (KE3_LEN * 8));
    let mut flipped = world.ke3.clone();
    flipped[bit / 8] ^= 1 << (bit % 8);
    let store = world.store_with_login();
    assert_eq!(
        world.finish(&store, id, &flipped, None).err(),
        Some(AuthError::Denied(DenyReason::Ke3))
    );
    assert!(store.is_empty());

    // The login id comes from the client too: any text but the right one
    // finds nothing, and the right KE3 does not help.
    let store = world.store_with_login();
    match world.finish(&store, body, &world.ke3, None) {
        Ok(_) => assert_eq!(body, id),
        Err(error) => {
            if LoginId::parse(body).is_ok() {
                assert_eq!(error, AuthError::Denied(DenyReason::StateMissing));
            } else {
                assert_eq!(error, AuthError::Malformed(Malformed::LoginId));
            }
            assert_eq!(store.len(), 1, "the state of the real login is untouched");
        }
    }

    // A login that was not started as a re-authentication is not finished as
    // one, with the right KE3 or with this one.
    let session = Some((SessionBinding([7; 32]), world.f.credential));
    for ke3 in [&world.ke3, &exact] {
        let store = world.store_with_login();
        assert_eq!(
            world.finish(&store, id, ke3, session).err(),
            Some(AuthError::Denied(DenyReason::StateInvalid))
        );
        assert!(store.is_empty());
    }
}
