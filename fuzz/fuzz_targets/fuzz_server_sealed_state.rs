//! The sealed login state, in four ways. The first byte picks one.
//!
//! 0. The input as a sealed blob: no input opens. The only answer is
//!    `Denied(StateInvalid)`, for every expected purpose, whatever the length.
//! 1. The input as the content of a state, which is sealed and opened again:
//!    `open(seal(x)) == x`; the blob has its fixed length; a state is dead at
//!    its expiry and not before; another login id, another key, another
//!    purpose or another session or account does not open it; and any flipped
//!    bit, one byte more or one byte less is refused with the one error.
//! 2. The input as the plaintext of a state (reached through `test-support`):
//!    it parses only at the exact length and only to something that encodes
//!    to the same bytes; the `ServerLogin` inside goes through the parser of
//!    `opaque-ke`, which must not panic.
//! 3. The input as the `ServerLogin` bytes of a state that is sealed
//!    correctly, finished by `login_finish`: never `Ok` unless the KE3 is the
//!    expected MAC stored in the state (its last 64 bytes), and a changed byte
//!    of that MAC in the real state is refused.
#![no_main]

#[path = "../common/server.rs"]
mod server;

use ferret_core::testing::TestRng;
use ferret_server_auth::testing::vectors::peek_server_login;
use ferret_server_auth::testing::{
    LoginFixture, SEALED_STATE_LEN, STATE_PLAIN_LEN, StateFields, encode_state_plain, open_fields,
    parse_state_plain, put_state, seal_fields, server_login_parses,
};
use ferret_server_auth::{
    AuthError, DenyReason, InMemoryLoginStateStore, InternalKind, LoginId, Malformed, SealedState,
    StateSealKey,
};
use libfuzzer_sys::fuzz_target;
use server::{World, fit};

const NOW: u64 = LoginFixture::START;
const SERVER_LOGIN_LEN: usize = 128;

type Reauth = Option<([u8; 32], [u8; 16])>;

struct State {
    key: StateSealKey,
    other_key: StateSealKey,
    world: World,
    /// The `ServerLogin` bytes of the real login of the world.
    real_login: [u8; SERVER_LOGIN_LEN],
}

fn state() -> State {
    let world = World::new();
    let id = LoginId::parse(&world.login_id).expect("a login id");
    let store = world.store_with_login();
    let real_login = *peek_server_login(&world.f.seal, &store, &id, NOW).expect("the real state");
    State {
        key: StateSealKey::random(&mut TestRng::new(b"fuzz seal key")),
        other_key: StateSealKey::random(&mut TestRng::new(b"fuzz other seal key")),
        world,
        real_login,
    }
}

thread_local! {
    static STATE: State = state();
}

fn id(n: u8) -> LoginId {
    LoginId::parse(format!("{:032x}", u128::from(n) + 1).as_bytes()).expect("a login id")
}

const INVALID: AuthError = AuthError::Denied(DenyReason::StateInvalid);

/// Bytes read from the input in turn; the input is read again from its start
/// when it runs out.
struct Bytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bytes<'_> {
    fn byte(&mut self) -> u8 {
        let byte = self.data.get(self.pos % self.data.len().max(1)).copied();
        self.pos = self.pos.wrapping_add(1);
        byte.unwrap_or(0)
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        std::array::from_fn(|_| self.byte())
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&select, body)) = data.split_first() else {
        return;
    };
    STATE.with(|s| match select % 4 {
        0 => raw_blob(s, body),
        1 => round_trip(s, body),
        2 => plaintext(body),
        _ => server_login_in_a_state(s, body),
    });
});

// ------------------------------------------------------ 0. a forged blob

fn raw_blob(s: &State, body: &[u8]) {
    let session = [3u8; 32];
    let account = [4u8; 16];
    let exact = fit(body, SEALED_STATE_LEN);
    let mut versioned = exact.clone();
    versioned[0] = 1;
    for blob in [body.to_vec(), exact, versioned] {
        let sealed = SealedState::from_bytes(blob);
        for expected in [None, Some((session, account))] {
            assert_eq!(
                open_fields(&s.key, &id(1), &sealed, expected, NOW).err(),
                Some(INVALID),
                "a blob that nobody sealed was opened"
            );
        }
    }
}

// --------------------------------------------------------- 1. round trip

fn round_trip(s: &State, body: &[u8]) {
    let mut bytes = Bytes { data: body, pos: 0 };
    let reauth: Reauth = (bytes.byte() & 1 == 1).then(|| (bytes.array(), bytes.array()));
    let fields = StateFields {
        credential: bytes.array(),
        reauth,
        expires_at: NOW + 1 + u64::from(u16::from_be_bytes(bytes.array())),
        ksf_profile: bytes.byte(),
        server_login: bytes.array(),
    };
    let flip = bytes.array::<2>();
    let login = id(bytes.byte() % 8);

    let seed: [u8; 8] = bytes.array();
    let sealed = seal_fields(&s.key, &mut TestRng::new(&seed), &login, &fields, NOW)
        .expect("a live state is sealed");
    assert_eq!(sealed.as_bytes().len(), SEALED_STATE_LEN);
    assert_eq!(
        open_fields(&s.key, &login, &sealed, fields.reauth, NOW).as_ref(),
        Ok(&fields),
        "open(seal(x)) is x"
    );
    // A second sealing is another blob that opens to the same content.
    let again = seal_fields(
        &s.key,
        &mut TestRng::new(&[b"second ".as_slice(), &seed].concat()),
        &login,
        &fields,
        NOW,
    )
    .expect("sealed again");
    assert_ne!(
        again.as_bytes(),
        sealed.as_bytes(),
        "the nonce is new each time"
    );
    assert_eq!(
        open_fields(&s.key, &login, &again, fields.reauth, NOW).as_ref(),
        Ok(&fields)
    );

    // Time: valid before the expiry, dead from it.
    assert!(
        open_fields(
            &s.key,
            &login,
            &sealed,
            fields.reauth,
            fields.expires_at - 1
        )
        .is_ok()
    );
    for now in [fields.expires_at, fields.expires_at + 1, u64::MAX] {
        assert_eq!(
            open_fields(&s.key, &login, &sealed, fields.reauth, now).err(),
            Some(AuthError::Denied(DenyReason::StateExpired))
        );
    }
    for now in [fields.expires_at, u64::MAX] {
        assert_eq!(
            seal_fields(&s.key, &mut TestRng::new(&seed), &login, &fields, now).err(),
            Some(AuthError::Internal(InternalKind::Clock)),
            "a state that is dead when it is made is not sealed"
        );
    }

    // Another login id, another key, another purpose.
    assert_eq!(
        open_fields(&s.key, &id(9), &sealed, fields.reauth, NOW).err(),
        Some(INVALID)
    );
    assert_eq!(
        open_fields(&s.other_key, &login, &sealed, fields.reauth, NOW).err(),
        Some(INVALID)
    );
    let mut wrong = vec![Some(([0; 32], [0; 16]))];
    if let Some((session, account)) = fields.reauth {
        let mut other_session = session;
        other_session[usize::from(flip[0]) % 32] ^= 1;
        let mut other_account = account;
        other_account[usize::from(flip[1]) % 16] ^= 1;
        wrong = vec![
            None,
            Some((other_session, account)),
            Some((session, other_account)),
        ];
    }
    for expected in wrong {
        assert_eq!(
            open_fields(&s.key, &login, &sealed, expected, NOW).err(),
            Some(INVALID)
        );
    }

    // Damage: the chosen bit, one bit in every byte, one byte more or less.
    let blob = sealed.as_bytes();
    let bit = usize::from(u16::from_be_bytes(flip)) % (blob.len() * 8);
    let refused = |changed: Vec<u8>| {
        open_fields(
            &s.key,
            &login,
            &SealedState::from_bytes(changed),
            fields.reauth,
            NOW,
        )
        .err()
            == Some(INVALID)
    };
    let mut changed = blob.to_vec();
    changed[bit / 8] ^= 1 << (bit % 8);
    assert!(refused(changed), "bit {bit} was not noticed");
    for index in 0..blob.len() {
        let mut changed = blob.to_vec();
        changed[index] ^= 1 << (flip[0] % 8);
        assert!(
            refused(changed),
            "a flipped bit in byte {index} was not noticed"
        );
    }
    let mut longer = blob.to_vec();
    longer.push(0);
    assert!(refused(longer));
    assert!(refused(blob[..blob.len() - 1].to_vec()));
}

// ----------------------------------------------------- 2. the plaintext

fn plaintext(body: &[u8]) {
    match parse_state_plain(body) {
        Ok(fields) => {
            assert_eq!(body.len(), STATE_PLAIN_LEN);
            assert_eq!(
                encode_state_plain(&fields),
                body,
                "a state that parses is canonical"
            );
            let _ = server_login_parses(&fields.server_login);
        }
        Err(error) => assert_eq!(error, INVALID),
    }
    if body.len() != STATE_PLAIN_LEN {
        assert!(parse_state_plain(body).is_err(), "only the exact length");
    }

    let exact = fit(body, STATE_PLAIN_LEN);
    match parse_state_plain(&exact) {
        Ok(fields) => assert_eq!(encode_state_plain(&fields), exact),
        Err(error) => assert_eq!(error, INVALID),
    }
    let mut longer = exact.clone();
    longer.push(0);
    assert!(parse_state_plain(&longer).is_err());
    assert!(parse_state_plain(&exact[..STATE_PLAIN_LEN - 1]).is_err());

    // The parser of the library inside the state, on any bytes.
    let _ = server_login_parses(body);
    let _ = server_login_parses(&exact[STATE_PLAIN_LEN - SERVER_LOGIN_LEN..]);
    let _ = server_login_parses(&fit(body, SERVER_LOGIN_LEN));
}

// --------------------------------------- 3. a ServerLogin inside a state

fn server_login_in_a_state(s: &State, body: &[u8]) {
    let world = &s.world;
    let login = LoginId::parse(&world.login_id).expect("a login id");
    let mut bytes = Bytes { data: body, pos: 0 };
    let mut server_login: [u8; SERVER_LOGIN_LEN] = bytes.array();
    let ke3 = fit(body.get(SERVER_LOGIN_LEN..).unwrap_or(&[]), 64);

    // Any bytes as the stored `ServerLogin`.
    let run = |server_login: [u8; SERVER_LOGIN_LEN], ke3: &[u8]| {
        let fields = StateFields {
            credential: *world.f.credential.as_bytes(),
            reauth: None,
            expires_at: NOW + 60,
            ksf_profile: 1,
            server_login,
        };
        let sealed = seal_fields(
            &world.f.seal,
            &mut TestRng::new(b"fuzz seal"),
            &login,
            &fields,
            NOW,
        )
        .expect("a live state is sealed");
        let store = InMemoryLoginStateStore::new();
        put_state(&store, &login, sealed, NOW);
        let answer = world.finish(&store, &world.login_id, ke3, None);
        assert!(store.is_empty(), "the state is used up whatever the answer");
        answer
    };
    match run(server_login, &ke3) {
        // The server compares the KE3 with the expected MAC it stored, so a
        // state whose MAC is the KE3 finishes; no other does.
        Ok(_) => assert_eq!(
            &server_login[64..],
            ke3.as_slice(),
            "a state with another MAC was finished"
        ),
        Err(AuthError::Denied(DenyReason::Ke3) | AuthError::Internal(InternalKind::Crypto)) => {}
        Err(error) => assert_eq!(error, AuthError::Malformed(Malformed::Ke3)),
    }

    // The real state, with one byte of it changed. The session key (the first
    // 64 bytes) is not checked by the server; the expected MAC (the last 64)
    // is, so a change there must be refused, and the real KE3 finishes the
    // login only with the real MAC.
    assert!(
        run(s.real_login, &world.ke3).is_ok(),
        "the real state finishes"
    );
    let index = usize::from(bytes.byte()) % SERVER_LOGIN_LEN;
    server_login = s.real_login;
    server_login[index] ^= 1 << (bytes.byte() % 8);
    match run(server_login, &world.ke3) {
        Ok(_) => assert!(index < 64, "a changed MAC was accepted"),
        Err(error) => assert!(
            matches!(
                error,
                AuthError::Denied(DenyReason::Ke3) | AuthError::Internal(InternalKind::Crypto)
            ),
            "unexpected error {error:?}"
        ),
    }
}
