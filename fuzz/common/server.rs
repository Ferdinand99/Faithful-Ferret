//! The fixed server that the `fuzz_server_*` targets run against: one
//! registered account, a throttle that admits everything, a clock that does
//! not move, and a login whose KE1, KE2 and KE3 are known.
//!
//! Every login of this server draws from the same seeded random source, so a
//! `login_start` for the same KE1 gives the same login id and the same KE2
//! each time. That is what lets a target hold a valid KE3 ready and still
//! start a fresh login (in a fresh store) for every input.
//!
//! The key stretching function is the small test one (`testing::SMALL`): the
//! server runs no Argon2, and the client side runs it once, here.
#![allow(dead_code)]

use ferret_core::OPAQUE_CONTEXT;
use ferret_core::testing::TestRng;
use ferret_server_auth::testing::{FIXTURE_PASSWORD, LoginFixture};
use ferret_server_auth::{
    AccountLookup, AuthContext, AuthError, Caller, CredentialId, InMemoryLoginStateStore,
    LoginFinishRequest, LoginPurpose, LoginStartRequest, LoginStartResponse, LoginVerified,
    NoThrottle, SessionBinding, SessionScope,
};

pub struct World {
    pub f: LoginFixture,
    /// A valid KE1 (96 bytes).
    pub ke1: Vec<u8>,
    /// The KE2 that `start` answers it with (320 bytes).
    pub ke2: Vec<u8>,
    /// The KE3 that finishes that login (64 bytes).
    pub ke3: Vec<u8>,
    /// The id of that login, as the client sends it (32 characters).
    pub login_id: Vec<u8>,
}

impl World {
    pub fn new() -> Self {
        let f = LoginFixture::new();
        let (ke1, client) = f.client_start(FIXTURE_PASSWORD, "fuzz client");
        let mut world = Self {
            f,
            ke1,
            ke2: Vec::new(),
            ke3: Vec::new(),
            login_id: Vec::new(),
        };
        let store = InMemoryLoginStateStore::new();
        let ke1 = world.ke1.clone();
        let started = world
            .start(&store, world.f.active(), &ke1, LoginPurpose::Login, None)
            .expect("the valid KE1 starts a login");
        world.ke3 = world
            .f
            .client_finish(client, FIXTURE_PASSWORD, &started.ke2, OPAQUE_CONTEXT)
            .expect("the client finishes");
        world.login_id = started.login_id.to_hex().into_bytes();
        world.ke2 = started.ke2;
        world
    }

    /// The server's context, with a throttle that admits everything.
    pub fn cx(&self) -> AuthContext<'_> {
        AuthContext::new(
            &self.f.keys,
            &self.f.prelogin,
            &self.f.seal,
            &self.f.clock,
            &NoThrottle,
            &self.f.policy,
            &self.f.profiles,
        )
    }

    pub fn caller() -> Caller {
        Caller { ip: None }
    }

    /// `login_start` for the account of the world (or whatever `lookup` says)
    /// with the one seeded random source.
    pub fn start(
        &self,
        store: &InMemoryLoginStateStore,
        lookup: AccountLookup<'_>,
        ke1: &[u8],
        purpose: LoginPurpose,
        session_scope: Option<SessionScope>,
    ) -> Result<LoginStartResponse, AuthError> {
        ferret_server_auth::login_start(
            &self.cx(),
            store,
            &mut TestRng::new(b"fuzz server"),
            &LoginStartRequest {
                caller: Self::caller(),
                name: &self.f.name,
                credential: self.f.credential,
                lookup,
                purpose,
                session_scope,
                ke1,
            },
        )
    }

    /// `login_finish` for the login id and KE3 given.
    pub fn finish(
        &self,
        store: &InMemoryLoginStateStore,
        login_id: &[u8],
        ke3: &[u8],
        current_session: Option<(SessionBinding, CredentialId)>,
    ) -> Result<LoginVerified, AuthError> {
        ferret_server_auth::login_finish(
            &self.cx(),
            store,
            &LoginFinishRequest {
                caller: Self::caller(),
                login_id,
                ke3,
                current_session,
            },
        )
    }

    /// A store that holds the valid login.
    pub fn store_with_login(&self) -> InMemoryLoginStateStore {
        let store = InMemoryLoginStateStore::new();
        let started = self
            .start(
                &store,
                self.f.active(),
                &self.ke1,
                LoginPurpose::Login,
                None,
            )
            .expect("the valid KE1 starts a login");
        assert_eq!(started.login_id.to_hex().as_bytes(), self.login_id);
        assert_eq!(started.ke2, self.ke2, "the login is deterministic");
        store
    }
}

/// The first `n` bytes of `data`, padded with zeros if it is shorter.
pub fn fit(data: &[u8], n: usize) -> Vec<u8> {
    let mut out = data.get(..n).unwrap_or(data).to_vec();
    out.resize(n, 0);
    out
}

// ------------------------------------------------------------ the signer

use ferret_core::{
    AccountId, AuthPublicKey, MutationOp, RecoveryKey, RecoveryPublicKey, UnlockedVault,
    VaultContext, VaultId, VaultKey, auth_sign, recovery_public_key, recovery_sign,
};
use ferret_server_auth::SignedAccount;

/// The client of one account, with the keys that sign its requests, and what
/// the server holds of that account.
pub struct Signer {
    vault: UnlockedVault,
    recovery_key: RecoveryKey,
    /// The account as the server's row holds it (epoch 1, row version 1).
    pub account: SignedAccount,
}

impl Signer {
    pub fn new() -> Self {
        let account_id = AccountId::from_bytes([0x11; 16]);
        let vault = UnlockedVault::from_vault_key(
            VaultContext {
                account_id,
                vault_id: VaultId::from_bytes([0x22; 16]),
                vk_epoch: 1,
            },
            VaultKey::from_test_bytes([3; 32]),
        )
        .expect("the keys derive");
        let recovery_key = RecoveryKey::from_test_bytes([5; 32]);
        let pk_r = recovery_public_key(&recovery_key, &account_id).expect("a recovery key");
        let account = SignedAccount {
            account_id,
            pk_a: AuthPublicKey::new(vault.auth_public_key()),
            pk_r: RecoveryPublicKey::new(pk_r),
            vk_epoch: 1,
            row_version: 1,
        };
        Self {
            vault,
            recovery_key,
            account,
        }
    }

    /// The proof of `op` over `nonce` and `body`, as the client makes it.
    pub fn sign(&self, op: MutationOp, nonce: &[u8; 32], body: &[u8]) -> [u8; 64] {
        match op.auth() {
            Some(auth) => auth_sign(&self.vault, auth, nonce, body),
            None => recovery_sign(&self.recovery_key, &self.account.account_id, 1, nonce, body),
        }
        .expect("a proof is signed")
    }
}
