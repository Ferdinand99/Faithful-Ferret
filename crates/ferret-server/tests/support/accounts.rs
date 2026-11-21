//! Test accounts straight into the database, with `create_account` of the vault
//! store: no registration, no OPAQUE exchange, just the rows.
//!
//! The ids of an account follow from a small number, so two accounts of a test
//! never share one, and a test can name an account by its number.
//!
//! For the routes that change the unlock methods there is also a client: a
//! [`Client`] is an account the client of `ferret-core` made, registered
//! against the app's own OPAQUE keys (with the small test key stretching), with
//! its open vault, its recovery key and its pinned record. The helpers below
//! it make the bodies of a password change, a new recovery key and a
//! recovery, sign them, and send them.

use std::sync::OnceLock;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use ferret_core::testing::opaque::{TestKsf, register_finish_with};
use ferret_core::{
    KsfProfile, ManifestRow, MasterPassword, MpPolicy, NewAccountIds, NewPassword, OpaqueInput,
    PasswordChange, PinState, Pinned, Recovered, RecoveryInput, RecoveryKey, RegistrationFinished,
    RenewedRecovery, SealedItem, TestRng, UnlockedVault, WrapRecord, change_password,
    encode_recovery_key, opaque_register_start, recover, renew_recovery,
};
use ferret_server::auth::session::{Origin, mark_reauth};
use ferret_server::ids::{AccountId, DeviceId, MANIFEST_ITEM_ID, MethodId, VaultId};
use ferret_server::state::VaultDb;
use ferret_server::vault::store::{
    CheckpointIn, ManifestIn, MethodRow, NewAccountRows, create_account,
};
use ferret_server::wire::{PasswordPutReq, RecoverReq, RecoveryPutReq, SealedRowJson, b64url};
use ferret_server_auth::testing::{LoginFixture, SMALL, register_start_open};
use ferret_server_auth::{
    Clock as _, CredentialId, ProfileRules, RegistrationKind, SessionScope, StoredRecord,
    register_finish,
};
use rusqlite::Connection;
use serde_json::json;

use super::session::{Issued, issue, nonce_for};
use super::{Jar, Req, Res, TestApp, VAULT_URL, Which};

/// The ids of a test account and its kit user.
#[derive(Clone, Copy, Debug)]
pub struct TestAccount {
    /// The kit user.
    pub user_id: i64,
    /// The account.
    pub account_id: AccountId,
    /// Its vault.
    pub vault_id: VaultId,
    /// A device that writes to it.
    pub device: DeviceId,
}

/// A 16-byte id: a kind byte, the number of the account and zeros.
pub fn id16(kind: u8, n: u8) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0] = kind;
    bytes[1] = n;
    bytes
}

/// A valid OPAQUE record. Made once: registering is the slow part.
pub fn stored_record() -> StoredRecord {
    static RECORD: OnceLock<StoredRecord> = OnceLock::new();
    RECORD.get_or_init(|| LoginFixture::new().record).clone()
}

/// A kit user with this name; returns its id.
pub fn insert_user(conn: &Connection, name: &str) -> i64 {
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?1, 'x', 'editor')",
        [name],
    )
    .expect("a user");
    conn.last_insert_rowid()
}

/// The ids of test account `n` (the kit user comes from `user_id`).
pub fn account_ids(user_id: i64, n: u8) -> TestAccount {
    TestAccount {
        user_id,
        account_id: AccountId::from_bytes(id16(0xa0, n)),
        vault_id: VaultId::from_bytes(id16(0xb0, n)),
        device: DeviceId(id16(0xd0, n)),
    }
}

/// The rows of test account `n` for kit user `user_id`: a password wrap and a
/// recovery wrap, a manifest of 40 bytes at revision 1, a checkpoint at 1.
pub fn rows(user_id: i64, n: u8, now: i64) -> NewAccountRows {
    let ids = account_ids(user_id, n);
    NewAccountRows {
        account_id: ids.account_id,
        user_id,
        vault_id: ids.vault_id,
        record: stored_record(),
        sk_hint: true,
        pk_a: [0x11; 32],
        pk_r: [0x22; 32],
        methods: vec![
            MethodRow {
                method_id: MethodId::from_bytes(id16(0xc1, n)),
                method_type: 1,
                wrap: vec![0x31; 60],
                kek_generation: 1,
                credential_id: None,
                prf_salt: None,
                aaguid: None,
            },
            MethodRow {
                method_id: MethodId::from_bytes(id16(0xc2, n)),
                method_type: 2,
                wrap: vec![0x32; 60],
                kek_generation: 1,
                credential_id: None,
                prf_salt: None,
                aaguid: None,
            },
        ],
        manifest: ManifestIn {
            rev: 1,
            envelope: vec![0x4d; 40],
            tag: [0x7a; 32],
        },
        checkpoint: CheckpointIn {
            seq: 1,
            digest: vec![0x41; 32],
            mac: vec![0x42; 32],
            entries: vec![0x43; 20],
        },
        now,
    }
}

/// Inserts a user and test account `n` into `conn`, in one transaction.
pub fn add_account(conn: &mut Connection, n: u8, now: i64) -> TestAccount {
    let user_id = insert_user(conn, &format!("user{n}@example.com"));
    let tx = conn.transaction().expect("a transaction");
    create_account(&tx, &rows(user_id, n, now)).expect("create_account");
    tx.commit().expect("commit");
    account_ids(user_id, n)
}

/// Inserts a user and test account `n` into the database of a running
/// [`TestApp`], with the app's clock as `created_at`.
pub async fn add_account_to_app(app: &TestApp, n: u8) -> TestAccount {
    let db: VaultDb = app.state.vault_db.clone();
    let now = i64::try_from(app.state.clock.now_unix()).expect("a time");
    db.with_conn(move |conn| Ok(add_account(conn, n, now)))
        .await
        .expect("an account")
}

/// The id of the manifest row, for tests that read it back.
pub const MANIFEST: ferret_server::ids::ItemId = MANIFEST_ITEM_ID;

// ---------------------------------------------------------------- clients

/// The master password of a [`Client`] when it is made.
pub const CLIENT_PASSWORD: &str = "correct horse battery staple";

/// The OPAQUE input of `password`, without a secret key.
pub fn opaque_input(password: &str) -> OpaqueInput {
    MasterPassword::new(password.as_bytes(), MpPolicy::WithoutSecretKey)
        .expect("a password")
        .opaque_input(None)
}

/// An account as its client holds it: the open vault, the recovery key, the
/// pinned record, and the wraps and the manifest the server holds now.
pub struct Client {
    /// The ids of the account and its kit user.
    pub ids: TestAccount,
    /// The master password the server knows now.
    pub password: String,
    /// The open vault.
    pub vault: UnlockedVault,
    /// The recovery key the server knows now.
    pub recovery_key: RecoveryKey,
    /// The device's pinned record.
    pub pinned: Pinned,
    /// The password wrap the server holds.
    pub password_wrap: WrapRecord,
    /// The recovery wrap the server holds.
    pub recovery_wrap: WrapRecord,
    /// The manifest row the server holds.
    pub manifest: SealedItem,
    /// Where the client's random bytes come from.
    pub rng: TestRng,
}

impl Client {
    /// The state after the server took `change`: the new wrap, manifest, pin
    /// and password.
    pub fn took_password(&mut self, change: &PasswordChange, password: &str) {
        self.pinned = change
            .pinned(&self.pinned)
            .expect("the pin after the change");
        self.password_wrap = change.wrap.clone();
        self.manifest = change.manifest.clone();
        self.password = password.to_string();
    }
}

/// A registration of `password` for `account`, finished by the client against
/// the app's keys (no route, no throttle).
pub fn registration_for(
    app: &TestApp,
    account: &AccountId,
    password: &str,
    rng: &mut TestRng,
) -> RegistrationFinished {
    let input = opaque_input(password);
    let (request, state) = opaque_register_start(rng, &input).expect("a first message");
    let response = register_start_open(
        &app.state.secrets.keys,
        &CredentialId::from(account),
        &request,
    )
    .expect("an answer");
    register_finish_with(rng, state, &input, &response, &TestKsf::new(SMALL))
        .expect("the client finishes")
}

/// Account `n` as the client of `ferret-core` makes it at registration, with
/// [`CLIENT_PASSWORD`], written into the app's database: a real OPAQUE record
/// against the app's keys, a real `pk_a` and `pk_r`, both wraps at generation
/// 1, the manifest at revision 1 and the first checkpoint.
pub async fn client_account(app: &TestApp, n: u8) -> Client {
    let mut rng = TestRng::new(format!("client account {n}").as_bytes());
    let ids = account_ids(0, n);
    let input = opaque_input(CLIENT_PASSWORD);
    let registration = registration_for(app, &ids.account_id, CLIENT_PASSWORD, &mut rng);
    let new = ferret_core::create_account(
        &mut rng,
        &NewAccountIds {
            account_id: ids.account_id,
            vault_id: ids.vault_id,
            password_method_id: MethodId::from_bytes(id16(0xc1, n)),
            recovery_method_id: MethodId::from_bytes(id16(0xc2, n)),
        },
        NewPassword {
            input: &input,
            registration,
            profile: KsfProfile::P1,
        },
        None,
    )
    .expect("the client makes the account");
    let record = register_finish(
        &new.registration_record,
        u32::from(new.ksf_profile.number()),
        &ProfileRules::ferret_v1(),
        RegistrationKind::NewAccount,
    )
    .expect("a record");
    let methods = new
        .wraps
        .iter()
        .map(|w| MethodRow {
            method_id: w.method_id,
            method_type: w.method.type_code(),
            wrap: w.wrap.clone(),
            kek_generation: u32::try_from(w.kek_generation).expect("a generation"),
            credential_id: None,
            prf_salt: None,
            aaguid: None,
        })
        .collect();
    let now = i64::try_from(app.clock.now_unix()).expect("a time");
    let mut account_rows = NewAccountRows {
        account_id: ids.account_id,
        user_id: 0,
        vault_id: ids.vault_id,
        record,
        sk_hint: false,
        pk_a: new.pk_a,
        pk_r: new.pk_r,
        methods,
        manifest: ManifestIn {
            rev: new.manifest.rev,
            envelope: new.manifest.envelope.clone(),
            tag: new.manifest.tag,
        },
        checkpoint: CheckpointIn {
            seq: new.checkpoint.seq,
            digest: new.checkpoint.digest.to_vec(),
            mac: new.checkpoint.mac.to_vec(),
            entries: new.checkpoint.entries.clone(),
        },
        now,
    };
    let user_id = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let user_id = insert_user(conn, &format!("client{n}@example.com"));
            account_rows.user_id = user_id;
            let tx = conn.transaction()?;
            create_account(&tx, &account_rows).expect("create the account");
            tx.commit()?;
            Ok(user_id)
        })
        .await
        .expect("write the account");
    let pinned = new.pinned(VAULT_URL).expect("a pinned record");
    let mut wraps = new.wraps.into_iter();
    let password_wrap = wraps.next().expect("the password wrap");
    let recovery_wrap = wraps.next().expect("the recovery wrap");
    Client {
        ids: account_ids(user_id, n),
        password: CLIENT_PASSWORD.to_string(),
        vault: new.vault,
        recovery_key: new.recovery_key,
        pinned,
        password_wrap,
        recovery_wrap,
        manifest: new.manifest,
        rng,
    }
}

/// A session of `client` on the vault listener from device `device_n`, of
/// `scope`. A full session is marked re-authenticated at the clock's time,
/// as a sign-in with `purpose: "reauth"` leaves it, so it is fresh for 300
/// seconds.
pub async fn client_session(
    app: &TestApp,
    client: &Client,
    scope: SessionScope,
    device_n: u8,
) -> Issued {
    let issued = issue(app, client.ids.user_id, Origin::Vault, scope, device_n).await;
    if scope == SessionScope::Full {
        let now = i64::try_from(app.clock.now_unix()).expect("a time");
        let sid = issued.sid;
        let marked = app
            .state
            .vault_db
            .with_conn(move |conn| Ok(mark_reauth(conn, &sid, now)?))
            .await
            .expect("mark the re-authentication");
        assert!(marked, "a live full session is marked");
    }
    issued
}

/// `POST /api/auth/opaque/reregister/start` with the cookies of `jar`.
pub async fn reregister_start(app: &TestApp, jar: &Jar, request: &[u8]) -> Res {
    let mut req = Req::post("/api/auth/opaque/reregister/start")
        .page_fetch(Which::Vault)
        .json(&json!({ "registration_request": b64url::encode(request) }));
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    app.call_raw(Which::Vault, req.build()).await
}

/// A new registration of `password` in the session of `jar`, through the
/// route, finished by the client. Panics unless the route answers.
pub async fn reregister(
    app: &TestApp,
    jar: &Jar,
    password: &str,
    rng: &mut TestRng,
) -> RegistrationFinished {
    let input = opaque_input(password);
    let (request, state) = opaque_register_start(rng, &input).expect("a first message");
    let res = reregister_start(app, jar, &request).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let response = b64url::decode(
        res.json()["registration_response"]
            .as_str()
            .expect("a response"),
    )
    .expect("base64url");
    register_finish_with(rng, state, &input, &response, &TestKsf::new(SMALL))
        .expect("the client finishes")
}

/// The manifest of a body.
fn sealed_row(item: &SealedItem) -> SealedRowJson {
    SealedRowJson {
        rev: item.rev,
        envelope: item.envelope.clone(),
        tag: item.tag,
    }
}

/// The change of `client`'s master password to `password`, made by the core
/// from a registration in the session of `jar`.
pub async fn password_change(
    app: &TestApp,
    jar: &Jar,
    client: &mut Client,
    password: &str,
) -> PasswordChange {
    let registration = reregister(app, jar, password, &mut client.rng).await;
    let input = opaque_input(password);
    change_password(
        &mut client.rng,
        &client.vault,
        NewPassword {
            input: &input,
            registration,
            profile: KsfProfile::P1,
        },
        &client.pinned,
        &client.password_wrap,
        &ManifestRow {
            rev: client.manifest.rev,
            envelope: &client.manifest.envelope,
            tag: &client.manifest.tag,
        },
    )
    .expect("the core makes the change")
}

/// The body of `PUT /api/vault/unlock-methods/password` for `change`.
pub fn password_put_req(change: &PasswordChange) -> PasswordPutReq {
    PasswordPutReq {
        registration_record: change.registration_record.clone(),
        ksf_profile: change.ksf_profile.number(),
        wrap: change.wrap.wrap.clone(),
        kek_generation: u32::try_from(change.wrap.kek_generation).expect("a generation"),
        manifest: sealed_row(&change.manifest),
    }
}

/// The bytes of a body as the client sends them.
pub fn body_bytes<T: serde::Serialize>(body: &T) -> Vec<u8> {
    serde_json::to_vec(body).expect("a JSON body")
}

/// A signed request on the vault listener as a page sends it: the cookies of
/// `jar`, the two proof headers and the exact `body`.
pub async fn send_signed(
    app: &TestApp,
    jar: &Jar,
    method: Method,
    path: &str,
    nonce: &[u8; 32],
    proof: &[u8; 64],
    body: Vec<u8>,
) -> Res {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", Which::Vault.url())
        .header("ferret-protocol", "1")
        .header(header::CONTENT_TYPE, "application/json")
        .header("ferret-nonce", b64url::encode(nonce))
        .header("ferret-proof", b64url::encode(proof));
    if let Some(cookie) = jar.header() {
        builder = builder.header(header::COOKIE, cookie);
    }
    app.call_raw(
        Which::Vault,
        builder.body(Body::from(body)).expect("a request"),
    )
    .await
}

/// The path of the password change.
pub const PASSWORD_PATH: &str = "/api/vault/unlock-methods/password";

/// `PUT /api/vault/unlock-methods/password` with `body`, signed by `client`
/// over a fresh nonce of the session of `jar`, for `change`'s operation.
pub async fn put_password_bytes(
    app: &TestApp,
    jar: &Jar,
    client: &Client,
    change: &PasswordChange,
    body: Vec<u8>,
) -> Res {
    let nonce = nonce_for(app, jar).await;
    let proof = change.sign(&client.vault, &nonce, &body).expect("a proof");
    send_signed(app, jar, Method::PUT, PASSWORD_PATH, &nonce, &proof, body).await
}

/// `PUT /api/vault/unlock-methods/password` for `change`, as the client sends
/// it.
pub async fn put_password(
    app: &TestApp,
    jar: &Jar,
    client: &Client,
    change: &PasswordChange,
) -> Res {
    let body = body_bytes(&password_put_req(change));
    put_password_bytes(app, jar, client, change, body).await
}

/// A new recovery key for `client`, made by the core.
pub fn renewed_recovery(client: &mut Client) -> RenewedRecovery {
    renew_recovery(
        &mut client.rng,
        &client.vault,
        &client.pinned,
        &client.recovery_wrap,
        &ManifestRow {
            rev: client.manifest.rev,
            envelope: &client.manifest.envelope,
            tag: &client.manifest.tag,
        },
    )
    .expect("the core renews the recovery key")
}

/// The body of `PUT /api/vault/unlock-methods/recovery` for `renewed`.
pub fn recovery_put_req(renewed: &RenewedRecovery) -> RecoveryPutReq {
    RecoveryPutReq {
        wrap: renewed.recovery_wrap.wrap.clone(),
        kek_generation: u32::try_from(renewed.recovery_wrap.kek_generation).expect("a generation"),
        pk_r: renewed.pk_r,
        manifest: sealed_row(&renewed.manifest),
    }
}

/// The path of a new recovery key.
pub const RECOVERY_PATH: &str = "/api/vault/unlock-methods/recovery";

/// `PUT /api/vault/unlock-methods/recovery` for `renewed`, signed by
/// `client` with `sk_a` over a fresh nonce of the session of `jar`.
pub async fn put_recovery(
    app: &TestApp,
    jar: &Jar,
    client: &Client,
    renewed: &RenewedRecovery,
) -> Res {
    let body = body_bytes(&recovery_put_req(renewed));
    let nonce = nonce_for(app, jar).await;
    let proof = renewed.sign(&client.vault, &nonce, &body).expect("a proof");
    send_signed(app, jar, Method::PUT, RECOVERY_PATH, &nonce, &proof, body).await
}

/// A recovery of `client` with its recovery key to the master password
/// `password`, made by the core from a registration in the session of `jar`.
/// `pinned` says whether the device holds the client's pinned record (`false`
/// is a new device). The new recovery wrap keeps the stored method id.
pub async fn recovered(
    app: &TestApp,
    jar: &Jar,
    client: &mut Client,
    password: &str,
    pinned: bool,
) -> Recovered {
    let registration = reregister(app, jar, password, &mut client.rng).await;
    let input = opaque_input(password);
    let rk_code = encode_recovery_key(&client.recovery_key);
    let ctx = *client.vault.context();
    let pin = if pinned {
        PinState::Pinned(&client.pinned)
    } else {
        PinState::FirstUse
    };
    recover(
        &mut client.rng,
        &RecoveryInput {
            ctx: &ctx,
            rk_code: &rk_code,
            rk_wrap: &client.recovery_wrap,
            manifest: ManifestRow {
                rev: client.manifest.rev,
                envelope: &client.manifest.envelope,
                tag: &client.manifest.tag,
            },
        },
        NewPassword {
            input: &input,
            registration,
            profile: KsfProfile::P1,
        },
        pin,
    )
    .expect("the core recovers the account")
}

/// The body of `POST /api/vault/recover` for `recovered`.
pub fn recover_req(recovered: &Recovered) -> RecoverReq {
    RecoverReq {
        registration_record: recovered.registration_record.clone(),
        ksf_profile: recovered.ksf_profile.number(),
        pw_wrap: recovered.password_wrap.wrap.clone(),
        rk_wrap: recovered.recovery_wrap.wrap.clone(),
        pw_kek_generation: u32::try_from(recovered.password_wrap.kek_generation)
            .expect("a generation"),
        rk_kek_generation: u32::try_from(recovered.recovery_wrap.kek_generation)
            .expect("a generation"),
        pk_r_new: recovered.pk_r,
        manifest: sealed_row(&recovered.manifest),
    }
}

/// The path of a recovery.
pub const RECOVER_PATH: &str = "/api/vault/recover";

/// `POST /api/vault/recover` for `recovered`, signed with the old recovery
/// key's `sk_r` over a fresh nonce of the session of `jar`.
pub async fn post_recover(app: &TestApp, jar: &Jar, recovered: &Recovered) -> Res {
    let body = body_bytes(&recover_req(recovered));
    let nonce = nonce_for(app, jar).await;
    let proof = recovered.sign(&nonce, &body).expect("a proof");
    send_signed(app, jar, Method::POST, RECOVER_PATH, &nonce, &proof, body).await
}

/// One stored wrap: `(method_type, method_id, generation, wrap)`.
pub type StoredWrap = (u8, [u8; 16], u32, Vec<u8>);

/// The stored wraps of an account, ordered by type.
pub async fn stored_wraps(app: &TestApp, account: AccountId) -> Vec<StoredWrap> {
    app.state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT method_type, method_id, kek_generation, wrap FROM ferret_unlock_methods
                 WHERE account_id = ?1 ORDER BY method_type",
            )?;
            let rows = stmt
                .query_map([account.as_bytes().as_slice()], |r| {
                    let id: Vec<u8> = r.get(1)?;
                    Ok((
                        u8::try_from(r.get::<_, i64>(0)?).expect("a type"),
                        <[u8; 16]>::try_from(id).expect("16 bytes"),
                        u32::try_from(r.get::<_, i64>(2)?).expect("a generation"),
                        r.get(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the wraps")
}

/// What the server holds of an account and its vault that a change of unlock
/// methods writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub record: Vec<u8>,
    pub ksf_profile: i64,
    pub pk_a: Vec<u8>,
    pub pk_r: Vec<u8>,
    pub vk_epoch: i64,
    pub manifest_rev: i64,
    pub manifest_seq: i64,
    pub manifest_envelope: Vec<u8>,
    pub manifest_tag: Vec<u8>,
    pub vault_seq: i64,
    pub bytes_used: i64,
    pub wraps: Vec<StoredWrap>,
}

/// The [`Snapshot`] of `client`'s account now.
pub async fn snapshot(app: &TestApp, client: &Client) -> Snapshot {
    let account = client.ids.account_id;
    let vault = client.ids.vault_id;
    let wraps = stored_wraps(app, account).await;
    app.state
        .vault_db
        .with_conn(move |conn| {
            let (record, ksf_profile, pk_a, pk_r, vk_epoch) = conn.query_row(
                "SELECT opaque_record, ksf_profile, pk_a, pk_r, vk_epoch FROM ferret_accounts
                 WHERE account_id = ?1",
                [account.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
            let (manifest_rev, manifest_seq, manifest_envelope, manifest_tag) = conn.query_row(
                "SELECT rev, seq, blob, tag FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
                [
                    vault.as_bytes().as_slice(),
                    MANIFEST_ITEM_ID.as_bytes().as_slice(),
                ],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            let (vault_seq, bytes_used) = conn.query_row(
                "SELECT seq, bytes_used FROM ferret_vaults WHERE vault_id = ?1",
                [vault.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(Snapshot {
                record,
                ksf_profile,
                pk_a,
                pk_r,
                vk_epoch,
                manifest_rev,
                manifest_seq,
                manifest_envelope,
                manifest_tag,
                vault_seq,
                bytes_used,
                wraps,
            })
        })
        .await
        .expect("a snapshot")
}
