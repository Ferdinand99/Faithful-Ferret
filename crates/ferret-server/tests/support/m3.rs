//! Helpers of the two matrices (`m3_matrix`, `backup_matrix`): a seeded random
//! source, a ledger that makes a matrix fail when a row was never exercised,
//! workers that run seeds on a few threads, a way to talk to a server that is
//! not a [`TestApp`] (one started on a restored data directory), the sign-in
//! that goes through the routes with the real OPAQUE client, and readers of
//! what the database holds of an account.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{
    Kek, OPAQUE_CONTEXT, OsRng, PinState, Recovered, RenewedRecovery, VaultContext, WrapRecord,
    decode_recovery_key, opaque_login_start, recovery_public_key, unwrap_vk,
};
use ferret_server::config::Config;
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::ids::{AccountId, MANIFEST_ITEM_ID, VaultId};
use ferret_server::server;
use ferret_server::state::FerretState;
use ferret_server::wire::b64url;
use ferret_server_auth::testing::SMALL;
use ferret_server_auth::{Clock, ManualClock, NoThrottle};
use rusqlite::Connection;
use serde_json::{Value, json};

use super::accounts::{Client, Snapshot, StoredWrap, opaque_input};
use super::{ADMIN_URL, Jar, PEER, Req, Res, TestApp, VAULT_URL, Which};

// ----------------------------------------------------------------- the seeds

/// A small seeded random source (SplitMix64): the same seed gives the same
/// run, on any machine, so a failing run is replayed from its seed.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number below `n` (`n` is not zero).
    pub fn below(&mut self, n: usize) -> usize {
        let n = u64::try_from(n).expect("a size");
        usize::try_from(self.next_u64() % n).expect("below n")
    }

    /// `true` with the chance `num` in `den`.
    pub fn chance(&mut self, num: u64, den: u64) -> bool {
        self.next_u64() % den < num
    }

    /// One of `items`.
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// The seed of run `index` of a matrix whose base seed is `base`.
pub fn seed_of(base: u64, index: u64) -> u64 {
    Rng::new(base ^ index.wrapping_mul(0xD6E8_FEB8_6659_FD93)).next_u64()
}

/// A number from the environment, or `default`.
pub fn env_number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

// ----------------------------------------------------------------- the ledger

/// What a matrix exercised: a count per named row. A matrix that has a list of
/// rows it must exercise fails when one of them has a count of zero, so a row
/// that stops being reached (a change of weights, a refusal that moved) cannot
/// pass silently.
#[derive(Clone, Default)]
pub struct Ledger(Arc<Mutex<BTreeMap<String, u64>>>);

impl Ledger {
    pub fn new() -> Ledger {
        Ledger::default()
    }

    /// Counts one exercise of `row`.
    pub fn hit(&self, row: &str) {
        *self
            .0
            .lock()
            .expect("the ledger")
            .entry(row.to_string())
            .or_default() += 1;
    }

    /// How often `row` was exercised.
    pub fn count(&self, row: &str) -> u64 {
        self.0
            .lock()
            .expect("the ledger")
            .get(row)
            .copied()
            .unwrap_or(0)
    }

    /// Fails when a row of `rows` was never exercised, or when a row was
    /// exercised that `rows` does not list (a new row needs a decision). The
    /// table is printed, for the record of what a run covered.
    pub fn assert_covers(&self, rows: &[&str]) {
        let seen = self.0.lock().expect("the ledger").clone();
        for (row, count) in &seen {
            println!("matrix row {row}: {count}");
        }
        let missing: Vec<&&str> = rows.iter().filter(|r| !seen.contains_key(**r)).collect();
        assert!(missing.is_empty(), "rows never exercised: {missing:?}");
        let unlisted: Vec<&String> = seen
            .keys()
            .filter(|r| !rows.contains(&r.as_str()))
            .collect();
        assert!(unlisted.is_empty(), "rows not in the list: {unlisted:?}");
    }
}

// ------------------------------------------------------------------ the workers

/// Runs `work` for `runs` seeds on `threads` threads, each with a runtime of
/// its own, and the seeds of a thread in one range. A panic of a worker is
/// raised again here, so the failing seed it names is in the test's output.
pub fn run_in_parallel<F, Fut>(runs: u64, threads: u64, work: F)
where
    F: Fn(Range<u64>) -> Fut + Sync,
    Fut: Future<Output = ()>,
{
    let threads = threads.clamp(1, runs.max(1));
    let per = runs.div_ceil(threads);
    std::thread::scope(|scope| {
        let work = &work;
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let range = (t * per)..((t + 1) * per).min(runs);
                std::thread::Builder::new()
                    .stack_size(16 * 1024 * 1024)
                    .spawn_scoped(scope, move || {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("a runtime");
                        runtime.block_on(work(range));
                    })
                    .expect("a thread")
            })
            .collect();
        let mut first = None;
        for handle in handles {
            if let Err(panic) = handle.join() {
                first.get_or_insert(panic);
            }
        }
        if let Some(panic) = first {
            std::panic::resume_unwind(panic);
        }
    });
}

// ---------------------------------------------------------------- talking to a server

/// Something that answers requests of the vault listener: a [`TestApp`], or a
/// server started on a data directory ([`Served`]).
#[allow(async_fn_in_trait)]
pub trait Vault {
    /// Sends `request` to the vault listener, as it is.
    async fn send(&self, request: Request<Body>) -> Res;
}

impl Vault for TestApp {
    async fn send(&self, request: Request<Body>) -> Res {
        self.call_raw(Which::Vault, request).await
    }
}

/// A server started on a data directory the way the binary starts (migrations,
/// secrets), with the vault router of it: for the data a restore left.
pub struct Served {
    pub state: FerretState,
    router: Router,
}

/// The settings of a server on `dir`.
pub fn config_for(dir: &Path) -> Config {
    Config {
        data_dir: dir.to_path_buf(),
        host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        vault_port: 3041,
        admin_port: 3040,
        vault_url: VAULT_URL.to_string(),
        admin_url: ADMIN_URL.to_string(),
        trusted_proxies: Vec::new(),
        backup_dir: None,
        backup_every_hours: 24,
        backup_keep_days: 30,
        backup_push_url: None,
    }
}

impl Served {
    /// Starts a server on `dir` with a clock at `now`. It believes the test
    /// peer as a proxy (so `https` sign-ins count) and has no throttle.
    pub async fn start(dir: &Path, now: i64) -> Result<Served, ferret_server::StartError> {
        let clock = Arc::new(ManualClock::new(u64::try_from(now).expect("a time")));
        let mut state = ferret_server::start(&config_for(dir), clock as Arc<dyn Clock>).await?;
        state.throttle = Arc::new(NoThrottle);
        state.proxies = Arc::new(
            ProxyList::parse(&[PEER.split(':').next().expect("an address").to_string()])
                .expect("a proxy list"),
        );
        Ok(Served {
            router: server::vault_router(state.clone()),
            state,
        })
    }
}

impl Vault for Served {
    async fn send(&self, mut request: Request<Body>) -> Res {
        use tower::ServiceExt as _;
        if !request.headers().contains_key(header::HOST) {
            request
                .headers_mut()
                .insert(header::HOST, Which::Vault.host().parse().expect("a host"));
        }
        let peer: SocketAddr = PEER.parse().expect("a peer");
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("a response");
        let (parts, body) = response.into_parts();
        Res {
            status: parts.status,
            headers: parts.headers,
            body: to_bytes(body, 16 * 1024 * 1024)
                .await
                .expect("a body")
                .to_vec(),
        }
    }
}

/// Sends `req` with the cookies of `jar` and keeps the cookies of the answer.
pub async fn send_with<V: Vault>(vault: &V, jar: &mut Jar, mut req: Req) -> Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = vault.send(req.build()).await;
    jar.absorb(&res.headers);
    res
}

/// A `POST` of a page of the vault over `https` (behind the trusted proxy).
pub fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

/// A `GET` of a page of the vault with the cookies of `jar`.
pub async fn vault_get<V: Vault>(vault: &V, jar: &Jar, path: &str) -> Res {
    let mut req = Req::get(path)
        .header("ferret-protocol", "1")
        .header("sec-fetch-site", "same-origin");
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    vault.send(req.build()).await
}

// ----------------------------------------------------------------- the sign-in

/// A sign-in half-way: the server answered `login/start` and the client has
/// made its third message.
pub struct HalfWay {
    pub jar: Jar,
    login_id: Value,
    ke3: Vec<u8>,
}

/// The first half of a sign-in of `email` with `password` from a new browser.
/// `None` when the client cannot finish (the password is not the one of the
/// record the server answered with).
pub async fn start_sign_in<V: Vault>(vault: &V, email: &str, password: &str) -> Option<HalfWay> {
    let input = opaque_input(password);
    let mut jar = Jar::default();
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).expect("a start");
    let started = send_with(
        vault,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &json!({"email": email, "ke1": b64url::encode(&ke1)}),
        ),
    )
    .await;
    assert_eq!(started.status, StatusCode::OK, "{}", started.text());
    let answer = started.json();
    let ke2 = b64url::decode(answer["ke2"].as_str().expect("a ke2")).expect("base64url");
    let ke3 = login_finish_with(
        &mut OsRng,
        state,
        &input,
        &ke2,
        &TestKsf::new(SMALL),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .ok()?
    .finished
    .ke3;
    Some(HalfWay {
        jar,
        login_id: answer["login_id"].clone(),
        ke3,
    })
}

/// The second half: `login/finish`. The answer and the cookies it set.
pub async fn finish_sign_in<V: Vault>(vault: &V, mut half: HalfWay) -> (Res, Jar) {
    let res = send_with(
        vault,
        &mut half.jar,
        vault_post(
            "/api/auth/opaque/login/finish",
            &json!({
                "login_id": half.login_id,
                "ke3": b64url::encode(&half.ke3),
                "device_id": "07".repeat(16),
                "device_name": "Test browser",
            }),
        ),
    )
    .await;
    (res, half.jar)
}

/// Whether a whole sign-in of `email` with `password` gives a session: `true`
/// for `200`; `false` when the client cannot finish or the server refuses.
pub async fn signs_in<V: Vault>(vault: &V, email: &str, password: &str) -> bool {
    let Some(half) = start_sign_in(vault, email, password).await else {
        return false;
    };
    finish_sign_in(vault, half).await.0.status == StatusCode::OK
}

// ------------------------------------------------------------ the client's view

/// The state of the client after the server took a new recovery key.
pub fn took_recovery(client: &mut Client, renewed: RenewedRecovery) {
    client.pinned = renewed
        .pinned(&client.pinned)
        .expect("the pin after the renewal");
    client.recovery_wrap = renewed.recovery_wrap;
    client.manifest = renewed.manifest;
    client.recovery_key = renewed.recovery_key;
}

/// The state of the client after the server took a recovery.
pub fn took_recovered(client: &mut Client, recovered: Recovered, password: &str) {
    client.pinned = recovered
        .pinned(VAULT_URL, Some(&client.pinned))
        .expect("the pin after the recovery");
    let Recovered {
        vault,
        recovery_key,
        password_wrap,
        recovery_wrap,
        manifest,
        ..
    } = recovered;
    client.vault = vault;
    client.recovery_key = recovery_key;
    client.password_wrap = password_wrap;
    client.recovery_wrap = recovery_wrap;
    client.manifest = manifest;
    client.password = password.to_string();
}

/// Whether the recovery key `rk_code` opens the vault with the recovery wrap
/// `stored` (what a server holds), in the context `ctx`. `template` gives the
/// method id and generation the wrap was made for.
pub fn recovery_key_opens(
    ctx: &VaultContext,
    rk_code: &str,
    template: &WrapRecord,
    stored: &[u8],
) -> bool {
    let Ok(rk) = decode_recovery_key(rk_code) else {
        return false;
    };
    let Ok(kek) = Kek::from_recovery_key(&ctx.account_id, &rk) else {
        return false;
    };
    let mut record = template.clone();
    record.wrap = stored.to_vec();
    unwrap_vk(ctx, &kek, &record).is_ok()
}

/// The `pk_r` of the client's recovery key.
pub fn pk_r_of(client: &Client) -> [u8; 32] {
    recovery_public_key(&client.recovery_key, &client.ids.account_id).expect("a recovery key")
}

// ------------------------------------------------------------ what the database holds

/// The stored wraps of an account, ordered by type.
pub fn stored_wraps_in(conn: &Connection, account: AccountId) -> Vec<StoredWrap> {
    let mut stmt = conn
        .prepare(
            "SELECT method_type, method_id, kek_generation, wrap FROM ferret_unlock_methods
             WHERE account_id = ?1 ORDER BY method_type",
        )
        .expect("prepare");
    stmt.query_map([account.as_bytes().as_slice()], |r| {
        let id: Vec<u8> = r.get(1)?;
        Ok((
            u8::try_from(r.get::<_, i64>(0)?).expect("a type"),
            <[u8; 16]>::try_from(id).expect("16 bytes"),
            u32::try_from(r.get::<_, i64>(2)?).expect("a generation"),
            r.get(3)?,
        ))
    })
    .expect("query")
    .collect::<Result<Vec<_>, _>>()
    .expect("rows")
}

/// What the database of `conn` holds of an account and its vault that a change
/// of unlock methods writes (the same fields as `accounts::snapshot`).
pub fn snapshot_in(conn: &Connection, account: AccountId, vault: VaultId) -> Snapshot {
    let (record, ksf_profile, pk_a, pk_r, vk_epoch) = conn
        .query_row(
            "SELECT opaque_record, ksf_profile, pk_a, pk_r, vk_epoch FROM ferret_accounts
             WHERE account_id = ?1",
            [account.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .expect("the account");
    let (manifest_rev, manifest_seq, manifest_envelope, manifest_tag) = conn
        .query_row(
            "SELECT rev, seq, blob, tag FROM ferret_items WHERE vault_id = ?1 AND item_id = ?2",
            [
                vault.as_bytes().as_slice(),
                MANIFEST_ITEM_ID.as_bytes().as_slice(),
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("the manifest");
    let (vault_seq, bytes_used) = conn
        .query_row(
            "SELECT seq, bytes_used FROM ferret_vaults WHERE vault_id = ?1",
            [vault.as_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("the vault");
    Snapshot {
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
        wraps: stored_wraps_in(conn, account),
    }
}

/// Opens a database file read-only, without touching it or its folder.
pub fn peek(db: &Path) -> Connection {
    Connection::open_with_flags(
        format!("file:{}?immutable=1", db.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open read-only")
}

/// `PRAGMA integrity_check` and `foreign_key_check` of a database file: `Ok`
/// when it is whole.
pub fn database_is_whole(db: &Path) -> Result<(), String> {
    let conn = peek(db);
    let verdict: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if verdict != "ok" {
        return Err(format!("integrity_check: {verdict}"));
    }
    let broken: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())?;
    if broken != 0 {
        return Err(format!("{broken} broken foreign keys"));
    }
    Ok(())
}

/// The `restore_epoch` of every vault of a database file, by vault id.
pub fn epochs_in(db: &Path) -> Vec<u64> {
    let conn = peek(db);
    let mut stmt = conn
        .prepare("SELECT restore_epoch FROM ferret_vaults ORDER BY vault_id")
        .expect("prepare");
    stmt.query_map([], |row| row.get::<_, i64>(0))
        .expect("query")
        .map(|r| u64::try_from(r.expect("row")).expect("unsigned"))
        .collect()
}

/// A count from a database file.
pub fn count_in(db: &Path, sql: &str) -> i64 {
    peek(db)
        .query_row(sql, [], |row| row.get(0))
        .expect("a count")
}
