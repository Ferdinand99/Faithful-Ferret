//! A sign-in is bound to the OPAQUE record it started from: a sign-in that
//! was half-way when the record was replaced (a new master password, a
//! recovery, a restore of an older record) cannot finish afterwards, and its
//! refusal is the one of a wrong password. Sign-ins of other accounts, and of
//! accounts whose record did not change, are not touched.
//!
//! Spec: Fase 1 § 4.2 ("Innlogging").

mod support;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use axum::http::StatusCode;
use ferret_core::testing::opaque::{TestKsf, login_finish_with};
use ferret_core::{OPAQUE_CONTEXT, OsRng, PinState, RecoveryKey, TestRng, opaque_login_start};
use ferret_server::http::proxy_guard::ProxyList;
use ferret_server::vault::reconcile::bump_restore_epoch;
use ferret_server::vault::unlock_write::{ChangeKind, UnlockChange, Writer, apply};
use ferret_server::wire::{SealedRowJson, b64url};
use ferret_server_auth::{
    Clock as _, Outcome, RetryAfter, SessionScope, Stage, Throttle, ThrottleKey, ValidatedRecord,
    WriteBasis,
};
use serde_json::{Value, json};
use support::accounts::{
    Client, client_account, client_session, opaque_input, password_change, put_password,
    registration_for, snapshot,
};
use support::session::session_version;
use support::{Jar, PEER, Req, Res, TestApp, Which};

const NEW_PASSWORD: &str = "a brand new horse battery staple";

// ------------------------------------------------------------------ helpers

/// An app that believes the test peer as a proxy, so sign-ins over `https`
/// count.
async fn app() -> TestApp {
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    TestApp::builder().proxies(proxies).build().await
}

fn email(client: &Client) -> String {
    let n = client.ids.account_id.as_bytes()[1];
    format!("client{n}@example.com")
}

/// Sends a request on the vault listener as a browser on `https` would.
async fn send(app: &TestApp, jar: &mut Jar, mut req: Req) -> Res {
    if let Some(cookie) = jar.header() {
        req = req.header("cookie", &cookie);
    }
    let res = app.call_raw(Which::Vault, req.build()).await;
    jar.absorb(&res.headers);
    res
}

fn vault_post(path: &str, body: &Value) -> Req {
    Req::post(path)
        .page_fetch(Which::Vault)
        .header("x-forwarded-proto", "https")
        .json(body)
}

/// A sign-in half-way: the server answered `login/start` and the client has
/// made its third message.
struct HalfWay {
    jar: Jar,
    login_id: Value,
    ke3: Vec<u8>,
    purpose: &'static str,
}

/// The first half of a sign-in (`purpose` `login`, from a new browser) or of
/// a re-authentication (`reauth`, in the session of `jar`), with `password`.
async fn start(
    app: &TestApp,
    mut jar: Jar,
    email: &str,
    password: &str,
    purpose: &'static str,
) -> HalfWay {
    let input = opaque_input(password);
    let (ke1, state) = opaque_login_start(&mut OsRng, &input).expect("a start");
    let started = send(
        app,
        &mut jar,
        vault_post(
            "/api/auth/opaque/login/start",
            &json!({"email": email, "ke1": b64url::encode(&ke1), "purpose": purpose}),
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
        &TestKsf::new(SMALL_KSF),
        Some(OPAQUE_CONTEXT),
        PinState::FirstUse,
    )
    .expect("the password opens the record")
    .finished
    .ke3;
    HalfWay {
        jar,
        login_id: answer["login_id"].clone(),
        ke3,
        purpose,
    }
}

const SMALL_KSF: ferret_core::KdfParams = ferret_server_auth::testing::SMALL;

/// The second half: `login/finish`.
async fn finish(app: &TestApp, mut half: HalfWay) -> Res {
    send(
        app,
        &mut half.jar,
        vault_post(
            "/api/auth/opaque/login/finish",
            &json!({
                "login_id": half.login_id,
                "ke3": b64url::encode(&half.ke3),
                "device_id": "07".repeat(16),
                "device_name": "Test browser",
                "purpose": half.purpose,
            }),
        ),
    )
    .await
}

/// How many session rows the user has, live or not, and when the user's live
/// sessions were last marked fresh.
async fn sessions(app: &TestApp, user_id: i64) -> (i64, Option<i64>) {
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(conn.query_row(
                "SELECT COUNT(*), MAX(reauth_at) FROM ferret_sessions WHERE user_id = ?1",
                [user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await
        .expect("a count")
}

/// The answer as a client sees it: the status, the body and the headers
/// that describe it.
fn seen(res: &Res) -> (StatusCode, String, String, String) {
    (
        res.status,
        res.text(),
        res.header("content-type").to_string(),
        res.header("cache-control").to_string(),
    )
}

/// A new master password for `client`, through the route.
async fn change_password(app: &TestApp, jar: &Jar, client: &mut Client) {
    let change = password_change(app, jar, client, NEW_PASSWORD).await;
    let res = put_password(app, jar, client, &change).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    client.took_password(&change, NEW_PASSWORD);
}

// ------------------------------------------------------------------- tests

#[tokio::test]
async fn a_sign_in_begun_before_a_password_change_is_refused_like_a_wrong_password() {
    let app = app().await;
    let mut client = client_account(&app, 1).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let old = client.password.clone();
    let stale = start(&app, Jar::default(), &email(&client), &old, "login").await;
    change_password(&app, &this.jar, &mut client).await;
    let rows = sessions(&app, client.ids.user_id).await;

    let refused = finish(&app, stale).await;
    assert_eq!(
        refused.status,
        StatusCode::UNAUTHORIZED,
        "{}",
        refused.text()
    );
    assert_eq!(refused.json()["error"], json!("denied"));
    assert_eq!(sessions(&app, client.ids.user_id).await, rows, "no session");

    // A wrong password after the change gets the very same answer.
    let mut wrong = start(&app, Jar::default(), &email(&client), NEW_PASSWORD, "login").await;
    wrong.ke3[0] ^= 1;
    let wrong = finish(&app, wrong).await;
    assert_eq!(seen(&wrong), seen(&refused));
    assert_eq!(sessions(&app, client.ids.user_id).await, rows, "no session");

    // The new password, begun after the change, signs in.
    let fresh = start(&app, Jar::default(), &email(&client), NEW_PASSWORD, "login").await;
    let res = finish(&app, fresh).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_re_authentication_begun_before_a_password_change_does_not_make_the_session_fresh() {
    let app = app().await;
    let mut client = client_account(&app, 2).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let old = client.password.clone();
    let stale = start(&app, this.jar.clone(), &email(&client), &old, "reauth").await;
    change_password(&app, &this.jar, &mut client).await;
    let rows = sessions(&app, client.ids.user_id).await;

    let res = finish(&app, stale).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json()["error"], json!("denied"));
    assert_eq!(sessions(&app, client.ids.user_id).await, rows, "not marked");

    // With the new password the session re-authenticates.
    app.clock.advance(1);
    let fresh = start(
        &app,
        this.jar.clone(),
        &email(&client),
        NEW_PASSWORD,
        "reauth",
    )
    .await;
    let res = finish(&app, fresh).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_password_change_leaves_the_sign_ins_of_other_accounts_alone() {
    let app = app().await;
    let mut client = client_account(&app, 3).await;
    let other = client_account(&app, 4).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    // Another account, half-way when this one changes its master password.
    let theirs = start(
        &app,
        Jar::default(),
        &email(&other),
        &other.password,
        "login",
    )
    .await;
    change_password(&app, &this.jar, &mut client).await;

    let res = finish(&app, theirs).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // And signs in again as before.
    let theirs = start(
        &app,
        Jar::default(),
        &email(&other),
        &other.password,
        "login",
    )
    .await;
    let res = finish(&app, theirs).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// The change of unlock methods on the database, with a stand-in for the
/// proof check (as `tests/unlock_write.rs` does): a recovery that writes
/// `record`.
async fn recover_to(
    app: &TestApp,
    client: &Client,
    sid: ferret_server::ids::SidHash,
    record: Vec<u8>,
) {
    let writer = Writer {
        account: client.ids.account_id,
        user_id: client.ids.user_id,
        sid,
        session_version: session_version(app, client.ids.user_id).await,
        keep_session: true,
        kind: ChangeKind::Recover,
    };
    let rk = RecoveryKey::generate(&mut TestRng::new(b"recovered"));
    let pk_r = ferret_core::recovery_public_key(&rk, &client.ids.account_id).expect("a key");
    let envelope = client.manifest.envelope.clone();
    let at = i64::try_from(app.clock.now_unix()).expect("a time");
    app.state
        .vault_db
        .with_conn(move |conn| {
            Ok(apply(conn, &writer, at, |state| {
                let read = state.account;
                Ok(ferret_server::vault::unlock_write::Authorized {
                    change: UnlockChange::Recover {
                        record: ValidatedRecord::parse(&record).expect("a record"),
                        profile: 1,
                        pw_wrap: vec![0x71; 104],
                        pw_generation: 2,
                        rk_wrap: vec![0x72; 72],
                        rk_generation: 2,
                        pk_r,
                    },
                    manifest: SealedRowJson {
                        rev: 2,
                        envelope,
                        tag: [0x5e; 32],
                    },
                    session_effect: ferret_server_auth::ScopeEffect::Keep,
                    basis: WriteBasis {
                        account_id: read.account_id,
                        vk_epoch: read.vk_epoch,
                        pk_a: read.pk_a,
                        pk_r: read.pk_r,
                        row_version: read.row_version,
                    },
                })
            }))
        })
        .await
        .expect("a connection")
        .expect("the recovery is written");
}

#[tokio::test]
async fn a_sign_in_begun_before_a_recovery_cannot_finish_after_it() {
    let app = app().await;
    let client = client_account(&app, 5).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let stale = start(
        &app,
        Jar::default(),
        &email(&client),
        &client.password,
        "login",
    )
    .await;
    let mut rng = TestRng::new(b"recovery registration");
    let new = registration_for(&app, &client.ids.account_id, NEW_PASSWORD, &mut rng);
    recover_to(&app, &client, this.sid, new.record.clone()).await;
    assert_eq!(snapshot(&app, &client).await.record, new.record);

    let res = finish(&app, stale).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json()["error"], json!("denied"));
    let fresh = start(&app, Jar::default(), &email(&client), NEW_PASSWORD, "login").await;
    let res = finish(&app, fresh).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn a_sign_in_begun_before_a_restore_of_an_older_record_cannot_finish_after_it() {
    let app = app().await;
    let mut client = client_account(&app, 6).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let older = snapshot(&app, &client).await.record;
    let first_password = client.password.clone();
    change_password(&app, &this.jar, &mut client).await;
    let stale = start(&app, Jar::default(), &email(&client), NEW_PASSWORD, "login").await;

    // A restore of a set made before the change puts the older record back
    // and raises the restore epoch.
    let account = client.ids.account_id;
    app.state
        .vault_db
        .with_conn(move |conn| {
            conn.execute(
                "UPDATE ferret_accounts SET opaque_record = ?1 WHERE account_id = ?2",
                rusqlite::params![older, account.as_bytes().as_slice()],
            )?;
            bump_restore_epoch(conn, None, 0)?;
            Ok(())
        })
        .await
        .expect("the restore");

    let res = finish(&app, stale).await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json()["error"], json!("denied"));
    // The password of the restored record signs in.
    let fresh = start(
        &app,
        Jar::default(),
        &email(&client),
        &first_password,
        "login",
    )
    .await;
    let res = finish(&app, fresh).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

/// A throttle that admits everything. The first successful `login/finish`
/// proof says so on its channel and waits for the test to let it go on: the
/// library has read the record and checked the proof by then, and the session
/// is not written yet.
struct HoldFinish(Mutex<Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>>);

impl Throttle for HoldFinish {
    fn admit(&self, _stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        Ok(())
    }

    fn record(&self, stage: Stage, _keys: &[ThrottleKey], outcome: Outcome, _now: u64) {
        if stage == Stage::LoginFinish && outcome == Outcome::Success {
            let held = self.0.lock().expect("the channels").take();
            if let Some((entered, go)) = held {
                entered.send(()).expect("the test listens");
                go.recv_timeout(Duration::from_secs(10))
                    .expect("the test lets it go on");
            }
        }
    }
}

#[tokio::test]
async fn a_change_that_commits_after_the_proof_was_checked_still_stops_the_session() {
    let (entered_tx, entered_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let throttle = Arc::new(HoldFinish(Mutex::new(Some((entered_tx, go_rx)))));
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    let app = TestApp::builder()
        .proxies(proxies)
        .throttle(throttle as Arc<dyn Throttle>)
        .build()
        .await;
    let mut client = client_account(&app, 7).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let old = client.password.clone();
    let stale = start(&app, Jar::default(), &email(&client), &old, "login").await;
    let rows = sessions(&app, client.ids.user_id).await;

    // The proof is checked against the old record, which is still the
    // account's; the new password commits before the session is written.
    let (res, ()) = tokio::join!(finish(&app, stale), async {
        tokio::task::spawn_blocking(move || entered_rx.recv())
            .await
            .expect("a thread")
            .expect("the proof was checked");
        change_password(&app, &this.jar, &mut client).await;
        go_tx.send(()).expect("the sign-in waits");
    });
    assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    assert_eq!(res.json()["error"], json!("denied"));
    assert_eq!(sessions(&app, client.ids.user_id).await, rows, "no session");
}

/// A throttle that holds every `login/finish` admission until it is let go,
/// and counts the ones it holds.
struct HoldAdmissions {
    held: AtomicUsize,
    open: AtomicBool,
}

impl Throttle for HoldAdmissions {
    fn admit(&self, stage: Stage, _keys: &[ThrottleKey], _now: u64) -> Result<(), RetryAfter> {
        if stage == Stage::LoginFinish {
            self.held.fetch_add(1, Ordering::SeqCst);
            let until = std::time::Instant::now() + Duration::from_secs(20);
            while !self.open.load(Ordering::SeqCst) && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }

    fn record(&self, _stage: Stage, _keys: &[ThrottleKey], _outcome: Outcome, _now: u64) {}
}

#[tokio::test]
async fn finishes_that_wait_hold_no_database_connection() {
    // Many finishes with made-up login ids (no account, no state, nothing to
    // prove) stuck in the sign-in step at once, far more than the pool has
    // connections. The rest of the server still gets a connection: a finish
    // takes one only for the one read of a record, after its state opened.
    const STUCK: usize = 96;
    let throttle = Arc::new(HoldAdmissions {
        held: AtomicUsize::new(0),
        open: AtomicBool::new(false),
    });
    let proxies =
        ProxyList::parse(&[PEER.split(':').next().unwrap().to_string()]).expect("a proxy list");
    let app = TestApp::builder()
        .proxies(proxies)
        .throttle(throttle.clone() as Arc<dyn Throttle>)
        .build()
        .await;
    let junk = (0..STUCK).map(|n| {
        let app = &app;
        async move {
            let mut jar = Jar::default();
            send(
                app,
                &mut jar,
                vault_post(
                    "/api/auth/opaque/login/finish",
                    &json!({
                        "login_id": format!("{n:032x}"),
                        "ke3": b64url::encode(&[5u8; 64]),
                        "device_id": "07".repeat(16),
                    }),
                ),
            )
            .await
        }
    });
    let check = async {
        let start = std::time::Instant::now();
        while throttle.held.load(Ordering::SeqCst) < STUCK {
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "the finishes are held"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let read = tokio::time::timeout(
            Duration::from_secs(3),
            app.state
                .vault_db
                .with_conn(|conn| Ok(conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?)),
        )
        .await;
        throttle.open.store(true, Ordering::SeqCst);
        read
    };
    let (answers, read) = tokio::join!(futures_util::future::join_all(junk), check);
    assert_eq!(
        read.expect("a connection while every finish waits")
            .expect("a read"),
        1
    );
    for res in answers {
        assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
    }
}

#[test]
fn a_flood_of_finishes_for_made_up_names_cannot_hang_the_database_routes() {
    // A runtime with few blocking threads. Every finish of a state that opens
    // (a made-up name has one) reads the record; if that read needed a pooled
    // connection or a second blocking thread while the finish holds one, a
    // flood larger than the blocking threads would leave none for the pool's
    // own work, and every database route would hang.
    const BLOCKING: usize = 6;
    const FLOOD: usize = 48;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(BLOCKING)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let app = app().await;
        // Half-way sign-ins for names nobody has: each has a state that opens.
        let mut halves = Vec::with_capacity(FLOOD);
        for n in 0..FLOOD {
            let (ke1, _) = opaque_login_start(&mut OsRng, &opaque_input("anything at all"))
                .expect("a start");
            let mut jar = Jar::default();
            let started = send(
                &app,
                &mut jar,
                vault_post(
                    "/api/auth/opaque/login/start",
                    &json!({"email": format!("nobody{n}@example.com"), "ke1": b64url::encode(&ke1)}),
                ),
            )
            .await;
            assert_eq!(started.status, StatusCode::OK, "{}", started.text());
            halves.push(started.json()["login_id"].clone());
        }
        let flood = halves.into_iter().map(|login_id| {
            let app = &app;
            async move {
                let mut jar = Jar::default();
                send(
                    app,
                    &mut jar,
                    vault_post(
                        "/api/auth/opaque/login/finish",
                        &json!({
                            "login_id": login_id,
                            "ke3": b64url::encode(&[5u8; 64]),
                            "device_id": "07".repeat(16),
                        }),
                    ),
                )
                .await
            }
        });
        let unrelated = async {
            // Let the flood start, then use the pool.
            tokio::time::sleep(Duration::from_millis(20)).await;
            app.state
                .vault_db
                .with_conn(|conn| Ok(conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0))?))
                .await
        };
        let (answers, read) = tokio::time::timeout(
            Duration::from_secs(60),
            async { tokio::join!(futures_util::future::join_all(flood), unrelated) },
        )
        .await
        .expect("nothing hangs");
        assert_eq!(read.expect("a read"), 1);
        for res in answers {
            assert_eq!(res.status, StatusCode::UNAUTHORIZED, "{}", res.text());
            assert_eq!(res.json()["error"], json!("denied"));
        }
    });
}
