//! `vault::unlock_write`: the one transaction that writes a change of unlock
//! methods, called here directly with a stand-in for the proof check, so each
//! kind of change and each refusal can be reached. Spec: Fase 1 § 4.3, § 4.6
//! and § 6.3.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ferret_core::{AccountId, ItemId};
use ferret_server::auth::session::{Origin, lookup, revoke};
use ferret_server::error::ApiError;
use ferret_server::ids::SidHash;
use ferret_server::vault::unlock_write::{
    Applied, Authorized, BACKUP_REASON, UnlockChange, Writer, after_commit, apply,
};
use ferret_server::wire::SealedRowJson;
use ferret_server_auth::{Clock as _, ScopeEffect, SessionScope};
use support::TestApp;
use support::accounts::{
    Client, Snapshot, client_account, client_session, snapshot, stored_record,
};
use support::session::{issue, session_version};

/// A manifest envelope the server stores: a copy of the client's current one
/// (the server does not open it), at `rev`.
fn manifest(client: &Client, rev: u64) -> SealedRowJson {
    SealedRowJson {
        rev,
        envelope: client.manifest.envelope.clone(),
        tag: [0x5e; 32],
    }
}

fn password(generation: u32) -> UnlockChange {
    UnlockChange::Password {
        record: stored_record().record,
        profile: 1,
        wrap: vec![0x77; 104],
        generation,
    }
}

/// The writer of the session `sid`, at the user's session version now.
async fn writer(app: &TestApp, client: &Client, sid: SidHash, keep_session: bool) -> Writer {
    Writer {
        account: client.ids.account_id,
        user_id: client.ids.user_id,
        sid,
        session_version: session_version(app, client.ids.user_id).await,
        keep_session,
    }
}

fn now(app: &TestApp) -> i64 {
    i64::try_from(app.clock.now_unix()).expect("a time")
}

/// Runs `apply` on the app's database with an `authorize` that gives
/// `authorized` without a proof, and says whether `authorize` ran.
async fn run(
    app: &TestApp,
    writer: Writer,
    authorized: Result<Authorized, ApiError>,
) -> (Result<Applied, ApiError>, bool) {
    let ran = Arc::new(AtomicBool::new(false));
    let flag = ran.clone();
    let at = now(app);
    let result = app
        .state
        .vault_db
        .with_conn(move |conn| {
            Ok(apply(conn, &writer, at, |state| {
                flag.store(true, Ordering::SeqCst);
                assert_eq!(state.account.account_id, writer.account);
                assert_eq!(state.account.row_version, 0);
                authorized
            }))
        })
        .await
        .expect("a connection");
    (result, ran.load(Ordering::SeqCst))
}

fn authorized(change: UnlockChange, manifest: SealedRowJson) -> Result<Authorized, ApiError> {
    Ok(Authorized {
        change,
        manifest,
        session_effect: ScopeEffect::Keep,
    })
}

async fn is_ended(app: &TestApp, sid: SidHash) -> bool {
    app.state
        .vault_db
        .with_conn(move |conn| Ok(lookup(conn, &sid)?))
        .await
        .expect("a row")
        .expect("the session")
        .revoked_at
        .is_some()
}

async fn unchanged(app: &TestApp, client: &Client, before: &Snapshot) {
    assert_eq!(&snapshot(app, client).await, before);
}

#[tokio::test]
async fn a_failure_after_the_first_write_leaves_nothing_behind() {
    let app = TestApp::new().await;
    let client = client_account(&app, 1).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let before = snapshot(&app, &client).await;
    // The manifest row refuses every update: the account and the wrap are
    // written by then, and must go back.
    app.state
        .vault_db
        .with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER test_no_manifest BEFORE UPDATE ON ferret_items
                 BEGIN SELECT RAISE(ABORT, 'refused by the test'); END;",
            )?;
            Ok(())
        })
        .await
        .expect("a trigger");
    let (result, ran) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(password(2), manifest(&client, 2)),
    )
    .await;
    assert!(ran);
    let refused = result.expect_err("the write fails");
    assert_eq!(refused.code, "internal");
    unchanged(&app, &client, &before).await;
    assert!(!is_ended(&app, other.sid).await, "no session ended either");
}

#[tokio::test]
async fn a_session_that_ended_while_it_waited_is_401_and_nothing_is_checked() {
    let app = TestApp::new().await;
    let client = client_account(&app, 2).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let before = snapshot(&app, &client).await;
    let sid = this.sid;
    let at = now(&app);
    app.state
        .vault_db
        .with_conn(move |conn| Ok(revoke(conn, &sid, at)?))
        .await
        .expect("end the session");
    let (result, ran) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(password(2), manifest(&client, 2)),
    )
    .await;
    assert_eq!(result.expect_err("refused").code, "unauthorized");
    assert!(!ran, "the proof is never checked, so its nonce is kept");
    unchanged(&app, &client, &before).await;

    // The same for a user signed out everywhere (a newer session version),
    // and for a session of another user than the writer says.
    let fresh = client_session(&app, &client, SessionScope::Full, 2).await;
    let mut stale = writer(&app, &client, fresh.sid, true).await;
    stale.session_version += 1;
    let (result, ran) = run(&app, stale, authorized(password(2), manifest(&client, 2))).await;
    assert_eq!(result.expect_err("refused").code, "unauthorized");
    assert!(!ran);
    let stranger = client_account(&app, 3).await;
    let theirs = client_session(&app, &stranger, SessionScope::Full, 3).await;
    let (result, ran) = run(
        &app,
        writer(&app, &client, theirs.sid, true).await,
        authorized(password(2), manifest(&client, 2)),
    )
    .await;
    assert_eq!(result.expect_err("refused").code, "unauthorized");
    assert!(!ran);
    // An account that is not the user's.
    let mut wrong = writer(&app, &client, fresh.sid, true).await;
    wrong.account = AccountId::from_bytes([0xee; 16]);
    let (result, ran) = run(&app, wrong, authorized(password(2), manifest(&client, 2))).await;
    assert_eq!(result.expect_err("refused").code, "unauthorized");
    assert!(!ran);
    unchanged(&app, &client, &before).await;
}

#[tokio::test]
async fn a_refusal_of_the_proof_check_is_the_answer_and_writes_nothing() {
    let app = TestApp::new().await;
    let client = client_account(&app, 4).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let before = snapshot(&app, &client).await;
    let (result, ran) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        Err(ApiError::coded("denied")),
    )
    .await;
    assert!(ran);
    assert_eq!(result.expect_err("refused").code, "denied");
    unchanged(&app, &client, &before).await;
}

#[tokio::test]
async fn a_new_recovery_key_replaces_the_recovery_wrap_and_pk_r_and_ends_no_session() {
    let app = TestApp::new().await;
    let client = client_account(&app, 5).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let before = snapshot(&app, &client).await;

    // A `pk_r` equal to the stored one would keep the old key valid.
    let same = UnlockChange::Recovery {
        wrap: vec![0x66; 72],
        generation: 2,
        pk_r: <[u8; 32]>::try_from(before.pk_r.as_slice()).unwrap(),
    };
    let (result, _) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(same, manifest(&client, 2)),
    )
    .await;
    assert_eq!(result.expect_err("refused").code, "malformed_recovery_key");
    unchanged(&app, &client, &before).await;

    let change = UnlockChange::Recovery {
        wrap: vec![0x66; 72],
        generation: 2,
        pk_r: [0x99; 32],
    };
    let (result, _) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(change, manifest(&client, 2)),
    )
    .await;
    let applied = result.expect("applied");
    assert_eq!(
        applied,
        Applied {
            seq: 2,
            ended: vec![]
        }
    );
    let after = snapshot(&app, &client).await;
    assert_eq!(after.pk_r, vec![0x99; 32]);
    assert_eq!(after.record, before.record, "the record is kept");
    assert_eq!(after.wraps[0], before.wraps[0], "the password wrap is kept");
    assert_eq!(after.wraps[1].1, before.wraps[1].1, "the same method id");
    assert_eq!((after.wraps[1].2, &after.wraps[1].3), (2, &vec![0x66; 72]));
    assert_eq!((after.manifest_rev, after.manifest_seq), (2, 2));
    assert!(!is_ended(&app, other.sid).await);
    assert!(!is_ended(&app, this.sid).await);
}

#[tokio::test]
async fn a_recovery_writes_the_record_both_wraps_and_pk_r_and_a_reset_session_ends_with_it() {
    let app = TestApp::new().await;
    let client = client_account(&app, 6).await;
    let reset = client_session(&app, &client, SessionScope::AccountReset, 1).await;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Admin,
        SessionScope::Full,
        2,
    )
    .await;
    let before = snapshot(&app, &client).await;
    let recover = |pw_generation, rk_generation| UnlockChange::Recover {
        record: stored_record().record,
        profile: 1,
        pw_wrap: vec![0x71; 104],
        pw_generation,
        rk_wrap: vec![0x72; 72],
        rk_generation,
        pk_r: [0x98; 32],
    };
    // Both generations must rise; one that does not refuses the whole change.
    for (pw, rk) in [(1, 2), (2, 1)] {
        let (result, _) = run(
            &app,
            writer(&app, &client, reset.sid, false).await,
            authorized(recover(pw, rk), manifest(&client, 2)),
        )
        .await;
        assert_eq!(result.expect_err("refused").code, "write_conflict");
        unchanged(&app, &client, &before).await;
    }

    let (result, _) = run(
        &app,
        writer(&app, &client, reset.sid, false).await,
        Ok(Authorized {
            change: recover(5, 7),
            manifest: manifest(&client, 2),
            session_effect: ScopeEffect::EndSession,
        }),
    )
    .await;
    let applied = result.expect("applied");
    assert_eq!(applied.seq, 2);
    let mut expected = vec![reset.sid, other.sid];
    expected.sort_unstable_by_key(|sid| sid.0);
    assert_eq!(applied.ended, expected, "every session, the asking one too");
    let after = snapshot(&app, &client).await;
    assert_eq!(after.record, stored_record().record.as_bytes());
    assert_eq!(after.pk_r, vec![0x98; 32]);
    assert_eq!(after.pk_a, before.pk_a);
    assert_eq!((after.wraps[0].2, after.wraps[1].2), (5, 7));
    assert_eq!(after.wraps[0].1, before.wraps[0].1);
    assert_eq!(after.wraps[1].1, before.wraps[1].1);
    assert!(is_ended(&app, reset.sid).await);
}

#[tokio::test]
async fn a_full_session_that_recovers_goes_on() {
    let app = TestApp::new().await;
    let client = client_account(&app, 7).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let other = issue(
        &app,
        client.ids.user_id,
        Origin::Vault,
        SessionScope::Full,
        2,
    )
    .await;
    let (result, _) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(
            UnlockChange::Recover {
                record: stored_record().record,
                profile: 1,
                pw_wrap: vec![0x71; 104],
                pw_generation: 2,
                rk_wrap: vec![0x72; 72],
                rk_generation: 2,
                pk_r: [0x97; 32],
            },
            manifest(&client, 2),
        ),
    )
    .await;
    assert_eq!(result.expect("applied").ended, vec![other.sid]);
    assert!(!is_ended(&app, this.sid).await);
}

#[tokio::test]
async fn after_commit_announces_the_seq_and_every_ended_session_and_asks_for_a_backup() {
    let app = TestApp::new().await;
    let events = app.sync_events();
    let mut changes = events.subscribe();
    let mut revocations = events.subscribe_revocations();
    let applied = Applied {
        seq: 42,
        ended: vec![SidHash([1; 32]), SidHash([2; 32])],
    };
    let vault = ferret_server::ids::VaultId::from_bytes([0xb7; 16]);
    assert!(!app.backup_status().has_request());
    after_commit(&applied, &events, &app.backup_status(), &vault);

    let change = tokio::time::timeout(Duration::from_secs(1), changes.recv())
        .await
        .expect("in time")
        .expect("a change");
    assert_eq!((change.vault, change.seq), (vault, 42));
    for sid in &applied.ended {
        let revoked = tokio::time::timeout(Duration::from_secs(1), revocations.recv())
            .await
            .expect("in time")
            .expect("a revocation");
        assert_eq!(&revoked, sid);
    }
    assert_eq!(app.backup_status().take_request(), Some(BACKUP_REASON));
    assert_eq!(BACKUP_REASON, "unlock_methods");
}

#[tokio::test]
async fn the_manifest_row_is_the_only_item_written() {
    let app = TestApp::new().await;
    let client = client_account(&app, 8).await;
    let this = client_session(&app, &client, SessionScope::Full, 1).await;
    let (result, _) = run(
        &app,
        writer(&app, &client, this.sid, true).await,
        authorized(password(2), manifest(&client, 2)),
    )
    .await;
    result.expect("applied");
    let vault = client.ids.vault_id;
    let rows: Vec<(Vec<u8>, i64, i64)> = app
        .state
        .vault_db
        .with_conn(move |conn| {
            let mut stmt =
                conn.prepare("SELECT item_id, rev, seq FROM ferret_items WHERE vault_id = ?1")?;
            let rows = stmt
                .query_map([vault.as_bytes().as_slice()], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
        .await
        .expect("the rows");
    assert_eq!(
        rows,
        vec![(ItemId::from_bytes([0; 16]).as_bytes().to_vec(), 2, 2)]
    );
}
