//! The sync routes together: the rate limit, the write queue, the checkpoint
//! pace, a resurrection in a batch and a write that reaches an open event
//! stream. Spec: Fase 1 § 8.2, § 8.4, § 8.6.
//!
//! Each of these needs more than one of the write routes or the limiter and the
//! queue at once, so they live here and not with one route. Everything runs on
//! the manual clock of the test server: no test sleeps, and the pace of ten
//! minutes is crossed by moving the clock.

mod support;

use axum::http::StatusCode;
use ferret_server::vault::rate::RateConfig;
use ferret_server::wire::b64url;
use serde_json::{Value, json};
use std::time::Duration;
use support::sync::{
    View, World, as_op, batch_results, checkpoint_body, error_code, item, live_body, tomb_body,
};
use support::{Res, TestApp};

fn error(res: &Res) -> String {
    error_code(res)
}

// ------------------------------------------------------------- the rate

#[tokio::test]
async fn item_write_over_the_rate_is_429_with_retry_after() {
    // One operation a second, and room for three at once.
    let rate = RateConfig {
        ops_per_min: 60,
        ops_burst: 3,
        ..RateConfig::DEFAULT
    };
    let world = World::on(TestApp::builder().rate(rate).build().await).await;
    let a = world.client("a").await;
    let b = world.client("b").await;
    let vault = world.vault();

    for n in 1..=3u16 {
        let res = a
            .put(item(n), &live_body(&vault, item(n), 0, "n", u32::from(n)))
            .await;
        assert_eq!(res.status, StatusCode::OK, "write {n}: {}", res.text());
    }
    let seq = world.server_seq().await;

    // The fourth is over the burst.
    let fourth = live_body(&vault, item(4), 0, "four", 4);
    let over = a.put(item(4), &fourth).await;
    assert_eq!(
        over.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        over.text()
    );
    assert_eq!(error(&over), "throttled");
    assert_eq!(over.header("retry-after"), "1");
    assert_eq!(over.header("cache-control"), "no-store");
    assert_eq!(
        world.server_seq().await,
        seq,
        "a refused write stores nothing"
    );

    // The bucket belongs to the device: another device of the account writes.
    let other = b
        .put(item(5), &live_body(&vault, item(5), 0, "five", 5))
        .await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.text());

    // A refused write takes nothing: after the wait the same request passes,
    // and the next one is over the rate again.
    world.app.clock.advance(1);
    let again = a.put(item(4), &fourth).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    let next = a
        .put(item(6), &live_body(&vault, item(6), 0, "six", 6))
        .await;
    assert_eq!(next.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(next.header("retry-after"), "1");
}

#[tokio::test]
async fn a_batch_counts_one_operation_for_each_item() {
    // One operation a second, and room for four at once.
    let rate = RateConfig {
        ops_per_min: 60,
        ops_burst: 4,
        ..RateConfig::DEFAULT
    };
    let world = World::on(TestApp::builder().rate(rate).build().await).await;
    let a = world.client("a").await;
    let vault = world.vault();
    let ops: Vec<Value> = (1..=6u16)
        .map(|n| as_op(item(n), &live_body(&vault, item(n), 0, "n", u32::from(n))))
        .collect();

    // Three operations take three from the bucket of four.
    let ok = batch_results(&a.post_batch(&ops[..3]).await);
    assert!(ok.results.iter().all(|r| r.status == 200));
    let seq = world.server_seq().await;

    // Three more are one too many, as a whole: none is stored, and the wait is
    // for the two that are missing.
    let over = a.post_batch(&ops[3..6]).await;
    assert_eq!(
        over.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        over.text()
    );
    assert_eq!(error(&over), "throttled");
    assert_eq!(over.header("retry-after"), "2");
    assert_eq!(world.server_seq().await, seq);

    // The one operation that is left is enough for one write, and then the
    // bucket is empty.
    let one = a.post_batch(&ops[3..4]).await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.text());
    let spent = a.post_batch(&ops[4..5]).await;
    assert_eq!(spent.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(spent.header("retry-after"), "1");
}

// -------------------------------------------------------- the write queue

#[tokio::test]
async fn item_write_when_the_gate_is_full_is_503_busy() {
    let world = World::on(TestApp::builder().gate(1, 0).build().await).await;
    let a = world.client("a").await;
    let vault = world.vault();
    let body = live_body(&vault, item(1), 0, "one", 1);
    let seq = world.server_seq().await;

    let permit = world
        .app
        .state
        .write_gate
        .enter()
        .await
        .expect("a free turn");
    let res = a.put(item(1), &body).await;
    assert_eq!(
        res.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        res.text()
    );
    assert_eq!(error(&res), "busy");
    assert_eq!(res.header("retry-after"), "2");
    assert_eq!(res.header("cache-control"), "no-store");
    assert_eq!(world.server_seq().await, seq, "nothing was written");

    // The turn comes back with the permit, the same request is stored (it was
    // not stored before, so it is no replay), and a write gives its turn back.
    drop(permit);
    let stored = a.put(item(1), &body).await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
    assert_eq!(stored.json()["replayed"], json!(false));
    let next = a
        .put(item(2), &live_body(&vault, item(2), 0, "two", 2))
        .await;
    assert_eq!(next.status, StatusCode::OK, "{}", next.text());
}

#[tokio::test]
async fn checkpoint_upload_when_the_gate_is_full_is_503_busy() {
    let world = World::on(TestApp::builder().gate(1, 0).build().await).await;
    let mut a = world.client("a").await;
    a.edit(item(1), "one");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 2);

    let permit = world
        .app
        .state
        .write_gate
        .enter()
        .await
        .expect("a free turn");
    let res = a.upload_checkpoint().await;
    assert_eq!(
        res.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        res.text()
    );
    assert_eq!(error(&res), "busy");
    assert_eq!(res.header("retry-after"), "2");
    assert_eq!(
        a.fetch_checkpoint().await.expect("a checkpoint").seq,
        1,
        "the first checkpoint is still the stored one"
    );

    // A refused upload used no turn of the pace: with the gate free again the
    // same upload goes through at once, with no time passed.
    drop(permit);
    let res = a.upload_checkpoint().await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(res.json(), json!({ "seq": 2 }));
    assert_eq!(a.fetch_checkpoint().await.expect("a checkpoint").seq, 2);
}

// ------------------------------------------------------ the checkpoint pace

#[tokio::test]
async fn second_stored_upload_within_ten_minutes_from_one_device_is_429_and_a_refused_one_does_not_count()
 {
    let world = World::new().await;
    let mut a = world.client("a").await;
    let mut b = world.client("b").await;
    a.edit(item(1), "one");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 2);

    // A refused upload (the digest is not that of the entries) uses no turn.
    let mut broken = checkpoint_body(&a.make_checkpoint());
    broken["digest"] = json!(b64url::encode(&[7u8; 32]));
    let refused = a.put_checkpoint(&broken).await;
    assert_eq!(refused.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(error(&refused), "checkpoint_invalid");

    // So the first stored upload passes at once, and the second, a little
    // later and with news in it, does not.
    let first = a.upload_checkpoint().await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.text());
    assert_eq!(first.json(), json!({ "seq": 2 }));
    a.edit(item(2), "two");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 3);
    let second = a.upload_checkpoint().await;
    assert_eq!(
        second.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        second.text()
    );
    assert_eq!(error(&second), "throttled");
    assert_eq!(second.header("retry-after"), "600");
    assert_eq!(a.fetch_checkpoint().await.expect("a checkpoint").seq, 2);

    // The pace belongs to the device. Another device has its own turn; its
    // first try is stale (409, which uses no turn), the next one is stored.
    b.pull().await;
    let old = ferret_core::make_checkpoint(&world.vault(), 1, Vec::new()).expect("a checkpoint");
    let stale = b.put_checkpoint(&checkpoint_body(&old)).await;
    assert_eq!(stale.status, StatusCode::CONFLICT, "{}", stale.text());
    assert_eq!(
        stale.json(),
        json!({ "error": "checkpoint_stale", "stored_seq": 2 })
    );
    let stored = b.upload_checkpoint().await;
    assert_eq!(stored.status, StatusCode::OK, "{}", stored.text());
    assert_eq!(stored.json(), json!({ "seq": 3 }));

    // The refusal of the first device did not start its pace over: ten minutes
    // after its stored upload (not after the refused one) it may upload again.
    world.app.clock.advance(599);
    a.edit(item(3), "three");
    a.sync().await;
    a.pull().await;
    assert_eq!(a.cursor(), 4);
    let early = a.upload_checkpoint().await;
    assert_eq!(
        early.status,
        StatusCode::TOO_MANY_REQUESTS,
        "{}",
        early.text()
    );
    assert_eq!(early.header("retry-after"), "1");
    world.app.clock.advance(1);
    let late = a.upload_checkpoint().await;
    assert_eq!(late.status, StatusCode::OK, "{}", late.text());
    assert_eq!(late.json(), json!({ "seq": 4 }));
}

// ----------------------------------------------------- resurrection, batch

#[tokio::test]
async fn resurrect_works_in_a_batch() {
    let world = World::new().await;
    let a = world.client("a").await;
    let vault = world.vault();

    // Three items, each written and then deleted: tombstones at rev 2.
    for n in 1..=3u16 {
        let made = a
            .put(
                item(n),
                &live_body(&vault, item(n), 0, "first", u32::from(n)),
            )
            .await;
        assert_eq!(made.status, StatusCode::OK, "{}", made.text());
        let gone = a
            .put(item(n), &tomb_body(&vault, item(n), 1, 10 + u32::from(n)))
            .await;
        assert_eq!(gone.status, StatusCode::OK, "{}", gone.text());
    }
    let seq = world.server_seq().await;

    let mut asked = live_body(&vault, item(1), 2, "back", 21);
    asked["resurrect"] = json!(true);
    let mut stale = live_body(&vault, item(2), 1, "stale", 22);
    stale["resurrect"] = json!(true);
    // The right base, but no `resurrect`: nobody chose to bring it back.
    let unasked = live_body(&vault, item(3), 2, "unasked", 23);
    let ops = [
        as_op(item(1), &asked),
        as_op(item(2), &stale),
        as_op(item(3), &unasked),
    ];

    let results = batch_results(&a.post_batch(&ops).await).results;
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].status, 200);
    assert_eq!(results[0].rev, Some(3));
    assert_eq!(results[0].replayed, Some(false));
    let seq_of_back = results[0].seq.expect("a seq");
    assert_eq!(seq_of_back, seq + 1);
    for (slot, result) in results.iter().enumerate().skip(1) {
        assert_eq!(result.status, 409, "slot {slot}");
        assert_eq!(result.deleted, Some(true), "slot {slot}");
        assert_eq!(result.current_rev, Some(2), "slot {slot}");
    }
    assert_eq!(world.server_seq().await, seq + 1, "one stored write");

    // What a device sees: the one that was asked for is back, with its new
    // content; the other two are still deleted.
    let mut b = world.client("b").await;
    let report = b.sync().await;
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(b.view(item(1)), View::note("back"));
    assert_eq!(b.rev_of(item(1)), 3);
    assert_eq!(b.view(item(2)), View::Deleted);
    assert_eq!(b.view(item(3)), View::Deleted);

    // Sent again, the batch answers the stored one from its record and the
    // others as they were: nothing changes on the server.
    let again = batch_results(&a.post_batch(&ops).await).results;
    assert_eq!(again[0].status, 200);
    assert_eq!(again[0].replayed, Some(true));
    assert_eq!(again[0].rev, Some(3));
    assert_eq!(again[0].seq, Some(seq_of_back));
    assert_eq!(again[1].status, 409);
    assert_eq!(again[2].status, 409);
    assert_eq!(world.server_seq().await, seq + 1);
}

// ------------------------------------------------------------- the stream

#[tokio::test]
async fn a_write_reaches_an_open_event_stream_within_one_second() {
    let world = World::new().await;
    let mut a = world.client("a").await;
    let mut b = world.client("b").await;
    let mut events = a.open_events().await;
    assert_eq!(events.status, StatusCode::OK);
    let hello = events.event("hello", Duration::from_secs(1)).await;
    assert_eq!(hello, json!({ "seq": world.server_seq().await }));

    b.edit(item(1), "from b");
    let report = b.sync().await;
    assert_eq!(report.pushed, 1);

    let seq = world.server_seq().await;
    let sync = events.event("sync", Duration::from_secs(1)).await;
    assert_eq!(sync, json!({ "seq": seq }));

    // And the event is only a hint: the device reads the row itself.
    let report = a.sync().await;
    assert!(report.warnings.is_empty());
    assert_eq!(a.view(item(1)), View::note("from b"));
}
