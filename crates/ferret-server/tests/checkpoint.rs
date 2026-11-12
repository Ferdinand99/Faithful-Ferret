//! `PUT` and `GET /api/sync/checkpoint`, and the checkpoint head of
//! `/api/sync/changes`. Spec: Fase 1 § 8.2, § 8.6.
//!
//! The server stores the checkpoint with the highest `seq` and checks only its
//! structure, never the MAC. The pace of uploads (one per device per ten
//! minutes) and the write queue are tested with the routes together, in
//! `tests/sync_routes.rs`; these tests move the manual clock past the pace
//! before each upload, so they hold with or without the limiter.

mod support;

use std::io;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ferret_core::integrity::checkpoint::ENTRY_LEN;
use ferret_core::{
    Checkpoint, CheckpointEntry, CheckpointFailure, Error as CoreError, ItemBody, ItemType, OsRng,
    RollbackMemory, RowState, ServerRow, UnlockedVault, VaultContext, VaultKey, encrypt_item,
    make_checkpoint, make_tombstone, verify_checkpoint,
};
use ferret_server::auth::session::Origin;
use ferret_server::ids::{ItemId, MANIFEST_ITEM_ID};
use ferret_server::vault::rate::RateConfig;
use ferret_server::wire::{CheckpointJson, b64url, hex16};
use ferret_server_auth::SessionScope;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::accounts::add_account_to_app;
use support::session::issue;
use support::{Jar, Req, Res, TestApp, VAULT_URL, Which};
use tracing_subscriber::fmt::MakeWriter;

/// A signed-in user: the browser's cookies and the keys the browser would
/// hold.
struct User {
    jar: Jar,
    vault: UnlockedVault,
}

async fn user(app: &TestApp, n: u8) -> User {
    let account = add_account_to_app(app, n).await;
    let issued = issue(app, account.user_id, Origin::Vault, SessionScope::Full, n).await;
    let vault = UnlockedVault::from_vault_key(
        VaultContext {
            account_id: account.account_id,
            vault_id: account.vault_id,
            vk_epoch: 1,
        },
        VaultKey::from_test_bytes([n; 32]),
    )
    .expect("an unlocked vault");
    User {
        jar: issued.jar,
        vault,
    }
}

fn item(n: u8) -> ItemId {
    let mut bytes = [0u8; 16];
    bytes[0] = 0x10;
    bytes[1] = n;
    ItemId::from_bytes(bytes)
}

fn idem(n: u8) -> [u8; 16] {
    [n; 16]
}

fn request(method: &str, uri: &str, jar: &Jar, body: Vec<u8>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("origin", VAULT_URL)
        .header("sec-fetch-site", "same-origin")
        .header("ferret-protocol", "1")
        .header("content-type", "application/json");
    if let Some(cookie) = jar.header() {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Body::from(body)).expect("a request")
}

/// Writes a note and returns the sealed row.
async fn write_note(app: &TestApp, u: &User, id: ItemId, n: u8) -> ferret_core::SealedItem {
    let mut body = ItemBody::new(ItemType::Note, format!("note {n}"), 1);
    body.notes = Some(format!("secret words of note {n}"));
    let sealed = encrypt_item(&mut OsRng, &u.vault, id, 1, &body, None).expect("an item");
    let json = json!({
        "base_rev": 0,
        "blob": b64url::encode(&sealed.envelope),
        "tag": b64url::encode(&sealed.tag),
        "idem": hex16::encode(&idem(n)),
    });
    let res = app
        .call_raw(
            Which::Vault,
            request(
                "PUT",
                &format!("/api/sync/items/{}", hex16::encode(id.as_bytes())),
                &u.jar,
                json.to_string().into_bytes(),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    sealed
}

/// The body of a checkpoint upload; the digest is the SHA-256 of `entries`
/// unless a test says otherwise.
fn body(seq: u64, entries: &[u8], digest: Option<[u8; 32]>, mac: [u8; 32]) -> Value {
    let digest = digest.unwrap_or_else(|| Sha256::digest(entries).into());
    json!({
        "seq": seq,
        "digest": b64url::encode(&digest),
        "mac": b64url::encode(&mac),
        "entries": b64url::encode(entries),
    })
}

/// One entry of `entries`: the item id, the revision and the hash.
fn entry(id: [u8; 16], rev: u64, hash: [u8; 32]) -> Vec<u8> {
    let mut out = id.to_vec();
    out.extend_from_slice(&rev.to_be_bytes());
    out.extend_from_slice(&hash);
    out
}

/// An id that sorts by `n`.
fn ordered_id(n: u128) -> [u8; 16] {
    n.to_be_bytes()
}

/// Uploads a checkpoint after the pace of a device (ten minutes) has passed.
async fn upload(app: &TestApp, u: &User, body: &Value) -> Res {
    app.clock.advance(601);
    upload_now(app, u, body.to_string().into_bytes()).await
}

async fn upload_now(app: &TestApp, u: &User, raw: Vec<u8>) -> Res {
    app.call_raw(
        Which::Vault,
        request("PUT", "/api/sync/checkpoint", &u.jar, raw),
    )
    .await
}

async fn fetch(app: &TestApp, u: &User) -> Res {
    app.call_raw(
        Which::Vault,
        request("GET", "/api/sync/checkpoint", &u.jar, Vec::new()),
    )
    .await
}

async fn changes(app: &TestApp, u: &User) -> Value {
    let res = app
        .call_raw(
            Which::Vault,
            request("GET", "/api/sync/changes?since=0", &u.jar, Vec::new()),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    res.json()
}

fn error(res: &Res) -> String {
    res.json()["error"].as_str().unwrap_or("").to_string()
}

/// The vault `seq` of the account.
async fn vault_seq(app: &TestApp, u: &User) -> u64 {
    changes(app, u).await["latest_seq"].as_u64().unwrap()
}

/// What the stored checkpoint is, as a client reads it back.
async fn stored(app: &TestApp, u: &User) -> Value {
    let res = fetch(app, u).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    res.json()
}

#[tokio::test]
async fn registration_checkpoint_is_served_by_get() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // The account was made with its first checkpoint, at seq 1 (as a
    // registration leaves it). GET serves it as it was stored.
    let res = fetch(&app, &u).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(
        res.json(),
        json!({
            "seq": 1,
            "digest": b64url::encode(&[0x41; 32]),
            "mac": b64url::encode(&[0x42; 32]),
            "entries": b64url::encode(&[0x43; 20]),
        })
    );
    // Without a session there is nothing to read.
    let res = app
        .call_raw(
            Which::Vault,
            request("GET", "/api/sync/checkpoint", &Jar::default(), Vec::new()),
        )
        .await;
    assert_eq!(res.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn higher_seq_replaces_and_get_returns_it_byte_for_byte() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=3u8 {
        write_note(&app, &u, item(n), n).await;
    }
    assert_eq!(vault_seq(&app, &u).await, 4);

    for (seq, mark) in [(2u64, 0x20u8), (3, 0x30), (4, 0x40)] {
        let entries = [
            entry(ordered_id(1), 1, [mark; 32]),
            entry(ordered_id(2), u64::from(mark), [mark.wrapping_add(1); 32]),
        ]
        .concat();
        let sent = body(seq, &entries, None, [mark.wrapping_add(2); 32]);
        let res = upload(&app, &u, &sent).await;
        assert_eq!(res.status, StatusCode::OK, "seq {seq}: {}", res.text());
        assert_eq!(res.json(), json!({ "seq": seq }));
        // What comes back is exactly what went in, bytes and text.
        assert_eq!(stored(&app, &u).await, sent, "seq {seq}");
    }
}

#[tokio::test]
async fn lower_seq_is_409_checkpoint_stale_with_the_stored_seq_and_changes_nothing() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=3u8 {
        write_note(&app, &u, item(n), n).await;
    }
    let entries = entry(ordered_id(1), 1, [1; 32]);
    let kept = body(3, &entries, None, [3; 32]);
    assert_eq!(upload(&app, &u, &kept).await.status, StatusCode::OK);

    for seq in [2u64, 1, 0] {
        let lower = body(seq, &entry(ordered_id(9), 5, [9; 32]), None, [9; 32]);
        let res = upload(&app, &u, &lower).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "seq {seq}");
        assert_eq!(
            res.json(),
            json!({ "error": "checkpoint_stale", "stored_seq": 3 }),
            "seq {seq}"
        );
        assert_eq!(stored(&app, &u).await, kept, "seq {seq}");
    }
}

#[tokio::test]
async fn same_seq_same_bytes_is_200_and_same_seq_other_bytes_is_409() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await;
    let entries = entry(ordered_id(1), 1, [1; 32]);
    let first = body(2, &entries, None, [2; 32]);
    assert_eq!(upload(&app, &u, &first).await.status, StatusCode::OK);

    // A retry of the same upload is fine.
    let again = upload(&app, &u, &first).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.text());
    assert_eq!(again.json(), json!({ "seq": 2 }));

    // Other bytes under the same seq are not: another MAC, other entries, or
    // another digest.
    let other_entries = entry(ordered_id(1), 2, [1; 32]);
    for (name, other) in [
        ("another MAC", body(2, &entries, None, [3; 32])),
        ("other entries", body(2, &other_entries, None, [2; 32])),
    ] {
        let res = upload(&app, &u, &other).await;
        assert_eq!(res.status, StatusCode::CONFLICT, "{name}");
        assert_eq!(
            res.json(),
            json!({ "error": "checkpoint_stale", "stored_seq": 2 }),
            "{name}"
        );
        assert_eq!(stored(&app, &u).await, first, "{name}");
    }
}

#[tokio::test]
async fn seq_above_the_vault_seq_is_422_checkpoint_invalid() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await;
    let top = vault_seq(&app, &u).await;
    let before = stored(&app, &u).await;

    let entries = entry(ordered_id(1), 1, [1; 32]);
    for seq in [top + 1, top + 1000, 9_007_199_254_740_991] {
        let res = upload(&app, &u, &body(seq, &entries, None, [1; 32])).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "seq {seq}");
        assert_eq!(error(&res), "checkpoint_invalid", "seq {seq}");
    }
    assert_eq!(stored(&app, &u).await, before, "nothing was stored");
    // The top itself is allowed.
    let res = upload(&app, &u, &body(top, &entries, None, [1; 32])).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn entries_not_a_multiple_of_56_unsorted_duplicated_rev_0_or_a_digest_mismatch_are_422() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await;
    let before = stored(&app, &u).await;
    let (a, b) = (ordered_id(1), ordered_id(2));
    let good = [entry(a, 1, [1; 32]), entry(b, 1, [2; 32])].concat();
    let mut extra_byte = good.clone();
    extra_byte.push(0);
    let cases: Vec<(&str, Value)> = vec![
        ("55 bytes", body(2, &good[..55], None, [1; 32])),
        ("57 bytes", body(2, &extra_byte[..57], None, [1; 32])),
        ("a byte too many", body(2, &extra_byte, None, [1; 32])),
        (
            "unsorted",
            body(
                2,
                &[entry(b, 1, [2; 32]), entry(a, 1, [1; 32])].concat(),
                None,
                [1; 32],
            ),
        ),
        (
            "duplicated",
            body(
                2,
                &[entry(a, 1, [1; 32]), entry(a, 2, [1; 32])].concat(),
                None,
                [1; 32],
            ),
        ),
        (
            "rev 0",
            body(
                2,
                &[entry(a, 1, [1; 32]), entry(b, 0, [2; 32])].concat(),
                None,
                [1; 32],
            ),
        ),
        (
            "a digest of other bytes",
            body(2, &good, Some(Sha256::digest(b"other").into()), [1; 32]),
        ),
        ("a digest of zeros", body(2, &good, Some([0; 32]), [1; 32])),
    ];
    for (name, sent) in cases {
        let res = upload(&app, &u, &sent).await;
        assert_eq!(res.status, StatusCode::UNPROCESSABLE_ENTITY, "{name}");
        assert_eq!(error(&res), "checkpoint_invalid", "{name}");
        assert_eq!(stored(&app, &u).await, before, "{name}");
    }
    // The well-formed one passes.
    let res = upload(&app, &u, &body(2, &good, None, [1; 32])).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
}

#[tokio::test]
async fn more_than_50000_entries_is_413() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await;
    let many = |count: u128| -> Vec<u8> {
        let mut out = Vec::with_capacity(usize::try_from(count).unwrap() * ENTRY_LEN);
        for n in 1..=count {
            out.extend_from_slice(&entry(ordered_id(n), 1, [7; 32]));
        }
        out
    };

    // 50 001 entries are well formed and one too many.
    let res = upload(&app, &u, &body(2, &many(50_001), None, [1; 32])).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&res), "too_large");

    // A body past 4 MiB is refused before it is read.
    let res = upload(&app, &u, &body(2, &many(60_000), None, [1; 32])).await;
    assert_eq!(res.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error(&res), "too_large");

    // 50 000 is the most that is stored.
    let full = body(2, &many(50_000), None, [1; 32]);
    let res = upload(&app, &u, &full).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    assert_eq!(stored(&app, &u).await, full);
}

#[tokio::test]
async fn server_never_checks_the_mac() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for n in 1..=3u8 {
        write_note(&app, &u, item(n), n).await;
    }
    // A MAC of zeros, of garbage, and one that a real client made for another
    // seq: the server has no key and says nothing about any of them.
    let entries = entry(ordered_id(1), 1, [1; 32]);
    let real = make_checkpoint(
        &u.vault,
        4,
        vec![CheckpointEntry::live(item(1), 1, b"envelope")],
    )
    .expect("a checkpoint");
    for (seq, mac) in [(2u64, [0u8; 32]), (3, [0xa5; 32]), (4, real.mac)] {
        let sent = body(seq, &entries, None, mac);
        let res = upload(&app, &u, &sent).await;
        assert_eq!(res.status, StatusCode::OK, "seq {seq}: {}", res.text());
        assert_eq!(stored(&app, &u).await, sent, "seq {seq}");
    }
}

#[tokio::test]
async fn changes_carries_the_checkpoint_head_and_never_the_entries() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;

    // The checkpoint of the registration is the head at first.
    let feed = changes(&app, &u).await;
    assert_eq!(
        feed["checkpoint"],
        json!({
            "seq": 1,
            "digest": b64url::encode(&[0x41; 32]),
            "mac": b64url::encode(&[0x42; 32]),
        })
    );

    for n in 1..=2u8 {
        write_note(&app, &u, item(n), n).await;
    }
    let entries = [
        entry(ordered_id(1), 1, [0x61; 32]),
        entry(ordered_id(2), 1, [0x62; 32]),
    ]
    .concat();
    let sent = body(3, &entries, None, [0x63; 32]);
    assert_eq!(upload(&app, &u, &sent).await.status, StatusCode::OK);

    let res = app
        .call_raw(
            Which::Vault,
            request("GET", "/api/sync/changes?since=0", &u.jar, Vec::new()),
        )
        .await;
    let feed = res.json();
    let head = feed["checkpoint"].as_object().expect("a head");
    assert_eq!(head.len(), 3, "seq, digest and mac, nothing else");
    assert_eq!(head["seq"], 3);
    assert_eq!(head["digest"], sent["digest"]);
    assert_eq!(head["mac"], sent["mac"]);
    assert!(
        !res.text().contains(sent["entries"].as_str().unwrap()),
        "the entries are not in the feed"
    );
    assert!(feed["latest_seq"].as_u64().unwrap() >= 3);

    // Another vault has its own head.
    let other = user(&app, 2).await;
    assert_eq!(changes(&app, &other).await["checkpoint"]["seq"], 1);
}

#[tokio::test]
async fn a_checkpoint_of_another_vault_leaves_this_vault_unchanged() {
    let app = TestApp::new().await;
    let a = user(&app, 1).await;
    let b = user(&app, 2).await;
    write_note(&app, &a, item(1), 1).await;
    write_note(&app, &b, item(1), 2).await;
    let a_entries = entry(ordered_id(1), 1, [0xa1; 32]);
    let a_sent = body(2, &a_entries, None, [0xa2; 32]);
    assert_eq!(upload(&app, &a, &a_sent).await.status, StatusCode::OK);
    let a_before = stored(&app, &a).await;
    let a_head_before = changes(&app, &a).await["checkpoint"].clone();
    assert_eq!(a_before, a_sent);

    // B uploads a newer checkpoint, a stale one and a refused one.
    write_note(&app, &b, item(2), 3).await;
    let b_entries = entry(ordered_id(7), 3, [0xb1; 32]);
    let b_sent = body(3, &b_entries, None, [0xb2; 32]);
    assert_eq!(upload(&app, &b, &b_sent).await.status, StatusCode::OK);
    let stale = body(2, &b_entries, None, [0xb3; 32]);
    assert_eq!(upload(&app, &b, &stale).await.status, StatusCode::CONFLICT);
    let above = body(99, &b_entries, None, [0xb4; 32]);
    assert_eq!(
        upload(&app, &b, &above).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );

    assert_eq!(stored(&app, &b).await, b_sent, "B has its own checkpoint");
    assert_eq!(stored(&app, &a).await, a_before, "A's is untouched");
    assert_eq!(changes(&app, &a).await["checkpoint"], a_head_before);
    assert_ne!(changes(&app, &b).await["checkpoint"], a_head_before);
}

#[tokio::test]
async fn a_burst_of_refused_uploads_ends_in_429() {
    // Only three operations in the bucket of a device.
    let app = TestApp::builder()
        .rate(RateConfig {
            ops_burst: 3,
            ..RateConfig::DEFAULT
        })
        .build()
        .await;
    // The limiter is shared with the item routes and is tested by its own
    // numbers in tests/rate.rs.
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await; // 1 of 3 operations
    let before = stored(&app, &u).await;

    // Same seq as the checkpoint of the registration with other bytes, above
    // the vault, and the same again: the store refuses each, and each takes an
    // operation, so the burst runs out. (No upload of this device was stored,
    // so the pace of ten minutes does not come into it.)
    let entries = entry(ordered_id(1), 1, [1; 32]);
    let stale = body(1, &entries, None, [2; 32]).to_string().into_bytes();
    let above = body(99, &entries, None, [3; 32]).to_string().into_bytes();
    let mut statuses = Vec::new();
    let mut last = None;
    for raw in [stale.clone(), above, stale.clone(), stale.clone(), stale] {
        let res = upload_now(&app, &u, raw).await;
        statuses.push(res.status);
        last = Some(res);
    }
    assert_eq!(
        statuses,
        [
            StatusCode::CONFLICT,
            StatusCode::UNPROCESSABLE_ENTITY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::TOO_MANY_REQUESTS,
        ]
    );
    let refused = last.expect("a response");
    assert_eq!(error(&refused), "throttled");
    assert!(refused.header("retry-after").parse::<u32>().unwrap() >= 1);
    // What was stored stays.
    assert_eq!(stored(&app, &u).await, before);
}

#[tokio::test]
async fn real_client_checkpoint_roundtrip() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    let (first, second) = (item(1), item(2));
    let sealed_first = write_note(&app, &u, first, 1).await;
    write_note(&app, &u, second, 2).await;
    // The second item is deleted again, so the checkpoint has a tombstone.
    let t = make_tombstone(&mut OsRng, &u.vault, second, 2).expect("a tombstone");
    let res = app
        .call_raw(
            Which::Vault,
            request(
                "PUT",
                &format!("/api/sync/items/{}", hex16::encode(second.as_bytes())),
                &u.jar,
                json!({
                    "base_rev": 1,
                    "deleted": true,
                    "tomb": b64url::encode(&t.tomb),
                    "idem": hex16::encode(&idem(9)),
                })
                .to_string()
                .into_bytes(),
            ),
        )
        .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    let top = vault_seq(&app, &u).await;
    assert_eq!(top, 4);

    // The client makes the checkpoint of what it holds at the top: the
    // manifest as the server stores it, the note, and the tombstone.
    let manifest_envelope = vec![0x4d; 40];
    let cp = make_checkpoint(
        &u.vault,
        top,
        vec![
            CheckpointEntry::live(first, 1, &sealed_first.envelope),
            CheckpointEntry::tombstone(second, 2),
            CheckpointEntry::live(MANIFEST_ITEM_ID, 1, &manifest_envelope),
        ],
    )
    .expect("a checkpoint");
    let sent = body(cp.seq, &cp.entries, Some(cp.digest), cp.mac);
    let res = upload(&app, &u, &sent).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    // Another device fetches it and checks it against the rows of the feed.
    let fetched: CheckpointJson = serde_json::from_slice(&fetch(&app, &u).await.body).unwrap();
    let fetched = Checkpoint {
        seq: fetched.seq,
        digest: fetched.digest,
        mac: fetched.mac,
        entries: fetched.entries,
    };
    assert_eq!(fetched, cp, "the server changes no byte");

    let feed = changes(&app, &u).await;
    let mut rows = Vec::new();
    for row in feed["changes"].as_array().unwrap() {
        let id =
            ItemId::from_bytes(hex16::decode(row["id"].as_str().unwrap()).expect("an item id"));
        let rev = row["rev"].as_u64().unwrap();
        let server_row = if row["deleted"] == true {
            let tomb = b64url::decode(row["tomb"].as_str().unwrap()).unwrap();
            ServerRow::deleted(&u.vault, id, rev, &tomb).expect("a valid tombstone")
        } else if id == MANIFEST_ITEM_ID {
            // The manifest of a test account is not sealed under the test
            // key; the row is made from what the server shows.
            let blob = b64url::decode(row["blob"].as_str().unwrap()).unwrap();
            ServerRow {
                item_id: id,
                rev,
                state: RowState::Live {
                    blob_sha256: Sha256::digest(&blob).into(),
                },
            }
        } else {
            let blob = b64url::decode(row["blob"].as_str().unwrap()).unwrap();
            let tag: [u8; 32] = b64url::decode(row["tag"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            ServerRow::live(&u.vault, id, rev, &blob, &tag).expect("a valid row")
        };
        rows.push(server_row);
    }
    assert_eq!(rows.len(), 3);
    verify_checkpoint(&u.vault, &fetched, &rows, top, RollbackMemory::NoMemory)
        .expect("the checkpoint holds against the rows");

    // One changed byte: the server refuses the upload, and a client that is
    // handed it anyway finds the digest wrong.
    let mut forged = fetched.clone();
    forged.entries[20] ^= 1;
    let sent = body(forged.seq, &forged.entries, Some(forged.digest), forged.mac);
    let res = upload(&app, &u, &sent).await;
    assert_eq!(
        res.status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        res.text()
    );
    assert_eq!(error(&res), "checkpoint_invalid");
    assert!(matches!(
        verify_checkpoint(&u.vault, &forged, &rows, top, RollbackMemory::NoMemory),
        Err(CoreError::Checkpoint(CheckpointFailure::BadDigest))
    ));
    assert_eq!(stored(&app, &u).await, sent_of(&fetched));
}

/// A checkpoint as the JSON that carries it.
fn sent_of(cp: &Checkpoint) -> Value {
    body(cp.seq, &cp.entries, Some(cp.digest), cp.mac)
}

// ---------------------------------------------------------------------------
// What leaves the server, and where the routes are.

#[tokio::test]
async fn checkpoint_answers_have_no_store() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    write_note(&app, &u, item(1), 1).await;
    let entries = entry(ordered_id(1), 1, [1; 32]);
    let good = body(2, &entries, None, [1; 32]);
    let responses = [
        ("stored", upload(&app, &u, &good).await, StatusCode::OK),
        ("unchanged", upload(&app, &u, &good).await, StatusCode::OK),
        (
            "stale",
            upload(&app, &u, &body(1, &entries, None, [1; 32])).await,
            StatusCode::CONFLICT,
        ),
        (
            "above the vault",
            upload(&app, &u, &body(99, &entries, None, [1; 32])).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "malformed entries",
            upload(&app, &u, &body(3, &entries[..55], None, [1; 32])).await,
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "not JSON",
            upload_now(&app, &u, b"{".to_vec()).await,
            StatusCode::BAD_REQUEST,
        ),
        (
            "an unknown field",
            {
                let mut extra = good.clone();
                extra["extra"] = json!(1);
                upload(&app, &u, &extra).await
            },
            StatusCode::BAD_REQUEST,
        ),
        ("get", fetch(&app, &u).await, StatusCode::OK),
        (
            "no session",
            app.call_raw(
                Which::Vault,
                request("GET", "/api/sync/checkpoint", &Jar::default(), Vec::new()),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "no session on put",
            app.call_raw(
                Which::Vault,
                request(
                    "PUT",
                    "/api/sync/checkpoint",
                    &Jar::default(),
                    good.to_string().into_bytes(),
                ),
            )
            .await,
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (name, res, status) in &responses {
        assert_eq!(res.status, *status, "{name}: {}", res.text());
        assert_eq!(res.header("cache-control"), "no-store", "{name}");
        assert!(
            res.header("content-type").starts_with("application/json"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn admin_listener_has_no_checkpoint_route() {
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    for method in ["GET", "PUT"] {
        let res = app
            .call(
                Which::Admin,
                Req::new(method.parse().expect("a method"), "/api/sync/checkpoint")
                    .header("cookie", &u.jar.header().unwrap_or_default())
                    .page_fetch(Which::Admin)
                    .build(),
            )
            .await;
        assert_eq!(res.status, StatusCode::NOT_FOUND, "{method}");
    }
    // The vault listener serves it to the same cookies.
    assert_eq!(fetch(&app, &u).await.status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// The log.

/// A log sink the test can read.
#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("sink").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Sink {
    type Writer = Sink;

    fn make_writer(&'a self) -> Sink {
        self.clone()
    }
}

/// One subscriber for the whole test binary, installed once.
fn log_sink() -> Sink {
    static SINK: std::sync::OnceLock<Sink> = std::sync::OnceLock::new();
    SINK.get_or_init(|| {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("one global subscriber");
        sink
    })
    .clone()
}

/// Every form in which a log line could carry `bytes`: base64url and hex of the
/// whole value, the inside of its `Debug` text, and the same three for a slice
/// of a long value (starting and ending on multiples of 3 bytes, so the
/// base64url of the slice is a substring of that of the whole).
fn canaries_for(bytes: &[u8]) -> Vec<String> {
    fn inner_debug(bytes: &[u8]) -> String {
        format!("{bytes:?}")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }
    let mut forms = vec![
        b64url::encode(bytes),
        ferret_core::testing::hex_encode(bytes),
        inner_debug(bytes),
    ];
    if let Some(slice) = bytes.get(42..81) {
        forms.push(b64url::encode(slice));
        forms.push(ferret_core::testing::hex_encode(slice));
        forms.push(inner_debug(slice));
    }
    forms
}

#[tokio::test]
async fn checkpoint_and_resurrect_bodies_never_reach_the_log() {
    let sink = log_sink();
    let app = TestApp::new().await;
    let u = user(&app, 1).await;
    // An item no other test of this file uses: the log is shared.
    let id = item(77);
    write_note(&app, &u, id, 77).await;
    let t = make_tombstone(&mut OsRng, &u.vault, id, 2).expect("a tombstone");
    let put = |body: Value| {
        app.call_raw(
            Which::Vault,
            request(
                "PUT",
                &format!("/api/sync/items/{}", hex16::encode(id.as_bytes())),
                &u.jar,
                body.to_string().into_bytes(),
            ),
        )
    };
    let res = put(json!({
        "base_rev": 1,
        "deleted": true,
        "tomb": b64url::encode(&t.tomb),
        "idem": hex16::encode(&idem(78)),
    }))
    .await;
    assert_eq!(res.status, StatusCode::OK);

    // The resurrection, with a body of its own, and a checkpoint with
    // entries and a MAC that are recognisable.
    let mut note = ItemBody::new(ItemType::Note, "canary back", 1);
    note.notes = Some("canary words of the resurrected note".to_string());
    let back = encrypt_item(&mut OsRng, &u.vault, id, 3, &note, None).expect("an item");
    let res = put(json!({
        "base_rev": 2,
        "blob": b64url::encode(&back.envelope),
        "tag": b64url::encode(&back.tag),
        "idem": hex16::encode(&idem(79)),
        "resurrect": true,
    }))
    .await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());

    let entries: Vec<u8> = (1..=4u128)
        .flat_map(|n| entry(ordered_id(n), 1, [u8::try_from(n).unwrap() * 17; 32]))
        .collect();
    let mac = [0xc7; 32];
    let sent = body_of(4, &entries, mac);
    let res = upload(&app, &u, &sent).await;
    assert_eq!(res.status, StatusCode::OK, "{}", res.text());
    // A stale one, a malformed one and a fetch.
    let stale = body_of(3, &entries, [0xc8; 32]);
    assert_eq!(upload(&app, &u, &stale).await.status, StatusCode::CONFLICT);
    let broken = body_of(4, &entries[..100], [0xc9; 32]);
    assert_eq!(
        upload(&app, &u, &broken).await.status,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(fetch(&app, &u).await.status, StatusCode::OK);
    changes(&app, &u).await;

    let mut canaries = Vec::new();
    for value in [
        back.envelope.as_slice(),
        back.tag.as_slice(),
        t.tomb.as_slice(),
        entries.as_slice(),
        mac.as_slice(),
        Sha256::digest(&entries).as_slice(),
    ] {
        canaries.extend(canaries_for(value));
    }
    canaries.push(hex16::encode(&idem(79)));

    // The control: the forms fire on a print of their value.
    tracing::info!(entries = ?entries, "canary self-test, Debug");
    tracing::info!(entries = %b64url::encode(&entries), "canary self-test, base64url");
    tracing::info!(
        entries = %ferret_core::testing::hex_encode(&entries),
        "canary self-test, hex"
    );
    let text = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("checkpoint stored"),
        "the upload is logged: {text}"
    );
    assert!(text.contains(&hex16::encode(id.as_bytes())));
    let control = canaries_for(&entries);
    assert_eq!(control.len(), 6);
    // Take the self-test lines out before the check.
    let logged: String = text
        .lines()
        .filter(|line| !line.contains("canary self-test"))
        .collect::<Vec<_>>()
        .join("\n");
    for form in &control {
        assert!(
            text.contains(form.as_str()),
            "the canary form {form:.40} does not fire on a print of its value"
        );
    }
    for canary in canaries {
        assert!(!logged.contains(&canary), "{canary:.60} is in the log");
    }
    assert!(!logged.contains("canary words"), "plaintext is in the log");
}

fn body_of(seq: u64, entries: &[u8], mac: [u8; 32]) -> Value {
    body(seq, entries, None, mac)
}
