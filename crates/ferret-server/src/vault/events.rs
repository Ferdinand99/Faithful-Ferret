//! `GET /api/sync/events`: a stream of hints that the vault changed. Spec:
//! Fase 1 § 8.2, § 7.6.
//!
//! The stream is only a hint. It says that the vault is at a sequence number;
//! the client fetches the rows and checks them itself. So the events carry the
//! sequence number and nothing else: no item id, no size, no content.
//!
//! * `hello {seq}` first, after the session has been checked once more with the
//!   stream already listening, so a sign-out that raced the opening is seen.
//! * `sync {seq}` after a change in this vault. A burst is merged into one
//!   event ([`QUIET`]); a stream that fell behind the notifications counts as a
//!   change, since it may have missed one.
//! * A comment every [`HEARTBEAT`], so proxies keep the connection. At each
//!   heartbeat the session is read from the database again
//!   (`auth::session::still_valid`, on a connection taken from the pool for
//!   that read and given back): a session that ended, expired or lost its
//!   `session_version` closes the stream. D5 expiry is therefore seen within one
//!   heartbeat. A stream holds no pool connection between heartbeats.
//! * A sign-out, and the sign-in that replaces a session, send `session_revoked`
//!   and close the stream of that session at once.
//! * The stream ends after [`LIFETIME`]; the client opens a new one, which is
//!   authorised again.
//!
//! A device opens the stream with its access token and a DPoP proof, as for
//! the other sync routes (`VaultCaller`). Its stream follows the same rules,
//! and also:
//!
//! * it ends when its access token expires, if that comes before
//!   [`LIFETIME`] (at most 15 minutes);
//! * at each heartbeat the token's row and the device are read again: a
//!   revoked or no longer valid device, or a token that expired, closes it;
//! * revoking the device closes its streams at once;
//! * `Sec-Fetch-Site` is not checked on it. A browser sends `none` or a
//!   cross-site value for a request of an extension, and the check guards
//!   against a cookie that a page of another site makes the browser send; a
//!   token request carries no cookie (the `Origin` guard refuses one with a
//!   cookie), and a page cannot add a token header without a pre-flight that
//!   Ferret never allows.
//!
//! Places ([`EventStreams`]): 2 per (vault, device), 40 per vault and 1 024 on
//! the server. A new stream beyond a limit is refused with `429 throttled` and
//! `Retry-After: 30`, rather than the oldest stream being cut: a client that
//! reconnects in a loop cannot push out a stream that works. The place is free
//! again when the stream ends or the client goes away.
//!
//! The answer is never buffered or transformed by a proxy that obeys
//! `Cache-Control: no-store, no-transform` and `X-Accel-Buffering: no`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{FromRef, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use futures_util::stream;
use rusqlite::{OptionalExtension as _, params};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};
use vole_kit::http::live::Changes;

use super::notify::{Revoked, SyncEvents, VaultChange};
use super::rate::{SyncLimits, WriteGate};
use crate::error::{ApiError, StoreError};
use crate::http::extract::{SessionAuth, VaultCaller};
use crate::http::origin_guard::{PROTOCOL_HEADER, PROTOCOL_VERSION};
use crate::ids::{DeviceId, VaultId};
use crate::state::VaultDb;
use crate::wire::SyncEventJson;

/// How often an idle stream sends a comment and checks its session again.
pub const HEARTBEAT: Duration = Duration::from_secs(25);
/// How long one stream lives. The client opens a new one.
pub const LIFETIME: Duration = Duration::from_secs(60 * 60);
/// How long a change waits for more changes before it is sent as one event.
pub const QUIET: Duration = Duration::from_millis(250);

/// Seconds a refused client is told to wait.
const RETRY_AFTER_SECS: u32 = 30;

/// How long the stream waits for a client that does not read before it gives
/// the place up.
const SEND_PATIENCE: Duration = HEARTBEAT;

/// Events that wait for a slow client before the stream is given up.
const BACKLOG: usize = 8;

/// The open event streams, counted per (vault, device), per vault and in all.
pub struct EventStreams {
    per_device: usize,
    per_vault: usize,
    total: usize,
    counts: Arc<Mutex<Counts>>,
    /// Becomes `true` when the server stops: every stream ends then.
    stop: watch::Sender<bool>,
}

/// The streams open now. An entry exists only while it counts a stream, so the
/// table never holds more than `total` of them.
#[derive(Default)]
struct Counts {
    total: usize,
    vaults: HashMap<VaultId, VaultCount>,
}

#[derive(Default)]
struct VaultCount {
    total: usize,
    devices: HashMap<DeviceId, usize>,
}

/// One open stream's place; the place is free again when this is dropped.
pub struct StreamSlot {
    counts: Arc<Mutex<Counts>>,
    vault: VaultId,
    device: DeviceId,
}

impl EventStreams {
    /// Streams that allow `per_device` for one (vault, device), `per_vault` for
    /// one vault and `total` on the server.
    pub fn new(per_device: usize, per_vault: usize, total: usize) -> Self {
        Self {
            per_device,
            per_vault,
            total,
            counts: Arc::new(Mutex::new(Counts::default())),
            stop: watch::channel(false).0,
        }
    }

    /// Ends every open stream, and every one that opens later: the server is
    /// stopping. A graceful shutdown waits for the answers in flight, and a
    /// stream would otherwise be one until its hour is out. The places are free
    /// when the tasks have ended.
    pub fn shutdown(&self) {
        self.stop.send_replace(true);
    }

    /// A place for a new stream of this device in this vault, or `None` when a
    /// limit is reached. The same device id in another vault has places of its
    /// own. The place stays taken until the slot is dropped.
    pub fn acquire(&self, vault: &VaultId, device: &DeviceId) -> Option<StreamSlot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.total >= self.total {
            return None;
        }
        let (in_vault, of_device) = counts.vaults.get(vault).map_or((0, 0), |v| {
            (v.total, v.devices.get(device).copied().unwrap_or(0))
        });
        if in_vault >= self.per_vault || of_device >= self.per_device {
            return None;
        }
        counts.total = counts.total.saturating_add(1);
        let entry = counts.vaults.entry(*vault).or_default();
        entry.total = entry.total.saturating_add(1);
        let device_count = entry.devices.entry(*device).or_default();
        *device_count = device_count.saturating_add(1);
        Some(StreamSlot {
            counts: Arc::clone(&self.counts),
            vault: *vault,
            device: *device,
        })
    }

    fn stop_signal(&self) -> watch::Receiver<bool> {
        self.stop.subscribe()
    }

    /// Streams open now, in all.
    pub fn open(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .total
    }
}

impl Drop for StreamSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        counts.total = counts.total.saturating_sub(1);
        if let Some(entry) = counts.vaults.get_mut(&self.vault) {
            entry.total = entry.total.saturating_sub(1);
            if let Some(n) = entry.devices.get_mut(&self.device) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    entry.devices.remove(&self.device);
                }
            }
            if entry.total == 0 {
                counts.vaults.remove(&self.vault);
            }
        }
    }
}

/// The event stream route.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    VaultDb: FromRef<S>,
    SessionAuth: FromRef<S>,
    SyncEvents: FromRef<S>,
    Arc<SyncLimits>: FromRef<S>,
    WriteGate: FromRef<S>,
    Arc<EventStreams>: FromRef<S>,
{
    Router::new().route("/api/sync/events", get(get_events))
}

/// The only value of a header: `Ok(None)` if there is none, `Err` if there are
/// several or the value is not text.
fn single<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Result<Option<&'a str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

/// The checks of a stream, which is a `GET` and so not seen by the `Origin`
/// check of mutations: the protocol header; and, for a session (`device` is
/// false), a browser that says the request is from another site is refused.
/// A device's stream has a token and no cookie, so `Sec-Fetch-Site` is not
/// read for it (see the module documentation).
///
/// Spec: Fase 1 § 8.2.
fn check_request(headers: &HeaderMap, device: bool) -> Result<(), ApiError> {
    let protocol = single(headers, &HeaderName::from_static(PROTOCOL_HEADER));
    if protocol != Ok(Some(PROTOCOL_VERSION)) {
        return Err(ApiError::bad_request("protocol_header_missing"));
    }
    if device {
        return Ok(());
    }
    match single(headers, &HeaderName::from_static("sec-fetch-site")) {
        Ok(None | Some("same-origin")) => Ok(()),
        _ => Err(ApiError::forbidden_origin()),
    }
}

/// An event as the bytes of one frame: the name and the sequence number.
fn frame(event: &str, seq: u64) -> Option<Bytes> {
    let data = serde_json::to_string(&SyncEventJson { seq }).ok()?;
    Some(Bytes::from(format!("event: {event}\ndata: {data}\n\n")))
}

/// What one stream's task holds besides the two receivers.
struct Open {
    tx: mpsc::Sender<Bytes>,
    /// `true` when the server stops.
    stop: watch::Receiver<bool>,
    db: VaultDb,
    caller: VaultCaller,
    /// The place; freed when the task ends.
    _slot: StreamSlot,
}

type Wanted = Box<dyn Fn(&VaultChange) -> bool + Send>;

/// How long a stream of `caller` may live: [`LIFETIME`], or less when its
/// access token expires sooner.
///
/// Spec: Fase 1 § 7.6 (short-lived access tokens).
fn lifetime_of(caller: &VaultCaller) -> Duration {
    match caller.ends_at() {
        None => LIFETIME,
        Some(ends_at) => {
            let left = u64::try_from(ends_at.saturating_sub(caller.now())).unwrap_or(0);
            LIFETIME.min(Duration::from_secs(left))
        }
    }
}

/// `GET /api/sync/events`.
async fn get_events(
    caller: VaultCaller,
    headers: HeaderMap,
    State(db): State<VaultDb>,
    State(events): State<SyncEvents>,
    State(streams): State<Arc<EventStreams>>,
) -> Result<Response, ApiError> {
    check_request(&headers, caller.is_device())?;
    let slot = streams
        .acquire(&caller.vault(), &caller.device())
        .ok_or(ApiError::throttled(RETRY_AFTER_SECS))?;

    // Listening starts before the sequence number is read and the caller is
    // checked once more, so neither a change nor a sign-out or a revocation
    // can fall in between.
    let vault = caller.vault();
    let wanted: Wanted = Box::new(move |change| change.vault == vault);
    let changes = Changes::new(events.subscribe(), wanted)
        .quiet(QUIET)
        .lifetime(lifetime_of(&caller));
    let revocations = events.subscribe_revocations();

    let (still, seq) = check(&db, &caller).await?;
    if !still {
        return Err(ApiError::unauthorized());
    }
    let hello = frame("hello", seq).ok_or_else(ApiError::internal)?;

    let (tx, rx) = mpsc::channel(BACKLOG);
    // The channel has room, so this does not wait.
    tx.try_send(hello).map_err(|_| ApiError::internal())?;
    let open = Open {
        tx,
        stop: streams.stop_signal(),
        db,
        caller,
        _slot: slot,
    };
    tokio::spawn(run(open, changes, revocations));

    let body = Body::from_stream(stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(bytes), rx))
    }));
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    headers.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    Ok(response)
}

/// Reads, on a connection from the pool that goes back at once, whether the
/// caller still counts (`VaultCaller::still_valid`: the session, or the device
/// and its access token) and the sequence number of the vault.
async fn check(db: &VaultDb, caller: &VaultCaller) -> Result<(bool, u64), ApiError> {
    // A clock that failed makes nothing valid.
    let Some(now) = caller.clock().now() else {
        return Ok((false, 0));
    };
    let caller = caller.clone();
    Ok(db
        .with_conn(move |conn| {
            let still = caller.still_valid(conn, now)?;
            let seq = vault_seq(conn, &caller.vault())?;
            Ok((still, seq))
        })
        .await?)
}

/// The sequence number of the vault.
fn vault_seq(conn: &rusqlite::Connection, vault: &VaultId) -> Result<u64, StoreError> {
    let seq: Option<i64> = conn
        .query_row(
            "SELECT seq FROM ferret_vaults WHERE vault_id = ?1",
            params![vault.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .optional()?;
    let seq = seq.ok_or(StoreError::NotFound)?;
    u64::try_from(seq).map_err(|_| StoreError::Invalid("seq"))
}

/// Returns when the server stops (or its signal is gone, which is the same).
async fn stopped(stop: &mut watch::Receiver<bool>) {
    // The guard the wait returns is not held past this line.
    let _ = stop.wait_for(|stopped| *stopped).await;
}

impl Open {
    /// Sends a frame; `false` when the client is gone or does not read.
    ///
    /// While this waits for a client that does not read (at most
    /// [`SEND_PATIENCE`]), revocations and heartbeats are not looked at; the
    /// stop of the server is. That is fine: nothing more is sent to that client
    /// in the meantime, since its channel is full, and when the wait is over the
    /// stream either ends (the client did not read) or goes on to the next look
    /// at them.
    async fn send(&self, frame: Bytes) -> bool {
        let mut stop = self.stop.clone();
        tokio::select! {
            biased;
            () = stopped(&mut stop) => false,
            sent = tokio::time::timeout(SEND_PATIENCE, self.tx.send(frame)) => {
                matches!(sent, Ok(Ok(())))
            }
        }
    }

    /// Whether the caller still counts. A database that fails closes the
    /// stream: the client opens a new one, which is checked again.
    async fn caller_holds(&self) -> bool {
        matches!(check(&self.db, &self.caller).await, Ok((true, _)))
    }
}

/// The task of one stream. It ends when the client is gone, the caller is
/// over, the lifetime is out or anything fails; the place is freed then.
async fn run(
    open: Open,
    mut changes: Changes<VaultChange, Wanted>,
    mut revocations: broadcast::Receiver<Revoked>,
) {
    let first = Instant::now()
        .checked_add(HEARTBEAT)
        .unwrap_or_else(Instant::now);
    let mut heartbeat = tokio::time::interval_at(first, HEARTBEAT);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut stop = open.stop.clone();
    loop {
        // The wait for a change is kept across the other wake-ups: a change
        // that was heard and waits for the quiet period must not be lost to a
        // heartbeat.
        let next = changes.next();
        tokio::pin!(next);
        loop {
            tokio::select! {
                biased;
                () = stopped(&mut stop) => return,
                () = open.tx.closed() => return,
                revoked = revocations.recv() => match revoked {
                    Ok(revoked) if open.caller.is_revoked_by(&revoked) => return,
                    Ok(_) => {}
                    // Some were missed: the database knows if this one ended.
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        if !open.caller_holds().await {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
                _ = heartbeat.tick() => {
                    if !open.caller_holds().await
                        || !open.send(Bytes::from_static(b": \n\n")).await
                    {
                        return;
                    }
                }
                woke = &mut next => {
                    if woke.is_none() {
                        return;
                    }
                    break;
                }
            }
        }
        // The hint carries the sequence number of now, read for the event,
        // never a number a notification brought.
        let seq = match check(&open.db, &open.caller).await {
            Ok((true, seq)) => seq,
            _ => return,
        };
        let Some(event) = frame("sync", seq) else {
            return;
        };
        if !open.send(event).await {
            return;
        }
    }
}
