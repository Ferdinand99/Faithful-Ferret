//! Helpers for the event stream tests: a request for the stream, and a reader
//! that takes the answer frame by frame instead of to the end (a stream has
//! none).
//!
//! The reader waits in real time and yields to the runtime between looks, so it
//! works with the clock of tokio paused too: a paused clock never moves because
//! the reader is idle, only when a test moves it.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::body::{Body, BodyDataStream};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use futures_util::{FutureExt as _, StreamExt as _};
use serde_json::Value;
use tower::ServiceExt as _;

use super::{Jar, PEER, Req, TestApp, Which};

/// One frame of an event stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `event: <name>` and `data: <data>`.
    Event { name: String, data: String },
    /// A comment line (`: …`), the text after the colon.
    Comment(String),
}

impl Frame {
    /// The data of an event, as JSON.
    pub fn data(&self) -> Value {
        match self {
            Frame::Event { data, .. } => serde_json::from_str(data).expect("JSON data"),
            Frame::Comment(_) => panic!("a comment has no data"),
        }
    }

    pub fn is_event(&self, wanted: &str) -> bool {
        matches!(self, Frame::Event { name, .. } if name == wanted)
    }
}

/// What the next look at a stream found.
#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Frame(Frame),
    /// Nothing came within the time given.
    Quiet,
    /// The stream is over.
    End,
}

/// An answer that is read as it comes.
pub struct Stream {
    pub status: StatusCode,
    pub headers: HeaderMap,
    body: BodyDataStream,
    buffer: String,
    ended: bool,
}

/// A request for the event stream as a page of the vault sends it, with the
/// cookies of `jar`.
pub fn events_req(jar: &Jar) -> Req {
    let req = Req::get("/api/sync/events")
        .header("ferret-protocol", "1")
        .header("sec-fetch-site", "same-origin");
    match jar.header() {
        Some(cookie) => req.header("cookie", &cookie),
        None => req,
    }
}

impl TestApp {
    /// Sends a request to the vault listener and returns as soon as the headers
    /// are there. No jar in, no jar out.
    pub async fn open_stream(&self, request: Request<Body>) -> Stream {
        let mut request = request;
        request
            .headers_mut()
            .entry(header::HOST)
            .or_insert(HeaderValue::from_static(Which::Vault.host()));
        let peer: SocketAddr = PEER.parse().expect("a peer address");
        request.extensions_mut().insert(ConnectInfo(peer));
        // A child of `support` sees the private field of `TestApp`.
        let router = self.vault.clone();
        let response = router.oneshot(request).await.expect("a response");
        let (parts, body) = response.into_parts();
        Stream {
            status: parts.status,
            headers: parts.headers,
            body: body.into_data_stream(),
            buffer: String::new(),
            ended: false,
        }
    }

    /// The stream of the session whose cookies `jar` holds.
    pub async fn events(&self, jar: &Jar) -> Stream {
        self.open_stream(events_req(jar).build()).await
    }
}

impl Stream {
    /// The first frame in the buffer, taken out of it.
    fn parse(&mut self) -> Option<Frame> {
        loop {
            let end = self.buffer.find("\n\n")?;
            let block: String = self.buffer.drain(..end.saturating_add(2)).collect();
            let block = block.trim_end_matches('\n');
            let mut event = None;
            let mut data = None;
            let mut comment = None;
            for line in block.split('\n') {
                if let Some(text) = line.strip_prefix(':') {
                    comment = Some(text.strip_prefix(' ').unwrap_or(text).to_string());
                } else if let Some(text) = line.strip_prefix("event: ") {
                    event = Some(text.to_string());
                } else if let Some(text) = line.strip_prefix("data: ") {
                    data = Some(text.to_string());
                } else {
                    panic!("a line that is no SSE field: {line:?}");
                }
            }
            match (event, data, comment) {
                (Some(name), Some(data), None) => return Some(Frame::Event { name, data }),
                (None, None, Some(text)) => return Some(Frame::Comment(text)),
                (None, None, None) => continue,
                other => panic!("a frame of mixed parts: {other:?}"),
            }
        }
    }

    /// The next frame, or `Quiet` after `within` of real time, or `End`.
    pub async fn next(&mut self, within: Duration) -> Next {
        let deadline = Instant::now() + within;
        loop {
            if let Some(frame) = self.parse() {
                return Next::Frame(frame);
            }
            if self.ended {
                return Next::End;
            }
            match self.body.next().now_or_never() {
                Some(Some(Ok(bytes))) => {
                    self.buffer.push_str(&String::from_utf8_lossy(&bytes));
                    continue;
                }
                Some(Some(Err(_)) | None) => {
                    self.ended = true;
                    continue;
                }
                None => {}
            }
            if Instant::now() >= deadline {
                return Next::Quiet;
            }
            std::thread::sleep(Duration::from_millis(2));
            tokio::task::yield_now().await;
        }
    }

    /// The next frame, which must be an event named `name`; its data.
    pub async fn event(&mut self, name: &str, within: Duration) -> Value {
        match self.next(within).await {
            Next::Frame(frame) if frame.is_event(name) => frame.data(),
            other => panic!("expected the event {name}, got {other:?}"),
        }
    }

    /// Nothing comes for `within` (comments count as something).
    pub async fn quiet(&mut self, within: Duration) {
        assert_eq!(self.next(within).await, Next::Quiet);
    }

    /// The next frame is a comment.
    pub async fn comment(&mut self, within: Duration) {
        match self.next(within).await {
            Next::Frame(Frame::Comment(_)) => {}
            other => panic!("expected a comment, got {other:?}"),
        }
    }

    /// Every frame that comes until the stream goes quiet for `quiet` or ends;
    /// and whether it ended.
    pub async fn frames(&mut self, quiet: Duration) -> (Vec<Frame>, bool) {
        let mut frames = Vec::new();
        loop {
            match self.next(quiet).await {
                Next::Frame(frame) => frames.push(frame),
                Next::Quiet => return (frames, false),
                Next::End => return (frames, true),
            }
        }
    }

    /// The stream ends within `within`; comments on the way are let through,
    /// events are not.
    pub async fn end(&mut self, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.next(left).await {
                Next::End => return,
                Next::Frame(Frame::Comment(_)) => {}
                other => panic!("expected the end of the stream, got {other:?}"),
            }
        }
    }

    /// The whole body of an answer that ends (an error), as text.
    pub async fn text(&mut self) -> String {
        let mut text = std::mem::take(&mut self.buffer);
        while let Some(Ok(bytes)) = self.body.next().await {
            text.push_str(&String::from_utf8_lossy(&bytes));
        }
        text
    }

    /// The `error` of a JSON error body.
    pub async fn error(&mut self) -> String {
        let text = self.text().await;
        let json: Value = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
        json["error"].as_str().unwrap_or("").to_string()
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }
}

/// Waits (real time, yielding) until `done` is true; panics after `within`.
pub async fn wait_until(within: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < deadline, "the condition did not come true");
        std::thread::sleep(Duration::from_millis(2));
        tokio::task::yield_now().await;
    }
}
