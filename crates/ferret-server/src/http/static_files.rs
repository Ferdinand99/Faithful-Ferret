//! The files of the web vault, served from the vault listener only.
//!
//! The files are built into the binary from `web/dist`. The admin listener
//! serves none of them: no WASM, no worker, no password field. Every response
//! carries the headers of `http::headers`.
//!
//! The source of the files is behind [`StaticSource`] so that tests can serve
//! a memory source. Not built yet: [`vault_routes`] serves nothing and the
//! default source is empty.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;

use crate::state::FerretState;

/// One file: its bytes, its content type and the SHA-256 of the bytes (the
/// `ETag`).
pub struct StaticFile {
    pub bytes: Cow<'static, [u8]>,
    pub content_type: &'static str,
    pub sha256: [u8; 32],
}

/// Where the files come from.
pub trait StaticSource: Send + Sync {
    /// The file at `path` (without a leading slash), if there is one.
    fn get(&self, path: &str) -> Option<StaticFile>;
}

/// Files held in memory, for tests.
#[derive(Default)]
pub struct MemorySource(pub HashMap<String, StaticFile>);

impl StaticSource for MemorySource {
    fn get(&self, path: &str) -> Option<StaticFile> {
        self.0.get(path).map(|f| StaticFile {
            bytes: f.bytes.clone(),
            content_type: f.content_type,
            sha256: f.sha256,
        })
    }
}

/// The files the binary serves.
pub fn default_source() -> Arc<dyn StaticSource> {
    Arc::new(MemorySource::default())
}

/// The routes that serve the files of `source` on the vault listener (none yet).
pub fn vault_routes(_source: Arc<dyn StaticSource>) -> Router<FerretState> {
    Router::new()
}
