//! The files of the web vault, served from the vault listener only.
//!
//! The files are built into the binary from `web/dist`. The admin listener
//! serves none of them: no WASM, no worker, no password field. Every response
//! of the vault listener carries the headers of `http::headers` (added by the
//! layers of `http::vault_layers`, so also a 404 and a 304).
//!
//! What is served:
//!
//! * `/`, `/index.html` and the web vault's own routes (`/vault` and
//!   everything below it) answer with `index.html`: the page decides what to
//!   show;
//! * the page carries the address of the admin pages in a
//!   `<meta name="ferret-admin-url">` tag (see `vault_routes_with_admin`);
//! * `/app/…`, `/js/…`, `/pkg-web/…` and `/assets/…` answer with the file of
//!   that path, if there is one;
//! * everything else is `404`, never `index.html`.
//!
//! The type of a file comes from its extension and nothing is sniffed: `.html`,
//! `.js`, `.mjs`, `.css`, `.json` and `.wasm`; any other file is not served. A
//! path with anything but letters, digits, `.`, `_`, `-` and `/` in it, with an
//! empty segment or with a `.` or `..` segment is `404` (this includes every
//! percent-encoded or backslash form). `ETag` is the SHA-256 of the file and
//! `Cache-Control` is `no-cache`, so a browser asks every time and gets `304`
//! when nothing changed.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use sha2::Digest as _;

use crate::error::ApiError;
use crate::state::FerretState;

/// The directories of the web vault that hold files.
const FILE_ROOTS: [&str; 4] = ["app", "js", "pkg-web", "assets"];

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

/// The content type of a file by its extension; `None` for a file that is not
/// served.
pub fn content_type_of(path: &str) -> Option<&'static str> {
    let (_, extension) = path.rsplit_once('.')?;
    Some(match extension {
        "html" => "text/html; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "wasm" => "application/wasm",
        _ => return None,
    })
}

/// The built web vault (`web/dist`), compiled into the binary. A debug build
/// reads the folder from disk instead. The folder may be missing when only the
/// server is built; the image build makes it first (and `default_source`
/// complains at start-up when it holds no `index.html`).
#[derive(rust_embed::RustEmbed)]
#[folder = "../../web/dist"]
#[allow_missing = true]
pub struct Embedded;

impl StaticSource for Embedded {
    fn get(&self, path: &str) -> Option<StaticFile> {
        let content_type = content_type_of(path)?;
        let file = <Embedded as rust_embed::RustEmbed>::get(path)?;
        Some(StaticFile {
            sha256: file.metadata.sha256_hash(),
            bytes: file.data,
            content_type,
        })
    }
}

/// The files the binary serves.
pub fn default_source() -> Arc<dyn StaticSource> {
    if <Embedded as rust_embed::RustEmbed>::get("index.html").is_none() {
        tracing::warn!(
            "the web vault is not built into this binary: web/dist/index.html is missing"
        );
    }
    Arc::new(Embedded)
}

/// `path` (the raw path of a request, with its leading slash) as a file name
/// below the web root, if it is a plain one.
fn plain_path(path: &str) -> Option<&str> {
    let relative = path.strip_prefix('/')?;
    let plain = relative.split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    });
    plain.then_some(relative)
}

fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Whether an `If-None-Match` header names `etag` (or `*`).
fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    headers.get_all(IF_NONE_MATCH).iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(',').map(str::trim).any(|candidate| {
                candidate == "*" || candidate.strip_prefix("W/").unwrap_or(candidate) == etag
            })
        })
    })
}

/// The answer for `file`: `200` with the bytes or `304`.
fn respond(file: StaticFile, headers: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", hex(&file.sha256));
    let Ok(etag_value) = HeaderValue::from_str(&etag) else {
        return ApiError::internal().into_response();
    };
    let mut response = if not_modified(headers, &etag) {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        response
    } else {
        let body = match file.bytes {
            Cow::Borrowed(bytes) => Body::from(bytes),
            Cow::Owned(bytes) => Body::from(bytes),
        };
        let mut response = Response::new(body);
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(file.content_type));
        response
    };
    response.headers_mut().insert(ETAG, etag_value);
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    response
}

/// The file at the path of `uri`, or `404`.
fn serve_path(source: &dyn StaticSource, uri: &Uri, headers: &HeaderMap) -> Response {
    let found = plain_path(uri.path())
        .filter(|path| content_type_of(path).is_some())
        .filter(|path| {
            path.split_once('/')
                .is_some_and(|(root, _)| FILE_ROOTS.contains(&root))
        })
        .and_then(|path| source.get(path));
    match found {
        Some(file) => respond(file, headers),
        None => ApiError::not_found().into_response(),
    }
}

/// `text` for the value of an HTML attribute in double quotes.
fn escape_attribute(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `index.html` with `<meta name="ferret-admin-url" content="...">` added at
/// the end of the head. The page reads the address of the admin pages from it:
/// a hand-over code is sent there, so it has to come from the page the server
/// delivers and never from an address a visitor can choose. A file with no
/// `</head>` or no text is returned as it was. The `ETag` follows the changed
/// bytes.
fn with_admin_url(file: StaticFile, admin: &str) -> StaticFile {
    let Ok(text) = std::str::from_utf8(&file.bytes) else {
        return file;
    };
    let Some(at) = text.find("</head>") else {
        return file;
    };
    let tag = format!(
        "<meta name=\"ferret-admin-url\" content=\"{}\">\n  ",
        escape_attribute(admin)
    );
    let mut bytes = String::with_capacity(text.len() + tag.len());
    bytes.push_str(&text[..at]);
    bytes.push_str(&tag);
    bytes.push_str(&text[at..]);
    let bytes = bytes.into_bytes();
    StaticFile {
        sha256: sha2::Sha256::digest(&bytes).into(),
        bytes: Cow::Owned(bytes),
        content_type: file.content_type,
    }
}

/// `index.html`, or `404` if the binary has none.
fn serve_index(source: &dyn StaticSource, admin: Option<&str>, headers: &HeaderMap) -> Response {
    match source.get("index.html") {
        Some(file) => respond(
            match admin {
                Some(admin) => with_admin_url(file, admin),
                None => file,
            },
            headers,
        ),
        None => ApiError::not_found().into_response(),
    }
}

/// The routes that serve the files of `source` on the vault listener, with
/// no address of the admin pages in the page.
pub fn vault_routes(source: Arc<dyn StaticSource>) -> Router<FerretState> {
    routes(source, None)
}

/// The routes that serve the files of `source` on the vault listener. The
/// page gets the address of the admin pages (`admin`, an origin) in a meta
/// tag; the admin listener serves no page at all.
pub fn vault_routes_with_admin(source: Arc<dyn StaticSource>, admin: &str) -> Router<FerretState> {
    routes(source, Some(Arc::from(admin)))
}

fn routes(source: Arc<dyn StaticSource>, admin: Option<Arc<str>>) -> Router<FerretState> {
    let index = {
        let source = source.clone();
        move |headers: HeaderMap| {
            let source = source.clone();
            let admin = admin.clone();
            async move { serve_index(source.as_ref(), admin.as_deref(), &headers) }
        }
    };
    let files = move |uri: Uri, headers: HeaderMap| {
        let source = source.clone();
        async move { serve_path(source.as_ref(), &uri, &headers) }
    };
    Router::new()
        .route("/", get(index.clone()))
        .route("/index.html", get(index.clone()))
        .route("/vault", get(index.clone()))
        .route("/vault/", get(index.clone()))
        .route("/vault/{*page}", get(index))
        .route("/app/{*path}", get(files.clone()))
        .route("/js/{*path}", get(files.clone()))
        .route("/pkg-web/{*path}", get(files.clone()))
        .route("/assets/{*path}", get(files))
}
