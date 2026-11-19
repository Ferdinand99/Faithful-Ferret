//! Helpers for the backup tests: a machine layer that records what it is told
//! (the fsync spy) and can be made to fail, a stand-in for the monitor, a
//! capture of the log, and small file helpers.

use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ferret_server::backup::push;
use ferret_server::backup::schedule::Job;
use ferret_server::backup::set::{self, Platform, RealPlatform};
use ferret_server::backup::{BackupConfig, BackupError, SetInfo};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tracing_subscriber::fmt::MakeWriter;

use super::TestApp;

/// One thing the set maker asked of the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A file was synced; the name is the file name only.
    SyncFile(String),
    /// A folder was synced.
    SyncDir(PathBuf),
    /// A folder was renamed.
    Rename {
        from: PathBuf,
        to: PathBuf,
        /// Whether `.complete` was inside `from` at that moment.
        complete_inside: bool,
        /// Whether `to` was there already.
        target_existed: bool,
    },
}

/// The real machine, with a record of the order of events, and switches for a
/// full disk and a rename that fails.
pub struct SpyPlatform {
    pub events: Mutex<Vec<Event>>,
    pub free: Mutex<Option<u64>>,
    pub fail_rename: AtomicBool,
    pub panic_rename: AtomicBool,
    pub fail_parent_sync: AtomicBool,
    /// The backup folder, for telling its sync from the temp folder's.
    pub parent: Mutex<Option<PathBuf>>,
}

impl SpyPlatform {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            free: Mutex::new(Some(u64::MAX)),
            fail_rename: AtomicBool::new(false),
            panic_rename: AtomicBool::new(false),
            fail_parent_sync: AtomicBool::new(false),
            parent: Mutex::new(None),
        })
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().expect("events").clone()
    }

    pub fn clear(&self) {
        self.events.lock().expect("events").clear();
    }

    fn push(&self, event: Event) {
        self.events.lock().expect("events").push(event);
    }
}

impl Platform for SpyPlatform {
    fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.push(Event::SyncFile(
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ));
        RealPlatform.sync_file(path)
    }

    fn sync_dir(&self, path: &Path) -> std::io::Result<()> {
        self.push(Event::SyncDir(path.to_path_buf()));
        if self.fail_parent_sync.load(Ordering::SeqCst)
            && self.parent.lock().expect("parent").as_deref() == Some(path)
        {
            return Err(std::io::Error::other("the sync was made to fail"));
        }
        RealPlatform.sync_dir(path)
    }

    fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.push(Event::Rename {
            from: from.to_path_buf(),
            to: to.to_path_buf(),
            complete_inside: from.join(set::COMPLETE_FILE).is_file(),
            target_existed: to.exists(),
        });
        assert!(
            !self.panic_rename.load(Ordering::SeqCst),
            "the rename was made to panic"
        );
        if self.fail_rename.load(Ordering::SeqCst) {
            return Err(std::io::Error::other("the rename was made to fail"));
        }
        RealPlatform.rename(from, to)
    }

    fn free_bytes(&self, _dir: &Path) -> Option<u64> {
        *self.free.lock().expect("free")
    }
}

/// The default backup settings of a test app: under its data directory, every
/// 24 hours, 30 days, no monitor.
pub fn cfg(app: &TestApp) -> BackupConfig {
    BackupConfig::from_parts(&app.dir, None, 24, 30, None).expect("a backup config")
}

/// Backup settings with the monitor at `address`.
pub fn cfg_with_push(app: &TestApp, address: &str) -> BackupConfig {
    let url = ferret_server::secret::SecretUrl::new(address);
    BackupConfig::from_parts(&app.dir, None, 24, 30, Some(&url)).expect("a backup config")
}

/// Makes a set at `now` through a pooled connection, as the job does.
pub async fn make(app: &TestApp, cfg: &BackupConfig, now: i64) -> Result<SetInfo, BackupError> {
    let (dir, cfg) = (app.dir.clone(), cfg.clone());
    app.state
        .vault_db
        .with_conn(move |conn| Ok(set::create(&dir, conn, &cfg, now)))
        .await
        .expect("a connection")
}

/// A backup job on the app's clock, status and database.
pub fn job(app: &TestApp, cfg: BackupConfig, platform: Arc<dyn Platform>) -> Job {
    Job::new(
        app.state.vault_db.clone(),
        app.dir.clone(),
        cfg,
        app.backup_status(),
        app.state.clock.clone(),
        push::client().expect("a client"),
    )
    .with_platform(platform)
}

/// The names of the folders in `dir` that hold a finished set.
pub fn listed(cfg: &BackupConfig) -> Vec<String> {
    set::list(cfg)
        .expect("a listing")
        .into_iter()
        .map(|info| info.name)
        .collect()
}

/// Every entry of `dir` by name, sorted.
pub fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("a folder")
        .map(|e| {
            e.expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// Copies a folder of plain files.
pub fn copy_set(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a folder");
    for entry in std::fs::read_dir(from).expect("a set") {
        let entry = entry.expect("an entry");
        std::fs::copy(entry.path(), to.join(entry.file_name())).expect("a copy");
    }
}

/// The text of the log lines written while a capture is held.
#[derive(Clone, Default)]
pub struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log")).into_owned()
    }
}

pub struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> LogWriter {
        LogWriter(self.0.clone())
    }
}

/// Captures every log line of this thread (at any level) until the guard is
/// dropped. A current-thread runtime keeps its tasks on this thread, so the
/// lines of an async test are caught; the lines of a blocking pool thread are
/// not, so a test that needs them calls the code on its own thread.
pub fn capture_log() -> (LogBuffer, tracing::subscriber::DefaultGuard) {
    let buffer = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buffer.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (buffer, guard)
}

/// How the stand-in for the monitor answers.
#[derive(Clone, Debug)]
pub enum Reply {
    /// `200 OK`.
    Ok,
    /// A status line with this code.
    Status(u16),
    /// `302` to this address.
    Redirect(String),
    /// Takes the request and never answers.
    Hang,
}

/// A stand-in for the monitor: a socket on the loopback that records the raw
/// text of every request it gets.
pub struct StandIn {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    pub async fn start(reply: Reply) -> StandIn {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("an address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut chunk = [0u8; 1024];
                while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    }
                }
                seen.lock()
                    .expect("requests")
                    .push(String::from_utf8_lossy(&raw).into_owned());
                match &reply {
                    Reply::Hang => held.push(stream),
                    Reply::Ok | Reply::Status(_) | Reply::Redirect(_) => {
                        let (code, location) = match &reply {
                            Reply::Status(code) => (*code, String::new()),
                            Reply::Redirect(to) => (302, format!("location: {to}\r\n")),
                            _ => (200, String::new()),
                        };
                        let head = format!(
                            "HTTP/1.1 {code} X\r\n{location}content-length: 2\r\nconnection: close\r\n\r\nok"
                        );
                        let _ = stream.write_all(head.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                }
            }
        });
        StandIn { addr, requests }
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("requests").clone()
    }
}

/// An address on the loopback that nothing listens on.
pub async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
    let addr = listener.local_addr().expect("an address");
    drop(listener);
    addr
}

/// Writes `text` into a file, for a test that makes a file by hand.
pub fn write(path: &Path, text: &[u8]) {
    std::fs::File::create(path)
        .and_then(|mut f| f.write_all(text))
        .expect("a file");
}
