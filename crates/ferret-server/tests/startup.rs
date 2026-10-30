//! Start-up: the secret files, their check against the database, and the
//! refusal to serve when the two do not fit. Every test runs the real
//! `ferret_server::start`, the call the binary makes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use ferret_core::OsRng;
use ferret_server::config::Config;
use ferret_server::state::FerretState;
use ferret_server::{StartError, product, start};
use ferret_server_auth::{
    Clock, FileKind, ManualClock, OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE, ServerKeys,
    SetupFingerprint, SystemClock, write_new_secret_file,
};
use rusqlite::{Connection, params};

/// A data directory that is removed again at the end of the test.
struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "ferret-startup-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn db(&self) -> Connection {
        Connection::open(self.file(product::DB_FILE)).unwrap()
    }

    /// The names in the directory, sorted, without the files SQLite keeps next
    /// to the database while it is open.
    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .map(|entries| {
                entries
                    .map(|e| e.unwrap().file_name().into_string().unwrap())
                    .filter(|n| !n.ends_with("-wal") && !n.ends_with("-shm"))
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// Starts the server here, as the binary does.
    async fn start(&self) -> Result<FerretState, StartError> {
        start(
            &self.config(),
            Arc::new(ManualClock::new(1_793_491_200)) as Arc<dyn Clock>,
        )
        .await
    }

    fn config(&self) -> Config {
        Config {
            data_dir: self.0.clone(),
            host: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            vault_port: 3041,
            admin_port: 3040,
            vault_url: "https://vault.ferret.test".to_string(),
            admin_url: "https://admin.ferret.test".to_string(),
            trusted_proxies: Vec::new(),
        }
    }

    /// An account with a record, straight into the database.
    fn add_account(&self) {
        let conn = self.db();
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES ('a@example.com', 'x', 'admin')",
            [],
        )
        .unwrap();
        let user = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO ferret_accounts (account_id, user_id, vault_id, opaque_record, ksf_profile, sk_hint, pk_a, pk_r, created_at) \
             VALUES (?1, ?2, ?3, ?4, 1, 0, ?5, ?5, 0)",
            params![[1u8; 16], user, [2u8; 16], [3u8; 192], [4u8; 32]],
        )
        .unwrap();
    }

    fn stored_fingerprint(&self) -> Option<Vec<u8>> {
        self.db()
            .query_row(
                "SELECT value FROM ferret_meta WHERE key = 'setup_fingerprint'",
                [],
                |r| r.get(0),
            )
            .ok()
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The text of a refused start.
fn refusal(result: Result<FerretState, StartError>) -> String {
    match result {
        Ok(_) => panic!("the server started, but it must not"),
        Err(e) => e.to_string(),
    }
}

/// A set-up file that is valid but is not the one on disk.
fn write_other_setup(dir: &Dir) {
    let path = dir.file(OPAQUE_SETUP_FILE);
    std::fs::remove_file(&path).unwrap();
    let keys = ServerKeys::generate(&mut OsRng).unwrap();
    write_new_secret_file(&path, FileKind::OpaqueSetup, &keys.payload()).unwrap();
}

/// A first start, then the server is stopped (the state is dropped).
async fn first_start(dir: &Dir) -> SetupFingerprint {
    let state = dir.start().await.expect("the first start");
    state.secrets.keys.fingerprint()
}

// -------------------------------------------------------------- first start

#[tokio::test]
async fn fresh_database_creates_both_files_mode_0600_and_records_fingerprint() {
    let dir = Dir::new();
    assert!(!dir.path().exists());
    let state = dir.start().await.expect("a fresh start");
    for name in [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE] {
        let meta = std::fs::metadata(dir.file(name)).expect(name);
        assert!(meta.is_file(), "{name}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name}");
        }
    }
    // The database remembers the fingerprint of the set-up that was made.
    let stored = dir.stored_fingerprint().expect("a stored fingerprint");
    assert_eq!(stored, state.secrets.keys.fingerprint().0.to_vec());
}

#[tokio::test]
async fn second_start_proceeds() {
    let dir = Dir::new();
    let first = first_start(&dir).await;
    let files: Vec<Vec<u8>> = [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE]
        .iter()
        .map(|n| std::fs::read(dir.file(n)).unwrap())
        .collect();
    let again = dir.start().await.expect("a second start");
    assert_eq!(again.secrets.keys.fingerprint(), first);
    // Nothing was rewritten.
    for (name, before) in [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE].iter().zip(files) {
        assert_eq!(std::fs::read(dir.file(name)).unwrap(), before, "{name}");
    }
    assert_eq!(dir.stored_fingerprint(), Some(first.0.to_vec()));
}

#[tokio::test]
async fn a_server_with_accounts_and_its_files_starts_again() {
    let dir = Dir::new();
    let first = first_start(&dir).await;
    dir.add_account();
    let again = dir.start().await.expect("a restart with accounts");
    assert_eq!(again.secrets.keys.fingerprint(), first);
}

// ------------------------------------------------------------------ refusals

#[tokio::test]
async fn deleted_opaque_setup_with_accounts_refuses() {
    let dir = Dir::new();
    first_start(&dir).await;
    dir.add_account();
    std::fs::remove_file(dir.file(OPAQUE_SETUP_FILE)).unwrap();
    let text = refusal(dir.start().await);
    assert!(
        text.contains("secret file is missing") && text.contains("restore it"),
        "{text}"
    );
}

#[tokio::test]
async fn replaced_opaque_setup_refuses() {
    let dir = Dir::new();
    first_start(&dir).await;
    dir.add_account();
    write_other_setup(&dir);
    let text = refusal(dir.start().await);
    assert!(
        text.contains("not the one this database was made with"),
        "{text}"
    );
}

#[tokio::test]
async fn deleted_prelogin_secret_with_accounts_refuses() {
    let dir = Dir::new();
    first_start(&dir).await;
    dir.add_account();
    std::fs::remove_file(dir.file(PRELOGIN_SECRET_FILE)).unwrap();
    let text = refusal(dir.start().await);
    assert!(
        text.contains("secret file is missing") && text.contains("restore it"),
        "{text}"
    );
}

#[tokio::test]
async fn refused_start_creates_no_new_file() {
    // Each case starts from a server that has run, damages one thing, and checks
    // that the refused start made no file and changed no file.
    enum Damage {
        NoSetup,
        NoPrelogin,
        NoFiles,
        OtherSetup,
    }
    for (damage, with_accounts) in [
        (Damage::NoSetup, true),
        (Damage::NoPrelogin, true),
        (Damage::NoFiles, true),
        (Damage::OtherSetup, true),
        // A fingerprint without accounts also means "this server has run".
        (Damage::NoSetup, false),
        (Damage::NoPrelogin, false),
        (Damage::NoFiles, false),
        (Damage::OtherSetup, false),
    ] {
        let dir = Dir::new();
        first_start(&dir).await;
        if with_accounts {
            dir.add_account();
        }
        match damage {
            Damage::NoSetup => std::fs::remove_file(dir.file(OPAQUE_SETUP_FILE)).unwrap(),
            Damage::NoPrelogin => std::fs::remove_file(dir.file(PRELOGIN_SECRET_FILE)).unwrap(),
            Damage::NoFiles => {
                std::fs::remove_file(dir.file(OPAQUE_SETUP_FILE)).unwrap();
                std::fs::remove_file(dir.file(PRELOGIN_SECRET_FILE)).unwrap();
            }
            Damage::OtherSetup => write_other_setup(&dir),
        }
        let names = dir.names();
        let contents: Vec<Option<Vec<u8>>> = [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE]
            .iter()
            .map(|n| std::fs::read(dir.file(n)).ok())
            .collect();
        let fingerprint = dir.stored_fingerprint();
        refusal(dir.start().await);
        assert_eq!(dir.names(), names, "accounts: {with_accounts}");
        let after: Vec<Option<Vec<u8>>> = [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE]
            .iter()
            .map(|n| std::fs::read(dir.file(n)).ok())
            .collect();
        assert_eq!(after, contents, "accounts: {with_accounts}");
        assert_eq!(dir.stored_fingerprint(), fingerprint);
    }
}

#[tokio::test]
async fn an_empty_data_directory_is_refused_once_accounts_exist() {
    // The whole directory is lost except the database.
    let dir = Dir::new();
    first_start(&dir).await;
    dir.add_account();
    std::fs::remove_file(dir.file(OPAQUE_SETUP_FILE)).unwrap();
    std::fs::remove_file(dir.file(PRELOGIN_SECRET_FILE)).unwrap();
    refusal(dir.start().await);
    assert!(!dir.file(OPAQUE_SETUP_FILE).exists());
    assert!(!dir.file(PRELOGIN_SECRET_FILE).exists());
}

#[tokio::test]
async fn a_missing_fingerprint_with_accounts_is_refused() {
    let dir = Dir::new();
    first_start(&dir).await;
    dir.add_account();
    dir.db()
        .execute(
            "DELETE FROM ferret_meta WHERE key = 'setup_fingerprint'",
            [],
        )
        .unwrap();
    let text = refusal(dir.start().await);
    assert!(text.contains("no fingerprint"), "{text}");
    assert_eq!(dir.stored_fingerprint(), None, "nothing was recorded");
}

#[tokio::test]
async fn a_missing_fingerprint_without_accounts_is_recorded_again() {
    let dir = Dir::new();
    let first = first_start(&dir).await;
    dir.db()
        .execute(
            "DELETE FROM ferret_meta WHERE key = 'setup_fingerprint'",
            [],
        )
        .unwrap();
    dir.start().await.expect("a start without accounts");
    assert_eq!(dir.stored_fingerprint(), Some(first.0.to_vec()));
}

#[tokio::test]
async fn a_fingerprint_that_is_not_32_bytes_is_refused() {
    for bad in [vec![0u8; 31], vec![0u8; 33], Vec::new()] {
        let dir = Dir::new();
        first_start(&dir).await;
        dir.db()
            .execute(
                "UPDATE ferret_meta SET value = ?1 WHERE key = 'setup_fingerprint'",
                [bad.as_slice()],
            )
            .unwrap();
        let text = refusal(dir.start().await);
        assert!(text.contains("not 32 bytes"), "{text}");
    }
    // A text value is not a fingerprint either.
    let dir = Dir::new();
    first_start(&dir).await;
    dir.db()
        .execute(
            "UPDATE ferret_meta SET value = CAST('text' AS BLOB) WHERE key = 'setup_fingerprint'",
            [],
        )
        .unwrap();
    refusal(dir.start().await);
}

#[tokio::test]
async fn a_lost_set_up_is_refused_when_only_a_fingerprint_remains() {
    // No accounts, but the database remembers a set-up: the file may not be
    // made again.
    let dir = Dir::new();
    first_start(&dir).await;
    std::fs::remove_file(dir.file(OPAQUE_SETUP_FILE)).unwrap();
    let text = refusal(dir.start().await);
    assert!(text.contains("can't load the secret files"), "{text}");
    assert!(!dir.file(OPAQUE_SETUP_FILE).exists());
}

#[tokio::test]
async fn a_replaced_set_up_is_refused_when_only_a_fingerprint_remains() {
    let dir = Dir::new();
    first_start(&dir).await;
    write_other_setup(&dir);
    let text = refusal(dir.start().await);
    assert!(
        text.contains("not the one this database was made with"),
        "{text}"
    );
}

// -------------------------------------------------- files that are not right

#[cfg(unix)]
#[tokio::test]
async fn a_secret_file_open_to_others_is_refused_and_left_alone() {
    use std::os::unix::fs::PermissionsExt as _;
    for name in [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE] {
        let dir = Dir::new();
        first_start(&dir).await;
        let path = dir.file(name);
        let before = std::fs::read(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let text = refusal(dir.start().await);
        assert!(
            text.contains("accessible to group or others"),
            "{name}: {text}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before, "{name}");
    }
}

#[tokio::test]
async fn a_damaged_secret_file_is_refused_and_never_replaced() {
    for name in [OPAQUE_SETUP_FILE, PRELOGIN_SECRET_FILE] {
        for accounts in [false, true] {
            let dir = Dir::new();
            first_start(&dir).await;
            if accounts {
                dir.add_account();
            }
            let path = dir.file(name);
            let mut bytes = std::fs::read(&path).unwrap();
            let middle = bytes.len() / 2;
            bytes[middle] ^= 0x01;
            std::fs::write(&path, &bytes).unwrap();
            refusal(dir.start().await);
            assert_eq!(std::fs::read(&path).unwrap(), bytes, "{name} (damaged)");
        }
    }
}

#[tokio::test]
async fn a_set_up_on_disk_that_the_database_never_saw_is_adopted() {
    // A directory that holds a set-up and a database that never saw it: the
    // set-up is adopted, the pre-login secret is made, the fingerprint is
    // recorded.
    let dir = Dir::new();
    std::fs::create_dir_all(dir.path()).unwrap();
    let keys = ServerKeys::generate(&mut OsRng).unwrap();
    write_new_secret_file(
        &dir.file(OPAQUE_SETUP_FILE),
        FileKind::OpaqueSetup,
        &keys.payload(),
    )
    .unwrap();
    let state = dir.start().await.expect("a start with a set-up on disk");
    assert_eq!(state.secrets.keys.fingerprint(), keys.fingerprint());
    assert!(dir.file(PRELOGIN_SECRET_FILE).exists());
    assert_eq!(
        dir.stored_fingerprint(),
        Some(keys.fingerprint().0.to_vec())
    );
}

// ------------------------------------------------------------- the real clock

#[tokio::test]
async fn the_binary_start_up_works_with_the_system_clock() {
    let dir = Dir::new();
    let state = start(&dir.config(), Arc::new(SystemClock) as Arc<dyn Clock>)
        .await
        .expect("a start with the system clock");
    // The login state store is the table in the same database file.
    assert!(state.clock.now_unix() > 1_700_000_000);
    assert!(dir.file(product::DB_FILE).exists());
}
