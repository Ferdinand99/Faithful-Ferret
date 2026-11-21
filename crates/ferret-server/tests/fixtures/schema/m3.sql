-- The schema of the database after every migration of this build: Faithful
-- Ferret's own and the ones that vole-kit runs, as SQLite stores them
-- (`sqlite_master`, in name order). A migration changes this file in the same
-- change; a test compares it with a database that the migrations made. To write
-- it again after a migration was added, run the schema tests with
-- FERRET_UPDATE_GOLDEN=1.

-- table api_token_scopes
CREATE TABLE api_token_scopes (
    token_id INTEGER NOT NULL REFERENCES api_tokens(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    PRIMARY KEY (token_id, scope)
) WITHOUT ROWID;

-- table api_tokens
CREATE TABLE api_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,                       -- first chars of the token, for display
    token_hash TEXT NOT NULL UNIQUE,            -- sha256 hex
    scope TEXT NOT NULL DEFAULT 'read' CHECK (scope IN ('read', 'write')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    expires_at TEXT
);

-- table ferret_accounts
CREATE TABLE ferret_accounts (
  account_id BLOB PRIMARY KEY CHECK(length(account_id) = 16),
  user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  vault_id BLOB NOT NULL UNIQUE CHECK(length(vault_id) = 16),
  opaque_record BLOB NOT NULL CHECK(length(opaque_record) = 192),
  ksf_profile INTEGER NOT NULL,
  sk_hint INTEGER NOT NULL CHECK(sk_hint IN (0, 1)),
  pk_a BLOB NOT NULL CHECK(length(pk_a) = 32),
  pk_r BLOB NOT NULL CHECK(length(pk_r) = 32),
  vk_epoch INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
) STRICT;

-- table ferret_checkpoints
CREATE TABLE ferret_checkpoints (
  vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  digest BLOB NOT NULL,
  mac BLOB NOT NULL,
  entries BLOB NOT NULL
) STRICT;

-- table ferret_handoffs
CREATE TABLE ferret_handoffs (
  code_hash BLOB PRIMARY KEY CHECK(length(code_hash) = 32),
  sid_hash BLOB NOT NULL CHECK(length(sid_hash) = 32) REFERENCES ferret_sessions ON DELETE CASCADE,
  user_id INTEGER NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('login', 'reauth')),
  next TEXT NOT NULL CHECK(length(next) BETWEEN 1 AND 512),
  challenge BLOB NOT NULL CHECK(length(challenge) = 32),
  expires_at INTEGER NOT NULL
, session_version INTEGER NOT NULL DEFAULT 0) STRICT;

-- index ferret_handoffs_exp
CREATE INDEX ferret_handoffs_exp ON ferret_handoffs(expires_at);

-- table ferret_idem
CREATE TABLE ferret_idem (
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  device_id BLOB NOT NULL CHECK(length(device_id) = 16),
  idem BLOB NOT NULL CHECK(length(idem) = 16),
  request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
  rev INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (vault_id, device_id, idem)
) STRICT, WITHOUT ROWID;

-- index ferret_idem_by_device_time
CREATE INDEX ferret_idem_by_device_time ON ferret_idem(vault_id, device_id, created_at);

-- table ferret_items
CREATE TABLE ferret_items (
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  item_id BLOB NOT NULL CHECK(length(item_id) = 16),
  rev INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  deleted INTEGER NOT NULL CHECK(deleted IN (0, 1)),
  blob BLOB,
  tag BLOB,
  tomb BLOB,
  size INTEGER NOT NULL,
  changed_at INTEGER NOT NULL,
  PRIMARY KEY (vault_id, item_id),
  CHECK((deleted = 0 AND blob IS NOT NULL AND tag IS NOT NULL AND length(tag) = 32 AND tomb IS NULL)
     OR (deleted = 1 AND blob IS NULL AND tag IS NULL AND tomb IS NOT NULL))
) STRICT, WITHOUT ROWID;

-- index ferret_items_seq
CREATE INDEX ferret_items_seq ON ferret_items(vault_id, seq);

-- index ferret_items_tombstones
CREATE INDEX ferret_items_tombstones ON ferret_items(vault_id, deleted, changed_at);

-- table ferret_login_states
CREATE TABLE ferret_login_states (
  key BLOB PRIMARY KEY,
  sealed BLOB NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

-- index ferret_login_states_exp
CREATE INDEX ferret_login_states_exp ON ferret_login_states(expires_at);

-- table ferret_meta
CREATE TABLE ferret_meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
) STRICT;

-- table ferret_registrations
CREATE TABLE ferret_registrations (
  registration_id BLOB PRIMARY KEY CHECK(length(registration_id) = 16),
  account_id BLOB NOT NULL CHECK(length(account_id) = 16),
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
  email TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL
) STRICT;

-- table ferret_restore_rows
CREATE TABLE ferret_restore_rows (
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  item_id BLOB NOT NULL CHECK(length(item_id) = 16),
  restore_epoch INTEGER NOT NULL, rev INTEGER NOT NULL, seq INTEGER NOT NULL,
  blob_sha256 BLOB CHECK(blob_sha256 IS NULL OR length(blob_sha256) = 32),
  PRIMARY KEY (vault_id, item_id)
) STRICT, WITHOUT ROWID;

-- table ferret_sessions
CREATE TABLE ferret_sessions (
  sid_hash BLOB PRIMARY KEY CHECK(length(sid_hash) = 32),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  issued_at INTEGER NOT NULL,
  origin TEXT NOT NULL CHECK(origin IN ('vault', 'admin')),
  device_id BLOB NOT NULL CHECK(length(device_id) = 16),
  device_name TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL CHECK(scope IN ('full', 'pending_2fa', 'account_reset', 'unverified')),
  last_seen INTEGER NOT NULL,
  revoked_at INTEGER
, parent_sid BLOB CHECK(parent_sid IS NULL OR length(parent_sid) = 32), reauth_at INTEGER CHECK(reauth_at IS NULL OR reauth_at >= 0)) STRICT;

-- index ferret_sessions_parent
CREATE INDEX ferret_sessions_parent ON ferret_sessions(parent_sid);

-- index ferret_sessions_user
CREATE INDEX ferret_sessions_user ON ferret_sessions(user_id);

-- table ferret_unlock_methods
CREATE TABLE ferret_unlock_methods (
  method_id BLOB PRIMARY KEY CHECK(length(method_id) = 16),
  account_id BLOB NOT NULL REFERENCES ferret_accounts ON DELETE CASCADE CHECK(length(account_id) = 16),
  method_type INTEGER NOT NULL CHECK(method_type IN (1, 2, 3)),
  wrap BLOB NOT NULL,
  kek_generation INTEGER NOT NULL CHECK(kek_generation BETWEEN 1 AND 4294967295),
  credential_id BLOB,
  prf_salt BLOB,
  aaguid BLOB,
  created_at INTEGER NOT NULL
) STRICT;

-- table ferret_vaults
CREATE TABLE ferret_vaults (
  vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16),
  account_id BLOB NOT NULL UNIQUE CHECK(length(account_id) = 16) REFERENCES ferret_accounts ON DELETE CASCADE,
  seq INTEGER NOT NULL DEFAULT 0,
  min_valid_since INTEGER NOT NULL DEFAULT 0,
  restore_epoch INTEGER NOT NULL DEFAULT 0,
  item_count INTEGER NOT NULL DEFAULT 0,
  bytes_used INTEGER NOT NULL DEFAULT 0
, restore_seq INTEGER NOT NULL DEFAULT 0) STRICT;

-- index idx_api_tokens_user
CREATE INDEX idx_api_tokens_user ON api_tokens (user_id);

-- index idx_passkeys_user
CREATE INDEX idx_passkeys_user ON passkeys (user_id);

-- index idx_push_devices_hash
CREATE INDEX idx_push_devices_hash ON push_devices (handle_hash);

-- index idx_push_devices_token
CREATE INDEX idx_push_devices_token ON push_devices (token_id);

-- index idx_push_events_created
CREATE INDEX idx_push_events_created ON push_events (created_at);

-- index idx_push_registrations_user
CREATE INDEX idx_push_registrations_user ON push_registrations (user_id, created_at);

-- index idx_sign_in_codes_user
CREATE INDEX idx_sign_in_codes_user ON sign_in_codes (user_id) WHERE used_at IS NULL AND revoked_at IS NULL;

-- table passkey_challenges
CREATE TABLE passkey_challenges (
    challenge TEXT PRIMARY KEY,                -- base64url
    purpose TEXT NOT NULL CHECK (purpose IN ('register', 'sign_in')),
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    user_handle BLOB,                          -- registration: the handle offered
    expires_at INTEGER NOT NULL                -- unix seconds
) WITHOUT ROWID;

-- table passkeys
CREATE TABLE passkeys (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,        -- as the authenticator chose it
    public_key BLOB NOT NULL,                  -- COSE_Key, as the authenticator sent it
    alg INTEGER NOT NULL,                      -- COSE algorithm: -7 ES256, -8 EdDSA, -257 RS256
    user_handle BLOB NOT NULL,                 -- random, the same for all of a user's passkeys
    name TEXT NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '',       -- comma-separated hints from the browser
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backed_up INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT
);

-- table push_devices
CREATE TABLE push_devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_id INTEGER REFERENCES api_tokens(id) ON DELETE CASCADE,
    handle_sealed TEXT NOT NULL,
    handle_hash TEXT NOT NULL,                  -- sha256 hex of the handle
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    UNIQUE (user_id, handle_hash)
);

-- table push_events
CREATE TABLE push_events (
    ref TEXT PRIMARY KEY,                       -- 16 random bytes, base64url
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    kind TEXT NOT NULL,                         -- problem, recovered, ...
    level TEXT NOT NULL,                        -- critical, warning, ok, info
    occurred_at TEXT NOT NULL,                  -- RFC 3339, UTC
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
) WITHOUT ROWID;

-- table push_registrations
CREATE TABLE push_registrations (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- table schema_migrations
CREATE TABLE schema_migrations (
             name TEXT PRIMARY KEY,
             applied_at TEXT NOT NULL DEFAULT (datetime('now'))
         );

-- table settings
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

-- table sign_in_codes
CREATE TABLE sign_in_codes (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BLOB NOT NULL UNIQUE,
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    used_at TEXT,
    revoked_at TEXT
);

-- table user_emails
CREATE TABLE user_emails (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    verified_at TEXT
);

-- table users
CREATE TABLE "users" (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'editor', 'viewer')),
    display_name TEXT NOT NULL DEFAULT '',
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    recovery_codes TEXT,                       -- JSON array of argon2 hashes
    active INTEGER NOT NULL DEFAULT 1,
    last_login_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
, session_version INTEGER NOT NULL DEFAULT 1, totp_last_step INTEGER, language TEXT);
