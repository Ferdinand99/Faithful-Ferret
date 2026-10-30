-- Sessions of the two origins, and the one-time codes that hand a session over
-- from the vault origin to the admin origin.
--
-- A session row is keyed by the SHA-256 of the random session id, so a copy of
-- the database does not hold a usable cookie value.

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
) STRICT;

CREATE INDEX ferret_sessions_user ON ferret_sessions(user_id);

CREATE TABLE ferret_handoffs (
  code_hash BLOB PRIMARY KEY CHECK(length(code_hash) = 32),
  sid_hash BLOB NOT NULL CHECK(length(sid_hash) = 32) REFERENCES ferret_sessions ON DELETE CASCADE,
  user_id INTEGER NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('login', 'reauth')),
  next TEXT NOT NULL CHECK(length(next) BETWEEN 1 AND 512),
  challenge BLOB NOT NULL CHECK(length(challenge) = 32),
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX ferret_handoffs_exp ON ferret_handoffs(expires_at);
