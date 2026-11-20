-- Devices and their tokens (Spec: Fase 1 § 7.6, § 8.2). A device client signs
-- in with OPAQUE as before and gets an access token and a refresh token, both
-- bound to the device key (DPoP, RFC 9449). Additive: three new tables, no
-- existing row or column changes.
--
-- A token is 32 random bytes. Only SHA-256 of the label "ferret/v1/token" and
-- the bytes is stored, so a copy of the database holds no usable token.
--
-- `jkt` is the RFC 7638 thumbprint of the device key; it is unique over every
-- row, so a key that was used once never names a second device. `name` is
-- counted in characters (SQLite counts the characters of a TEXT, as Rust's
-- `chars()` does). A refresh token has at most one successor (`prev_hash` is
-- unique where it is set), and used refresh rows are found by `used_at` when
-- they are purged.

CREATE TABLE ferret_devices (
  device_id BLOB PRIMARY KEY CHECK(length(device_id) = 16),
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  jkt BLOB NOT NULL UNIQUE CHECK(length(jkt) = 32),
  name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
  platform TEXT NOT NULL CHECK(platform IN ('windows','macos','linux','android','ios','chromeos','other')),
  session_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL CHECK(created_at >= 0),
  last_seen INTEGER NOT NULL CHECK(last_seen >= 0),
  revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at >= 0)
) STRICT;
CREATE INDEX ferret_devices_user ON ferret_devices(user_id);

CREATE TABLE ferret_refresh (
  token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
  device_id BLOB NOT NULL CHECK(length(device_id) = 16) REFERENCES ferret_devices(device_id) ON DELETE CASCADE,
  prev_hash BLOB CHECK(prev_hash IS NULL OR length(prev_hash) = 32),
  issued_at INTEGER NOT NULL CHECK(issued_at >= 0),
  idle_expires_at INTEGER NOT NULL CHECK(idle_expires_at >= 0),
  abs_expires_at INTEGER NOT NULL CHECK(abs_expires_at >= 0),
  used_at INTEGER CHECK(used_at IS NULL OR used_at >= 0)
) STRICT;
CREATE INDEX ferret_refresh_device ON ferret_refresh(device_id);
CREATE UNIQUE INDEX ferret_refresh_prev ON ferret_refresh(prev_hash) WHERE prev_hash IS NOT NULL;
CREATE INDEX ferret_refresh_used ON ferret_refresh(used_at) WHERE used_at IS NOT NULL;

CREATE TABLE ferret_access (
  token_hash BLOB PRIMARY KEY CHECK(length(token_hash) = 32),
  device_id BLOB NOT NULL CHECK(length(device_id) = 16) REFERENCES ferret_devices(device_id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL CHECK(expires_at >= 0)
) STRICT;
CREATE INDEX ferret_access_device ON ferret_access(device_id);
