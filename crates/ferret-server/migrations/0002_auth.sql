-- Sealed login states between the two OPAQUE steps, registrations that wait for
-- their second step, and a small key/value table for server metadata.

CREATE TABLE ferret_login_states (
  key BLOB PRIMARY KEY,
  sealed BLOB NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;

CREATE INDEX ferret_login_states_exp ON ferret_login_states(expires_at);

CREATE TABLE ferret_registrations (
  registration_id BLOB PRIMARY KEY CHECK(length(registration_id) = 16),
  account_id BLOB NOT NULL CHECK(length(account_id) = 16),
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16),
  email TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL
) STRICT;

-- The fingerprint of the OPAQUE set-up and other facts the server remembers.
CREATE TABLE ferret_meta (
  key TEXT PRIMARY KEY,
  value BLOB NOT NULL
) STRICT;
