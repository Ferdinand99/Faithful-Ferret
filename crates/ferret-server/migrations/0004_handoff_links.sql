-- Links an admin session to the vault session it was handed over from, so that
-- signing out of the vault ends the admin sessions that came from it. The
-- column is empty for every vault session and for any session without a parent.
ALTER TABLE ferret_sessions
  ADD COLUMN parent_sid BLOB CHECK(parent_sid IS NULL OR length(parent_sid) = 32);

CREATE INDEX ferret_sessions_parent ON ferret_sessions(parent_sid);

-- The kit's session version of the parent when the code was made. A code is
-- refused when the version has moved since ("sign out everywhere", a password
-- change). Codes live 60 seconds, so no row needs a real value for the default.
ALTER TABLE ferret_handoffs
  ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0;
