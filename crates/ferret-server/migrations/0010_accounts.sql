-- Several accounts on one server (delivery 1). Additive: one new column, one
-- new table and its index; no existing row or column changes. The kit's table
-- of invitation links (`kit/0007_invites.sql`) comes with it as a core
-- migration of its own, and the kit runs it before this file.
--
-- `ferret_registrations.invite_hash` is the SHA-256 of the invitation a
-- pending registration was started with (the kit's `invites.token_hash`), or
-- NULL for the first administrator, who registers with the setup token. Every
-- row of an older release is such a row and stays NULL.
--
-- `ferret_account_events` is the account log: what was done to an account by
-- an administrator (`admin`, with that administrator's e-mail in `actor_name`,
-- empty once that account is gone), by a command on the server
-- (`server_command`), by the server itself (`server`, a restore) or by the
-- account (`account`, a redeemed sign-in code). `at` is Unix seconds. `kind` is
-- free text of 1 to 64 characters, so a later delivery adds kinds without a
-- new table. The log of an account goes with the account (ON DELETE CASCADE).
-- An event holds no code and no token. The index reads the log of one account
-- newest first, a page at a time.

ALTER TABLE ferret_registrations ADD COLUMN invite_hash BLOB
  CHECK(invite_hash IS NULL OR length(invite_hash) = 32);

CREATE TABLE ferret_account_events (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  at INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK(length(kind) BETWEEN 1 AND 64),
  actor TEXT NOT NULL CHECK(actor IN ('admin','server_command','server','account')),
  actor_name TEXT NOT NULL DEFAULT '' CHECK(length(actor_name) <= 254)
) STRICT;

CREATE INDEX ferret_account_events_user ON ferret_account_events(user_id, id);
