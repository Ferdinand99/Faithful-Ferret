-- The server's rule for quick unlock: one row, set by an administrator on the
-- admin pages and read by every client (`GET /api/vault/policy`). Additive: one
-- new table, no existing row or column changes. The schema is part of every
-- build; whether the rule is served and editable is decided by a cargo feature,
-- so a build without it still migrates the same way.
--
-- `pin_allowed` is the emergency switch: off, every PIN is deleted at the next
-- contact of its device. `pin_after_restart` says whether a PIN may be kept on
-- disk (on) or only in memory (off). `pin_min_length` is the shortest PIN the
-- server accepts, counted in Unicode scalar values; 4 is the floor of the
-- clients too. The row is seeded with the defaults (a PIN is allowed, it
-- survives a restart, six characters at least) and is never deleted: the check
-- on `id` keeps the table at one row.

CREATE TABLE ferret_unlock_policy (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  pin_allowed INTEGER NOT NULL CHECK(pin_allowed IN (0, 1)),
  pin_after_restart INTEGER NOT NULL CHECK(pin_after_restart IN (0, 1)),
  pin_min_length INTEGER NOT NULL CHECK(pin_min_length BETWEEN 4 AND 64),
  updated_at INTEGER NOT NULL CHECK(updated_at >= 0)
) STRICT;

INSERT INTO ferret_unlock_policy (id, pin_allowed, pin_after_restart, pin_min_length, updated_at)
VALUES (1, 1, 1, 6, 0);
