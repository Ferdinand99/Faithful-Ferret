-- The vault: accounts, unlock methods, the vault counter row, items,
-- checkpoints and idempotency records.
--
-- Every id column holds exactly 16 bytes. Every table is STRICT. The rule that
-- a live item has a blob and a tag and a tombstone has neither is a CHECK, so
-- no code path can store a row that breaks it.
--
-- Everything that belongs to a vault (items, checkpoint, idempotency records)
-- references the vault row and goes with it, and the vault goes with its account
-- and the account with its user: deleting a user in the kit's admin pages
-- removes the ciphertext as well.

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

CREATE TABLE ferret_vaults (
  vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16),
  account_id BLOB NOT NULL UNIQUE CHECK(length(account_id) = 16) REFERENCES ferret_accounts ON DELETE CASCADE,
  seq INTEGER NOT NULL DEFAULT 0,
  min_valid_since INTEGER NOT NULL DEFAULT 0,
  restore_epoch INTEGER NOT NULL DEFAULT 0,
  item_count INTEGER NOT NULL DEFAULT 0,
  bytes_used INTEGER NOT NULL DEFAULT 0
) STRICT;

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

CREATE INDEX ferret_items_seq ON ferret_items(vault_id, seq);

CREATE TABLE ferret_checkpoints (
  vault_id BLOB PRIMARY KEY CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  digest BLOB NOT NULL,
  mac BLOB NOT NULL,
  entries BLOB NOT NULL
) STRICT;

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
