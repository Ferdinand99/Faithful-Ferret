-- What the server knows about a restore, for the clients that accept an older
-- state afterwards. Additive: no existing row or column changes, and a vault
-- that was never restored keeps `restore_seq` 0 and has no frozen rows.
--
-- `ferret restore-epoch bump` writes both. `restore_seq` is the `seq` of the
-- vault at the bump. `ferret_restore_rows` holds one row for each item the
-- vault had then: its revision, its `seq` and the SHA-256 of its envelope
-- (NULL for a tombstone). The server has no key, so the list has no MAC: it is
-- information for the honest case and nothing a client can prove.
ALTER TABLE ferret_vaults ADD COLUMN restore_seq INTEGER NOT NULL DEFAULT 0;
CREATE TABLE ferret_restore_rows (
  vault_id BLOB NOT NULL CHECK(length(vault_id) = 16) REFERENCES ferret_vaults(vault_id) ON DELETE CASCADE,
  item_id BLOB NOT NULL CHECK(length(item_id) = 16),
  restore_epoch INTEGER NOT NULL, rev INTEGER NOT NULL, seq INTEGER NOT NULL,
  blob_sha256 BLOB CHECK(blob_sha256 IS NULL OR length(blob_sha256) = 32),
  PRIMARY KEY (vault_id, item_id)
) STRICT, WITHOUT ROWID;
