-- Indexes for the sync milestone. No table or column changes.
--
-- The retention job finds the idempotency records of one device by age, and
-- the tombstones of one vault by the time they were written. Without these
-- indexes both are scans of everything the vault has ever stored.
CREATE INDEX ferret_idem_by_device_time ON ferret_idem(vault_id, device_id, created_at);
CREATE INDEX ferret_items_tombstones ON ferret_items(vault_id, deleted, changed_at);
