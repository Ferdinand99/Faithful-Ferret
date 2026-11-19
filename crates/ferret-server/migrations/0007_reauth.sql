-- When a session last proved the master password again for a sensitive
-- operation (Spec: Fase 1 § 4.6 a). Additive: no existing row or column
-- changes, and every session starts with no re-authentication (NULL). The time
-- belongs to the session row, so the freshness is bound to that session and no
-- other.
ALTER TABLE ferret_sessions ADD COLUMN reauth_at INTEGER CHECK(reauth_at IS NULL OR reauth_at >= 0);
