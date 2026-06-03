-- ─────────────────────────────────────────────────────────────────────────────
-- Migration v2: session heartbeat + cross-device single-session enforcement
-- Run once in DBeaver against fp_university
-- ─────────────────────────────────────────────────────────────────────────────

-- Heartbeat TTL: tracks when the client last pinged (for stale-session cleanup)
ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS session_last_seen_at TIMESTAMPTZ;

-- Cross-device enforcement: which visitorId is the active session for each user?
-- When a user logs in from a new device, this is updated to their new visitorId.
-- Their old device's session token will no longer match → session_displaced.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS active_visitor_id TEXT;
