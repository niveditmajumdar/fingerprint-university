-- ─────────────────────────────────────────────────────────────────────────────
-- RESET — drops and recreates all tables from scratch
-- Run in DBeaver against fp_university
-- WARNING: permanently deletes all data
-- ─────────────────────────────────────────────────────────────────────────────

DROP TABLE IF EXISTS smart_signals      CASCADE;
DROP TABLE IF EXISTS fp_api_log         CASCADE;
DROP TABLE IF EXISTS reviews            CASCADE;
DROP TABLE IF EXISTS certifications     CASCADE;
DROP TABLE IF EXISTS video_views        CASCADE;
DROP TABLE IF EXISTS devices            CASCADE;
DROP TABLE IF EXISTS password_resets    CASCADE;
DROP TABLE IF EXISTS contact_enquiries  CASCADE;
DROP TABLE IF EXISTS users              CASCADE;

-- ── Users ─────────────────────────────────────────────────────────────────────
CREATE TABLE users (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email            TEXT UNIQUE NOT NULL,
  password_hash    TEXT NOT NULL,
  name             TEXT NOT NULL,
  -- Active visitor ID — set on every login, used for cross-device single-session enforcement
  active_visitor_id TEXT,
  created_at       TIMESTAMPTZ DEFAULT NOW()
);

-- ── Password reset tokens ─────────────────────────────────────────────────────
CREATE TABLE password_resets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── Devices (keyed by Fingerprint visitorId) ──────────────────────────────────
CREATE TABLE devices (
  visitor_id            TEXT PRIMARY KEY,
  active_email          TEXT,
  suspect_score         INTEGER DEFAULT 0,
  vpn                   BOOLEAN DEFAULT FALSE,
  high_activity         BOOLEAN DEFAULT FALSE,
  fp_signals            JSONB,
  last_api_call_at      TIMESTAMPTZ,
  -- Single-session enforcement: only one active session per visitorId at a time.
  -- Overwritten on every new login. Old sessions detect the mismatch on next API call.
  active_session_token  TEXT,
  session_started_at    TIMESTAMPTZ,
  -- Heartbeat: updated every 60s by the client while the page is open.
  -- Sessions with no heartbeat for >5 min are considered stale.
  session_last_seen_at  TIMESTAMPTZ,
  created_at            TIMESTAMPTZ DEFAULT NOW(),
  updated_at            TIMESTAMPTZ DEFAULT NOW()
);

-- ── Video views ───────────────────────────────────────────────────────────────
CREATE TABLE video_views (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id  TEXT NOT NULL REFERENCES devices(visitor_id) ON DELETE CASCADE,
  video_id    TEXT NOT NULL,
  watched_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(visitor_id, video_id)
);

-- ── Certifications ────────────────────────────────────────────────────────────
CREATE TABLE certifications (
  visitor_id    TEXT PRIMARY KEY REFERENCES devices(visitor_id) ON DELETE CASCADE,
  attempts      INTEGER DEFAULT 0,
  passed        BOOLEAN DEFAULT FALSE,
  score         INTEGER,
  submitted_at  TIMESTAMPTZ
);

-- ── Reviews ───────────────────────────────────────────────────────────────────
CREATE TABLE reviews (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id                  TEXT UNIQUE NOT NULL REFERENCES devices(visitor_id) ON DELETE CASCADE,
  email                       TEXT NOT NULL,
  rating                      INTEGER,
  subject                     TEXT,
  body                        TEXT,
  status                      TEXT NOT NULL DEFAULT 'pending',
  suspect_score_at_submission INTEGER,
  vpn_at_submission           BOOLEAN,
  visitor_id_at_submission    TEXT,
  submitted_at                TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_reviews_email  ON reviews(LOWER(email));
CREATE INDEX idx_reviews_status ON reviews(status);

-- ── Contact enquiries (pre-login, Team Training form) ─────────────────────────
CREATE TABLE contact_enquiries (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  -- Fingerprint fields (the only identifier at this stage — no account exists)
  visitor_id        TEXT,
  request_id        TEXT,
  confidence        NUMERIC(4,3),
  incognito         BOOLEAN,
  vpn               BOOLEAN,
  bot_result        TEXT,
  suspect_score     INTEGER,
  ip_country        TEXT,
  ip_timezone       TEXT,
  -- Form fields
  name              TEXT NOT NULL,
  email             TEXT NOT NULL,
  company           TEXT,
  team_size         TEXT,
  message           TEXT,
  -- Risk decision
  status            TEXT NOT NULL DEFAULT 'new',  -- new | flagged | contacted | spam
  flag_reason       TEXT,
  -- Deduplication: has this device/email enquired before?
  is_duplicate      BOOLEAN DEFAULT FALSE,
  -- Raw signals for audit
  raw_signals       JSONB,
  submitted_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_contact_visitor ON contact_enquiries(visitor_id);
CREATE INDEX idx_contact_email   ON contact_enquiries(LOWER(email));
CREATE INDEX idx_contact_status  ON contact_enquiries(status);

-- ── Smart Signals (one structured row per Server API call) ────────────────────
CREATE TABLE smart_signals (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id        TEXT REFERENCES devices(visitor_id) ON DELETE CASCADE,
  request_id        TEXT,
  ui_trigger        TEXT,
  confidence        NUMERIC(4,3),
  first_seen_at     TIMESTAMPTZ,
  last_seen_at      TIMESTAMPTZ,
  incognito         BOOLEAN,
  vpn               BOOLEAN,
  proxy             BOOLEAN,
  tor               BOOLEAN,
  tampering         BOOLEAN,
  high_activity     BOOLEAN,
  location_spoofing BOOLEAN,
  bot_result        TEXT,
  bot_type          TEXT,
  suspect_score     INTEGER,
  ip_v4_address     TEXT,
  ip_country        TEXT,
  ip_city           TEXT,
  ip_timezone       TEXT,
  vpn_origin_country TEXT,
  raw               JSONB,
  captured_at       TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_smart_signals_visitor  ON smart_signals(visitor_id);
CREATE INDEX idx_smart_signals_captured ON smart_signals(captured_at DESC);

-- ── FPJS API call log ─────────────────────────────────────────────────────────
CREATE TABLE fp_api_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id  TEXT,
  event       TEXT NOT NULL,
  ui_trigger  TEXT,
  signals     JSONB,
  called_at   TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_fp_log_visitor  ON fp_api_log(visitor_id);
CREATE INDEX idx_fp_log_called   ON fp_api_log(called_at DESC);

-- ── Permissions ───────────────────────────────────────────────────────────────
GRANT ALL PRIVILEGES ON ALL TABLES    IN SCHEMA public TO fp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fp_user;
