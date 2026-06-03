-- ─────────────────────────────────────────────────────────────────────────────
-- Fingerprint University — PostgreSQL schema
-- Run once: psql -U fp_user -d fp_university -f db/schema.sql
-- ─────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name          TEXT NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS password_resets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
  visitor_id    TEXT PRIMARY KEY,
  active_email  TEXT,
  suspect_score INTEGER DEFAULT 0,
  vpn           BOOLEAN DEFAULT FALSE,
  high_activity BOOLEAN DEFAULT FALSE,
  fp_signals    JSONB,
  created_at    TIMESTAMPTZ DEFAULT NOW(),
  updated_at    TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS video_views (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id  TEXT NOT NULL REFERENCES devices(visitor_id) ON DELETE CASCADE,
  video_id    TEXT NOT NULL,
  watched_at  TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(visitor_id, video_id)
);

CREATE TABLE IF NOT EXISTS certifications (
  visitor_id    TEXT PRIMARY KEY REFERENCES devices(visitor_id) ON DELETE CASCADE,
  attempts      INTEGER DEFAULT 0,
  passed        BOOLEAN DEFAULT FALSE,
  score         INTEGER,
  submitted_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS reviews (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id    TEXT UNIQUE NOT NULL REFERENCES devices(visitor_id) ON DELETE CASCADE,
  email         TEXT NOT NULL,
  rating        INTEGER,
  subject       TEXT,
  body          TEXT,
  submitted_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fp_api_log (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id  TEXT,
  event       TEXT NOT NULL,
  ui_trigger  TEXT,
  signals     JSONB,
  called_at   TIMESTAMPTZ DEFAULT NOW()
);

-- Seed demo users (password = 'test' hashed with bcrypt cost 10)
INSERT INTO users (email, password_hash, name) VALUES
  ('test@test.com',  '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test User'),
  ('foo@bar.com',    '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Foo Bar'),
  ('alpha@beta.com', '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Alpha Beta')
ON CONFLICT (email) DO NOTHING;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fp_user;

-- Smart Signals — one row per Server API call
-- Gives structured columns for DBeaver/Preset analysis
CREATE TABLE IF NOT EXISTS smart_signals (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  visitor_id    TEXT REFERENCES devices(visitor_id) ON DELETE CASCADE,
  request_id    TEXT,
  ui_trigger    TEXT,
  -- Identification
  confidence    NUMERIC(4,3),
  first_seen_at TIMESTAMPTZ,
  last_seen_at  TIMESTAMPTZ,
  -- Smart Signals (boolean flags)
  incognito     BOOLEAN,
  vpn           BOOLEAN,
  proxy         BOOLEAN,
  tor           BOOLEAN,
  tampering     BOOLEAN,
  high_activity BOOLEAN,
  location_spoofing BOOLEAN,
  -- Bot detection
  bot_result    TEXT,       -- 'not_detected' | 'good' | 'bad'
  bot_type      TEXT,       -- 'headlessChrome' | 'selenium' | etc.
  -- Risk
  suspect_score INTEGER,
  -- IP info
  ip_v4_address TEXT,
  ip_country    TEXT,
  ip_city       TEXT,
  ip_timezone   TEXT,
  -- VPN detail
  vpn_origin_country TEXT,
  -- Full raw payload for anything not in the columns above
  raw           JSONB,
  captured_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_smart_signals_visitor ON smart_signals(visitor_id);
CREATE INDEX IF NOT EXISTS idx_smart_signals_captured ON smart_signals(captured_at DESC);

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO fp_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO fp_user;
