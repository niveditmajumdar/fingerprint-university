-- Migration: add single-session enforcement to devices table
-- Run once in DBeaver against fp_university

ALTER TABLE devices
  ADD COLUMN IF NOT EXISTS active_session_token TEXT,
  ADD COLUMN IF NOT EXISTS session_started_at   TIMESTAMPTZ;
