-- ─────────────────────────────────────────────────────────────────────────────
-- Migration: add status, signals, and deduplication support to reviews table
-- Run once in DBeaver against fp_university
-- ─────────────────────────────────────────────────────────────────────────────

-- Status column: 'pending' | 'approved' | 'flagged'
ALTER TABLE reviews
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';

-- Fingerprint signals captured at submission time
ALTER TABLE reviews
  ADD COLUMN IF NOT EXISTS suspect_score_at_submission INTEGER;

ALTER TABLE reviews
  ADD COLUMN IF NOT EXISTS vpn_at_submission BOOLEAN;

ALTER TABLE reviews
  ADD COLUMN IF NOT EXISTS visitor_id_at_submission TEXT;

-- Index on email for the duplicate-email check (CHECK 2)
CREATE INDEX IF NOT EXISTS idx_reviews_email ON reviews(email);

-- Index on status for admin/analytics queries
CREATE INDEX IF NOT EXISTS idx_reviews_status ON reviews(status);
