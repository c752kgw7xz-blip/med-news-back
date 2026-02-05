-- 010_pipeline_candidates_items.sql

-- =========================
-- PIPELINE: candidates + items
-- =========================

CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 1) candidates = collecte brute (crawler)
CREATE TABLE IF NOT EXISTS candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  source TEXT NOT NULL,

  official_url TEXT NOT NULL,
  official_date DATE NOT NULL,

  title_raw TEXT,
  pdf_url TEXT,

  content_raw TEXT,
  raw_sha256 TEXT,

  dedupe_key TEXT NOT NULL UNIQUE,

  status TEXT NOT NULL DEFAULT 'NEW',
  llm_error TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE candidates
  DROP CONSTRAINT IF EXISTS candidates_status_chk;

ALTER TABLE candidates
  ADD CONSTRAINT candidates_status_chk
  CHECK (status IN ('NEW','LLM_DONE','LLM_FAILED','DUPLICATE'));

CREATE INDEX IF NOT EXISTS idx_candidates_official_date ON candidates (official_date DESC);
CREATE INDEX IF NOT EXISTS idx_candidates_source ON candidates (source);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates (status);

-- 2) items = sortie LLM structurée + review admin
CREATE TABLE IF NOT EXISTS items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,

  audience TEXT NOT NULL,
  specialty_slug TEXT,

  tri_json JSONB NOT NULL,
  lecture_json JSONB NOT NULL,
  score_density INT,

  llm_raw TEXT,
  llm_model TEXT,
  llm_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  review_status TEXT NOT NULL DEFAULT 'PENDING',
  note_internal TEXT,

  published_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE items
  DROP CONSTRAINT IF EXISTS items_audience_chk;

ALTER TABLE items
  ADD CONSTRAINT items_audience_chk
  CHECK (audience IN ('TRANSVERSAL_LIBERAL','SPECIALITE'));

ALTER TABLE items
  DROP CONSTRAINT IF EXISTS items_review_status_chk;

ALTER TABLE items
  ADD CONSTRAINT items_review_status_chk
  CHECK (review_status IN ('PENDING','APPROVED','REJECTED'));

ALTER TABLE items
  DROP CONSTRAINT IF EXISTS items_specialty_slug_chk;

ALTER TABLE items
  ADD CONSTRAINT items_specialty_slug_chk
  CHECK (
    (audience = 'TRANSVERSAL_LIBERAL' AND (specialty_slug IS NULL OR specialty_slug = ''))
    OR
    (audience = 'SPECIALITE' AND specialty_slug IS NOT NULL AND specialty_slug <> '')
  );

CREATE UNIQUE INDEX IF NOT EXISTS ux_items_candidate_id ON items (candidate_id);

CREATE INDEX IF NOT EXISTS idx_items_review_status ON items (review_status);
CREATE INDEX IF NOT EXISTS idx_items_published_at ON items (published_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_created_at ON items (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_items_audience_specialty ON items (audience, specialty_slug);
