-- 010_pipeline_candidates_items.sql

-- =========================
-- PIPELINE: candidates + items
-- =========================

-- -------------------------
-- Schema migrations helper
-- -------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
  filename TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- 1) candidates = collecte brute (crawler / sources officielles)
-- ============================================================
CREATE TABLE IF NOT EXISTS candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  -- provenance
  source TEXT NOT NULL,                       -- ex: 'legifrance_jorf'
  jorftext_id TEXT,                           -- ex: JORFTEXT0000...

  -- données opposables
  official_url TEXT NOT NULL,
  official_date DATE NOT NULL,

  -- contenu brut
  title_raw TEXT NOT NULL,
  pdf_url TEXT,

  content_raw TEXT,                           -- rempli plus tard (consult/jorf)
  raw_json JSONB NOT NULL,                    -- payload brut PISTE (/search)
  raw_sha256 TEXT NOT NULL,                   -- hash du raw_json canonique

  -- déduplication
  dedupe_key TEXT NOT NULL,                   -- sha256(source|external_id)

  -- état technique (PAS métier)
  status TEXT NOT NULL DEFAULT 'NEW',
  llm_error TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -------------------------
-- Contraintes candidates
-- -------------------------
ALTER TABLE candidates
  DROP CONSTRAINT IF EXISTS candidates_status_chk;

ALTER TABLE candidates
  ADD CONSTRAINT candidates_status_chk
  CHECK (status IN ('NEW','LLM_DONE','LLM_FAILED'));

-- -------------------------
-- Index candidates
-- -------------------------
-- déduplication forte
CREATE UNIQUE INDEX IF NOT EXISTS ux_candidates_dedupe_key
ON candidates (dedupe_key);

-- unicité logique source + id externe
CREATE UNIQUE INDEX IF NOT EXISTS ux_candidates_source_jorftext
ON candidates (source, jorftext_id)
WHERE jorftext_id IS NOT NULL;

-- perfs usuelles
CREATE INDEX IF NOT EXISTS idx_candidates_official_date
ON candidates (official_date DESC);

CREATE INDEX IF NOT EXISTS idx_candidates_source
ON candidates (source);

CREATE INDEX IF NOT EXISTS idx_candidates_status
ON candidates (status);

CREATE INDEX IF NOT EXISTS idx_candidates_jorftext_id
ON candidates (jorftext_id);

-- ============================================================
-- 2) items = sortie LLM structurée + review admin
-- ============================================================
CREATE TABLE IF NOT EXISTS items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  candidate_id UUID NOT NULL
    REFERENCES candidates(id)
    ON DELETE CASCADE,

  -- cible éditoriale
  audience TEXT NOT NULL,                     -- TRANSVERSAL_LIBERAL | SPECIALITE
  specialty_slug TEXT,

  -- sortie LLM
  tri_json JSONB NOT NULL,
  lecture_json JSONB NOT NULL,
  score_density INT,

  llm_raw TEXT,
  llm_model TEXT,
  llm_created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

  -- décision humaine
  review_status TEXT NOT NULL DEFAULT 'PENDING',
  note_internal TEXT,

  -- publication
  published_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- -------------------------
-- Contraintes items
-- -------------------------
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

-- -------------------------
-- Index items
-- -------------------------
-- 1 item max par candidate (pas de double analyse)
CREATE UNIQUE INDEX IF NOT EXISTS ux_items_candidate_id
ON items (candidate_id);

CREATE INDEX IF NOT EXISTS idx_items_review_status
ON items (review_status);

CREATE INDEX IF NOT EXISTS idx_items_published_at
ON items (published_at DESC);

CREATE INDEX IF NOT EXISTS idx_items_created_at
ON items (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_items_audience_specialty
ON items (audience, specialty_slug);
