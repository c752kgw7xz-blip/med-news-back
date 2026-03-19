-- Migration 110 — Ajout de source_type sur items
-- Valeurs : 'reglementaire' | 'recommandation' | 'therapeutique' | 'formation'
-- Permet au portail de distinguer veille réglementaire et recommandations pratiques.

ALTER TABLE items ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'reglementaire';

-- Backfill : items issus de HAS RBP (recommandations de bonne pratique)
UPDATE items
SET source_type = 'recommandation'
WHERE source_type = 'reglementaire'
  AND candidate_id IN (
    SELECT id FROM candidates WHERE source = 'has_rbp'
  );

-- Index pour le filtre rapide dans le portail
CREATE INDEX IF NOT EXISTS idx_items_source_type ON items (source_type)
