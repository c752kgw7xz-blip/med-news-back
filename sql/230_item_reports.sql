-- Migration 230 — Signalements d'articles par les praticiens
-- Stocke les retours utilisateurs sur les articles (erreur, non pertinent, etc.)

CREATE TABLE IF NOT EXISTS item_reports (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id      UUID NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id) ON DELETE SET NULL,
    reason       TEXT NOT NULL,          -- 'not_relevant' | 'factual_error' | 'wrong_specialty' | 'other'
    comment      TEXT,                   -- commentaire libre optionnel
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_item_reports_item_id ON item_reports(item_id);
CREATE INDEX IF NOT EXISTS idx_item_reports_created_at ON item_reports(created_at DESC);
