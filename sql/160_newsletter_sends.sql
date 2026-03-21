-- Migration 160 : table de suivi des envois de newsletter
-- Permet d'éviter les doubles envois et de déclencher l'envoi automatiquement
-- dès que la file d'articles PENDING est vide.

CREATE TABLE IF NOT EXISTS newsletter_sends (
    id            SERIAL PRIMARY KEY,
    newsletter_type TEXT NOT NULL,   -- 'reglementaire' | 'recommandation'
    period_label  TEXT NOT NULL,     -- ex. '2026-03' (mensuel) ou '2026-W12' (hebdo)
    sent_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    articles_sent INT,               -- nombre d'articles envoyés au total
    UNIQUE (newsletter_type, period_label)
);

COMMENT ON TABLE newsletter_sends IS
  'Historique des envois newsletter — 1 ligne par type × période. '
  'Empêche les doublons et sert de déclencheur pour l''envoi automatique.';
