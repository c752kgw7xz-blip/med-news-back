-- 040_expand_specialties.sql
-- Ajoute la table email_verification_tokens + 12 nouvelles spécialités

-- ── Table de vérification email ──────────────────────────────────
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_evt_token_hash ON email_verification_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_evt_user_id ON email_verification_tokens(user_id);

-- ── Nouvelles spécialités (total 15) ─────────────────────────────
INSERT INTO specialties (slug, name) VALUES
  ('dermatologie',       'Dermatologie'),
  ('endocrinologie',     'Endocrinologie'),
  ('gastro-enterologie', 'Gastro-entérologie'),
  ('gynecologie',        'Gynécologie'),
  ('neurologie',         'Neurologie'),
  ('ophtalmologie',      'Ophtalmologie'),
  ('orl',                'ORL'),
  ('pediatrie',          'Pédiatrie'),
  ('pneumologie',        'Pneumologie'),
  ('psychiatrie',        'Psychiatrie'),
  ('rhumatologie',       'Rhumatologie'),
  ('urologie',           'Urologie')
ON CONFLICT (slug) DO NOTHING;
