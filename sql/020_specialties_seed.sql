-- 020_specialties_seed.sql
-- Spécialités médicales prioritaires (phase 1)
-- Idempotent: ON CONFLICT DO NOTHING

CREATE TABLE IF NOT EXISTS specialties (
  slug TEXT PRIMARY KEY,
  name TEXT NOT NULL
);

INSERT INTO specialties (slug, name) VALUES
  ('medecine-generale',  'Médecine générale'),
  ('cardiologie',        'Cardiologie'),
  ('chirurgie',          'Chirurgie')
ON CONFLICT (slug) DO NOTHING;
