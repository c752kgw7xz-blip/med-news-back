CREATE TABLE IF NOT EXISTS candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  title TEXT,
  url TEXT,
  pdf_url TEXT,
  date_publi DATE,
  date_texte DATE,
  raw JSONB,
  status TEXT DEFAULT 'NEW',
  score REAL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Complète une table existante mais incomplète (cas très probable chez toi)
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS url TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS pdf_url TEXT;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS date_publi DATE;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS date_texte DATE;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS raw JSONB;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'NEW';
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS score REAL;
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now();
ALTER TABLE candidates ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

-- Index après garantie des colonnes
CREATE UNIQUE INDEX IF NOT EXISTS candidates_uniq
  ON candidates(source, source_type, source_id);

CREATE INDEX IF NOT EXISTS candidates_status_idx
  ON candidates(status);

CREATE INDEX IF NOT EXISTS candidates_date_publi_idx
  ON candidates(date_publi);
