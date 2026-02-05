CREATE TABLE IF NOT EXISTS candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  source TEXT NOT NULL,              -- 'legifrance'
  source_type TEXT NOT NULL,         -- 'JORF'
  source_id TEXT NOT NULL,           -- 'JORFTEXT...'

  title TEXT,
  url TEXT,
  pdf_url TEXT,

  date_publi DATE,
  date_texte DATE,

  raw JSONB NOT NULL,

  status TEXT NOT NULL DEFAULT 'NEW',
  score REAL,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS candidates_uniq
  ON candidates(source, source_type, source_id);

CREATE INDEX IF NOT EXISTS candidates_status_idx
  ON candidates(status);

CREATE INDEX IF NOT EXISTS candidates_date_publi_idx
  ON candidates(date_publi);
