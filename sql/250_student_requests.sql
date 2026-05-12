-- 250_student_requests.sql
-- Plan utilisateur + demandes accès étudiant

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'standard';

CREATE TABLE IF NOT EXISTS student_requests (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_data BYTEA       NOT NULL,
  document_mime TEXT        NOT NULL DEFAULT 'image/jpeg',
  status        TEXT        NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
  reject_reason TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  reviewed_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_student_requests_user_id ON student_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_student_requests_status  ON student_requests(status);
