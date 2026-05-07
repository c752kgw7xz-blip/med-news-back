CREATE TABLE IF NOT EXISTS pending_emails (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  to_email    TEXT        NOT NULL,
  subject     TEXT        NOT NULL,
  html_body   TEXT        NOT NULL,
  plain_body  TEXT        NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  sent_at     TIMESTAMPTZ,
  attempts    INT         NOT NULL DEFAULT 0,
  last_error  TEXT,
  max_attempts INT        NOT NULL DEFAULT 5
);

CREATE INDEX IF NOT EXISTS idx_pending_emails_unsent
  ON pending_emails (created_at)
  WHERE sent_at IS NULL;
