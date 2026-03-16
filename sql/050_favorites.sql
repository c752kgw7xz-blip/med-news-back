-- Migration 050: table favorites (bookmarks utilisateur)

CREATE TABLE IF NOT EXISTS favorites (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    UUID        NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
  item_id    UUID        NOT NULL REFERENCES items(id)  ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, item_id)
);

CREATE INDEX IF NOT EXISTS favorites_user_id_idx ON favorites (user_id);
