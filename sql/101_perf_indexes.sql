-- 101_perf_indexes.sql
-- Index de performance (renommé depuis 100_perf_indexes.sql).

-- Index partiel pour accélérer la liste des articles approuvés
CREATE INDEX IF NOT EXISTS idx_items_approved_score
  ON items (score_density DESC, candidate_id)
  WHERE review_status = 'APPROVED';

-- Index sur official_date pour les filtres de date dans /articles
CREATE INDEX IF NOT EXISTS idx_candidates_official_date_desc
  ON candidates (official_date DESC);

-- Note : idx_favorites_user_item supprimé — doublon de la contrainte
-- UNIQUE (user_id, item_id) déjà indexée par 050_favorites.sql.
