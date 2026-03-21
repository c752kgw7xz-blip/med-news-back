-- 101_perf_indexes.sql
-- Index de performance (renommé depuis 100_perf_indexes.sql).

-- Index partiel pour accélérer la liste des articles approuvés
CREATE INDEX IF NOT EXISTS idx_items_approved_score
  ON items (score_density DESC, candidate_id)
  WHERE review_status = 'APPROVED';

-- Note : idx_candidates_official_date_desc supprimé — doublon de
-- idx_candidates_official_date (010_pipeline_candidates_items.sql).
-- Note : idx_favorites_user_item supprimé — doublon de la contrainte
-- UNIQUE (user_id, item_id) déjà indexée par 050_favorites.sql.
