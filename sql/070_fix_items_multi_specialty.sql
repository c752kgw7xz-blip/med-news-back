-- 070_fix_items_multi_specialty.sql
-- Corrige l'index unique sur items(candidate_id) qui bloque la création
-- de plusieurs items par candidat (un par spécialité).
-- L'index est remplacé par un index composite (candidate_id, specialty_slug)
-- ce qui permet exactement 1 item par couple (candidat, spécialité).

-- Supprimer l'ancien index bloquant
DROP INDEX IF EXISTS ux_items_candidate_id;

-- Nouvel index composite : 1 item max par (candidat, spécialité)
-- COALESCE gère le cas NULL (items TRANSVERSAL_LIBERAL sans slug)
CREATE UNIQUE INDEX IF NOT EXISTS ux_items_candidate_specialty
ON items (candidate_id, COALESCE(specialty_slug, ''));
