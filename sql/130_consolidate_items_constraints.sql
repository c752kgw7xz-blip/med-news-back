-- 130_consolidate_items_constraints.sql
-- Consolidation des contraintes items après les migrations 030-100.
--
-- Situation avant cette migration :
--   - items_audience_chk    : OK (TRANSVERSAL_LIBERAL | SPECIALITE | PHARMACIENS)
--   - items_specialty_slug_chk : ABSENTE (supprimée en 100, jamais recréée)
--   - items_review_status_chk  : OK
--   - Logique PHARMACIENS : specialty_slug = 'pharmacien' (pas NULL)
--     → les migrations 030/090 disaient NULL mais le code insère 'pharmacien'
--     → on aligne la contrainte sur la réalité du code
--
-- Idempotent (DROP IF EXISTS + ADD IF NOT EXISTS via DROP/ADD).

-- 1. Contrainte audience — idempotent
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_audience_chk;
ALTER TABLE items ADD CONSTRAINT items_audience_chk
  CHECK (audience IN ('TRANSVERSAL_LIBERAL', 'SPECIALITE', 'PHARMACIENS'));

-- 2. Contrainte specialty_slug — reflète la réalité du code Python :
--    TRANSVERSAL_LIBERAL → slug NULL
--    PHARMACIENS         → slug = 'pharmacien'
--    SPECIALITE          → slug non nul et non vide
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_specialty_slug_chk;
ALTER TABLE items ADD CONSTRAINT items_specialty_slug_chk
  CHECK (
    (audience = 'TRANSVERSAL_LIBERAL' AND (specialty_slug IS NULL OR specialty_slug = ''))
    OR
    (audience = 'PHARMACIENS' AND specialty_slug = 'pharmacien')
    OR
    (audience = 'SPECIALITE' AND specialty_slug IS NOT NULL AND specialty_slug <> '')
  );

-- 3. Contrainte review_status — idempotent
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_review_status_chk;
ALTER TABLE items ADD CONSTRAINT items_review_status_chk
  CHECK (review_status IN ('PENDING', 'APPROVED', 'REJECTED'));

-- 4. S'assurer que l'index unique composite est bien présent
--    (créé en 070, on le recrée si absent pour robustesse)
DROP INDEX IF EXISTS ux_items_candidate_id;
CREATE UNIQUE INDEX IF NOT EXISTS ux_items_candidate_specialty
  ON items (candidate_id, COALESCE(specialty_slug, ''));
