-- 090_add_pharmaciens_audience.sql
-- Ajout de PHARMACIENS comme valeur d'audience valide dans items
-- (précédemment masqué comme TRANSVERSAL_LIBERAL, désormais tracé correctement)

ALTER TABLE items DROP CONSTRAINT IF EXISTS items_audience_chk;

ALTER TABLE items ADD CONSTRAINT items_audience_chk
  CHECK (audience IN ('TRANSVERSAL_LIBERAL', 'SPECIALITE', 'PHARMACIENS'));

-- Mettre à jour la contrainte de cohérence specialty_slug
-- PHARMACIENS se comporte comme TRANSVERSAL_LIBERAL (pas de specialty_slug)
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_specialty_slug_chk;

ALTER TABLE items ADD CONSTRAINT items_specialty_slug_chk
  CHECK (
    (audience IN ('TRANSVERSAL_LIBERAL', 'PHARMACIENS')
      AND (specialty_slug IS NULL OR specialty_slug = ''))
    OR
    (audience = 'SPECIALITE'
      AND specialty_slug IS NOT NULL AND specialty_slug <> '')
  );
