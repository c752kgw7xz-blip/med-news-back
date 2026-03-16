-- 030_add_pharmaciens_audience.sql
-- Ajoute l'audience PHARMACIENS dans la contrainte items

ALTER TABLE items
  DROP CONSTRAINT IF EXISTS items_audience_chk;

ALTER TABLE items
  ADD CONSTRAINT items_audience_chk
  CHECK (audience IN ('TRANSVERSAL_LIBERAL', 'SPECIALITE', 'PHARMACIENS'));

-- Mettre à jour la contrainte specialty_slug : PHARMACIENS sans slug, comme TRANSVERSAL
ALTER TABLE items
  DROP CONSTRAINT IF EXISTS items_specialty_slug_chk;

ALTER TABLE items
  ADD CONSTRAINT items_specialty_slug_chk
  CHECK (
    (audience IN ('TRANSVERSAL_LIBERAL', 'PHARMACIENS')
      AND (specialty_slug IS NULL OR specialty_slug = ''))
    OR
    (audience = 'SPECIALITE'
      AND specialty_slug IS NOT NULL AND specialty_slug <> '')
  );
