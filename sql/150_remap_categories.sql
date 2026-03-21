-- 150_remap_categories.sql
-- Simplification des catégories métier : 7 → 3
--   medicament + dispositifs_medicaux  → therapeutique
--   sante_publique                     → clinique
--   facturation + administratif        → exercice  (exercice reste exercice)

UPDATE items
SET categorie = 'therapeutique'
WHERE categorie IN ('medicament', 'dispositifs_medicaux');

UPDATE items
SET categorie = 'clinique'
WHERE categorie = 'sante_publique';

UPDATE items
SET categorie = 'exercice'
WHERE categorie IN ('facturation', 'administratif')
