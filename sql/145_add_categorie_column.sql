-- 145_add_categorie_column.sql
-- Ajoute la colonne categorie (clinique | therapeutique | exercice)
-- manquante depuis la création de la table items en 010.
-- Doit être appliquée AVANT 150_remap_categories.sql qui fait UPDATE sur cette colonne.

ALTER TABLE items ADD COLUMN IF NOT EXISTS categorie TEXT;
