-- 100_add_type_praticien.sql
-- Ajoute le champ type_praticien aux items pour affiner le filtrage par profil de praticien.
-- Valeurs : prescripteur | interventionnel | biologiste | pharmacien | tous
-- Idempotent.

ALTER TABLE items ADD COLUMN IF NOT EXISTS type_praticien TEXT;

-- Ajouter pharmacien comme spécialité inscriptible
INSERT INTO specialties (slug, name) VALUES
  ('pharmacien', 'Pharmacien')
ON CONFLICT (slug) DO NOTHING;

-- Mettre à jour la contrainte specialty_slug pour autoriser PHARMACIENS
-- à avoir specialty_slug = 'pharmacien' (nouvelle logique) OU NULL (données existantes).
ALTER TABLE items DROP CONSTRAINT IF EXISTS items_specialty_slug_chk;
