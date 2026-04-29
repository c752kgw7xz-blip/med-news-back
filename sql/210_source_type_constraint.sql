-- Contrainte sur les valeurs autorisées de source_type.
-- Empêche toute valeur hors du triptyque portal/newsletter.
ALTER TABLE items
  ADD CONSTRAINT chk_source_type
  CHECK (source_type IN ('reglementaire', 'recommandation', 'innovation'));
