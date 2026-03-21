-- 140_remove_chirurgie_generic.sql
-- Supprime le slug 'chirurgie' générique de la table specialties.
-- Il est interdit dans KNOWN_SPECIALTIES (llm_analysis.py) et aucun item
-- ne peut l'avoir — c'est une ligne orpheline depuis la migration 020.
-- Les sous-spécialités (chirurgie-vasculaire, etc.) restent intactes.

DELETE FROM specialties WHERE slug = 'chirurgie';
