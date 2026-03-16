-- 080_complete_specialties.sql
-- Ajoute toutes les spécialités référencées dans KNOWN_SPECIALTIES (llm_analysis.py)
-- mais absentes des migrations précédentes.
-- Idempotent : ON CONFLICT DO NOTHING

INSERT INTO specialties (slug, name) VALUES
  -- Spécialités médicales manquantes
  ('medecine-interne',      'Médecine interne'),
  ('medecine-urgences',     'Médecine d''urgences'),
  ('geriatrie',             'Gériatrie'),
  ('medecine-physique',     'Médecine physique et réadaptation'),
  ('oncologie',             'Oncologie'),
  ('hematologie',           'Hématologie'),
  ('infectiologie',         'Infectiologie'),
  ('nephrologie',           'Néphrologie'),
  ('radiologie',            'Radiologie'),
  ('anesthesiologie',       'Anesthésiologie'),
  -- Chirurgie (sous-spécialités)
  ('chirurgie-vasculaire',  'Chirurgie vasculaire'),
  ('chirurgie-orthopedique','Chirurgie orthopédique'),
  ('chirurgie-thoracique',  'Chirurgie thoracique'),
  ('chirurgie-plastique',   'Chirurgie plastique'),
  ('neurochirurgie',        'Neurochirurgie'),
  ('chirurgie-pediatrique', 'Chirurgie pédiatrique'),
  ('chirurgie-cardiaque',   'Chirurgie cardiaque'),
  -- Paramédicaux
  ('infirmiers',            'Infirmiers'),
  ('kinesitherapie',        'Kinésithérapie'),
  ('sage-femme',            'Sage-femme'),
  ('biologiste',            'Biologie médicale')
ON CONFLICT (slug) DO NOTHING;
