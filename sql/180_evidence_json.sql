-- Migration 180 : colonne evidence_json dans items
--
-- Stocke les métadonnées de maturité clinique extraites par le LLM pour les
-- articles de journaux scientifiques (sources innovation : JVS, EJVES, JET,
-- JAMA, NEJM, Lancet, BMJ, etc.).
--
-- Champs clés :
--   clinical_maturity     : exploratory | preliminary | pivotal | confirmatory |
--                           practice-defining | regulatory-event
--   actionability_horizon : immediate | 1-3y | 3-5y | exploratory
--   study_design          : RCT | meta-analysis | registry | ...
--   paradigm_shift        : true si contredit un guideline établi
--   negative_result       : true si endpoint primaire non atteint
--   safety_signal         : true si nouveau signal de sécurité
--
-- NULL pour les candidats non-innovation (réglementaire, recommandation).

ALTER TABLE items
    ADD COLUMN IF NOT EXISTS evidence_json JSONB;

-- Index partiel sur clinical_maturity pour filtrage portail / newsletter
CREATE INDEX IF NOT EXISTS idx_items_clinical_maturity
    ON items ((evidence_json->>'clinical_maturity'))
    WHERE evidence_json IS NOT NULL;

-- Index partiel sur actionability_horizon pour tri par urgence pratique
CREATE INDEX IF NOT EXISTS idx_items_actionability_horizon
    ON items ((evidence_json->>'actionability_horizon'))
    WHERE evidence_json IS NOT NULL;

-- Index partiel sur les signaux critiques (paradigm_shift et safety_signal)
-- Seuls les vrais positifs sont indexés (performance)
CREATE INDEX IF NOT EXISTS idx_items_paradigm_shift
    ON items ((evidence_json->>'paradigm_shift'))
    WHERE evidence_json IS NOT NULL
      AND evidence_json->>'paradigm_shift' = 'true';

CREATE INDEX IF NOT EXISTS idx_items_safety_signal
    ON items ((evidence_json->>'safety_signal'))
    WHERE evidence_json IS NOT NULL
      AND evidence_json->>'safety_signal' = 'true';
