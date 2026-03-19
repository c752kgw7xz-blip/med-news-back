-- Migration 120 — Backfill source_type complet sur items existants
-- Applique le mapping SOURCE_TO_TYPE pour tous les items en base.
-- La migration 110 avait déjà backfillé has_rbp → recommandation.
-- Cette migration couvre toutes les autres sources connues.

-- Sources réglementaires (DEFAULT = 'reglementaire', mais on force pour clarté)
UPDATE items
SET source_type = 'reglementaire'
WHERE source_type = 'reglementaire'
  AND candidate_id IN (
    SELECT id FROM candidates
    WHERE source IN (
      'legifrance_jorf',
      'legifrance_kali',
      'ansm_alertes',
      'ansm_ruptures',
      'has_alertes',
      'bo_sante',
      'bo_social'
    )
  );

-- Sources recommandation
UPDATE items
SET source_type = 'recommandation'
WHERE candidate_id IN (
    SELECT id FROM candidates
    WHERE source IN (
      'has_rbp',
      'has_fiches_memo',
      'has_parcours',
      'academie_medecine',
      'sfc_recommandations',
      'sfmu_recommandations',
      'sfp_recommandations',
      'sofcot_recommandations',
      'cngof_recommandations'
    )
  );

-- Sources thérapeutiques
UPDATE items
SET source_type = 'therapeutique'
WHERE candidate_id IN (
    SELECT id FROM candidates
    WHERE source IN (
      'ansm_bon_usage'
    )
  );

-- Sources formation (aucune encore active, préparé pour la suite)
UPDATE items
SET source_type = 'formation'
WHERE candidate_id IN (
    SELECT id FROM candidates
    WHERE source IN (
      'dpc_replays',
      'ogdpc_formations'
    )
  )
