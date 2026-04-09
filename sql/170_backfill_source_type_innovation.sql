-- Migration 170 — Backfill source_type='innovation' pour les items existants
-- Couvre les 23 sources de la section Innovation :
--   • ema_new_medicines (EMA nouvelles AMM)
--   • 12 revues JAMA spécialisées + JAMA Network Open
--   • 4 revues médicales généralistes (NEJM, Lancet, BMJ, Nature Medicine)
--   • 6 revues paramédicales (Clinical Chemistry, PTJ, BJOG, CPT, JDR, JAN)

UPDATE items
SET source_type = 'innovation'
WHERE source_type != 'innovation'
  AND candidate_id IN (
    SELECT id FROM candidates
    WHERE source IN (
      -- EMA
      'ema_new_medicines',
      -- JAMA Network (Silverchair)
      'jama',
      'jama_cardiology',
      'jama_dermatology',
      'jama_internal_med',
      'jama_neurology',
      'jama_oncology',
      'jama_ophthalmology',
      'jama_otolaryngology',
      'jama_pediatrics',
      'jama_psychiatry',
      'jama_surgery',
      'jama_network_open',
      -- Revues généralistes haut-volume
      'nejm',
      'lancet',
      'bmj',
      'nature_medicine',
      -- Paramédical
      'clinical_chemistry',
      'ptj_kine',
      'bjog',
      'cpt_pharmacol',
      'jdr_dental',
      'jan_nursing'
    )
  );
