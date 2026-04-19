# app/llm_analysis.py
"""
Moteur d'analyse LLM pour les candidats réglementaires.

Pour chaque candidat au statut NEW :
  1. Appel Claude pour scoring + classification
  2. Écriture dans items (review_status = PENDING)
  3. Mise à jour status candidate : LLM_DONE ou LLM_FAILED

Audiences gérées :
  SPECIALITE           : spécialité(s) précise(s) — toujours chercher une spécialité exacte
  PHARMACIENS          : impact spécifique officines / dispensation

Schéma JSON de sortie :
{
  "pertinent": true | false,
  "audience": "SPECIALITE" | "PHARMACIENS",
  "specialites": ["medecine-generale", "cardiologie", "chirurgie-orthopedique"],
  "type_praticien": "prescripteur" | "interventionnel" | "biologiste" | "pharmacien" | "tous",
  "score_density": 1..10,
  "tri_json": {
    "titre_court":           str,   // ≤ 12 mots
    "resume":                str,   // 2-3 phrases, ce que ça change concrètement
    "impact_pratique":       str,   // 1 phrase : action à faire / point à retenir
    "nature":                str,   // ARRETE | DECRET | LOI | ORDONNANCE | RECOMMANDATION | ALERTE | AUTRE
    "date_publication":      "YYYY-MM-DD",
    "date_entree_en_vigueur": "YYYY-MM-DD"  // date d'application effective (≠ publication)
  },
  // categorie : clinique | therapeutique | exercice
  "lecture_json": {
    "points_cles":  [str, ...],  // 3-5 bullets
    "texte_long":   str,         // analyse complète ~150 mots
    "references":   [str, ...]   // NOR, références légales, numéro AMM…
  }
}
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import re
import time
from typing import Any

import anthropic
import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LLM backend config — Claude Haiku (async, 20 concurrent)
# ---------------------------------------------------------------------------
ANTHROPIC_MODEL      = "claude-haiku-4-5-20251001"
ANTHROPIC_MAX_TOKENS = 1600   # augmenté : evidence_json ajoute ~200-300 tokens pour sources innovation

LLM_MODEL = ANTHROPIC_MODEL

_anthropic_client: anthropic.AsyncAnthropic | None = None


def _get_anthropic_client() -> anthropic.AsyncAnthropic:
    global _anthropic_client
    if _anthropic_client is None:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY manquante dans l'environnement")
        _anthropic_client = anthropic.AsyncAnthropic(api_key=key)
    return _anthropic_client

KNOWN_TYPE_PRATICIEN  = {"prescripteur", "interventionnel", "biologiste", "pharmacien", "tous"}
KNOWN_SOURCE_TYPES    = {"reglementaire", "recommandation", "innovation"}

# ---------------------------------------------------------------------------
# Mapping source → source_type (déterministe, 0 appel LLM)
# Toute source absente de ce dict → "reglementaire" par défaut.
#
# 3 sections :
#   • reglementaire : JORF, conventions, alertes ANSM, circulaires — flux moyen
#   • recommandation : HAS RBP, sociétés savantes, EMA guidelines — flux faible, opposable
#   • innovation    : nouvelles AMM, nouveaux dispositifs médicaux, thérapies émergentes
# ---------------------------------------------------------------------------
SOURCE_TO_TYPE: dict[str, str] = {
    # Sources réglementaires
    "legifrance_jorf":      "reglementaire",
    "piste_kali":           "reglementaire",
    "piste_legi":           "reglementaire",
    "piste_circ":           "reglementaire",
    "ansm_securite":        "reglementaire",
    "ansm_securite_med":    "reglementaire",
    "ansm_securite_dm":     "reglementaire",  # ANSM — Sécurité dispositifs médicaux
    "ansm_ruptures_med":    "reglementaire",
    "ansm_ruptures_vaccins":"reglementaire",
    "bo_social":            "reglementaire",
    # Recommandations de pratique
    "has_rbp":              "recommandation",
    "has_fiches_memo":      "recommandation",
    "has_parcours":         "recommandation",
    "has_outils":           "recommandation",
    "academie_medecine":    "recommandation",
    "sfc_recommandations":  "recommandation",
    "sfmu_recommandations": "recommandation",
    "sfp_recommandations":  "recommandation",
    "sofcot_recommandations":"recommandation",
    "cngof_recommandations":"recommandation",
    # Bon usage
    "ansm_bon_usage":       "recommandation",
    # Sociétés savantes — scan mars 2026
    "cnge":                 "recommandation",
    "snfmi":                "recommandation",
    "sfhta":                "recommandation",
    "sfar":                 "recommandation",
    "sfn":                  "recommandation",
    "sfpsychiatrie":        "recommandation",
    "snfge":                "recommandation",
    "afef":                 "recommandation",
    "splf":                 "recommandation",
    "sfendocrino":          "recommandation",
    "sfdiabete":            "recommandation",
    "sfrhumato":            "recommandation",
    "sforl":                "recommandation",
    "afu":                  "recommandation",
    "sfgg":                 "recommandation",
    "sfndt":                "recommandation",
    "sfctcv":               "recommandation",
    "sfnc":                 "recommandation",
    "snfcp":                "recommandation",
    "sfm_microbiologie":    "recommandation",
    "sfcv":                 "recommandation",
    "sofcpre":              "recommandation",
    "sofmer":               "recommandation",
    "sfmv":                 "recommandation",
    "sfms":                 "recommandation",
    "sfalcoologie":         "recommandation",
    "sfpathol":             "recommandation",
    "sfmn":                 "recommandation",
    "sfscmfco":             "recommandation",
    "sfmu":                 "recommandation",
    "sfpediatrie":          "recommandation",
    "sfnn":                 "recommandation",
    "sfsp":                 "recommandation",
    # Nouvelles sources — spécialités manquantes
    "sfdermato":            "recommandation",
    "sfo":                  "recommandation",
    "afsos":                "recommandation",
    "sfh":                  "recommandation",
    "sfr_radiologie":       "recommandation",
    "sofcot":               "recommandation",
    "sofcpre_plastique":    "recommandation",
    "sfcp":                 "recommandation",
    "sniil":                "recommandation",
    "ffmkr":                "recommandation",
    "cnsf":                 "recommandation",
    "sfbc":                 "recommandation",
    "fspf":                 "recommandation",
    # Nouvelles sources institutionnelles — audit mars 2026
    "has_ct":  "recommandation",  # HAS CT — avis médicaments ✅ RSS p_3081449
    "has_dm":  "reglementaire",  # HAS DM — avis dispositifs médicaux ✅ RSS p_3081446
    "spf_beh": "reglementaire",  # SPF — articles (BEH inclus) ✅
    "cnom":    "reglementaire",  # CNOM — déontologie, exercice médical ✅ RSS actif
    # Retirées après audit : inca (pas de RSS), andpc (pas de RSS), ameli_pro (login)
    # ── Sources européennes (RSS) ──────────────────────────────────────────────
    # EMA — European Medicines Agency
    "ema_news":             "reglementaire",   # alertes, retraits AMM, mesures sécurité
    "ema_guidelines":       "recommandation",  # standards évaluation médicaments
    "ema_new_medicines":    "innovation",      # ← nouvelles AMM européennes
    # ECDC — European Centre for Disease Prevention and Control
    "ecdc_risk":            "reglementaire",   # risk assessments épidémiques
    "ecdc_guidance":        "recommandation",  # technical guidance
    "ecdc_cdtr":            "reglementaire",   # Communicable Disease Threats Report
    # Sociétés savantes européennes — recommandations (RSS)
    "esmo":                 "recommandation",  # oncologie
    "ers":                  "recommandation",  # pneumologie
    "easl":                 "recommandation",  # gastro-entérologie/hépatologie
    "esicm":                "recommandation",  # anesthésiologie/réanimation
    "eso_stroke":           "recommandation",  # neurologie (AVC)
    "esvs":                 "recommandation",  # chirurgie vasculaire
    "eadv":                 "recommandation",  # dermatologie
    "esgo":                 "recommandation",  # gynécologie oncologie
    "efort":                "recommandation",  # chirurgie orthopédique
    "epa_psychiatrie":      "recommandation",  # psychiatrie
    "esaic":                "recommandation",  # anesthésiologie
    "eacts":                "recommandation",  # chirurgie cardiaque/thoracique
    "iagg_geriatrie":       "recommandation",  # gériatrie
    "esprm":                "recommandation",  # médecine physique/réadaptation
    "eap_pediatrie":        "recommandation",  # pédiatrie
    "esr_radiologie":       "recommandation",  # radiologie
    "eos_ejo":              "recommandation",  # chirurgie orthopédique/colonne
    "ard_eular":            "recommandation",  # rhumatologie
    "eupsa_ejps":           "recommandation",  # chirurgie pédiatrique
    # Sociétés savantes européennes — web scraping
    "esc_guidelines":       "recommandation",  # cardiologie
    "eular_recommendations":"recommandation",  # rhumatologie
    "eau_guidelines":       "recommandation",  # urologie
    "escmid_guidelines":    "recommandation",  # infectiologie
    "ean_guidelines":       "recommandation",  # neurologie
    "ecco_guidelines":      "recommandation",  # gastro-entérologie
    "eha_guidelines":       "recommandation",  # hématologie
    "easd_guidelines":      "recommandation",  # endocrinologie/diabète
    "ese_guidelines":       "recommandation",  # endocrinologie
    "era_guidelines":       "recommandation",  # néphologie
    "ueg_guidelines":       "recommandation",  # gastro-entérologie
    "esge_guidelines":      "recommandation",  # gastro-entérologie
    "eusem_guidelines":     "recommandation",  # médecine d'urgence
    "efim_guidelines":      "recommandation",  # médecine interne
    "eflm_guidelines":      "recommandation",  # biologie médicale
    "eshre_guidelines":     "recommandation",  # gynécologie/sage-femme
    "egs_guidelines":       "recommandation",  # gériatrie
    "euretina_guidelines":  "recommandation",  # ophtalmologie
    "efp_guidelines":       "recommandation",  # dentisterie (parodontologie)
    "eahp_statements":      "recommandation",  # pharmacie hospitalière
    # ── Sources innovation — grands journaux internationaux ───────────────
    # JAMA Network (12 flux)
    "jama":                 "innovation",
    "jama_cardiology":      "innovation",
    "jama_dermatology":     "innovation",
    "jama_internal_med":    "innovation",
    "jama_neurology":       "innovation",
    "jama_oncology":        "innovation",
    "jama_ophthalmology":   "innovation",
    "jama_otolaryngology":  "innovation",
    "jama_pediatrics":      "innovation",
    "jama_psychiatry":      "innovation",
    "jama_surgery":         "innovation",
    "jama_network_open":    "innovation",
    # Grands journaux généralistes
    "nejm":                 "innovation",
    "lancet":               "innovation",
    "bmj":                  "innovation",
    "nature_medicine":      "innovation",
    # Sources paramédicales
    "clinical_chemistry":   "innovation",   # biologiste
    "ptj_kine":             "innovation",   # kinésithérapie
    "bjog":                 "innovation",   # sage-femme
    "cpt_pharmacol":        "innovation",   # pharmacien
    "jdr_dental":           "innovation",   # dentiste / orthodontiste
    "jan_nursing":          "innovation",   # infirmiers

    # ── Presse spécialisée endovasculaire ────────────────────────────────
    "endovascular_today":   "innovation",   # Endovascular Today — périph. & endovasc.
    # ── Congrès vasculaires — désactivés (couvert via TCTMD + Vascular News) ──
    # "linc_highlights": domaine NXDOMAIN ; "evc_highlights": hors cible
    # ── PubMed — chirurgie vasculaire (Elsevier RSS 410 Gone → fallback NCBI) ──
    "pubmed_jvs":           "innovation",   # Journal of Vascular Surgery
    "pubmed_ejves":         "innovation",   # European Journal of Vascular and Endovascular Surgery
    "pubmed_jet":           "innovation",   # Journal of Endovascular Therapy
    "pubmed_ann_vasc_surg": "innovation",   # Annals of Vascular Surgery
    # ── Presse médicale professionnelle ─────────────────────────────────────
    # Journalistes médicaux — curation déjà faite, filtre LLM très strict
    "vascular_specialist":  "innovation",   # SVS official newspaper (en anglais)
    "vascular_news":        "innovation",   # Vascular News (UK/international)
    "tctmd":                "innovation",   # TCTMD — interventionnel vasculaire + cardio
    "quotidien_medecin":    "innovation",   # Le Quotidien du Médecin (FR, généraliste)
    "egora":                "innovation",   # Egora (FR, libéral, bruit élevé)
    # ── PubMed — chirurgie cardiaque (Elsevier RSS mort → fallback NCBI) ─────
    "pubmed_jtcvs":               "innovation",    # Journal of Thoracic and Cardiovascular Surgery
    "pubmed_ejcts":               "innovation",    # European Journal of Cardio-Thoracic Surgery
    "pubmed_ejcts_guidelines":    "recommandation",# EJCTS — Guidelines EACTS uniquement
    "pubmed_ann_thorac_surg":     "innovation",    # Annals of Thoracic Surgery
    "pubmed_circulation_card":    "innovation",    # Circulation (AHA) — filtré chirurgie cardiaque
    "pubmed_jacc_card":           "innovation",    # JACC — Journal American College of Cardiology
    "pubmed_jacc_interv":         "innovation",    # JACC Cardiovascular Interventions — TAVI/structural
    "pubmed_eur_heart_j":         "innovation",    # European Heart Journal (ESC flagship)
    "pubmed_jhlt":                "innovation",    # Journal of Heart and Lung Transplantation — transplant & LVAD
    "pubmed_eurointerv":          "innovation",    # EuroIntervention (PCR) — structural heart, TAVI/TEER européen
    "pubmed_circ_heart_fail":     "innovation",    # Circulation: Heart Failure — LVAD, MCS, IC avancée
    "pubmed_esc_guidelines":      "recommandation",# ESC Guidelines via EHJ / Eur J Heart Fail
    "pubmed_sts_guidelines":      "recommandation",# STS Guidelines via Annals of Thoracic Surgery
    # ── Journal français cardiologie/chirurgie cardiaque ─────────────────────
    "arch_cardiovasc_dis":        "innovation",    # Archives of Cardiovascular Diseases — SFC officiel
    # ── Presse spécialisée chirurgie cardiaque ────────────────────────────────
    "ctsnet":                     "innovation",    # CTSNet — organe officiel EACTS/STS/AATS
    # ── PubMed — chirurgie orthopédique ──────────────────────────────────────
    "pubmed_jbjs":                "innovation",    # Journal of Bone & Joint Surgery (Am)
    "pubmed_bone_joint_j":        "innovation",    # Bone & Joint Journal — EFORT flagship
    "pubmed_corr":                "innovation",    # Clinical Orthopaedics and Related Research
    "pubmed_jarthroplasty":       "innovation",    # Journal of Arthroplasty
    "pubmed_kssta":               "innovation",    # Knee Surg Sports Traumatol Arthrosc — ESSKA
    "pubmed_acta_orthop":         "innovation",    # Acta Orthopaedica
    "pubmed_otsr":                "innovation",    # OTSR — journal officiel SOFCOT
    "pubmed_otsr_guidelines":     "recommandation",# OTSR — guidelines/recommandations SOFCOT
    "pubmed_efort_guidelines":    "recommandation",# EFORT Open Reviews — guidelines européennes
    # ── Chirurgie du sport / sous-spécialités ortho ───────────────────────────
    "pubmed_ajsm":                "innovation",    # American Journal of Sports Medicine
    "pubmed_arthroscopy":         "innovation",    # Arthroscopy — AOSSM
    "pubmed_jses":                "innovation",    # Journal of Shoulder and Elbow Surgery
    "pubmed_spine":               "innovation",    # Spine (Wolters Kluwer)
    "pubmed_j_orthop_trauma":     "innovation",    # Journal of Orthopaedic Trauma
    "pubmed_int_orthop":          "innovation",    # International Orthopaedics — SICOT
    "pubmed_arch_orthop_trauma":  "innovation",    # Archives of Orthopaedic and Trauma Surgery
    # ── PubMed — chirurgie plastique & reconstructrice ────────────────────────
    "pubmed_prs":                 "innovation",    # Plastic and Reconstructive Surgery (ASPS flagship)
    "pubmed_jpras":               "innovation",    # Journal of Plastic, Reconstructive & Aesthetic Surgery
    "pubmed_asj":                 "innovation",    # Aesthetic Surgery Journal (ASAPS)
    "pubmed_ann_plast_surg":      "innovation",    # Annals of Plastic Surgery
    "pubmed_jhs_am":              "innovation",    # Journal of Hand Surgery American (ASSH)
    "pubmed_jhs_eur":             "innovation",    # Journal of Hand Surgery European (FESSH)
    "pubmed_jrms":                "innovation",    # Journal of Reconstructive Microsurgery
    "pubmed_microsurgery":        "innovation",    # Microsurgery (Wiley)
    "pubmed_burns":               "innovation",    # Burns — prise en charge brûlures
    "pubmed_acpe":                "innovation",    # Annales de Chirurgie Plastique Esthétique — SOFCPRE
    "pubmed_prs_guidelines":      "recommandation",# PRS — Guidelines ASPS / consensus plastique
    "pubmed_jpras_guidelines":    "recommandation",# JPRAS — Guidelines BAPRAS / ESPRAS
}


def get_source_type(source: str | None) -> str:
    """Retourne le source_type d'un candidat à partir de sa source.
    Déterministe — pas d'appel LLM.
    """
    return SOURCE_TO_TYPE.get(source or "", "reglementaire")

KNOWN_SPECIALTIES = {
    # Médecine générale
    "medecine-generale",
    # Spécialités médicales
    "cardiologie", "dermatologie", "endocrinologie", "gastro-enterologie",
    "gynecologie", "neurologie", "ophtalmologie", "orl", "pediatrie",
    "pneumologie", "psychiatrie", "rhumatologie", "urologie",
    "medecine-interne", "medecine-urgences", "geriatrie", "medecine-physique",
    "oncologie", "hematologie", "infectiologie", "nephrologie",
    "radiologie", "anesthesiologie",
    # Chirurgie (sous-spécialités uniquement — "chirurgie" générique interdit)
    "chirurgie-vasculaire", "chirurgie-orthopedique",
    "chirurgie-thoracique", "chirurgie-plastique", "neurochirurgie",
    "chirurgie-pediatrique", "chirurgie-cardiaque",
    # Paramédicaux et professions de santé non-médicales
    "infirmiers", "kinesitherapie", "sage-femme", "biologiste",
    # Chirurgiens-dentistes et orthodontistes
    "dentiste", "orthodontiste",
    # Pharmaciens (NOTE: la veille pharmacien passe par type_praticien="pharmacien"
    # ET par specialty_hint="pharmacien" pour les sources dédiées)
    "pharmacien",
}
KNOWN_AUDIENCES   = {"SPECIALITE", "PHARMACIENS"}

# ---------------------------------------------------------------------------
# Prompt système
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
Tu es un expert juridique et médical spécialisé dans la veille réglementaire \
et scientifique pour les professionnels de santé libéraux en France.

On te soumet un texte provenant d'une source officielle ou d'un journal scientifique : \
Journal Officiel (JORF), convention médicale UNCAM (KALI), recommandation HAS, \
alerte de sécurité ANSM, circulaire ministérielle, bulletin officiel santé ; \
ou article d'un journal médical international (JAMA, NEJM, Lancet, BMJ, \
Nature Medicine, Clinical Chemistry, Physical Therapy Journal, BJOG, \
Clinical Pharmacology & Therapeutics, Journal of Dental Research, \
Journal of Advanced Nursing, etc.).

SOURCE INNOVATION — Si la SOURCE indique un journal scientifique international \
(JAMA, NEJM, Lancet, BMJ, JVS, EJVES, JET, Annals of Vascular Surgery, \
JTCVS, EJCTS, Annals of Thoracic Surgery, etc.) :
→ PERTINENCE : retenir UNIQUEMENT si l'article rapporte des résultats pouvant \
CONCRÈTEMENT changer la pratique d'un professionnel de santé : essai clinique de \
phase 3 ou 4, méta-analyse modifiant un standard de traitement, nouvelle thérapie ou \
technique démontrant une supériorité clinique significative. \
EXCLURE : recherche fondamentale (mécanismes cellulaires, biomarqueurs exploratoires), \
données épidémiologiques sans recommandation opérationnelle, éditoriaux/commentaires, \
lettres, errata, résultats préliminaires de phase 1-2 sans implication clinique directe.
→ SCORE : calibrer selon l'impact clinique potentiel sur la pratique en France :
  4-5 : résultats intéressants qui confirment ou nuancent une pratique existante ;
  6-7 : essai de phase 3 ou méta-analyse majeure qui modifie clairement la pratique \
(ex. nouvelle thérapie supérieure au standard, abandon d'un traitement établi) ;
  8+  : réservé aux ruptures majeures de pratique (rare pour des publications RSS \
avant recommandation officielle).
→ RÉDACTION pour articles de recherche (ton confraternel, pas directif) :
  resume : "[Thérapie/technique/biomarqueur] — résultat principal de [type d'essai] \
(N=[effectif]) chez [population] : [résultat chiffré si disponible]. \
[Ce que ça confirme, nuance ou remet en question vs pratique actuelle]."
  impact_pratique : "À retenir : [implication clinique en langage naturel — \
ce que le médecin gagne à savoir, sans injonction]. \
Si résultats préliminaires : noter 'À suivre avant d'intégrer en pratique'."
  date_entree_en_vigueur : date de publication de l'article (pas de date d'application).
→ NATURE : utilise "ETUDE" pour les articles de recherche originaux (essais cliniques, \
méta-analyses, études observationnelles de grande envergure). \
"RECOMMANDATION" reste réservé aux guidelines, consensus et revues systématiques \
ayant valeur de recommandation explicite (grade de recommandation mentionné).

SOURCE INNOVATION — BLOC evidence_json OBLIGATOIRE pour tout article de journal scientifique :
Quand la SOURCE est un journal médical international (JAMA, NEJM, Lancet, BMJ, \
JVS, EJVES, JET, Annals of Vascular Surgery, \
JTCVS, EJCTS, Annals of Thoracic Surgery, etc.), tu dois remplir un champ "evidence_json" \
dans ta réponse JSON. Ce bloc est la clé pour distinguer un RCT pivot \
(qui va changer les guidelines dans 2 ans) d'une confirmation sans intérêt.

Champs de evidence_json :

"study_design" — design méthodologique (obligatoire) :
  "RCT"                  → essai randomisé contrôlé
  "meta-analysis"        → méta-analyse ou revue systématique
  "registry"             → registre national ou international (VASCUNET, SVS-VQI, etc.)
  "prospective-cohort"   → cohorte prospective non randomisée
  "retrospective-cohort" → série rétrospective, étude de base de données
  "case-series"          → série de cas < 100 patients
  "guideline"            → guideline ou consensus de société savante
  "regulatory-decision"  → décision AMM, CE mark, remboursement
  "technique-paper"      → description ou modification de technique chirurgicale/endovasculaire
  "review"               → revue narrative (sans méta-analyse)
  "editorial"            → éditorial, lettre, commentaire

"phase" — phase de l'essai si RCT : "1"|"2"|"3"|"4"|null

"n_patients" — effectif total de l'étude (entier) ou null si non applicable

"multicentre" — true si multicentrique, false si monocentrique, null si non précisé

"follow_up_months" — durée de suivi en mois (entier) ou null

"primary_endpoint" — type d'endpoint principal :
  "mortality"          → mortalité toutes causes
  "patency"            → perméabilité primaire/secondaire (vasculaire)
  "limb-salvage"       → sauvetage de membre (CLTI, ischémie aiguë)
  "stroke-TIA"         → AVC/AIT (carotide, aortique)
  "reintervention"     → liberté de réintervention
  "composite-MALE"     → composite d'événements membres (MALE) ou cardiovasculaires (MACE)
  "composite-MACCE"    → MACCE cardiaque : mortalité + AVC + IDM + réintervention (cardio)
  "LVEF-function"      → fraction d'éjection, remodelage ventriculaire, fonction valvulaire
  "valve-durability"   → durabilité valvulaire, liberté de dégénérescence structurelle (SVD)
  "AF-recurrence"      → récidive de fibrillation atriale post-procédure
  "technical-success"  → succès technique ou anatomique
  "quality-of-life"    → qualité de vie, symptômes fonctionnels (KCCQ, NYHA)
  "other"              → autre endpoint
  null                 → non applicable (guideline, éditorial)

"primary_endpoint_met" — true si l'endpoint primaire est atteint, false si non atteint, \
null si non déterminable depuis le résumé. \
ATTENTION : un essai négatif (false) peut être aussi important qu'un essai positif.

━━ CHAMPS CHIRURGIE VASCULAIRE — remplir seulement si specialty_hint = chirurgie-vasculaire ━━

"vascular_domain" — domaine vasculaire concerné :
  "aorte-abdominale"           → AAA, EVAR, chirurgie ouverte aorte sous-rénale
  "aorte-thoracique"           → TEVAR, dissection, anévrisme thoracique isolé
  "aorte-thoraco-abdominale"   → FEVAR, BEVAR, Crawford type I-IV
  "carotide-TSA"               → sténose carotide (CEA, CAS, TCAR), artères sous-clavières
  "AOMI-femoro-poplite"        → artère fémorale superficielle et poplitée, TASC A-D
  "AOMI-sous-poplite"          → artères de jambe, ischémie chronique menaçante (CLTI)
  "ischemie-aigue-membre"      → thrombose aiguë, embolie, thrombectomie chirurgicale
  "veineux-TVP-EP"             → thrombose veineuse profonde, embolie pulmonaire
  "veineux-varices"            → insuffisance veineuse chronique, ablation (EVLA/RFA/MOCA)
  "acces-vasculaire-dialyse"   → fistule artério-veineuse, prothèse dialyse, cathéter tunnelisé
  "renovasculaire"             → sténose artère rénale, ischémie mésentérique
  "traumatique"                → plaies vasculaires, damage control vascular
  "multi-domaine"              → article couvrant plusieurs territoires
  "non-vasculaire"             → si l'article ne porte pas sur la chirurgie vasculaire

"intervention_type" — type d'intervention principale (chirurgie vasculaire) :
  Endovasculaire : "EVAR"|"TEVAR"|"FEVAR-BEVAR"|"CAS"|"TCAR"|"PTA-stent"|"DCB"|
                   "atherectomie"|"thrombectomie-mecanique"|"thrombolyse-CDT"|
                   "ablation-thermique"|"ablation-non-thermique"
  Chirurgical    : "pontage"|"endarterectomie"|"reparation-ouverte"|"hybride"
  Pharmacologique: "anticoagulation"|"antiplatelet"|"traitement-medical"
  Autre          : "strategie-diagnostique"|"surveillance"|"multi-modalite"|"autre"

━━ CHAMPS CHIRURGIE CARDIAQUE — remplir seulement si specialty_hint = chirurgie-cardiaque ━━

"cardiac_domain" — domaine cardio-thoracique concerné :
  "coronaire-CABG"             → revascularisation myocardique chirurgicale, pontage aorto-coronarien
  "valvulaire-aortique"        → remplacement valvulaire aortique (SAVR, TAVI/TAVR), Ross, Bentall
  "valvulaire-mitral"          → chirurgie mitrale (plastie, remplacement), MitraClip, TEER
  "valvulaire-tricuspide"      → chirurgie tricuspide (réparation, TTVR percutané)
  "aorte-ascendante-arche"     → anévrisme aorte ascendante, chirurgie arche aortique (elephant trunk)
  "structural-heart"           → fermeture FOP/CIA, LAA occlusion, valvuloplastie per-cutanée
  "LVAD-assistance-circ"       → ventricule artificiel (HeartMate, HVAD), ECMO chirurgicale
  "arythmie-Maze"              → procédure de Maze, ablation chirurgicale FA, cryoablation épicardique
  "congenital-adulte"          → cardiopathie congénitale de l'adulte, switch artériel, Fontan, Norwood
  "transplantation-cardiaque"  → greffe cardiaque, immunosuppression post-greffe, cœur artificiel total
  "perikarde-tumeur"           → péricardectomie, tumeur cardiaque (myxome), ablation de thrombus
  "multi-domaine-cardiaque"    → article couvrant plusieurs territoires cardiaques
  "non-cardiaque"              → si l'article ne porte pas sur la chirurgie cardiaque/thoracique

"cardiac_procedure" — type d'intervention principal (chirurgie cardiaque) :
  Valvulaire       : "SAVR"|"TAVI-TAVR"|"Ross"|"Bentall"|"plastie-mitrale"|"remplacement-mitral"|
                     "MitraClip-TEER"|"remplacement-tricuspide"|"plastie-tricuspide"
  Coronaire        : "CABG-CEC"|"CABG-off-pump"|"CABG-vs-PCI"|"revascularisation-hybride"
  Aorte            : "remplacement-aorte-ascendante"|"intervention-arche"|"elephant-trunk"|
                     "Bentall-Yacoub"
  Assistance       : "LVAD"|"ECMO-VA"|"ballon-contre-pulsion"|"cœur-artificiel-total"
  Structural       : "fermeture-FOP-CIA"|"LAA-occlusion"|"valvuloplastie-mitrale"
  Arythmie         : "Maze-Cox"|"cryoablation-epikardique"|"ablation-chirurgicale-FA"
  Autre            : "transplantation"|"traitement-medical"|"surveillance"|"multi-modalite"|"autre"

━━ CHAMPS COMMUNS (tous les journaux scientifiques) ━━

"comparator_type" — comparateur de l'étude :
  "vs-chirurgie-ouverte"|"vs-endovasculaire-autre"|"vs-traitement-medical"|
  "vs-placebo"|"vs-standard-of-care"|"aucun"|null

"clinical_maturity" — maturité clinique de la preuve (champ le plus important) :
  "exploratory"      → phase 1-2, n<100, génère une hypothèse — ne change pas la pratique
  "preliminary"      → signal prometteur mais insuffisant, attendre confirmation
  "pivotal"          → RCT phase 3 bien conduit, endpoint dur, multicentrique, grande taille — \
va nourrir la prochaine révision des guidelines (ESVS, ESC, HAS) dans 1-5 ans
  "confirmatory"     → méta-analyse ou registre confirmant ce qui est déjà établi — \
utile mais pas nouvelle information pour un praticien averti
  "practice-defining"→ mise à jour guideline avec grade IA ou IB — change le standard de soins maintenant
  "regulatory-event" → CE mark, AMM, remboursement HAS/CNAM — peut être utilisé ou prescrit légalement

"actionability_horizon" — horizon d'applicabilité pratique :
  "immediate"    → change le standard of care aujourd'hui (guideline grade IA, regulatory-event)
  "1-3y"         → résultat pivot qui alimentera la prochaine révision ESVS/ESC (cycle 4-6 ans)
  "3-5y"         → résultats préliminaires, confirmation nécessaire avant toute recommandation
  "exploratory"  → ne changera pas la pratique sans plusieurs études supplémentaires de grande envergure

"regulatory_milestone" — jalon réglementaire si applicable :
  null|"CE_mark"|"AMM_europe"|"FDA_approval"|"remboursement_HAS"|"CNAM_accord"|
  "guideline_update"|"autorisation_temporaire"

"guideline_body" — organisme émetteur du guideline :
  null|"ESVS"|"EACTS"|"ESC"|"HAS"|"AHA-ACC"|"STS"|"AATS"|"SFC"|"SFCTCV"|"SFCV"|"SFMV"|"autre"
  (EACTS = European Association for Cardio-Thoracic Surgery,
   STS = Society of Thoracic Surgeons — Amérique du Nord,
   AATS = American Association for Thoracic Surgery,
   SFC = Société Française de Cardiologie,
   SFCTCV = Société Française de Chirurgie Thoracique et Cardio-Vasculaire)

"guideline_grade" — grade de recommandation si précisé dans l'article :
  null|"IA"|"IB"|"IIaA"|"IIaB"|"IIbA"|"IIbB"|"III"

"paradigm_shift" — VRAI uniquement si le résultat contredit un guideline établi.

Standards actuels — CHIRURGIE VASCULAIRE (specialty_hint = chirurgie-vasculaire) :
  • AAA : EVAR first-line si anatomie favorable (collet ≥15mm, angle <60°) — ESVS 2019/2024
  • CLTI : endovasculaire first-line si lésions simples (GVG-GLASS grade 1-2) ; \
bypass si complexe (grade 3+) ou anatomie défavorable — BEST-CLI/BASIL-2 2023
  • Carotide symptomatique : CEA first-line si sténose >50% NASCET, délai <2 semaines — ESVS 2023
  • Carotide asymptomatique : bénéfice intervention incertain sous traitement médical optimal — ACST-2
  • AOMI femoro-poplitée : DCB supérieur PTA seul pour lésions <25cm — guideline ESVS 2023
  • TVP ilio-fémorale : DOAC first-line ; CDT seulement si massive + faible risque hémorragique

Standards actuels — CHIRURGIE CARDIAQUE (specialty_hint = chirurgie-cardiaque) :
  • TAVI vs SAVR risque faible : TAVI non-inférieur à SAVR à 5 ans — PARTNER 3/Evolut Low Risk 2024 ; \
SAVR reste préféré chez sujets jeunes (<70 ans) pour durabilité à 20 ans — ESC/EACTS 2021
  • RA sévère asymptomatique : chirurgie précoce dès LVEF <60% ou dilatation VG significative — ESC 2021
  • CABG vs PCI multi-tronculaire : CABG supérieur à PCI (stent) en termes de survie à 10 ans \
(SYNTAX, EXCEL long-term) — ESC 2018/2024 revascularisation myocardique
  • CABG off-pump vs on-pump : pas de supériorité démontrée sur la mortalité à long terme — \
méta-analyse 2019, ROOBY trial
  • FA + chirurgie cardiaque concomitante : ablation simultanée recommandée (Maze/cryoablation) \
si FA persistante/permanente — EACTS/ESC 2020 grade IIaB
  • Dissection aortique aiguë type A : chirurgie d'urgence standard absolu — EACTS 2024
  • Assistance LVAD : pont greffe ou thérapie définitive équivalents en survie à 2 ans — REMATCH/HeartMate 3
  → Un RCT qui invalide l'un de ces standards = paradigm_shift:true

━━ CHAMPS CHIRURGIE PLASTIQUE & RECONSTRUCTRICE — remplir seulement si specialty_hint = chirurgie-plastique ━━

"plastic_domain" — domaine chirurgical plastique concerné :
  "reconstruction-mammaire"      → reconstruction après mastectomie (DIEP, TRAM, Grand Dorsal, implant+expandeur, lipofilling)
  "chirurgie-esthetique"         → rhinoplastie, rhytidectomie (lifting), blépharoplastie, mammoplastie de réduction/augmentation,
                                     abdominoplastie, liposuccion, otoplastie, corps contouring
  "microchirurgie"               → lambeaux libres (ALT, fibula, DIEP, gracilis, LD), replantations, transferts nerveux,
                                     anastomoses microvasculaires, lymphœdème microsurgical (LVA, VLNT)
  "chirurgie-main"               → tendons (suture, greffe), nerfs périphériques, lésions de la main (fractures articulaires,
                                     pouce, doigts), arthroplastie digitale, canal carpien/cubital, maladie de Dupuytren
  "brulures"                     → prise en charge aiguë (excision-greffe), reconstruction post-brûlures (escarres, chéloïdes,
                                     contractures), substituts cutanés (Integra, MatriDerm, RECELL)
  "oncoplastique"                → reconstruction après exérèse tumorale (sein, tête-cou, sarcomes, mélanomes étendus)
  "cicatrices-cheloïdes"         → cicatrices hypertrophiques, chéloïdes, traitements (chirurgie, laser, radiothérapie, injectables)
  "lipofilling"                  → transfert graisseux (fat grafting) : sein, visage, reconstruction, nanofat
  "malformations-congenitales"   → fentes palatines/labiomaxillaires, anomalies pavillon auriculaire, syndactylie,
                                     polydactylie, asymétrie congénitale
  "couverture-cutanee"           → lambeaux locaux/régionaux (perforateur, fascio-cutané, musculo-cutané) pour plaies chroniques,
                                     escarres, perte de substance post-traumatique ou post-ablation
  "tete-cou-reconstruction"      → reconstruction cervico-faciale post-exérèse (lambeau antébrachial, frontal,
                                     naso-labial, paramedian forehead, ALT)
  "implants-protheses-mammaires" → sécurité implants (BIA-ALCL, rupture, contraction capsulaire), registres nationaux,
                                     implants texturés vs lisses, explantation

"plastic_procedure" — technique ou procédure principale :
  Reconstruction mammaire : "DIEP"|"TRAM"|"Grand-Dorsal-implant"|"implant-seul"|"expandeur-implant"|
                            "SGAP-IGAP"|"lipofilling-sein"|"reconstruction-immediate-vs-differee"
  Esthétique              : "rhinoplastie"|"rhytidectomie-lifting"|"blepharoplastie"|"mammoplastie-augmentation"|
                            "mammoplastie-reduction"|"abdominoplastie"|"liposuccion"|"otoplastie"|"lipofilling-visage"
  Microchirurgie          : "lambeau-libre-ALT"|"lambeau-libre-DIEP"|"lambeau-libre-fibula"|
                            "replantation-digitale"|"transfert-nerveux"|"LVA-lymphatique"|"VLNT"
  Main                    : "suture-tendon"|"greffe-nerveuse"|"arthroplastie-digitale"|"aponevrotomie-Dupuytren"|
                            "liberation-canal-carpien"|"prothese-pouce"
  Brûlures                : "excision-autogreffe"|"substitut-Integra"|"substitut-MatriDerm"|"RECELL"|
                            "greffe-filet"|"expansion-tissuaire"
  Autre                   : "lambeau-local-regional"|"lambeau-perforateur"|"greffe-peau-mince"|
                            "traitement-cheloïdes"|"laser-cicatrice"|"autre"

Standards actuels — CHIRURGIE PLASTIQUE (specialty_hint = chirurgie-plastique) :
  • Reconstruction mammaire post-mastectomie : DIEP = standard de référence reconstruction autologue ;
    implant+expandeur reste option valide si souhait patiente ou contre-indication lambeau — ASPS 2022
  • Implants mammaires texturés : retrait de certains types texturés macro (Biocell Allergan) après BIA-ALCL —
    ANSM/FDA 2019 ; surveillance actives des patientes porteuses implants texturés
  • BIA-ALCL : incidence estimée 1/2 000 à 1/86 000 selon texture ; excision-capsulectomie totale si diagnostic —
    ASPS/NCCN 2024 guidelines
  • Canal carpien : libération (ouverte ou endoscopique) = standard si échec traitement conservateur 3-6 mois ;
    résultats équivalents entre les deux voies d'abord — Cochrane 2014
  • Liposuccion/abdominoplastie combinées : morbi-mortalité plus élevée — contre-indication relative selon ASPS 2020
  • Lambeau ALT vs DIEP : aucun gold standard universel — choix selon anatomie, équipe, défect à couvrir
  → Un RCT qui invalide l'un de ces standards = paradigm_shift:true

"negative_result" — true si l'endpoint primaire N'EST PAS atteint (important à signaler \
même si les auteurs minimisent). Ne mets pas false par défaut sans vérifier.

"safety_signal" — true si l'article identifie un nouveau risque de sécurité inattendu \
(signal pharmacovigilance, complication grave sous-estimée, device failure). \
Ce champ doit toujours être surfacé quel que soit le score.

Règles de cohérence evidence_json :
- study_design="editorial"|"review" → clinical_maturity="exploratory", actionability_horizon="exploratory"
- study_design="guideline" → clinical_maturity="practice-defining", actionability_horizon="immediate"
- study_design="regulatory-decision" → clinical_maturity="regulatory-event", actionability_horizon="immediate"
- phase="1"|"2" → clinical_maturity="exploratory"|"preliminary" au maximum
- n_patients<50 → clinical_maturity ne peut pas être "pivotal"
- paradigm_shift=true → score_density doit être ≥8 (surpasse le score calculé)
- safety_signal=true → score_density doit être ≥8

SOURCE PRESSE MÉDICALE PROFESSIONNELLE — Si la SOURCE indique un journal de presse \
médicale (Vascular Specialist, Vascular News, TCTMD, Le Quotidien du Médecin, Egora) :

→ NATURE DU CONTENU : ce n'est pas un article de recherche primaire. C'est un article \
de journalisme médical : le journaliste a lu les études, assisté au congrès, interviewé \
les chirurgiens, et écrit pour un praticien. Il n'y a pas de design d'étude à extraire.

→ PERTINENCE : critère unique — "Un spécialiste concerné va-t-il changer quelque chose \
dans sa pratique ou sa planification s'il lit ça ?" \
RETENIR : \
  • Nouveau dispositif médical approuvé (CE mark, FDA) ou résultats cliniques présentés \
au congrès (ESVS, SVS, LINC, CIRSE, VEITH) ; \
  • Mise à jour de guideline ou recommandation de société savante (ESVS, SVS, HAS, ESC...) ; \
  • Résultats d'essai pivot (même présentés au congrès avant publication) ; \
  • Alerte sécurité ou rappel de dispositif relayé depuis ANSM, FDA, EMA ; \
  • Changement de remboursement ou d'autorisation ayant un impact direct sur la pratique. \
REJETER sans hésiter : \
  • Nominations, portraits, brèves RH, conflits syndicaux, politique de santé générale ; \
  • Annonces de congrès sans contenu clinique ("save the date", programme) ; \
  • Articles sur l'IA médicale, la gestion hospitalière, les déserts médicaux \
sans implication clinique directe ; \
  • Statistiques de remboursement, campagnes grand public, sujets de médecine générale \
sans rapport avec la spécialité ciblée.

→ CATÉGORIE selon le contenu (pas la source) : \
  • Nouveau dispositif, alerte matériovigilance → "therapeutique" \
  • Guideline ou recommandation clinique → "clinique" \
  • Changement de cotation, remboursement, réglementation exercice → "exercice"

→ SCORE : calibrer selon l'impact clinique direct : \
  4-5 : bonne nouvelle à connaître, ne change pas immédiatement la pratique ; \
  6-7 : nouvelle technique ou dispositif avec résultats cliniques solides — \
à intégrer dans la réflexion opératoire ; \
  8-9 : alerte sécurité sur un dispositif implanté, guideline majeure mise à jour \
(grade IA ou IB), nouveau standard de soins confirmé.

→ PAS d'evidence_json pour les sources presse : laisser ce champ absent.

→ RÉDACTION pour les articles de presse médicale (même ton confraternel) : \
  resume : "[Dispositif/technique/guideline] — [résultat ou décision principale] \
présenté(e) [au congrès / dans le numéro X]. [Ce que ça signifie pour la pratique]." \
  impact_pratique : "En pratique : [implication clinique concrète — ou 'À confirmer \
en guideline officielle' si résultats de congrès pas encore publiés]."

SOURCE HAS DM — Si la SOURCE indique "HAS — Avis sur les dispositifs médicaux \
(admission remboursement, conditions utilisation)" (code source : has_dm) :

→ NATURE DU CONTENU : avis de la CNEDiMTS (Commission Nationale d'Évaluation \
des Dispositifs Médicaux et des Technologies de Santé) sur l'admission d'un dispositif \
médical au remboursement. Ce n'est ni un article de recherche, ni un arrêté légal, mais \
une décision réglementaire d'accès au marché français avec évaluation clinique.

→ PERTINENCE : retenir si le dispositif médical a un impact direct sur la pratique \
d'une spécialité (chirurgie, cardiologie interventionnelle, etc.). \
REJETER : dispositifs de soins courants sans enjeu clinique (pansements banaux, \
lentilles de contact), accessoires de confort sans bénéfice clinique démontré.

→ SCORE :
  6-7 : dispositif admis ou réévalué, conditions de remboursement précisées, \
         impact organisationnel (prothèse amputé, pansement chronique) ;
  8-9 : dispositif majeur pour la spécialité — endoprothèse aortique, système \
         de boucle fermée insuline, valvuloplastie transcathéter, neurostimulateur, \
         micro-stent trabéculaire — avec SA/ASA impactant directement la sélection \
         des patients et les conditions d'implantation.

→ RÉDACTION (ton éditorial de journal vasculaire / médical spécialisé) :
  resume : "[Dispositif] (fabricant) — La CNEDiMTS évalue le Service Attendu \
[suffisant/insuffisant] dans l'indication : [indication retenue en 1-2 phrases]. \
ASA [niveau I-V] par rapport à [comparateur nommé]. [Condition-clé de prise en \
charge si mentionnée : critère anatomique, niveau de centre, restriction d'indication]."
  impact_pratique : "En pratique : [ce qui change concrètement — accès au \
remboursement, conditions anatomiques à respecter, centres habilités, ou restriction \
d'indication par rapport à la version précédente]."
  nature : "AVIS_CNEDiMTS" pour tous les avis dispositifs médicaux.
  date_entree_en_vigueur : date de l'avis (l'inscription LPP suit généralement \
  sous 13 jours, mais la date de l'avis fait foi pour le praticien).

→ PAS d'evidence_json pour les avis CNEDiMTS : laisser ce champ absent.

Ta mission :

1. PERTINENCE — Ce texte change-t-il quelque chose de concret pour un professionnel \
de santé ? Réponds NON si c'est : une nomination, un avis de concours, \
un texte purement administratif ou budgétaire sans impact sur la pratique ou \
la rémunération, un rapport épidémiologique sans recommandation opérationnelle.

2. AUDIENCE — Qui est principalement concerné ?
   - SPECIALITE : une ou plusieurs spécialités ou professions précises (voir liste ci-dessous).
     Pour les textes transversaux (honoraires, CCAM, convention médicale, tiers payant, \
     exercice libéral général) : liste TOUTES les spécialités réellement impactées — \
     n'utilise PAS medecine-generale comme spécialité par défaut. \
     medecine-generale est RÉSERVÉ aux articles ayant un impact clinique direct \
     pour le médecin généraliste (pathologie, protocole, prescription courante).
   - PHARMACIENS : impact DIRECT et EXCLUSIF sur l'exercice en officine. \
     Critères stricts — LE TEXTE DOIT porter sur au moins l'un de ces points : \
     règle de substitution générique, gestion de rupture de stock en officine, \
     obligation légale propre à l'officine (préparations magistrales, \
     dispensation à l'unité, PDA), rémunération ou convention pharmacien, \
     autorisation d'ouverture/fermeture d'officine.

   RÈGLE ANTI-PHARMACIENS — Ces cas NE SONT PAS PHARMACIENS :
   - Retrait AMM ou alerte sécurité médicament → audience = SPECIALITE \
     (médecin prescripteur) ; le pharmacien n'est qu'un relais d'information
   - Nouvelle indication, restriction de prescription, REMS → SPECIALITE
   - Alerte pharmacovigilance sans action officine spécifique → SPECIALITE
   - Tout texte dont l'acteur principal est le médecin prescripteur, \
     même si un médicament est mentionné

   Exemples corrects audience :
     Arrêté substitution biosimilaire en officine  → PHARMACIENS ✓
     Rupture stock amoxicilline (consigne officine) → PHARMACIENS ✓
     Retrait AMM Valsartan (alerte prescripteurs)   → SPECIALITE (cardiologie + medecine-generale) ✓
     Alerte ANSM paracétamol 1g surdosage          → SPECIALITE (medecine-urgences + medecine-generale) ✓
     Nouvelle indication immunothérapie oncologie   → SPECIALITE (oncologie) ✓

RÈGLE D'ATTRIBUTION — À LIRE ATTENTIVEMENT :
1. Audience = TOUJOURS SPECIALITE. Cherche la ou les spécialités exactes concernées.
   Demande-toi : "Quel professionnel de santé — médecin, chirurgien, infirmier, kiné,
   sage-femme, pharmacien — va concrètement changer sa pratique ou ses actes grâce à cet article ?"
2. Un article peut concerner 2-5 spécialités simultanément — liste-les toutes.
3. Pour les textes transversaux (honoraires, CCAM, convention, tiers payant, exercice libéral) :
   → Identifie les spécialités réellement impactées. Si le texte concerne TOUS les médecins \
sans distinction, utilise les 4-6 spécialités les plus représentatives (cardiologie, \
medecine-interne, pneumologie, gynecologie, pediatrie, etc.) plutôt que medecine-generale seul.
4. medecine-generale UNIQUEMENT si l'article a un impact clinique direct pour un généraliste : \
   pathologie courante en ville, prescription ambulatoire, protocole de suivi en cabinet. \
   NE PAS utiliser medecine-generale pour un texte purement administratif ou réglementaire \
   qui concerne toutes les spécialités au même titre.
5. En cas de doute → préfère sur-attribuer (plusieurs slugs) plutôt que sous-attribuer.
Exemples corrects :
  Alerte acide tranexamique → SPECIALITE + [anesthesiologie, chirurgie-orthopedique, medecine-urgences]
  Recommandation HAS HTA   → SPECIALITE + [cardiologie, medecine-generale]
  Arrêté honoraires conventionnels (tous médecins) → SPECIALITE + [cardiologie, medecine-interne, gynecologie, pediatrie, pneumologie]
  Modification CCAM actes chirurgicaux → SPECIALITE + [chirurgie-orthopedique, chirurgie-vasculaire, anesthesiologie]
  Décret installation médecins zones sous-dotées → SPECIALITE + [medecine-generale, medecine-interne]
  Recommandation HAS diabète type 2 → SPECIALITE + [endocrinologie, medecine-generale]
  Arrêté vaccination grippe médecin traitant → SPECIALITE + [medecine-generale, pediatrie]
  Rappel implant prothèse de hanche (matériovigilance) → SPECIALITE + [chirurgie-orthopedique]
  Modification NGAP actes infirmiers (pansements complexes) → SPECIALITE + [infirmiers]
  Alerte dispositif d'injection insuline (stylo défectueux) → SPECIALITE + [infirmiers, endocrinologie]
  Nouveau tarif actes de kinésithérapie NGAP → SPECIALITE + [kinesitherapie]
  Alerte lentilles intraoculaires (matériovigilance) → SPECIALITE + [ophtalmologie]
  Recommandation protocole cicatrisation plaies chroniques → SPECIALITE + [infirmiers, chirurgie-vasculaire, medecine-generale]

3. SPÉCIALITÉS — Si audience = SPECIALITE, liste les slugs concernés parmi :

   Médecine générale : medecine-generale

   Spécialités médicales : cardiologie, dermatologie, endocrinologie, \
gastro-enterologie, gynecologie, neurologie, ophtalmologie, orl, pediatrie, \
pneumologie, psychiatrie, rhumatologie, urologie, medecine-interne, \
medecine-urgences, geriatrie, medecine-physique, oncologie, hematologie, \
infectiologie, nephrologie, radiologie, anesthesiologie

   Chirurgie — TOUJOURS choisir la sous-spécialité exacte (le slug "chirurgie" \
générique n'existe pas) : chirurgie-vasculaire, chirurgie-orthopedique, \
chirurgie-thoracique, chirurgie-plastique, neurochirurgie, \
chirurgie-pediatrique, chirurgie-cardiaque

   Paramédicaux et professions de santé non-médicales : infirmiers, kinesitherapie, \
sage-femme, biologiste

   Chirurgiens-dentistes et orthodontistes : dentiste, orthodontiste
   - "dentiste" : parodontologie, implantologie, soins conservateurs, prothèse dentaire,\
 chirurgie orale
   - "orthodontiste" : traitements orthodontiques fixes/amovibles, orthopédie dento-faciale

   Pharmaciens : pharmacien (pour les sources dédiées pharmacie)

   Règles :
   - Distingue la sous-spécialité chirurgicale exacte plutôt que "chirurgie" générique.
   - Pour les paramédicaux, utilise leurs slugs dédiés (infirmiers, kinesitherapie, \
sage-femme, biologiste).
   - Pour les chirurgiens-dentistes, utilise dentiste ou orthodontiste selon la discipline.
   - Un texte peut concerner plusieurs spécialités : retourne un tableau complet.

4. SCORE D'URGENCE (score_density) de 1 à 10 :
   - 1-3 : informatif, pas d'action immédiate (rapport épidémio, données statistiques)
   - 4-6 : à lire — recommandation de bonne pratique, guideline clinique, bon usage
   - 7-10 : lecture OBLIGATOIRE — change la pratique, la rémunération, \
     ou crée une obligation légale immédiate

   RÈGLE RECOMMANDATIONS : une recommandation HAS, une fiche mémo, un guideline de \
   société savante ou un guide de bon usage médicament mérite un score 4-6. \
   Ce sont des articles utiles à la pratique, même sans urgence réglementaire. \
   Ne les classer en 1-3 que s'ils n'apportent aucune information actionnable.

   RÈGLE ANCIENNETÉ : Si le document est une recommandation (HAS, SOFMER, ANSM, \
   société savante, guideline) dont la date de publication ORIGINALE est antérieure \
   à 2020 — même s'il réapparaît dans un flux RSS en 2025-2026 — le contenu est \
   probablement périmé et remplacé par des versions plus récentes. \
   Dans ce cas : score ≤ 3 OBLIGATOIREMENT, et ajoute dans le résumé \
   "(document de [année], vérifier existence d'une version actualisée)". \
   Si la date originale ne peut pas être déterminée à partir du contenu, score normalement.

   Exemples de score 9-10 :
     - Avenant tarifaire UNCAM, modification majeure de la convention médicale
     - Rappel/retrait d'implant orthopédique ou d'instrument chirurgical défectueux
     - Nouvelle cotation CCAM ou modification NGAP infirmiers/kinés (actes remboursés)
     - Retrait AMM médicament courant, nouvelle contre-indication majeure
     - Alerte matériovigilance obligeant un praticien à contacter ses patients
     - Alerte ANSM implant dentaire ou matériau défectueux → retrait marché
     - Nouvelle cotation CCAM actes dentaires ou orthodontiques
   Exemples de score 6-7 (innovation / recherche) :
     - Essai de phase 3 NEJM : nouveau traitement supérieur au standard (ex. thérapie ciblée oncologie)
     - Méta-analyse Lancet modifiant les seuils de traitement d'une pathologie courante
     - Étude JAMA Surgery : technique chirurgicale montrant réduction significative de complications
     - Essai randomisé PTJ : protocole de rééducation supérieur au standard chez les kinés
     - BJOG : intervention sage-femme réduisant significativement la mortalité maternelle
   Exemples de score 4-6 :
     - Recommandation HAS sur une pathologie, fiche mémo pratique
     - Guideline société savante, guide bon usage médicament
     - Nouveau protocole de rééducation, actualisation technique chirurgicale
     - Guideline EFP parodontite (scores 5-6 : change la pratique des dentistes)
     - Guideline EOS / consensus orthodontique (score 4-5 pour orthodontistes)
     - Étude JAMA confirmant l'efficacité d'un traitement existant (confirmation utile, pas rupture)
     - Article JAMA Internal Medicine nuançant une pratique de prescription courante
   Exemples de score 1-3 :
     - Rapport statistique sans recommandation opérationnelle
     - Données épidémiologiques sans changement de pratique
     - Communication institutionnelle sans impact sur les actes
     - Article de recherche fondamentale (mécanismes, biomarqueurs) sans implication clinique
     - Éditorial, lettre, commentaire, revue narrative sans méta-analyse ni essai original

   SCORE PAR SPÉCIALITÉ (score_par_specialite) — champ optionnel :
   Quand un article concerne plusieurs spécialités avec des degrés de pertinence \
   différents, renseigne ce dictionnaire pour moduler le score par spécialité.
   Règle : utilise ce champ UNIQUEMENT si au moins une spécialité a un score \
   différent du score_density global.

   Cas typiques :
   - Recommandation d'anesthésie (SFAR) distribuée aux chirurgiens : \
     anesthesiologie → score global (7), chirurgie-* → score réduit (3-4, indirect)
   - Alerte médicament ciblant cardiologie mais distribuée à médecine-générale : \
     cardiologie → score global (8), medecine-generale → score réduit (5, pour info)
   - Arrêté JORF purement réglementaire transversal → NE PAS utiliser ce champ \
     (le score est identique pour toutes les spécialités)

   Exemple :
     "score_par_specialite": {{
       "anesthesiologie": 7,
       "chirurgie-orthopedique": 4,
       "chirurgie-plastique": 3
     }}

5. RÉDACTION — Ton : journal médical professionnel (EJVES, JVS, Lancet, JAMA Surgery, \
   Le Quotidien du Médecin). Le lecteur est un spécialiste confirmé — aucun terme \
   médical n'a besoin d'être défini. Phrases directes, donnée quantitative en premier.

   PRINCIPES DE RÉDACTION :
   • Quantitatif en premier : OR, HR, IC95%, p-value, effectif (n=), taux (%) \
     avant tout commentaire narratif. Ex. : "mortalité à 30 j : 1,4 % vs 3,9 % \
     (OR 0,35 ; IC95% 0,14–0,88)" — pas "les résultats sont meilleurs".
   • Nommer la source : essai clinique ("Dans BEST-CLI, N=1 830"), congrès \
     ("présenté à ESVS 2025"), journal ("JAMA Surgery, jan. 2026") — \
     jamais "une étude récente" ou "des chercheurs ont montré".
   • Comparatif explicite : nommer systématiquement le comparateur \
     ("vs bypass", "vs PTA seule", "vs placebo"). Sans comparateur, pas de conclusion.
   • Incertitude signalée : "données à 1 an uniquement", "analyse de sous-groupe \
     non pré-spécifiée", "essai monocentrique", "à confirmer en guideline officielle".
   • Jamais de redondance : resume ≠ paraphrase du titre — apporter un contenu nouveau \
     (chiffres, population, comparateur, limite principale).

   RÈGLES DE TON :
   • Éviter absolument : "l'étude montre que", "les résultats indiquent que", \
     "il est important de noter", "il semblerait que", "les auteurs concluent". \
     Aussi : "Action requise", "Vous devez", "Veiller à", "Ne plus prescrire".
   • Préférer : constructions actives directes ("TCAR réduisait de 64 % la \
     survenue d'AVC"), données brutes entre parenthèses, formulations cliniques \
     précises sans jargon administratif.
   • impact_pratique : UNE seule phrase cliniquement actionnelle — commence par \
     "En pratique :" ou "À retenir :". Ce n'est PAS un résumé de l'étude. \
     C'est l'implication concrète pour le praticien dans sa pratique quotidienne.

   Adapte la rédaction selon la nature du texte :

   Texte RÉGLEMENTAIRE (loi, décret, arrêté, circulaire, avenant tarifaire) :
   → resume : "[Ce qui change] entre en vigueur le [date]. [Qui est concerné et \
pourquoi c'est notable]. [Contexte ou enjeu si utile]."
   → impact_pratique : "En pratique : [conséquence concrète pour l'exercice \
quotidien, formulée comme une information, pas un ordre]."
   → date_entree_en_vigueur : cherche la date d'application effective dans le texte \
(souvent différente de la date de publication au JO). \
Si absente, utilise la date de publication.

   Texte CLINIQUE / RECOMMANDATION (HAS, société savante, guideline) :
   → resume : "[Société savante/HAS] publie [recommandation sur X]. [Ce que ça \
précise ou modifie]. [Population concernée si pertinente]."
   → impact_pratique : "À retenir : [point clinique clé en langage médical naturel, \
avec niveau de preuve si disponible]."
   → date_entree_en_vigueur : date de publication de la recommandation.

   Texte ALERTE SÉCURITÉ (ANSM retrait, matériovigilance) :
   → resume : "[Produit/molécule] fait l'objet d'[une suspension / d'un retrait / \
d'une restriction] en raison de [risque identifié]. [Mesure prise et périmètre]."
   → impact_pratique : "En pratique : [ce que ça change pour les patients \
concernés — alternative disponible si mentionnée, ou en attente de nouvelles \
recommandations]."
   → date_entree_en_vigueur : date de l'alerte (généralement immédiate).

6. CATÉGORIE MÉTIER — Assigne UNE seule valeur parmi :
   - clinique       : recommandations HAS, protocoles, guidelines diagnostiques ou thérapeutiques, \
dépistage, vaccination, épidémies, prévention, plans de santé publique
   - therapeutique  : alertes pharmacovigilance sur une MOLÉCULE nommée, retrait/suspension AMM, \
nouvelle indication thérapeutique, modification posologie/CI/contre-indication, \
remboursement d'un médicament ; alertes matériovigilance, problèmes de sécurité ou réglementation \
concernant équipements médicaux, imagerie (IRM, scanner, échographe, radiologie), \
implants, prothèses, instruments chirurgicaux, DM-DIV, réactifs de laboratoire
   - exercice       : convention médicale, installation, déserts médicaux, gardes, \
télémédecine, statut libéral, logiciels métier (LAP, DMP, DxCare…) ; \
CCAM, NGAP, tarifs, cotations, honoraires, remboursement actes ; \
obligations déclaratives, formations DPC, certifications, accréditations

   RÈGLES DE DISCRIMINATION (prioritaires sur les définitions ci-dessus) :
   - Molécule / DCI / spécialité pharmaceutique nommée / AMM → 'therapeutique'
   - Équipement, matériel, appareil, dispositif médical (y compris imagerie) → 'therapeutique'
   - Logiciel métier santé (LAP, DxCare, NETSoins, Cortexte, DMP) → 'exercice'
   - Facturation, cotation CCAM/NGAP, honoraires, avenant tarifaire → 'exercice'
   - Dépistage, vaccination, alerte épidémique, plan national → 'clinique'

   Exemples corrects :
       Alerte ANSM paracétamol 1 g          → therapeutique
       Retrait AMM Valsartan                → therapeutique
       Alerte ANSM scanner Siemens          → therapeutique
       Alerte ANSM IRM Philips              → therapeutique
       Alerte ANSM bistouri / prothèse      → therapeutique
       Alerte ANSM DxCare (logiciel)        → exercice
       Obligation utilisation LAP DMP       → exercice
       Recommandation HAS vaccination       → clinique
       Avenant tarifaire UNCAM              → exercice

7. TYPE DE PRATICIEN (type_praticien) — Détermine le profil professionnel PRINCIPALEMENT \
concerné par ce texte. Choisis parmi :

   "prescripteur" — médecin généraliste, interniste, pédiatre, cardiologue, \
pneumologue, endocrinologue, psychiatre et tout médecin prescrivant en ambulatoire.
   CONCERNE : médicaments remboursés, déremboursements, génériques ; alertes \
pharmacovigilance, retraits AMM, contre-indications ; protocoles thérapeutiques \
et recommandations HAS de traitement ; cotations CCAM/NGAP des consultations, \
téléconsultation ; certificats, ordonnances, responsabilité médicale.
   NE CONCERNE PAS : dispositifs chirurgicaux, prothèses implantables, \
instruments de bloc opératoire, matériovigilance sur DM invasifs.

   "interventionnel" — chirurgien (toutes sous-spécialités), anesthésiste, \
gynécologue-obstétricien réalisant des actes, radiologue interventionnel, \
chirurgien-dentiste (dentiste + orthodontiste), stomatologue.
   CONCERNE : dispositifs implantables, prothèses (y compris prothèses dentaires, \
implants dentaires, appareils orthodontiques), matériaux et instruments de soins ; \
matériovigilance sur DM invasifs ; cotations CCAM des actes techniques (chirurgicaux, \
dentaires, orthodontiques) ; recommandations HAS et EFP sur gestes techniques ; \
accréditation chirurgicale et dentaire.
   NE CONCERNE PAS : alertes médicaments de ville, listes remboursables de \
médicaments, protocoles médicamenteux ambulatoires.

   "biologiste" — biologiste médical (laboratoire d'analyses médicales).
   CONCERNE : nomenclature NABM, accréditation COFRAC ; automates, réactifs, \
équipements de laboratoire (hémostase, bactériologie, gazométrie…) ; nouveaux \
examens remboursés, DM-DIV.
   NE CONCERNE PAS : médicaments (sauf interaction biologie), \
dispositifs chirurgicaux invasifs.

   "pharmacien" — pharmacien d'officine ou hospitalier.
   CONCERNE : alertes médicaments, retraits AMM, génériques, remboursements \
spécialités pharmaceutiques ; nouvelles missions officine (vaccination, \
substitution biosimilaires, dépistage) ; rémunération sur objectifs, \
honoraires de dispensation ; stupéfiants, psychotropes, réglementation des \
délivrances ; convention pharmaceutique ; pharmacie hospitalière (EAHP).
   NE CONCERNE PAS : cotations d'actes médicaux, dispositifs chirurgicaux, \
matériovigilance sur DM non dispensés en officine.

   "tous" — tous les professionnels de santé libéraux sans distinction.
   CONCERNE : conditions d'exercice libéral, conventionnement médical ; \
formation médicale continue (DPC, accréditation, certification périodique) ; \
télémédecine, DMP, logiciels métier ; responsabilité professionnelle générale ; \
réforme des retraites médicales, protection sociale des libéraux.

   RÈGLE DE PRIORITÉ — En cas de doute, préfère la valeur la plus spécifique. \
   Un texte sur les cotations CCAM d'une consultation → "prescripteur" (pas "tous"). \
   Un texte sur une alerte DM chirurgical → "interventionnel" (pas "tous"). \
   "tous" est réservé aux textes qui s'appliquent SANS EXCEPTION à toutes \
   les professions libérales de santé.

   Exemples corrects :
     Alerte ANSM paracétamol 1 g (surdosage)            → prescripteur
     Nouvelle indication immunothérapie oncologie        → prescripteur
     Alerte ANSM prothèse de hanche (débris métalliques) → interventionnel
     Vis ostéosynthèse Stryker — matériovigilance        → interventionnel
     Guidelines EFP parodontite stade I-III              → interventionnel  (dentiste)
     Alerte ANSM implant dentaire (corrosion)            → interventionnel  (dentiste)
     Cotation CCAM acte orthodontique (contention)       → interventionnel  (orthodontiste)
     Automate gazométrie GEM Premier / réactifs Beckman  → biologiste
     Nomenclature NABM nouveaux actes de biologie        → biologiste
     Rupture stock amoxicilline (consigne officine)      → pharmacien
     Rémunération honoraires dispensation officine       → pharmacien
     Certification périodique ordres professionnels      → tous
     Réforme conventionnement médical national           → tous

IMPORTANT : réponds UNIQUEMENT avec un objet JSON valide, sans markdown, \
sans explication autour.
"""

# ---------------------------------------------------------------------------
# Prompt utilisateur
# ---------------------------------------------------------------------------

# Sources pour lesquelles on extrait evidence_json (source_type=innovation)
# NB : les sources "presse médicale" (_PRESS_SOURCES) sont exclues — pas de design d'étude à extraire
_INNOVATION_SOURCES: frozenset[str] = frozenset({
    "jama", "jama_cardiology", "jama_dermatology", "jama_internal_med",
    "jama_neurology", "jama_oncology", "jama_ophthalmology",
    "jama_otolaryngology", "jama_pediatrics", "jama_psychiatry",
    "jama_surgery", "jama_network_open",
    "nejm", "lancet", "bmj", "nature_medicine",
    "clinical_chemistry", "ptj_kine", "bjog", "cpt_pharmacol",
    "jdr_dental", "jan_nursing",
    # PubMed sources
    "pubmed_jvs", "pubmed_ejves", "pubmed_jet", "pubmed_ann_vasc_surg",
    # EMA nouvelles AMM
    "ema_new_medicines",
})

# Sources presse médicale professionnelle — traitement différent des journaux académiques :
#   • Pas d'evidence_json (journaliste, pas chercheur)
#   • Filtre "est-ce que ça change la pratique ?" plutôt que "phase 3 seulement"
#   • Peut signaler innovation, réglementation OU recommandation selon le contenu
_PRESS_SOURCES: frozenset[str] = frozenset({
    "vascular_specialist", "vascular_news", "tctmd",
    "endovascular_today",
    "quotidien_medecin", "egora",
    # Congrès vasculaires — highlights (couverts via TCTMD + Vascular News)
    # linc_highlights et evc_highlights désactivés (domaines NXDOMAIN)
})


def _build_user_prompt(
    title: str,
    content: str | None,
    date_pub: str,
    source_hint: str | None = None,
    is_innovation: bool = False,
    is_press: bool = False,
) -> str:
    """
    source_hint   : indication sur la provenance pour contextualiser Claude.
    is_innovation : True → ajoute le bloc evidence_json dans le template JSON.
    is_press      : True → source presse médicale (pas d'evidence_json, filtre différent).
    """
    source_line = f"\nSOURCE : {source_hint}" if source_hint else ""
    content_section = ""
    if content and len(content.strip()) > 50:
        excerpt = content.strip()[:3000]
        content_section = f"\n\nEXTRAIT :\n{excerpt}"

    evidence_block = ""
    # is_press sources : pas de evidence_json — le journaliste ne fournit pas de design d'étude
    if is_innovation and not is_press:
        evidence_block = """,
  "evidence_json": {{
    "study_design": "<RCT|meta-analysis|registry|prospective-cohort|retrospective-cohort|case-series|guideline|regulatory-decision|technique-paper|review|editorial>",
    "phase": <"1"|"2"|"3"|"4"|null>,
    "n_patients": <int|null>,
    "multicentre": <true|false|null>,
    "follow_up_months": <int|null>,
    "primary_endpoint": "<mortality|patency|limb-salvage|stroke-TIA|reintervention|composite-MALE|technical-success|quality-of-life|other|null>",
    "primary_endpoint_met": <true|false|null>,
    "vascular_domain": "<aorte-abdominale|aorte-thoracique|aorte-thoraco-abdominale|carotide-TSA|AOMI-femoro-poplite|AOMI-sous-poplite|ischemie-aigue-membre|veineux-TVP-EP|veineux-varices|acces-vasculaire-dialyse|renovasculaire|traumatique|multi-domaine|non-vasculaire>",
    "intervention_type": "<EVAR|TEVAR|FEVAR-BEVAR|CAS|TCAR|PTA-stent|DCB|atherectomie|thrombectomie-mecanique|thrombolyse-CDT|ablation-thermique|ablation-non-thermique|pontage|endarterectomie|reparation-ouverte|hybride|anticoagulation|antiplatelet|traitement-medical|strategie-diagnostique|surveillance|multi-modalite|autre>",
    "comparator_type": "<vs-chirurgie-ouverte|vs-endovasculaire-autre|vs-traitement-medical|vs-placebo|vs-standard-of-care|aucun|null>",
    "clinical_maturity": "<exploratory|preliminary|pivotal|confirmatory|practice-defining|regulatory-event>",
    "actionability_horizon": "<immediate|1-3y|3-5y|exploratory>",
    "regulatory_milestone": <"CE_mark"|"AMM_europe"|"FDA_approval"|"remboursement_HAS"|"CNAM_accord"|"guideline_update"|"autorisation_temporaire"|null>,
    "guideline_body": <"ESVS"|"ESC"|"HAS"|"AHA-ACC"|"SFCV"|"SFMV"|"autre"|null>,
    "guideline_grade": <"IA"|"IB"|"IIaA"|"IIaB"|"IIbA"|"IIbB"|"III"|null>,
    "paradigm_shift": <bool>,
    "negative_result": <bool>,
    "safety_signal": <bool>
  }}"""

    return f"""\
Analyse ce texte et retourne UNIQUEMENT le JSON demandé.

TITRE : {title}
DATE : {date_pub}{source_line}{content_section}

JSON attendu (strict, pas de markdown) :
{{
  "pertinent": <bool>,
  "audience": "<SPECIALITE|PHARMACIENS>",
  "specialites": [<slugs parmi: medecine-generale, cardiologie, dermatologie, endocrinologie, gastro-enterologie, gynecologie, neurologie, ophtalmologie, orl, pediatrie, pneumologie, psychiatrie, rhumatologie, urologie, medecine-interne, medecine-urgences, geriatrie, medecine-physique, oncologie, hematologie, infectiologie, nephrologie, radiologie, anesthesiologie, chirurgie-vasculaire, chirurgie-orthopedique, chirurgie-thoracique, chirurgie-plastique, neurochirurgie, chirurgie-pediatrique, chirurgie-cardiaque, infirmiers, kinesitherapie, sage-femme, biologiste, dentiste, orthodontiste, pharmacien>],
  "type_praticien": "<prescripteur|interventionnel|biologiste|pharmacien|tous>",
  // Note : dentiste et orthodontiste → "interventionnel" (praticiens d'actes techniques)
  "score_density": <int 1-10>,
  "score_par_specialite": {{"<slug>": <int 1-10>}},
  "categorie": "<clinique|therapeutique|exercice>",
  "tri_json": {{
    "titre_court": "<≤12 mots>",
    "resume": "<2-3 phrases concrètes selon nature du texte>",
    "impact_pratique": "<1 phrase : action précise à faire / retenir>",
    "nature": "<ARRETE|DECRET|LOI|ORDONNANCE|RECOMMANDATION|ALERTE|AVENANT|CIRCULAIRE|ETUDE|AUTRE>",
    "date_publication": "{date_pub}",
    "date_entree_en_vigueur": "<YYYY-MM-DD — date d'application effective, différente de date_publication si précisée dans le texte>"
  }},
  "lecture_json": {{
    "points_cles": ["<bullet 1>", "..."],
    "texte_long": "<~150 mots>",
    "references": ["<NOR, ref légale, numéro AMM...>"]
  }}{evidence_block}
}}
"""

# ---------------------------------------------------------------------------
# Mapping source → hint contextuel pour Claude
# ---------------------------------------------------------------------------

SOURCE_HINTS: dict[str, str] = {
    # Sources réglementaires
    "legifrance_jorf":       "JORF — texte réglementaire (loi, décret, arrêté)",
    "piste_kali":            "Convention collective / accord UNCAM — impact sur honoraires et pratique libérale",
    "piste_legi":            "Code de la santé publique — modification de texte codifié (CSP, CSS, CASF)",
    "piste_circ":            "Circulaire ou instruction ministérielle — directive santé ou social",
    "ansm_securite":         "ANSM — Information de sécurité (pharmacovigilance, matériovigilance)",
    "ansm_securite_med":     "ANSM — Alerte sécurité médicament (retrait AMM, contre-indication, restriction)",
    "ansm_securite_dm":      "ANSM — Alerte matériovigilance dispositif médical (implants, instruments chirurgicaux, DM soins infirmiers)",
    "ansm_ruptures_med":     "ANSM — Rupture ou tension d'approvisionnement médicament",
    "ansm_ruptures_vaccins": "ANSM — Disponibilité vaccins",
    "bo_social":             "Bulletin officiel ministères sociaux — circulaire ou instruction ministère Santé",
    # Recommandations de pratique
    "has_rbp":               "HAS — Recommandation de bonne pratique clinique (RBP)",
    "has_fiches_memo":       "HAS — Fiche mémo (synthèse pratique, directement actionnable en consultation)",
    "has_parcours":          "HAS — Parcours de soins (organisation prise en charge par pathologie)",
    "has_outils":            "HAS — Outil ou méthode HAS (évaluation, amélioration des pratiques)",
    "academie_medecine":     "Académie Nationale de Médecine — publication ou avis scientifique",
    "sfc_recommandations":   "Société Française de Cardiologie — recommandation ou guideline cardiologie",
    "sfmu_recommandations":  "SFMU — Recommandation médecine d'urgence",
    "sfp_recommandations":   "Société Française de Pédiatrie — recommandation pédiatrique",
    "sofcot_recommandations":"SOFCOT — recommandation chirurgie orthopédique et traumatologie",
    "cngof_recommandations": "CNGOF — recommandation gynécologie-obstétrique",
    # Bon usage
    "ansm_bon_usage":        "ANSM — Bon usage du médicament (guide positif, pas une alerte)",
    # Sociétés savantes — scan mars 2026
    "cnge":              "CNGE — Recommandation médecine générale et soins primaires",
    "snfmi":             "SNFMI — Recommandation médecine interne",
    "sfhta":             "SFHTA — Recommandation hypertension artérielle",
    "sfar":              "SFAR — Recommandation anesthésie et réanimation",
    "sfn":               "SFN — Recommandation neurologie",
    "sfpsychiatrie":     "SFP — Recommandation psychiatrie",
    "snfge":             "SNFGE — Recommandation gastroentérologie",
    "afef":              "AFEF — Recommandation hépatologie",
    "splf":              "SPLF — Recommandation pneumologie",
    "sfendocrino":       "SFE — Recommandation endocrinologie",
    "sfdiabete":         "SFD — Recommandation diabétologie",
    "sfrhumato":         "SFRhumato — Recommandation rhumatologie",
    "sforl":             "SFORL — Recommandation ORL et chirurgie cervico-faciale",
    "afu":               "AFU — Recommandation urologie",
    "sfgg":              "SFGG — Recommandation gériatrie et gérontologie",
    "sfndt":             "SFNDT — Recommandation néphrologie, dialyse et transplantation",
    "sfctcv":            "SFCTCV — Recommandation chirurgie thoracique et cardio-vasculaire",
    "sfnc":              "SFNC — Recommandation neurochirurgie",
    "snfcp":             "SNFCP — Recommandation coloproctologie",
    "sfm_microbiologie": "SFM — Recommandation microbiologie et infectiologie",
    "sfcv":              "SFCV — Recommandation chirurgie vasculaire et endovasculaire",
    "sofcpre":           "SOFCPRE — Recommandation chirurgie de l'obésité et maladies métaboliques",
    "sofmer":            "SOFMER — Recommandation médecine physique et réadaptation",
    "sfmv":              "SFMV — Recommandation médecine vasculaire",
    "sfms":              "SFMS — Recommandation médecine du sport",
    "sfalcoologie":      "SFA — Recommandation alcoologie et addictologie",
    "sfpathol":          "SFP — Recommandation anatomie et cytologie pathologiques",
    "sfmn":              "SFMN — Recommandation médecine nucléaire",
    "sfscmfco":          "SFSCMFCO — Recommandation stomatologie et chirurgie maxillo-faciale",
    "sfmu":              "SFMU — Recommandation médecine d'urgence",
    "sfpediatrie":       "SFP — Recommandation pédiatrie",
    "sfnn":              "SFN — Recommandation néonatalogie",
    "sfsp":              "SFSP — Recommandation santé publique et prévention",
    "sfdermato":         "SFDermato — Recommandation dermatologie",
    "sfo":               "SFO — Recommandation ophtalmologie",
    "afsos":             "AFSOS — Recommandation soins oncologiques de support",
    "sfh":               "SFH — Recommandation hématologie",
    "sfr_radiologie":    "SFR — Recommandation radiologie diagnostique et interventionnelle",
    "sofcot":            "SOFCOT — Recommandation chirurgie orthopédique et traumatologique",
    "sofcpre_plastique": "SOFCPRE — Recommandation chirurgie plastique reconstructrice et esthétique",
    "sfcp":              "SFCP — Recommandation chirurgie pédiatrique",
    "sniil":             "SNIIL — Recommandation et actualités infirmiers libéraux",
    "ffmkr":             "FFMKR — Recommandation kinésithérapie et rééducation",
    "cnsf":              "CNSF — Recommandation sages-femmes",
    "sfbc":              "SFBC — Recommandation biologie clinique et médicale",
    "fspf":              "FSPF — Actualités réglementaires pharmaciens d'officine",
    # Nouvelles sources institutionnelles — audit mars 2026
    "has_ct":  "HAS Commission de la Transparence — Avis remboursement médicament (ASMR/SMR)",
    "has_dm":  "HAS — Avis sur les dispositifs médicaux (admission remboursement, conditions utilisation)",
    "spf_beh": "Santé publique France — Article épidémiologique (BEH, alerte sanitaire, vaccination)",
    "cnom":    "CNOM (Ordre des Médecins) — Déontologie médicale, réglementation exercice libéral",
    # ── Sources innovation — journaux scientifiques internationaux ────────
    # JAMA Network
    "jama":                "JAMA (Journal of the American Medical Association) — Article de recherche clinique ou editorial (toutes spécialités)",
    "jama_cardiology":     "JAMA Cardiology — Essai clinique ou méta-analyse en cardiologie",
    "jama_dermatology":    "JAMA Dermatology — Essai clinique ou méta-analyse en dermatologie",
    "jama_internal_med":   "JAMA Internal Medicine — Essai clinique ou méta-analyse en médecine interne",
    "jama_neurology":      "JAMA Neurology — Essai clinique ou méta-analyse en neurologie",
    "jama_oncology":       "JAMA Oncology — Essai clinique ou méta-analyse en oncologie",
    "jama_ophthalmology":  "JAMA Ophthalmology — Essai clinique ou méta-analyse en ophtalmologie",
    "jama_otolaryngology": "JAMA Otolaryngology — Essai clinique ou méta-analyse en ORL et chirurgie cervico-faciale",
    "jama_pediatrics":     "JAMA Pediatrics — Essai clinique ou méta-analyse en pédiatrie",
    "jama_psychiatry":     "JAMA Psychiatry — Essai clinique ou méta-analyse en psychiatrie",
    "jama_surgery":        "JAMA Surgery — Essai clinique ou méta-analyse en chirurgie (toutes sous-spécialités)",
    "jama_network_open":   "JAMA Network Open — Article de recherche en accès libre (toutes spécialités médicales et paramédicales)",
    # Grands journaux généralistes
    "nejm":          "New England Journal of Medicine (NEJM) — Essai clinique de référence ou méta-analyse (impact mondial sur les standards de soins)",
    "lancet":        "The Lancet — Essai clinique ou méta-analyse internationale (toutes spécialités, focus santé mondiale)",
    "bmj":           "BMJ (British Medical Journal) — Essai clinique, méta-analyse ou étude observationnelle (pratique clinique britannique et internationale)",
    "nature_medicine":"Nature Medicine — Recherche translationnelle de pointe (immunothérapies, génomique, IA médicale, nouvelles thérapies)",
    # Sources paramédicales
    "clinical_chemistry": "Clinical Chemistry (AACC) — Article de recherche en biologie médicale (nouveaux biomarqueurs, méthodes analytiques, DM-DIV)",
    "ptj_kine":           "Physical Therapy Journal (PTJ/APTA) — Essai clinique ou méta-analyse en kinésithérapie et rééducation fonctionnelle",
    "bjog":               "BJOG (British Journal of Obstetrics and Gynaecology) — Essai clinique ou méta-analyse en obstétrique et pratique sage-femme",
    "cpt_pharmacol":      "Clinical Pharmacology & Therapeutics (ASCPT) — Article de recherche en pharmacologie clinique (pharmacocinétique, interactions, nouvelles molécules)",
    "jdr_dental":         "Journal of Dental Research (IADR) — Essai clinique ou étude en chirurgie dentaire, parodontologie, implantologie, orthodontie",
    "jan_nursing":        "Journal of Advanced Nursing (JAN) — Essai clinique ou étude en sciences infirmières et pratiques de soins",
    # ── PubMed — chirurgie vasculaire ────────────────────────────────────────
    "pubmed_jvs":           "Journal of Vascular Surgery (JVS) — Essai clinique, registre ou méta-analyse en chirurgie vasculaire ouverte et endovasculaire (AAA, AOMI, carotide, CLTI)",
    "pubmed_ejves":         "European Journal of Vascular and Endovascular Surgery (EJVES/ESVS) — Guidelines ESVS et essais cliniques en chirurgie vasculaire européenne",
    "pubmed_jet":           "Journal of Endovascular Therapy (JET) — Techniques endovasculaires : EVAR, TEVAR, FEVAR, drug-coated balloons, stenting carotide (CAS/TCAR)",
    "pubmed_ann_vasc_surg": "Annals of Vascular Surgery — Chirurgie vasculaire francophone : techniques opératoires, résultats, complications",
    # ── Presse médicale professionnelle ─────────────────────────────────────
    "vascular_specialist": "Vascular Specialist (SVS official newspaper) — Presse médicale chirurgie vasculaire : nouveaux dispositifs, résultats d'essais pivots, congrès SVS/ESVS/VEITH. Journaliste médical spécialisé, pas chercheur.",
    "vascular_news":       "Vascular News — Presse médicale vasculaire internationale : résultats d'études, approbations CE/FDA dispositifs endovasculaires, congrès ESVS/CIRSE/LINC. Peut couvrir alertes réglementaires ou changements de guideline.",
    "tctmd":               "TCTMD (Cardiovascular Research Foundation) — Presse médicale interventionnelle : vasculaire périphérique (stenting iliaque, CLTI, carotide, AOMI), plus cardiologie interventionnelle. Filtrer sévèrement ce qui ne concerne pas le chirurgien vasculaire.",
    "quotidien_medecin":   "Le Quotidien du Médecin — Presse médicale française généraliste : peut couvrir alertes ANSM, nouvelles recommandations HAS, changements de remboursement. Bruit élevé (politique santé, RH médicales) → ne retenir que les news cliniquement actionnables.",
    "egora":               "Egora — Presse médicale libérale française : orientation médecine générale, parfois alertes réglementaires ou nouveaux remboursements. Bruit très élevé → seuil maximal.",
    # ── PubMed — chirurgie plastique & reconstructrice ────────────────────────
    "pubmed_prs":          "Plastic and Reconstructive Surgery (PRS/ASPS) — Essai clinique, méta-analyse ou guideline ASPS en chirurgie plastique reconstructrice et esthétique",
    "pubmed_jpras":        "Journal of Plastic, Reconstructive & Aesthetic Surgery (JPRAS/BAPRAS/ESPRAS) — Études multicentriques européennes : reconstruction mammaire, microchirurgie, brûlures, chirurgie de la main",
    "pubmed_asj":          "Aesthetic Surgery Journal (ASJ/ASAPS) — Essai clinique ou guideline en chirurgie esthétique : rhinoplastie, mammoplastie, liposuccion, lifting, implants mammaires",
    "pubmed_ann_plast_surg":"Annals of Plastic Surgery — Chirurgie plastique reconstructrice : méta-analyses techniques reconstructives, études multicentriques",
    "pubmed_jhs_am":       "Journal of Hand Surgery American (ASSH) — Essai clinique ou méta-analyse en chirurgie de la main : tendons, nerfs, arthroplastie digitale, Dupuytren, canal carpien",
    "pubmed_jhs_eur":      "Journal of Hand Surgery European (FESSH) — Études européennes en chirurgie de la main : registres nordiques, séries multicentriques FESSH",
    "pubmed_jrms":         "Journal of Reconstructive Microsurgery (JRM) — Essai clinique ou méta-analyse en microchirurgie reconstructrice : lambeaux libres (DIEP, ALT, fibula), replantations, lymphœdème microsurgical",
    "pubmed_microsurgery": "Microsurgery (Wiley) — Études en microchirurgie : anastomoses, cartographie perforateurs, techniques LVA/VLNT lymphatique, transferts nerveux",
    "pubmed_burns":        "Burns (Elsevier) — Essai clinique ou méta-analyse en chirurgie et prise en charge des brûlures : substituts cutanés, excision-greffe, cicatrisation, réhabilitation",
    "pubmed_acpe":         "Annales de Chirurgie Plastique Esthétique (ACPE/SOFCPRE) — Journal officiel SOFCPRE : études françaises, recommandations SOFCPRE, registres implants mammaires, bilinguisme FR/EN",
    "pubmed_prs_guidelines":   "PRS Guidelines ASPS — Recommandation ou consensus ASPS en chirurgie plastique : sécurité implants mammaires, BIA-ALCL, reconstruction mammaire, techniques esthétiques",
    "pubmed_jpras_guidelines": "JPRAS Guidelines BAPRAS/ESPRAS — Recommandation européenne chirurgie plastique : reconstruction, brûlures, main, techniques esthétiques",
}

# ---------------------------------------------------------------------------
# Mapping source → spécialité principale (pour sélection du prompt dédié)
# Seules les sources mono-spécialité ont une entrée ici.
# Les sources multi-spécialités (JORF, HAS, JAMA…) n'ont PAS d'entrée →
# le prompt générique est utilisé, la spécialité est déterminée par le LLM.
# ---------------------------------------------------------------------------
SOURCE_SPECIALTY_HINTS: dict[str, str] = {
    # ── Chirurgie vasculaire ───────────────────────────────────────────────
    "pubmed_jvs":              "chirurgie-vasculaire",
    "pubmed_ejves":            "chirurgie-vasculaire",
    "pubmed_ejves_guidelines": "chirurgie-vasculaire",
    "pubmed_jet":              "chirurgie-vasculaire",
    "pubmed_ann_vasc_surg":    "chirurgie-vasculaire",
    "pubmed_jama_surgery":     "chirurgie-vasculaire",  # filtré sur termes vasculaires
    "vascular_specialist":     "chirurgie-vasculaire",
    "vascular_news":           "chirurgie-vasculaire",
    "endovascular_today":      "chirurgie-vasculaire",
    # linc_highlights / evc_highlights désactivés (domaines NXDOMAIN)
    "esvs":                    "chirurgie-vasculaire",
    "sfcv":                    "chirurgie-vasculaire",
    "sfmv":                    "chirurgie-vasculaire",
    # ── TCTMD — multi-spécialité (vasculaire + cardio interventionnel) ─────
    # Pas de specialty_hint → prompt générique : le LLM classe chaque article
    # en chirurgie-vasculaire OU chirurgie-cardiaque selon le contenu.
    # "tctmd": None  ← absent du dict = comportement générique automatique
    # ── Chirurgie cardiaque ────────────────────────────────────────────────
    "pubmed_jtcvs":               "chirurgie-cardiaque",
    "pubmed_ejcts":               "chirurgie-cardiaque",
    "pubmed_ejcts_guidelines":    "chirurgie-cardiaque",
    "pubmed_ann_thorac_surg":     "chirurgie-cardiaque",
    "pubmed_circulation_card":    "chirurgie-cardiaque",
    "pubmed_jacc_card":           "chirurgie-cardiaque",
    "pubmed_jacc_interv":         "chirurgie-cardiaque",
    "pubmed_eur_heart_j":         "chirurgie-cardiaque",
    "pubmed_jhlt":                "chirurgie-cardiaque",  # Journal of Heart and Lung Transplantation
    "pubmed_eurointerv":          "chirurgie-cardiaque",  # EuroIntervention — structural heart
    "pubmed_circ_heart_fail":     "chirurgie-cardiaque",  # Circulation: Heart Failure
    "pubmed_esc_guidelines":      "chirurgie-cardiaque",  # ESC Guidelines via EHJ
    "pubmed_sts_guidelines":      "chirurgie-cardiaque",  # STS Guidelines via Ann Thorac Surg
    "arch_cardiovasc_dis":        "chirurgie-cardiaque",  # RSS ScienceDirect — SFC officiel
    "eacts":                      "chirurgie-cardiaque",
    "sfctcv":                     "chirurgie-cardiaque",
    # ── Chirurgie orthopédique ─────────────────────────────────────────────────
    "pubmed_jbjs":                "chirurgie-orthopedique",
    "pubmed_bone_joint_j":        "chirurgie-orthopedique",
    "pubmed_corr":                "chirurgie-orthopedique",
    "pubmed_jarthroplasty":       "chirurgie-orthopedique",
    "pubmed_kssta":               "chirurgie-orthopedique",
    "pubmed_acta_orthop":         "chirurgie-orthopedique",
    "pubmed_otsr":                "chirurgie-orthopedique",
    "pubmed_otsr_guidelines":     "chirurgie-orthopedique",
    "pubmed_efort_guidelines":    "chirurgie-orthopedique",
    # efort (RSS) déjà configuré dans sources_europe.py → specialty_hint implicite
    "pubmed_ajsm":                "chirurgie-orthopedique",
    "pubmed_arthroscopy":         "chirurgie-orthopedique",
    "pubmed_jses":                "chirurgie-orthopedique",
    "pubmed_spine":               "chirurgie-orthopedique",
    "pubmed_j_orthop_trauma":     "chirurgie-orthopedique",
    "pubmed_int_orthop":          "chirurgie-orthopedique",
    "pubmed_arch_orthop_trauma":  "chirurgie-orthopedique",
    # ── Chirurgie plastique & reconstructrice ─────────────────────────────────
    "pubmed_prs":                 "chirurgie-plastique",
    "pubmed_jpras":               "chirurgie-plastique",
    "pubmed_asj":                 "chirurgie-plastique",
    "pubmed_ann_plast_surg":      "chirurgie-plastique",
    "pubmed_jhs_am":              "chirurgie-plastique",
    "pubmed_jhs_eur":             "chirurgie-plastique",
    "pubmed_jrms":                "chirurgie-plastique",
    "pubmed_microsurgery":        "chirurgie-plastique",
    "pubmed_burns":               "chirurgie-plastique",
    "pubmed_acpe":                "chirurgie-plastique",
    "pubmed_prs_guidelines":      "chirurgie-plastique",
    "pubmed_jpras_guidelines":    "chirurgie-plastique",
    # ── Cardiologie (à activer quand le prompt cardiologie sera implémenté) ──
    # "jama_cardiology":      "cardiologie",
    # "sfc_recommandations":  "cardiologie",
    # "sfhta":                "cardiologie",
    # ── Oncologie ──────────────────────────────────────────────────────────
    # "jama_oncology":        "oncologie",
    # "esmo":                 "oncologie",
    # ── Pneumologie ────────────────────────────────────────────────────────
    # "splf":                 "pneumologie",
    # "ers":                  "pneumologie",
    # … (ajouter au fur et à mesure des prompts spécialité implémentés)
}

# ---------------------------------------------------------------------------
# Addendum spécialité — injecté à la fin du SYSTEM_PROMPT pour les sources
# mono-spécialité. Chaque addendum affine : contexte clinique, terminologie,
# exemples de rédaction dans le style de la presse de la spécialité.
# ---------------------------------------------------------------------------

_SPECIALTY_ADDENDUM_VASCULAIRE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE VASCULAIRE ET ENDOVASCULAIRE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien vasculaire (CHU / clinique privée, France / Europe), \
maîtrisant chirurgie ouverte ET techniques endovasculaires (EVAR, TEVAR, FEVAR, \
CAS, CEA, TCAR, pontage, endarterectomie, DCB/DES infrainguinal). \
Référentiels actuels : ESVS guidelines 2023-2024, ESC/ESVS joint guidelines, \
recommandations SFCV/SFMV, HAS. \
Essais pivots récents de référence : BEST-CLI, BASIL-2, ACST-2, ACST-3, \
ROADSTER-3, TRITON, IN.PACT SFA 5 ans, CALCIFIED, ZILVER PTX 10 ans.

CRITÈRE DE PERTINENCE VASCULAIRE :
"Ce résultat va-t-il modifier une décision chirurgicale, le choix d'un dispositif, \
ou la stratégie de prise en charge dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une pratique \
déjà établie sans gain de précision, population non représentative de la pratique \
FR/EU (ex. cohorte mono-centrique asiatique sans équivalent anatomique), \
sous-groupe non pré-spécifié sur petits effectifs.

TERMINOLOGIE — employer sans guillemets ni définition :
AAA / anévrisme de l'aorte abdominale, EVAR, TEVAR, FEVAR, BEVAR, \
chimney / snorkel, zone d'étanchéité (ZE), collet proximal, endofuite type I/II/III/IV, \
CLTI (Chronic Limb-Threatening Ischaemia), AOMI, Rutherford 4/5/6, IPS (ABI), \
GLASS (Global Anatomic Staging System), TASC, CEA, CAS, TCAR (nFlow), ICA/ECA, \
patency primaire / secondaire / assistée, MALE (Major Adverse Limb Events), \
MACE, TLR (Target Lesion Revascularisation), TVP iliaque / fémorale, \
FAV (fistule artério-veineuse), cathéter tunnelisé, DCB (Drug-Coated Balloon), \
DES (Drug-Eluting Stent), PTA, atherectomie orbitale / rotatoire / laser, \
thrombolyse CDT, EKOS, pontage infrainguinal, veine grande saphène (VGS), \
prothèse PTFE / Dacron, endarterectomie carotide / rénale.

EXEMPLES DE RÉDACTION (style EJVES / JVS / Vascular Specialist — format cible) :

Essai clinique (innovation, presse ou académique) :
  titre_court : "DCB vs PTA pour lésions FP : CHALLENGER DCB 12 mois"
  resume : "CHALLENGER DCB (N=437, occlusions fémorales 5–25 cm, suivi 12 mois) : \
perméabilité primaire 78,3 % (DCB) vs 61,2 % (PTA seule) — p < 0,001. \
TLR à 12 mois : 8,4 % vs 19,6 % (HR 0,40 ; IC95% 0,27–0,59). \
Population comparable aux cohortes IN.PACT SFA et THUNDER. \
Absence d'excès de mortalité tardive (signal paclitaxel non confirmé à 1 an)."
  impact_pratique : "En pratique : consolide l'indication DCB pour les lésions FP \
≤ 25 cm ; données à 5 ans attendues pour statuer sur la sécurité long terme."

Nouveau dispositif (presse médicale) :
  titre_court : "Gore EXCLUDER Conformable : CE mark AAA col court/angulé"
  resume : "Gore EXCLUDER Conformable avec ACTIVE CONTROL System (CE mark jan. 2026) : \
conçu pour les AAA à col proximal court (8–15 mm) ou angulé (> 60°). \
CONFORMABLE-EVAR (n=186, suivi 2 ans) : succès technique 98,4 %, absence \
d'endofuite type I/III 97,2 %, réintervention pour endofuite 3,2 %. \
Anatomie cible précédemment dévolue à la chirurgie ouverte ou aux fenestrations."
  impact_pratique : "En pratique : alternative endovasculaire pour les AAA complexes \
sans accès à un programme FEVAR/BEVAR — vérification IFU anatomique indispensable."

Guideline update :
  titre_court : "ESVS 2024 CLTI : bypass first-line pour lésions GLASS grade 3"
  resume : "ESVS Guidelines AOMI 2024 (EJVES suppl.) : révision majeure du chapitre CLTI. \
Bypass avec VGS recommandé en 1re intention pour lésions GLASS grade 3 infrainguinales \
(recommandation IA). Endovasculaire conservé pour grade 1-2 (IA). \
Basé sur BEST-CLI (N=1 830) : MALE-free survival à 4 ans +7,9 points avec bypass \
chez les patients candidats au VGS (p=0,004)."
  impact_pratique : "À retenir : classification GLASS systématique en RCP devient \
opposable — grade 3 = orientation bypass de 1re intention."

Alerte sécurité dispositif :
  titre_court : "ANSM : suspension endoprothèses Endologix AFX2 lot xxxx"
  resume : "ANSM (décision 14 jan. 2026) : suspension d'implantation des endoprothèses \
Endologix AFX2 (lot xxxx) après 7 cas de migration proximale précoce en matériovigilance \
(délai médian 18 mois post-implant). Environ 340 prothèses implantées en France depuis 2023. \
Mesure conservatoire — surveillance renforcée des patients porteurs."
  impact_pratique : "En pratique : identifier les patients porteurs d'un AFX2 du lot \
concerné et planifier un scanner de contrôle sans attendre le suivi annuel."
"""

_SPECIALTY_ADDENDUM_CARDIAQUE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE CARDIAQUE ET CARDIO-THORACIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien cardiaque (CHU / clinique privée, France / Europe), \
maîtrisant chirurgie à cœur ouvert sous CEC ET techniques mini-invasives (MICS, \
robotique, TAVI/TAVR, MitraClip/TEER, structural heart en Heart Team). \
Référentiels actuels : ESC/EACTS Guidelines valvulaire 2021, ESC Guidelines \
revascularisation myocardique 2018/2024, EACTS Guidelines chirurgie de l'aorte 2024, \
ESC/EACTS FA 2020, recommandations SFCTCV / SFC. \
Essais pivots récents de référence : PARTNER 3, Evolut Low Risk (TAVI risque faible), \
COAPT, MITRA-FR (MitraClip IM secondaire), CLASP IID/IIF (TEER mitral/tricuspide), \
TRILUMINATE Pivotal (TEER tricuspide), EXCEL long-term, NOBLE 10 ans \
(CABG vs PCI tronc commun), MOMENTUM 3 / HeartMate 3 (LVAD), ROOBY (off-pump).

CRITÈRE DE PERTINENCE CARDIAQUE :
"Ce résultat va-t-il modifier une indication opératoire, le choix d'un dispositif \
prothétique valvulaire ou de revascularisation, ou la stratégie de prise en charge \
dans la Heart Team dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires sans gain de précision \
clinique, population non représentative de la pratique FR/EU (cohorte mono-centrique \
asiatique sans équivalent anatomique, exclusion systématique des > 80 ans qui sont \
la majorité des TAVI en France), sous-groupe non pré-spécifié sur petits effectifs.
ATTENTION : en cardiologie interventionnelle (TAVI, MitraClip, coronaire), une étude \
peut être pertinente à la fois pour le chirurgien cardiaque ET le cardiologue \
interventionnel — toujours vérifier quel praticien prend la décision finale en Heart Team.

TERMINOLOGIE — employer sans guillemets ni définition :
RA (rétrécissement aortique) / IM (insuffisance mitrale) / IT (insuffisance tricuspide), \
SAVR (Surgical Aortic Valve Replacement), TAVI/TAVR (Transcatheter Aortic Valve \
Implantation/Replacement), SVD (Structural Valve Deterioration — dégénérescence \
structurelle), EOA (Effective Orifice Area — surface effective d'ouverture), \
PPM (Prothèse Prothèse-Patient Mismatch), TEER (Transcatheter Edge-to-Edge Repair), \
CEC (circulation extracorporelle), DCC (défibrillation / cardioversion), \
CABG (Coronary Artery Bypass Grafting), CEC / off-pump (à cœur battant), \
VGS (veine grande saphène), ITA (artère thoracique interne) / LIMA / RIMA, \
Bentall (remplacement aorte ascendante + valvule + réimplantation coronaires), \
Ross (autogreffe pulmonaire), Maze / Cox-Maze IV (ablation chirurgicale FA), \
LVAD (Left Ventricular Assist Device), ECMO-VA (extracorporeal membrane oxygenation \
veino-artérielle), LCOS (Low Cardiac Output Syndrome), MACCE (Major Adverse Cardiac \
and Cerebrovascular Events), NYHA (classe fonctionnelle I-IV), \
KCCQ (Kansas City Cardiomyopathy Questionnaire — QdV), STS score / EuroSCORE II, \
Heart Team (décision interdisciplinaire chirurgien + cardiologue interventionnel).

EXEMPLES DE RÉDACTION (style JTCVS / EJCTS / Arch Cardiovasc Dis — format cible) :

Essai clinique TAVI (innovation) :
  titre_court : "TAVI vs SAVR risque faible : PARTNER 3 à 5 ans"
  resume : "PARTNER 3 (N=1 000, risque faible STS <4 %, suivi 5 ans) : taux composite \
MACCE (décès + AVC + réhospitalisation) : 22,8 % (TAVI) vs 27,2 % (SAVR) — \
non-infériorité confirmée (p<0,001). SVD radiologique à 5 ans comparable (5,3 % vs 4,9 %). \
Sous-groupe < 70 ans : tendance à plus de SVD TAVI mais non significatif (effectif limité)."
  impact_pratique : "À retenir : TAVI confirme sa non-infériorité à 5 ans chez les < 80 ans à \
risque faible — la discussion Heart Team doit intégrer la durabilité à 20 ans, \
déterminante pour les sujets < 65 ans (données insuffisantes)."

Guideline update :
  titre_court : "ESC/EACTS 2024 : TAVI étendu aux < 70 ans en Heart Team"
  resume : "ESC/EACTS Guidelines valvulaires (mise à jour oct. 2024) : TAVI recommandé \
(IIaB) pour les patients de 70-75 ans si anatomie favorable et accord Heart Team. \
SAVR reste recommandation IA pour < 65 ans. Nouvelle recommandation sur la valve \
bicuspide : TAVI n'est plus contre-indiqué (IIaB si anatomie adaptée et opérateur expert)."
  impact_pratique : "En pratique : la tranche 70-75 ans entre dans le champ TAVI — \
la Heart Team doit formaliser la discussion anatomique (MDCT) et documenter le consentement \
comparatif TAVI/SAVR pour cette tranche d'âge."

Nouveau dispositif / résultats de registre :
  titre_court : "TRILUMINATE Pivotal : TEER tricuspide CLASP à 1 an"
  resume : "TRILUMINATE Pivotal (N=350, IT sévère / très sévère symptomatique, \
non opérable, KCCQ 40±18) : réduction IT ≥1 grade à 1 an : 87 % (TEER) vs 49 % \
(traitement médical) — p<0,001. Mortalité 1 an : 14,5 % vs 22,6 %. \
KCCQ +12 points (TEER) vs +0,8 (contrôle)."
  impact_pratique : "En pratique : TEER tricuspide franchit le seuil de preuve randomisée \
— à discuter en Heart Team pour les IT sévères symptomatiques non chirurgicaux \
(STS > 8 % ou contre-indication opératoire)."

Alerte sécurité dispositif :
  titre_court : "ANSM : signal valve Perceval S lot xxxx — migration"
  resume : "ANSM (décision 8 fév. 2026) : surveillance renforcée des bioprothèses \
Perceval S (Corcym, lot xxxx) après 4 cas de migration valvulaire précoce en \
matériovigilance (délai médian 22 mois). Environ 180 valves implantées en France. \
Mesure conservatoire — échocardiographie de contrôle recommandée avant 3 ans."
  impact_pratique : "En pratique : identifier les patients porteurs d'un Perceval S du \
lot concerné et planifier un ETT de surveillance avant l'échéance habituelle."
"""

_SPECIALTY_ADDENDUM_PLASTIQUE = """\
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTEXTE SPÉCIALITÉ — CHIRURGIE PLASTIQUE, RECONSTRUCTRICE ET ESTHÉTIQUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

LECTEUR CIBLE : chirurgien plasticien reconstructeur (CHU / clinique privée, France / Europe), \
maîtrisant reconstruction mammaire post-mastectomie (DIEP, TRAM, Grand Dorsal, implant), \
microchirurgie (lambeaux libres, replantations), chirurgie de la main (tendons, nerfs, \
Dupuytren), brûlures (excision-greffe, substituts cutanés), chirurgie esthétique \
(rhinoplastie, mammoplastie, liposuccion, lifting). \
Référentiels actuels : ASPS guidelines reconstruction mammaire 2022, ASPS/NCCN BIA-ALCL \
2024, SOFCPRE recommandations nationales, BAPRAS/ESPRAS guidelines, FESSH (main). \
Essais pivots récents de référence : MACS lift RCT, essais randomisés Botox vs chirurgie \
esthétique, DIEP vs implant reconstruction mammaire, canal carpien endoscopique vs ouvert \
(Cochrane), RECELL essai brûlures pivotal.

CRITÈRE DE PERTINENCE PLASTIQUE :
"Ce résultat va-t-il modifier une indication opératoire, le choix d'une technique \
reconstructrice, la sélection des patients candidats à une procédure esthétique, \
ou la gestion d'une complication dans les 1-3 ans qui viennent ?" \
Rejeter même un RCT bien conduit si : résultats confirmatoires d'une technique déjà \
établie sans gain de précision clinique, études de satisfaction patient non validées \
(questionnaire maison, non comparatif), description de technique sans résultats cliniques \
comparatifs, cohortes de moins de 50 patients pour les études non-RCT.

FILTRES SPÉCIFIQUES CHIRURGIE ESTHÉTIQUE :
→ Retenir : RCTs comparant deux techniques chirurgicales esthétiques (ex. SMAS vs deep plane \
lifting), méta-analyses sur complications d'implants, études multicentriques sur résultats \
à long terme rhinoplastie, guidelines sur sécurité des procédures esthétiques invasives. \
→ Rejeter : études de satisfaction sur moins de 100 patients, cohortes rétrospectives \
monocentriques sans comparateur actif, études sur injectables non-chirurgicaux (toxine \
botulique, acide hyaluronique) sauf si complication grave ou changement de pratique majeur.

TERMINOLOGIE — employer sans guillemets ni définition :
DIEP (Deep Inferior Epigastric Perforator flap), TRAM (Transverse Rectus Abdominis \
Myocutaneous flap), Grand Dorsal + implant, SGAP/IGAP (fessiers), ALT (Antero-Lateral \
Thigh flap), lambeau antébrachial radial, lambeau fibulaire (NF libre), \
expandeur + implant en 2 temps (prepectoral vs subpectoral), lipofilling mammaire, \
BIA-ALCL (Breast Implant-Associated Anaplastic Large Cell Lymphoma), BIA-SIA \
(Breast Implant Illness), texturé macro/micro, contraction capsulaire (Baker I-IV), \
capsulectomie totale / partielle, rhinoplastie ouverte/fermée, SMAS (Superficial \
Musculoaponeurotic System), deep plane lifting, MACS lift, blépharoplastie \
supérieure/inférieure, mammoplastie de réduction (Lejour, Wise, inverted-T), \
abdominoplastie (lipoabdominoplastie, mini-abdominoplastie), liposuccion (VASER, \
power-assisted), liposuccion haute définition, suture tendon (Kessler, Tsuge, Savage), \
greffe nerveuse, transfert nerveux (Oberlin, Souquet), tunnel carpien / canal de \
Guyon, aponévrotomie à l'aiguille Dupuytren, fasciectomie totale, arthroplastie \
PIP (Swanson, pyrocarbone), Integra / MatriDerm (substituts dermiques), RECELL \
(ReCell — spray de cellules autologues), greffe en maille (meshtome), cicatrisation \
dirigée par pression négative (NPWT), cicatrices hypertrophiques / chéloïdes, \
LVA (lympho-veinous anastomosis), VLNT (vascularized lymph node transfer), \
LYMPHA (Lymphatic Microsurgical Preventive Healing Approach), \
TRAM / DIEP bilatéral, flap delay, supercharge, perforasome, SCIP flap, MSCT \
(mapping préopératoire perforateurs), BREAST-Q (patient-reported outcomes reconstruction).

EXEMPLES DE RÉDACTION (style PRS / JPRAS / ACPE — format cible) :

Essai clinique reconstruction mammaire :
  titre_court : "DIEP vs implant prépectoral : RCT satisfaction à 2 ans"
  resume : "RCT multicentrique (N=312, mastectomie bilatérale prophylactique, suivi 24 mois) : \
score BREAST-Q satisfaction sein 74,2 ± 12,1 (DIEP) vs 68,5 ± 14,3 (implant prépectoral) — \
p = 0,012. Taux de complications majeures à 30 j : 8,2 % (DIEP) vs 5,1 % (implant). \
Durée opératoire médiane : 310 min (DIEP) vs 180 min (implant). \
Satisfaction mammaire à 2 ans significativement supérieure pour DIEP, au prix d'une \
morbidité peropératoire plus élevée."
  impact_pratique : "À retenir : DIEP offre une meilleure satisfaction à 2 ans chez les \
patientes à haut risque de complications implant (tabac, obésité, radiothérapie préalable) — \
discussion préopératoire à adapter selon le profil."

Guideline BIA-ALCL / implants :
  titre_court : "ASPS/NCCN 2024 : BIA-ALCL — explantation systématique si texturé macro"
  resume : "ASPS/NCCN Guideline BIA-ALCL (mise à jour 2024) : capsulectomie totale avec \
explantation recommandée (Grade 1A) pour tout BIA-ALCL confirmé, quel que soit le stade. \
Surveillance des patientes porteuses de texturés macros (Biocell, Siltex) : IRM + cytologie \
épanchement si symptômes (douleur, gonflement > 1 an post-op). \
Incidence cumulée révisée : 1/3 817 pour texturés macros Allergan (vs 1/355 000 lisses)."
  impact_pratique : "En pratique : proposer une information proactive aux patientes \
porteuses d'implants texturés Biocell/Siltex et planifier une surveillance échographique \
annuelle à partir de 5 ans post-implantation."

Essai clinique chirurgie de la main :
  titre_court : "Canal carpien : endoscopique vs ouvert — méta-analyse 34 RCTs"
  resume : "Méta-analyse (34 RCTs, N=4 203, suivi médian 12 mois) : libération endoscopique \
du canal carpien vs ouverte. Retour au travail : −9 jours (endoscopique) — IC95% −12 à −6 j. \
Douleur cicatricielle à 3 mois : SMD −0,42 (endoscopique) — p < 0,001. \
Complications équivalentes (taux global 3,1 % vs 3,4 %). Résultats fonctionnels (BCTQ, \
force de poignet) à 12 mois : pas de différence significative."
  impact_pratique : "En pratique : la libération endoscopique permet un retour au travail \
plus rapide et moins de douleur cicatricielle — avantage significatif chez les travailleurs \
manuels et les patients à contrainte professionnelle forte."

Alerte sécurité implants :
  titre_court : "ANSM : retrait implants mammaires Allergan Natrelle (lot xxxx)"
  resume : "ANSM (décision 3 mars 2026) : retrait du marché des implants mammaires \
Allergan Natrelle texturés Biocell (lot xxxx) après 12 nouveaux cas de BIA-ALCL \
en matériovigilance française (délai médian 9 ans post-implantation). \
Environ 2 800 implants du lot concerné implantés en France depuis 2018. \
Consultations de suivi recommandées en urgence pour les patientes porteuses."
  impact_pratique : "En pratique : identifier les patientes porteuses via registre \
d'implants, les contacter pour information et planifier une consultation de surveillance \
(examen clinique + imagerie selon symptômes) avant la fin du trimestre."
"""

_SPECIALTY_ADDENDA: dict[str, str] = {
    "chirurgie-vasculaire": _SPECIALTY_ADDENDUM_VASCULAIRE,
    "chirurgie-cardiaque":  _SPECIALTY_ADDENDUM_CARDIAQUE,
    "chirurgie-plastique":  _SPECIALTY_ADDENDUM_PLASTIQUE,
    # À implémenter : "cardiologie", "oncologie", "pneumologie", "neurologie", etc.
}


def build_system_prompt(specialty_hint: str | None = None) -> str:
    """Construit le system prompt adapté à la spécialité de la source.

    - specialty_hint présent et connu → SYSTEM_PROMPT + addendum spécialité
    - specialty_hint absent ou inconnu → SYSTEM_PROMPT générique seul
    """
    addendum = _SPECIALTY_ADDENDA.get(specialty_hint or "", "")
    if addendum:
        return SYSTEM_PROMPT + "\n\n" + addendum
    return SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Appel Claude async (Anthropic SDK — utilisé par le batch script)
# ---------------------------------------------------------------------------

async def call_claude_async(
    title: str,
    content: str | None,
    date_pub: str,
    source: str | None = None,
    max_retries: int = 3,
) -> dict[str, Any]:
    """Appel Anthropic async avec retry exponentiel sur 429/timeout."""
    source_hint      = SOURCE_HINTS.get(source or "", None)
    specialty_hint   = SOURCE_SPECIALTY_HINTS.get(source or "", None)
    is_press         = (source or "") in _PRESS_SOURCES
    is_innovation    = (source or "") in _INNOVATION_SOURCES
    system_prompt    = build_system_prompt(specialty_hint)
    user_prompt = _build_user_prompt(
        title, content, date_pub, source_hint,
        is_innovation=is_innovation,
        is_press=is_press,
    )
    client = _get_anthropic_client()

    last_error: Exception | None = None
    for attempt in range(max_retries):
        try:
            response = await client.messages.create(
                model=ANTHROPIC_MODEL,
                max_tokens=ANTHROPIC_MAX_TOKENS,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            raw_text = response.content[0].text
            return _parse_llm_output(raw_text)

        except anthropic.RateLimitError as e:
            last_error = e
            wait = 5 * (3 ** attempt)  # 5s, 15s, 45s
            logger.warning("Anthropic 429 (tentative %d/%d) — attente %ds", attempt + 1, max_retries, wait)
            await asyncio.sleep(wait)

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            last_error = e
            logger.warning("Parsing JSON échoué (tentative %d/%d): %s", attempt + 1, max_retries, e)
            if attempt == max_retries - 1:
                raise ValueError(f"json_parse_error: {e}") from e

        except Exception as e:
            last_error = e
            wait = 2 ** attempt
            logger.warning("Anthropic erreur (tentative %d/%d) — %s", attempt + 1, max_retries, e)
            await asyncio.sleep(wait)

    raise ValueError(f"Échec après {max_retries} tentatives: {last_error}")


async def analyse_candidate_async(
    candidate_id: str,
    title_raw: str,
    content_raw: str | None,
    official_date: str,
    source: str | None = None,
) -> dict[str, Any]:
    result = await call_claude_async(title_raw, content_raw, official_date, source=source)
    result["llm_model"]    = ANTHROPIC_MODEL
    result["candidate_id"] = candidate_id
    return result


# ---------------------------------------------------------------------------
# Configuration par source — seuils LLM pour créer un item
# ---------------------------------------------------------------------------

SOURCE_CONFIG: dict[str, dict] = {
    # ── Sources réglementaires ──────────────────────────────────────────────
    "legifrance_jorf": {
        "require_whitelist": True,   # titre doit contenir un terme santé
        "min_llm_score": 6,          # score_density LLM >= 6 pour créer un item
    },
    "ansm_securite": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "ansm_securite_med": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "ansm_securite_dm": {
        "require_whitelist": False,
        "min_llm_score": 6,  # Alertes DM — même exigence que les alertes médicaments
    },
    "ansm_ruptures_med": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "ansm_ruptures_vaccins": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "bo_social": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    "piste_kali": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "piste_legi": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    "piste_circ": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── Sources recommandations — seuil plus bas (contenu utile sans urgence) ─
    "has_rbp": {
        "require_whitelist": False,
        # Seuil relevé à 5 (vs 4 initial) pour éviter que des révisions mineures
        # ou des mises à jour cosmétiques de RBP noient la newsletter.
        # Seules les RBP apportant un changement clinique actionnable passent.
        "min_llm_score": 5,
    },
    "has_fiches_memo": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "has_parcours": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "has_outils": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "academie_medecine": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "sfc_recommandations": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "sfmu_recommandations": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "sfp_recommandations": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "sofcot_recommandations": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    "cngof_recommandations": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    # ── Sources bon usage / thérapeutique ────────────────────────────────────
    "ansm_bon_usage": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    # ── Sociétés savantes — toutes à min_llm_score=4 ─────────────────────────
    **{src: {"require_whitelist": False, "min_llm_score": 4} for src in [
        "cnge", "snfmi", "sfhta", "sfar", "sfn", "sfpsychiatrie",
        "snfge", "afef", "splf", "sfendocrino", "sfdiabete", "sfrhumato",
        "sforl", "afu", "sfgg", "sfndt", "sfctcv", "sfnc", "snfcp",
        "sfm_microbiologie", "sfcv", "sofcpre", "sofmer", "sfmv", "sfms",
        "sfalcoologie", "sfpathol", "sfmn", "sfscmfco", "sfmu",
        "sfpediatrie", "sfnn", "sfsp",
        "sfo", "afsos", "sfh", "sfr_radiologie",
        # sofcot = source web scraper (pas de RSS)
        "sofcot",
        # sfdermato retiré : aucun RSS disponible (vérifié mars 2026)
        "sofcpre_plastique", "sfcp", "sniil", "ffmkr", "cnsf", "sfbc", "fspf",
        # INCa — recommandations oncologie haute qualité
        "inca",
    ]},
    # ── HAS Commission Transparence — avis médicaments remboursables ──────
    # Faible volume, haute valeur : chaque avis impacte directement les prescriptions
    "has_ct": {
        "require_whitelist": False,
        "min_llm_score": 4,
    },
    # ── Santé publique France (articles + BEH) ───────────────────────────
    # RSS général SPF — données épidémio pas toujours actionnables directement
    # Seuil 5 : seules les alertes sanitaires et changements de recommandation passent
    "spf_beh": {
        "require_whitelist": False,
        "min_llm_score": 5,
    },
    # ── CNOM — déontologie et exercice libéral ────────────────────────────
    # Contenu institutionnel varié → whitelist médicale + seuil 5
    # CGU CNOM autorisent RSS avec attribution ✅
    "cnom": {
        "require_whitelist": True,
        "min_llm_score": 5,
    },
    # Sources retirées après audit mars 2026 :
    # "ameli_pro" → login requis
    # "andpc"     → pas de RSS, CGU restrictives
    # "inca"      → pas de RSS, autorisation requise
    # "spf_maladies" → fusionné dans spf_beh
    # ── Sources innovation ─────────────────────────────────────────────────
    # JAMA journaux spécialisés : volume modéré, ciblés → seuil 6
    **{src: {"require_whitelist": False, "min_llm_score": 6} for src in [
        "jama", "jama_cardiology", "jama_dermatology", "jama_internal_med",
        "jama_neurology", "jama_oncology", "jama_ophthalmology",
        "jama_otolaryngology", "jama_pediatrics", "jama_psychiatry",
        "jama_surgery", "nature_medicine",
    ]},
    # Journaux généralistes + JAMA Network Open : volume élevé → seuil 7 (filtrage strict)
    # NEJM/Lancet/BMJ publient ~100-150 articles/semaine — seules les études
    # vraiment pratique-changeantes doivent passer.
    **{src: {"require_whitelist": False, "min_llm_score": 7} for src in [
        "nejm", "lancet", "bmj", "jama_network_open",
    ]},
    # Sources paramédicales : volume faible, SNR élevé → seuil 6
    **{src: {"require_whitelist": False, "min_llm_score": 6} for src in [
        "clinical_chemistry", "ptj_kine", "bjog",
        "cpt_pharmacol", "jdr_dental", "jan_nursing",
    ]},
    # ── Sources PubMed — chirurgie vasculaire ─────────────────────────────
    # JVS/EJVES/JET : seuil relevé à 8 (était 5) — les score 7 représentaient
    # 75% du backlog avec valeur marginale faible pour la newsletter mensuelle.
    # Seuls les articles vraiment practice-changing (RCTs, NMAs, guidelines) passent.
    **{src: {"require_whitelist": False, "min_llm_score": 8} for src in [
        "pubmed_jvs", "pubmed_ejves", "pubmed_jet",
    ]},
    # Ann Vasc Surg : qualité plus variable (registres rétrospectifs, séries courtes)
    # → seuil relevé à 8 pour aligner sur JVS/EJVES et réduire le bruit.
    "pubmed_ann_vasc_surg": {"require_whitelist": False, "min_llm_score": 8},
    # EJVES Guidelines : filtre titre guideline/consensus → article toujours pertinent
    # → seuil bas à 4 (ne pas rater une guideline ESVS majeure).
    "pubmed_ejves_guidelines": {"require_whitelist": False, "min_llm_score": 4},
    # ── Presse médicale professionnelle ───────────────────────────────────────
    # Seuils alignés sur les min_score_hint définis dans sources_presse_medicale.py
    "vascular_specialist": {"require_whitelist": False, "min_llm_score": 7},
    "vascular_news":       {"require_whitelist": False, "min_llm_score": 7},
    "tctmd":               {"require_whitelist": False, "min_llm_score": 8},
    "quotidien_medecin":   {"require_whitelist": False, "min_llm_score": 8},
    "egora":               {"require_whitelist": False, "min_llm_score": 9},
    # JAMA Surgery via PubMed (RSS 403 depuis avril 2026) :
    # requête déjà filtrée sur termes vasculaires → seuil 6 (LLM affine).
    "pubmed_jama_surgery": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    # ── EMA — section Innovation ───────────────────────────────────────────
    # ema_new_medicines : ~200 AMM/an dont ~150 génériques/biosimilaires → bruit.
    # Seuil 8 : seule l'innovation truly breakthrough passe (first-in-class,
    # thérapie génique, pathologie sans alternative). Objectif : 5-15 items/an.
    "ema_new_medicines": {
        "require_whitelist": False,
        "min_llm_score": 8,
    },
    # ema_news : alertes sécurité EMA (retraits AMM, contre-indications).
    # Niveau alerte ANSM → seuil 6 comme ansm_securite.
    "ema_news": {
        "require_whitelist": False,
        "min_llm_score": 6,
    },
    # ── Sources PubMed — chirurgie orthopédique ───────────────────────────────
    # Seuil 7 : même logique que chirurgie cardiaque au lancement.
    # Ajustable vers 8 si trop de bruit (séries courtes, registres rétrospectifs).
    **{src: {"require_whitelist": False, "min_llm_score": 7} for src in [
        "pubmed_jbjs", "pubmed_bone_joint_j", "pubmed_corr",
        "pubmed_jarthroplasty", "pubmed_kssta", "pubmed_acta_orthop",
    ]},
    # OTSR : journal SOFCOT — moins sélectif que JBJS mais fort contexte FR → seuil 6.
    "pubmed_otsr": {"require_whitelist": False, "min_llm_score": 6},
    # Guidelines ortho : filtre titre déjà sélectif → seuil bas, ne pas rater.
    "pubmed_otsr_guidelines":  {"require_whitelist": False, "min_llm_score": 4},
    "pubmed_efort_guidelines": {"require_whitelist": False, "min_llm_score": 4},
    # Chirurgie du sport / sous-spécialités : IF élevé (AJSM, Arthroscopy) → seuil 7.
    **{src: {"require_whitelist": False, "min_llm_score": 7} for src in [
        "pubmed_ajsm", "pubmed_arthroscopy", "pubmed_jses",
        "pubmed_spine", "pubmed_j_orthop_trauma",
    ]},
    # Journaux européens complémentaires : IF plus modeste → seuil 6.
    **{src: {"require_whitelist": False, "min_llm_score": 6} for src in [
        "pubmed_int_orthop", "pubmed_arch_orthop_trauma",
    ]},
}

_DEFAULT_SOURCE_CONFIG = {"require_whitelist": False, "min_llm_score": 5}


def get_source_config(source: str | None) -> dict:
    return SOURCE_CONFIG.get(source or "", _DEFAULT_SOURCE_CONFIG)


# ---------------------------------------------------------------------------
# Whitelist JORF — au moins un terme santé doit apparaître dans le titre
# ---------------------------------------------------------------------------

_JORF_WHITELIST_PATTERNS = [
    # Professions de santé
    r"(?i)\bmédecin\b", r"(?i)\bmédicale?\b", r"(?i)\bpharmacie\b", r"(?i)\bpharmacien\b",
    r"(?i)\binfirmier", r"(?i)\bsage-femme\b", r"(?i)\bkinésithér", r"(?i)\bbiologiste\b",
    r"(?i)\bchirurgien\b", r"(?i)\bchirurgie\b", r"(?i)\bdentiste\b", r"(?i)\bodontolog",
    r"(?i)\borthophoniste\b", r"(?i)\borthoptiste\b", r"(?i)\bpodologue\b",
    r"(?i)\bpsychiatr", r"(?i)\bpsycholog",
    # Médicaments & dispositifs
    r"(?i)\bmédicament\b", r"(?i)\bspécialités? pharmaceutiques?\b", r"(?i)\bAMM\b",
    r"(?i)\bpharmacovigilance\b", r"(?i)\bsubstance\b",
    r"(?i)\bdispositif médical\b", r"(?i)\bmatériovigilance\b",
    r"(?i)\bvaccin", r"(?i)\bvaccination\b",
    # Remboursement & financement
    r"(?i)\bremboursement\b", r"(?i)\bnomenclature\b", r"(?i)\bcotation\b",
    r"(?i)\bhonoraires\b", r"(?i)\btarif\b", r"(?i)\bCPAM\b",
    r"(?i)\bassurance.maladie\b", r"(?i)\bsécurité sociale\b",
    r"(?i)\bconvention médicale\b", r"(?i)\bUNCAM\b",
    r"(?i)\bprescription\b", r"(?i)\bordonnance\b",
    # LPP — liste des produits et prestations (implants, dispositifs remboursés)
    r"(?i)\bLPP\b", r"(?i)\bliste\s+des\s+produits?\s+et\s+prestations?\b",
    r"(?i)\bproduits?\s+et\s+prestations?\s+remboursables?\b",
    r"(?i)\bprothèse\b", r"(?i)\bendoprothèse\b", r"(?i)\bimplant\b",
    r"(?i)\bDMI\b",   # Dispositif Médical Implantable (registre, nomenclature)
    # Système de santé
    r"(?i)\bsanté publique\b", r"(?i)\bétablissement de santé\b",
    r"(?i)\bhospitalier\b", r"(?i)\bclinique\b",
    r"(?i)\bARS\b", r"(?i)\bagence régionale de santé\b",
    r"(?i)\bprofessionnel de santé\b", r"(?i)\bexercice libéral\b",
    r"(?i)\btéléconsultation\b", r"(?i)\btelemédecine\b",
    r"(?i)\bprise en charge\b",
    # Pathologies / actes
    r"(?i)\bpatient\b", r"(?i)\bsoins\b", r"(?i)\bthérapeutique\b",
    r"(?i)\bcancer\b", r"(?i)\boncolog", r"(?i)\btumeur\b",
    r"(?i)\bcardiolog", r"(?i)\bneurolog", r"(?i)\bpédiatrie\b",
    r"(?i)\bmaternité\b", r"(?i)\bgrossesse\b", r"(?i)\baccouchement\b",
    r"(?i)\bdouleur\b", r"(?i)\banesthés",
    # Épidémiologie / santé publique
    # Nécessaires pour SPF, alertes sanitaires — termes absents de la whitelist JORF initiale
    r"(?i)\bdépistage\b",                           # coloscopie post-dépistage, cancer...
    r"(?i)\bépidémie\b",                            # alertes épidémiques
    r"(?i)\bépidémiolog",                           # épidémiologie, épidémiologique
    r"(?i)\bflambée\b",                             # flambée épidémique
    r"(?i)\bmorbidité\b",
    r"(?i)\bmortalité\b",
    r"(?i)\bincidence\b",
    r"(?i)\bprévalence\b",
    r"(?i)\binfectieux\b", r"(?i)\binfectieuse\b",
    r"(?i)\bfacteur(s)?\s+de\s+risque\b",
    r"(?i)\bprogramme\s+(national|de\s+dépistage|de\s+vaccination|de\s+prévention)\b",
]
_JORF_WHITELIST_RES = [re.compile(p) for p in _JORF_WHITELIST_PATTERNS]


def _passes_jorf_whitelist(title: str) -> bool:
    return any(p.search(title) for p in _JORF_WHITELIST_RES)


# ---------------------------------------------------------------------------
# Pré-filtre local (0 appel API)
# ---------------------------------------------------------------------------

_DROP_TITLE_PATTERNS = [
    # ── Nominations / RH ────────────────────────────────────────────────────
    r"(?i)\bnomination\b",
    r"(?i)portant nomination",
    r"(?i)\bavis de vacance",
    r"(?i)portant promotion de grade",
    r"(?i)portant d[eé]tachement",
    r"(?i)portant placement en disponibilit",
    r"(?i)portant titularisation",
    r"(?i)portant naturalisation",
    r"(?i)portant r[eé]int[eé]gration",
    r"(?i)portant radiation",
    r"(?i)portant d[eé]l[eé]gation de signature",
    r"(?i)\btableau d.avancement\b",
    r"(?i)\bliste d.aptitude\b",
    r"(?i)\bconcours\b",
    r"(?i)\bdocuments? déposés?",
    r"(?i)\brésultats? d[eu']",
    r"(?i)désignation d.un",
    r"(?i)cessation de fonctions?",
    r"(?i)admission à la retraite",
    # ── Justice / Magistrature ───────────────────────────────────────────────
    r"(?i)\bmagistrat(ure)?\b",
    r"(?i)tribunal administratif",
    r"(?i)cour administrative d.appel",
    r"(?i)conseil d.[eé]tat",
    r"(?i)d[eé]tachement judiciaire",
    # ── Militaire / Sécurité ────────────────────────────────────────────────
    r"(?i)\bofficier\b",
    r"(?i)\bsous-officier\b",
    r"(?i)\bgendarmerie\b",
    r"(?i)\barm[eé]e de\b",
    r"(?i)\bmarine nationale\b",
    r"(?i)\barmement\b",
    r"(?i)\bcote\s*&\s*score",
    r"(?i)\bmédaille\b",
    r"(?i)\bdécoration\b",
    r"(?i)\blégion d.honneur",
    r"(?i)\bordre national du mérite",
    # ── Divers hors scope ───────────────────────────────────────────────────
    r"(?i)\bjury\b",
    r"(?i)\bélection\b",
    r"(?i)\bassesseur\b",
    r"(?i)commission de discipline",
    r"(?i)administration p[eé]nitentiaire",
    r"(?i)\bpr[eé]fecture\b",
    r"(?i)\bambassadeur\b",
    r"(?i)\bconsulat\b",
    r"(?i)commissaire du gouvernement",
    r"(?i)contrôleur général",
    r"(?i)radiation des cadres",
    # ── Événements / Congrès / Appels (toutes sources) ──────────────────────
    # Ces titres n'apportent aucune info clinique actionnable
    r"(?i)\bappel\s+[àa]\s+candidature(s)?\b",
    r"(?i)\bappel\s+[àa]\s+(communication|abstract)(s)?\b",
    r"(?i)\boffre\s+d[e']\s*(emploi|poste)\b",
    r"(?i)\brecrutement\b",
    r"(?i)\bposte\s+(ouvert|[àa]\s+pourvoir)\b",
    r"(?i)\bfelicitation(s)?\b",
    r"(?i)\bfélicitation(s)?\b",
    r"(?i)\bprix\s+(de\s+(thèse|recherche|la\s+société)|annuel)\b",
    r"(?i)\bdistinction(s)?\s+honorifique(s)?\b",
    r"(?i)\bin\s+memoriam\b",
    r"(?i)\bnécrolog",
    r"(?i)\bnouveau(x)?\s+(président|bureau|conseil)\b",
    r"(?i)\bélection\s+du\s+(président|bureau|conseil)\b",
    r"(?i)\brésultats?\s+(de\s+l.élection|du\s+vote|du\s+scrutin)\b",
    r"(?i)\bvotre\s+inscription\b",
    r"(?i)\bprogramme\s+(définitif|complet|détaillé)\b",
    r"(?i)\bsave\s+the\s+date\b",
    r"(?i)\bj-\d+\s+(avant|pour)\b",                # J-30 avant le congrès
    r"(?i)\binscription(s)?\s+(ouvertes?|disponibles?|en\s+ligne)\b",
    r"(?i)\bformulaire\s+d.inscription\b",
    # ── Presse / Communiqués institutionnels sans contenu clinique ───────────
    r"(?i)\bcommuniqu[eé]\s+de\s+presse\b",
    r"(?i)\bconférence\s+de\s+presse\b",
    r"(?i)\boutcomes?\s+médiatiques?\b",
    r"(?i)\brevue\s+de\s+presse\b",
    # ── Finance / Gestion interne sociétés savantes ──────────────────────────
    r"(?i)\bcompte\s+rendu\s+(de\s+)?d[']?assembl[eé]e\s+g[eé]n[eé]rale\b",
    r"(?i)\brapport\s+moral\b",
    r"(?i)\brapport\s+financier\b",
    # ── Petites annonces / marché de l'occasion ──────────────────────────────
    # Détectées dans les feeds SPLF, SNFGE : ventes de matériel, offres de poste
    r"(?i)\bà\s+vendre\b",
    r"(?i)\bétat\s+(impeccable|neuf|excellent|parfait|bon)\b",
    r"(?i)\bocca?sion\b",
    r"(?i)(cherche?|recherche?)\s+(un|des|un\.e?)?\s*(remplaçant|remplacant|associé|collaborateur)",
    r"(?i)\bremplaçant(s|e|es)?\s+(cherch|disponible|libéral|pour\s+(congé|vacances))\b",
    r"(?i)\bcabinet.*\brecherche\b",
    r"(?i)\bposte\s+(de\s+)?(mé?decin|assistant|interne|praticien)\b",
    r"(?i)\bopportunit[eé]\s+(d[e']\s+)?installa",
    # ── Bourses / Prix / Appels à projets formation ───────────────────────────
    # "bourse" seul est trop risqué (bourse testiculaire → médical)
    # On cible les formulations typiques des sociétés savantes
    r"(?i)\bbourses?\s+(annuell|d[e']\s+recherche|de\s+voyage|MAHGE|DES|interne|master|thèse)",
    r"(?i)\bappel\s+[àa]\s+projets?\b",
    r"(?i)\bprix\s+\w+\s+202[0-9]\b",           # "Prix XYZ 2026"
    # ── Applications mobiles / outils numériques (annonces, pas recommandations)
    r"(?i)\bapplication\s+\w+\s+(est\s+)?disponible\b",
    r"(?i)\btélécharger\s+(notre|l[a'])\s+application\b",
    # ── Statuts / documents internes société ─────────────────────────────────
    r"(?i)^\s*statuts?\s*$",                     # titre = "Statuts" seul
    r"(?i)\bmise\s+[àa]\s+jour\s+des\s+statuts\b",
    r"(?i)\brèglement\s+int[eé]rieur\b",
    # ── HAS : documents préparatoires sans contenu clinique ──────────────────
    # "Note de cadrage" = document de planification (HAS annonce qu'elle VA travailler
    # sur X, pas de contenu clinique). "Note de synthèse" = document intermédiaire.
    # Ces titres finissent systématiquement par "– Note de cadrage" ou similaire.
    r"(?i)\bnote\s+de\s+cadrage\b",
    r"(?i)\bnote\s+de\s+synth[eè]se\b",
    # "Note de problématique" = autre doc préparatoire HAS
    r"(?i)\bnote\s+de\s+probl[eé]matique\b",
]
_DROP_TITLE_RES = [re.compile(p) for p in _DROP_TITLE_PATTERNS]

# ---------------------------------------------------------------------------
# Sources à fort volume ou bruit institutionnel — whitelist médicale obligatoire
# En plus de require_whitelist dans SOURCE_CONFIG, ce set permet d'appliquer
# le filtre au moment de la COLLECTE (avant insert DB) pour garder la DB propre.
# ---------------------------------------------------------------------------
NOISY_SOURCES: frozenset[str] = frozenset({
    "cnom",      # Ordre des Médecins — déontologie + contenu institutionnel varié
    "bo_social", # BO ministères sociaux — nombreuses circulaires hors santé
    "spf_beh",   # SPF — articles sans résumé, dont beaucoup non actionnables
                 # (ruralité, sociologie, statistiques) → whitelist médicale obligatoire
})

# Dispositifs médicaux non-médicamenteux — hors scope de tous les praticiens libéraux.
# NB : prothèses, implants, robots chirurgicaux, instruments de bloc sont CONSERVÉS
#      car ils concernent les chirurgiens libéraux. Le filtrage fin est géré par
#      type_praticien dans le pipeline LLM.
_ANSM_DM_EXCLUDE_PATTERNS = [
    # ── Équipements de confort / hôpital (non-clinique) ─────────────────────
    r"(?i)\bfauteuil roulant\b",
    r"(?i)\bdéambulateur\b",
    r"(?i)\blit médical\b",
    r"(?i)\bmatelas\b",
    r"(?i)\bcoussin\b",
    # ── Perfusion / pompes externes (DM hôpital, hors libéral) ──────────────
    r"(?i)\bdispositif de perfusion\b",
    r"(?i)\bpompe à insuline externe\b",
    r"(?i)\bpompe externe\b",
    # ── Monitoring / imagerie (DM institution, alerte biomédicale) ──────────
    r"(?i)\béchographe\b",
    r"(?i)\bscanner\b",
    r"(?i)\bIRM\b",
    r"(?i)\bmonitorage\b",
    r"(?i)\bsystème de monitorage\b",
    r"(?i)\bkwik-stik\b",
    r"(?i)\blyfo disk\b",
    r"(?i)\bbactériologie.*contrôle\b",
    r"(?i)\bcontrôle.*bactériologie\b",
    # ── Diagnostic in vitro / réactifs de laboratoire ────────────────────────
    r"(?i)\bréactif\b",
    r"(?i)dispositif de diagnostic in vitro",
    r"(?i)\bDM-DIV\b",
    r"(?i)\bautomate\b",
    r"(?i)\banalyseur\b",
    r"(?i)\bconsommable\b",
    r"(?i)réactif de laboratoire",
    r"(?i)kit de d[eé]tection",
    r"(?i)\bPCR\b",
    r"(?i)test rapide",
    # "bandelette" seul retiré : trop large — exclut les bandelettes de glycémie
    # (autocontrôle diabète) qui sont un DM ambulatoire courant pour MG, endocrinologues
    # et IDE. On cible uniquement les bandelettes de laboratoire hospitalier.
    r"(?i)\bbandelette\b.*\b(?:urinaire|bactériolog|laboratoire|réactif)\b",
    r"(?i)\b(?:urinaire|bactériolog|laboratoire)\b.*\bbandelette\b",
]
_ANSM_DM_EXCLUDE_RES = [re.compile(p) for p in _ANSM_DM_EXCLUDE_PATTERNS]

# Sources pour lesquelles on applique _ANSM_DM_EXCLUDE_PATTERNS
# (filtrage des DM non-cliniques avant appel LLM)
# ansm_securite_dm est EXCLU intentionnellement : c'est un feed 100% DM,
# on lui applique un filtre dédié _ANSM_DM_LIBÉRAL_EXCLUDE_PATTERNS ci-dessous.
_ANSM_SOURCES = {"ansm_securite", "ansm_securite_med", "ansm_ruptures_med", "ansm_ruptures_vaccins"}

# Filtre pré-LLM pour ansm_securite_dm : exclure les DM purement hospitaliers
# (biomédical, imagerie lourde, labo hospitalier) qui ne concernent ni le
# chirurgien libéral, ni l'infirmière libérale (IDEL).
_ANSM_DM_LIBERAL_EXCLUDE_PATTERNS = [
    r"(?i)\bautomate\b",           # automate de labo hospitalier
    r"(?i)\banalyseur\b",          # analyseur biologique
    r"(?i)\bréactif\b",            # réactifs de laboratoire
    r"(?i)\bDM-DIV\b",             # dispositif diagnostic in vitro
    r"(?i)diagnostic in vitro",
    r"(?i)\bIRM\b",
    r"(?i)\bscanner\b",
    r"(?i)\btomographe\b",
    r"(?i)\baccélérateur de particules\b",
    r"(?i)\blithotriteur\b",
    r"(?i)\bmonitorage hémodynamique\b",
    r"(?i)\bsystème de monitorage\b",
    r"(?i)\blit m[eé]dic(?:al|alis[eé])\b",   # "lit médical" et "lit médicalisé"
    r"(?i)\bmatelas\b",
    r"(?i)\bfauteuil roulant\b",
    r"(?i)\bdéambulateur\b",
    r"(?i)\bkwik.stik\b",
    r"(?i)\blyfo.disk\b",
]
_ANSM_DM_LIBERAL_EXCLUDE_RES = [re.compile(p) for p in _ANSM_DM_LIBERAL_EXCLUDE_PATTERNS]


def pre_filter_candidate(title: str, source: str | None = None) -> tuple[bool, str | None]:
    """Retourne (keep, reason). Si keep=False, pas besoin d'appel LLM."""
    t = (title or "").strip()
    if not t:
        return False, "empty_title"
    for pat in _DROP_TITLE_RES:
        if pat.search(t):
            return False, f"drop_title:{pat.pattern}"
    # Exclusion ANSM dispositifs médicaux non-médicamenteux (feeds généraux)
    if source in _ANSM_SOURCES:
        for pat in _ANSM_DM_EXCLUDE_RES:
            if pat.search(t):
                return False, f"ansm_dm:{pat.pattern}"
    # Exclusion ANSM DM libéral : filtre dédié pour ansm_securite_dm
    # Élimine les DM purement hospitaliers (labo, imagerie lourde)
    # avant appel LLM — conserve implants, instruments, DM soins infirmiers
    if source == "ansm_securite_dm":
        for pat in _ANSM_DM_LIBERAL_EXCLUDE_RES:
            if pat.search(t):
                return False, f"ansm_dm_liberal:{pat.pattern}"
    # Whitelist JORF : titre doit contenir au moins un terme santé
    cfg = get_source_config(source)
    if cfg.get("require_whitelist") and not _passes_jorf_whitelist(t):
        return False, "jorf_no_health_term"
    return True, None


# ---------------------------------------------------------------------------
# Appel Claude sync — wrapper sur l'async (utilisé par FastAPI routes)
# ---------------------------------------------------------------------------

def call_claude(
    title: str,
    content: str | None,
    date_pub: str,
    source: str | None = None,
    max_retries: int = 3,
) -> dict[str, Any]:
    """Wrapper sync sur call_claude_async.

    Utilise un ThreadPoolExecutor pour lancer asyncio.run() dans un thread
    dédié, ce qui évite le RuntimeError quand appelé depuis un event loop
    déjà en cours (routes FastAPI async).
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            asyncio.run,
            call_claude_async(title, content, date_pub, source=source, max_retries=max_retries),
        )
        return future.result()


# ---------------------------------------------------------------------------
# Parsing + validation
# ---------------------------------------------------------------------------

def _extract_json_block(text: str) -> str:
    """Extrait le premier bloc JSON complet (accolades équilibrées)."""
    start = text.find("{")
    if start == -1:
        raise ValueError("Pas de '{' trouvé")
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text[start:], start):
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise ValueError("JSON non fermé")


# ---------------------------------------------------------------------------
# Evidence JSON — valeurs valides
# ---------------------------------------------------------------------------

_VALID_STUDY_DESIGN = {
    "RCT", "meta-analysis", "registry", "prospective-cohort",
    "retrospective-cohort", "case-series", "guideline",
    "regulatory-decision", "technique-paper", "review", "editorial",
}
_VALID_PRIMARY_ENDPOINT = {
    "mortality", "patency", "limb-salvage", "stroke-TIA",
    "reintervention", "composite-MALE", "technical-success",
    "quality-of-life", "other",
}
_VALID_VASCULAR_DOMAIN = {
    "aorte-abdominale", "aorte-thoracique", "aorte-thoraco-abdominale",
    "carotide-TSA", "AOMI-femoro-poplite", "AOMI-sous-poplite",
    "ischemie-aigue-membre", "veineux-TVP-EP", "veineux-varices",
    "acces-vasculaire-dialyse", "renovasculaire", "traumatique",
    "multi-domaine", "non-vasculaire",
}
_VALID_INTERVENTION_TYPE = {
    "EVAR", "TEVAR", "FEVAR-BEVAR", "CAS", "TCAR", "PTA-stent", "DCB",
    "atherectomie", "thrombectomie-mecanique", "thrombolyse-CDT",
    "ablation-thermique", "ablation-non-thermique",
    "pontage", "endarterectomie", "reparation-ouverte", "hybride",
    "anticoagulation", "antiplatelet", "traitement-medical",
    "strategie-diagnostique", "surveillance", "multi-modalite", "autre",
}
_VALID_COMPARATOR = {
    "vs-chirurgie-ouverte", "vs-endovasculaire-autre", "vs-traitement-medical",
    "vs-placebo", "vs-standard-of-care", "aucun",
}
_VALID_CLINICAL_MATURITY = {
    "exploratory", "preliminary", "pivotal", "confirmatory",
    "practice-defining", "regulatory-event",
}
_VALID_ACTIONABILITY = {"immediate", "1-3y", "3-5y", "exploratory"}
_VALID_REGULATORY_MILESTONE = {
    "CE_mark", "AMM_europe", "FDA_approval", "remboursement_HAS",
    "CNAM_accord", "guideline_update", "autorisation_temporaire",
}
_VALID_GUIDELINE_BODY = {"ESVS", "ESC", "HAS", "AHA-ACC", "SFCV", "SFMV", "autre"}
_VALID_GUIDELINE_GRADE = {"IA", "IB", "IIaA", "IIaB", "IIbA", "IIbB", "III"}

# Matrice clinical_maturity × actionability_horizon → score de base
# Remplace le score LLM pour les sources innovation (plus fiable)
_MATURITY_SCORE: dict[tuple[str, str], int] = {
    ("practice-defining",  "immediate"):   9,
    ("regulatory-event",   "immediate"):   9,
    ("pivotal",            "immediate"):   8,   # rare : RCT adopté immédiatement
    ("practice-defining",  "1-3y"):        7,
    ("pivotal",            "1-3y"):        6,
    ("confirmatory",       "immediate"):   5,
    ("pivotal",            "3-5y"):        5,
    ("confirmatory",       "1-3y"):        4,
    ("preliminary",        "1-3y"):        4,
    ("preliminary",        "3-5y"):        3,
    ("confirmatory",       "3-5y"):        3,
    ("exploratory",        "immediate"):   4,
    ("exploratory",        "1-3y"):        3,
    ("exploratory",        "3-5y"):        2,
    ("exploratory",        "exploratory"): 2,
    ("preliminary",        "exploratory"): 2,
    ("confirmatory",       "exploratory"): 3,
}


def _derive_evidence_score(ev: dict) -> int | None:
    """
    Calcule un score_density fiable depuis evidence_json.
    Retourne None si les champs nécessaires sont absents.
    safety_signal et paradigm_shift forcent le score à 8 minimum.
    """
    maturity = ev.get("clinical_maturity")
    horizon  = ev.get("actionability_horizon")
    if not maturity or not horizon:
        return None

    score = _MATURITY_SCORE.get((maturity, horizon))
    if score is None:
        # Fallback : maturity seule
        _maturity_base = {
            "practice-defining": 8, "regulatory-event": 8,
            "pivotal": 6, "confirmatory": 4,
            "preliminary": 3, "exploratory": 2,
        }
        score = _maturity_base.get(maturity, 4)

    # Signaux critiques — toujours ≥ 8
    if ev.get("paradigm_shift") or ev.get("safety_signal"):
        score = max(score, 8)

    # Résultat négatif important → maintenir score si pivotal, sinon +1
    if ev.get("negative_result") and maturity == "pivotal":
        score = max(score, 6)

    return max(1, min(10, score))


def _validate_evidence_json(raw: Any) -> dict:
    """Valide et nettoie evidence_json. Retourne {} si invalide."""
    if not isinstance(raw, dict):
        return {}
    ev: dict = {}

    # Champs enum
    sd = raw.get("study_design")
    if sd in _VALID_STUDY_DESIGN:
        ev["study_design"] = sd

    for field, valid_set in [
        ("primary_endpoint", _VALID_PRIMARY_ENDPOINT),
        ("vascular_domain", _VALID_VASCULAR_DOMAIN),
        ("intervention_type", _VALID_INTERVENTION_TYPE),
        ("comparator_type", _VALID_COMPARATOR),
        ("clinical_maturity", _VALID_CLINICAL_MATURITY),
        ("actionability_horizon", _VALID_ACTIONABILITY),
        ("guideline_body", _VALID_GUIDELINE_BODY),
        ("guideline_grade", _VALID_GUIDELINE_GRADE),
    ]:
        val = raw.get(field)
        if val in valid_set:
            ev[field] = val
        elif val is not None and val != "null":
            ev[field] = None  # valeur invalide → null explicite

    rm = raw.get("regulatory_milestone")
    ev["regulatory_milestone"] = rm if rm in _VALID_REGULATORY_MILESTONE else None

    # Champs numériques
    for field in ("n_patients", "follow_up_months"):
        val = raw.get(field)
        if isinstance(val, (int, float)) and val > 0:
            ev[field] = int(val)
        else:
            ev[field] = None

    # Phase
    phase = raw.get("phase")
    ev["phase"] = str(phase) if str(phase) in {"1", "2", "3", "4"} else None

    # Booléens
    for field in ("multicentre", "primary_endpoint_met",
                  "paradigm_shift", "negative_result", "safety_signal"):
        val = raw.get(field)
        ev[field] = bool(val) if isinstance(val, bool) else None

    return ev


def _parse_llm_output(raw: str) -> dict[str, Any]:
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    json_str = _extract_json_block(cleaned)
    # Corriger les valeurs d'enum non quotées (ex: audience: PHARMACIENS → "PHARMACIENS")
    json_str = re.sub(
        r'("audience"\s*:\s*)([A-Z_]+)(\s*[,}])',
        lambda m: f'{m.group(1)}"{m.group(2)}"{m.group(3)}',
        json_str,
    )
    data = json.loads(json_str)

    if not isinstance(data.get("pertinent"), bool):
        raise ValueError("Champ 'pertinent' manquant ou invalide")

    audience = data.get("audience", "")
    if audience not in KNOWN_AUDIENCES:
        data["audience"] = "SPECIALITE"

    raw_slugs = data.get("specialites", [])
    data["specialites"] = [s for s in raw_slugs if s in KNOWN_SPECIALTIES]

    if data.get("type_praticien") not in KNOWN_TYPE_PRATICIEN:
        # Infer from audience/specialites if Claude missed it
        aud = data.get("audience", "")
        specs = data.get("specialites", [])
        if aud == "PHARMACIENS":
            data["type_praticien"] = "pharmacien"
        elif any(s.startswith("chirurgie") or s in ("anesthesiologie", "neurochirurgie",
                                                     "dentiste", "orthodontiste") for s in specs):
            data["type_praticien"] = "interventionnel"
        elif any(s in ("infirmiers", "kinesitherapie", "sage-femme", "biologiste") for s in specs):
            # Paramédicaux : "tous" est plus juste que "prescripteur" pour un avenant
            # NGAP kiné ou une modification des actes infirmiers.
            data["type_praticien"] = "tous"
        else:
            data["type_praticien"] = "prescripteur"

    try:
        data["score_density"] = max(1, min(10, int(data.get("score_density", 5))))
    except (TypeError, ValueError):
        data["score_density"] = 5

    # Valider score_par_specialite : garder uniquement les slugs connus avec scores valides
    raw_sps = data.get("score_par_specialite", {})
    if isinstance(raw_sps, dict):
        data["score_par_specialite"] = {
            slug: max(1, min(10, int(s)))
            for slug, s in raw_sps.items()
            if slug in KNOWN_SPECIALTIES
            and isinstance(s, (int, float))
        }
    else:
        data["score_par_specialite"] = {}

    KNOWN_CATEGORIES = {"clinique", "therapeutique", "exercice"}
    if data.get("categorie") not in KNOWN_CATEGORIES:
        data["categorie"] = None  # sera assigné rétroactivement

    if not isinstance(data.get("tri_json"), dict):
        data["tri_json"] = {}
    if not isinstance(data.get("lecture_json"), dict):
        data["lecture_json"] = {}

    # evidence_json — présent uniquement pour les sources innovation
    raw_ev = data.get("evidence_json")
    if raw_ev is not None:
        ev = _validate_evidence_json(raw_ev)
        data["evidence_json"] = ev if ev else None
        # Dériver le score depuis la matrice maturity×horizon — plus fiable que le LLM
        derived = _derive_evidence_score(ev) if ev else None
        if derived is not None:
            data["score_density"] = derived
    else:
        data["evidence_json"] = None

    return data


# ---------------------------------------------------------------------------
# Fonction principale
# ---------------------------------------------------------------------------

def analyse_candidate(
    candidate_id: str,
    title_raw: str,
    content_raw: str | None,
    official_date: str,
    source: str | None = None,
    llm_model: str = ANTHROPIC_MODEL,
) -> dict[str, Any]:
    """
    Analyse un candidat et retourne un dict prêt pour la table items.
    Lève une exception si l'appel LLM échoue.
    """
    result = call_claude(title_raw, content_raw, official_date, source=source)
    result["llm_model"]    = llm_model
    result["candidate_id"] = candidate_id
    return result
